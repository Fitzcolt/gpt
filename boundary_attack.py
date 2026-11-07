"""
Structural boundary ATTACK harness — v5: probing the four boundaries.

The adversary's mirror of the defensive middleware. Same four books, read from
the attacker's side of the wire: each book names a boundary the middleware
CLAIMS to hold, and this harness mounts the concrete payloads that try to cross
it. It drives the middleware IN-PROCESS — the target is constructed below and
called directly through ASGI, not reached over a socket — and reports, per
attack, whether the defense HELD *for the reason the attack targets*, held for
some other reason (a test that cannot detect a regression), or the payload
reached the application (a bypass / finding).

The four books as attack surfaces:

  BOOK I  — AMBIGUITY (what):     make the edge and the app disagree about the
        request. Duplicate a trusted header and hope for last-wins collapse;
        send CL+TE together for a desync; smuggle a non-numeric length or a
        NaN / non-canonical timestamp past a permissive parse; feed a malformed
        or self-referential signed-headers list; percent-encode the path so the
        decoded route matches a captured signature while the raw bytes differ.
        The middleware's move is to refuse the ambiguity at the grammar, not
        resolve it.
  BOOK II — EXTENT (how much):    lie about magnitude. Claim a small
        Content-Length while shipping megabytes, or ship an unbounded chunked
        body with no length at all, or bury the server in an oversized header
        block. The defense MEASURES instead of trusting the label.
  BOOK III— FRESHNESS (when):     move the request through time. Capture a
        valid request and replay it; back-date or post-date the timestamp to
        slide the skew window. The defense binds a signed timestamp + a
        single-use nonce.
  BOOK IV — LEAKAGE / COVERAGE (observable + signed set): forge, swap, inject.
        Forge a signature without the key; keep a valid signature but swap the
        body, query, path encoding or port under it; inject an unsigned
        decision header a captured HMAC still verifies around; downgrade
        coverage by declaring less than you send; exploit a non-injective
        canonical to reuse one signature for two different requests; skip the
        HTTP checks entirely by speaking WebSocket. The defense is a
        constant-time compare over a length-prefixed canonical, a server-side
        coverage floor, a body-hash bind, and fail-closed handling of every
        ASGI scope type.

Legitimate signed requests (HTTP and WebSocket) are included as CONTROLS: they
SHOULD reach the app — with the body intact — which is how the harness
distinguishes a real bypass from the requests that are supposed to get through.

Every attack names the rejection it expects (book + detail). An attack that is
blocked by a DIFFERENT check is reported as "WRONG REASON": the defense it was
written to exercise could be deleted and the test would still pass, so it is
counted as a finding against the harness.

Scope, stated plainly: everything here targets the StructuralBoundaryMiddleware
instance built in __main__. This is a self-test / red-team harness for that
middleware — code you own — not a client for arbitrary servers. Nothing here
opens a network connection, and the payloads are shaped to this middleware's
own SBv5 scheme, not a generic protocol. Point it at your own target.
"""

from __future__ import annotations

import hashlib
import heapq
import hmac
import json
import logging
import math
import re
import secrets
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]

log = logging.getLogger("structural_boundary")

# Headers we make a trust decision on: a duplicate is an ambiguity we refuse,
# not collapse last-wins.
_SENSITIVE_SINGLETON = (
    b"host",
    b"content-length",
    b"transfer-encoding",
    b"x-request-timestamp",
    b"x-request-nonce",
    b"x-request-signature",
    b"x-content-sha256",
    b"x-request-signed-headers",
)

# Decision headers that must be signed WHENEVER PRESENT. An unsigned one is
# an input the downstream will act on that the signer never saw. Extend per
# deployment: any header your app/framework/proxy treats as authoritative
# belongs here (or in required_signed_headers).
_DEFAULT_MUST_SIGN_IF_PRESENT = frozenset({
    b"authorization",
    b"content-encoding",   # body hash is over encoded bytes; app may decode
    b"content-length",
    b"content-type",
    b"cookie",
    b"forwarded",          # RFC 7239
    b"range",
    b"true-client-ip",
    b"x-forwarded-for",
    b"x-forwarded-host",
    b"x-forwarded-port",
    b"x-forwarded-prefix",
    b"x-forwarded-proto",
    b"x-http-method-override",
    b"x-method-override",
    b"x-original-url",
    b"x-real-ip",
    b"x-rewrite-url",
})

# The signed-headers list may never name the signature itself or the list
# itself: self-reference is not coverage.
_SELF_REFERENTIAL = frozenset({b"x-request-signature", b"x-request-signed-headers"})

_TOKEN_RE = re.compile(rb"[a-z0-9!#$%&'*+\-.^_`|~]+")
# Strict wire grammars. Python's float() accepts ' 1e9 ', '1_700_000_000',
# 'nan', 'inf'; int() accepts '+5' and '1_0'. Neither is a wire grammar.
_TS_RE = re.compile(rb"[0-9]{1,12}(?:\.[0-9]{1,9})?")
_NONCE_RE = re.compile(rb"[A-Za-z0-9_\-]{16,128}")
_SIG_RE = re.compile(rb"[0-9a-f]{64}")

# Domain separator: v5 signatures can never be confused with an earlier
# scheme's, even if every other field coincides. (v5 changed the canonical:
# raw path + root_path + full authority are now bound.)
_SCHEME = b"SBv5"


def _lp_join(fields: List[bytes]) -> bytes:
    """Length-prefixed join: injective by construction.

    b"\\n".join is NOT injective when a field may contain b"\\n" — the field
    boundary is information the encoding destroys. Emitting 'len:field' for
    each field preserves the boundary exactly, for any field bytes.
    """
    return b"".join(str(len(f)).encode("ascii") + b":" + f for f in fields)


class BoundaryViolation(Exception):
    def __init__(self, book: str, detail: str, status_code: int) -> None:
        self.book = book
        self.detail = detail
        self.status_code = status_code
        super().__init__(f"[{book}] {detail}")


def _parse_signed_headers(raw: bytes) -> List[bytes]:
    """Strict grammar for X-Request-Signed-Headers (Book I).

    Lowercase RFC tokens, ';'-separated, sorted, unique, no empty entries,
    no self-reference. Anything else is malformed — reject at the grammar,
    don't let a permissive parse downstream guess.
    """
    if not raw:
        raise BoundaryViolation("I_AMBIGUITY", "empty signed-headers list", 400)
    parts = raw.split(b";")
    for p in parts:
        if not _TOKEN_RE.fullmatch(p):  # also rejects '', uppercase, spaces
            raise BoundaryViolation("I_AMBIGUITY", f"malformed signed-header name {p!r}", 400)
    if len(set(parts)) != len(parts):
        raise BoundaryViolation("I_AMBIGUITY", "duplicate name in signed-headers list", 400)
    if parts != sorted(parts):
        raise BoundaryViolation("I_AMBIGUITY", "signed-headers list not sorted", 400)
    if _SELF_REFERENTIAL.intersection(parts):
        raise BoundaryViolation("I_AMBIGUITY", "signed-headers list is self-referential", 400)
    return parts


def _build_canonical(
    *,
    method: bytes,
    authority: bytes,
    root_path: bytes,
    raw_path: bytes,
    query: bytes,
    ts_raw: bytes,
    nonce: bytes,
    chash: bytes,
    signed_raw: bytes,
    signed_names: List[bytes],
    headers: Dict[bytes, bytes],
) -> bytes:
    """The one canonical construction, shared by signer and verifier.

    Fields: scheme | method | authority (host[:port], lowercased) |
    root_path | raw_path | query | ts | nonce | body-hash | signed-list-raw |
    (name | presence | value) per declared header, in declared (sorted) order.

    - authority keeps the port: h:443 and h:8443 are different requests even
      if an operator drops 'host' from the required signed set.
    - raw_path is the exact wire bytes, not ASGI's percent-DECODED 'path':
      '/a%2Fb' and '/a/b' decode identically but route differently for
      anything that reads raw_path. Bind what was sent.
    - presence is its own field so missing and present-but-empty differ.
    """
    fields: List[bytes] = [_SCHEME, method, authority, root_path, raw_path,
                           query, ts_raw, nonce, chash, signed_raw]
    for name in signed_names:
        fields.append(name)
        fields.append(b"1" if name in headers else b"0")
        fields.append(headers.get(name, b""))
    return _lp_join(fields)


def _norm_header_set(names) -> frozenset:
    out = set()
    for n in names or ():
        if isinstance(n, str):
            n = n.encode("ascii")
        out.add(n.lower())
    return frozenset(out)


def _parse_host(raw: bytes) -> str:
    """Host minus port, IPv6-safe. '[::1]:443' -> '::1', 'h:80' -> 'h'."""
    s = raw.decode("latin1").strip().lower()
    if s.startswith("["):  # IPv6 literal
        end = s.find("]")
        return s[1:end] if end != -1 else s
    return s.split(":", 1)[0]


def _scope_raw_path(scope: Scope) -> bytes:
    """Exact request-target path bytes. Falls back to re-encoding 'path' only
    for servers that don't supply raw_path (then there is no divergence to
    exploit, because nothing downstream can see a different raw form)."""
    rp = scope.get("raw_path")
    if isinstance(rp, (bytes, bytearray)):
        return bytes(rp)
    return scope.get("path", "").encode("utf-8")


class _NonceCache:
    """Per-process replay guard with O(log n) amortized eviction (a min-heap
    of expiries, not a full scan per request). PRODUCTION: replace with a
    shared atomic store (e.g. Redis SET NX PX) so the check is global, not
    per-worker."""

    def __init__(self) -> None:
        self._seen: Dict[bytes, float] = {}
        self._heap: List[Tuple[float, bytes]] = []

    def check_and_add(self, nonce: bytes, expires_at: float) -> bool:
        now = time.time()
        while self._heap and self._heap[0][0] <= now:
            exp, n = heapq.heappop(self._heap)
            if self._seen.get(n) == exp:
                del self._seen[n]
        if nonce in self._seen:
            return False
        self._seen[nonce] = expires_at
        heapq.heappush(self._heap, (expires_at, nonce))
        return True


class StructuralBoundaryMiddleware:
    """TARGET UNDER TEST. The attack harness in __main__ drives this."""

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        allowed_hosts: set[str],
        signing_key: bytes,
        max_header_size: int = 8192,
        max_body_size: int = 1_048_576,
        freshness_window_sec: float = 300.0,
        required_signed_headers=frozenset({b"host"}),
        must_sign_if_present=None,
        on_reject: Optional[Callable[[BoundaryViolation], None]] = None,
    ) -> None:
        if not signing_key:
            raise ValueError("signing_key required; load from config, not source")
        self.app = app
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.signing_key = signing_key
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.freshness_window_sec = freshness_window_sec
        # Anti-downgrade, server-side: the client declares coverage, the
        # server sets its floor.
        self.required_signed_headers = _norm_header_set(required_signed_headers)
        self.must_sign_if_present = (
            _DEFAULT_MUST_SIGN_IF_PRESENT if must_sign_if_present is None
            else _norm_header_set(must_sign_if_present)
        )
        # Observability hook (tests, metrics). Server-side only; never alters
        # what the client sees.
        self.on_reject = on_reject
        self._nonces = _NonceCache()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "http":
            await self._http(scope, receive, send)
        elif kind == "websocket":
            await self._websocket(scope, receive, send)
        elif kind == "lifespan":
            # Server lifecycle, not a client request: nothing to authenticate.
            await self.app(scope, receive, send)
        else:
            # Fail closed: an ASGI scope type this boundary doesn't understand
            # is not forwarded unchecked.
            log.warning("boundary reject: unknown scope type %r", kind)

    # ---- HTTP -----------------------------------------------------------
    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            headers = self._collect(scope)                          # I + header EXTENT
            ts = self._verify_signature(scope, headers, scope.get("method", ""))  # III window + IV
            body = await self._drain_bounded(receive)               # II (measure)
            self._verify_body_integrity(headers, body)              # IV binds II
            self._claim_nonce(headers, ts)                          # III (anti-replay, last)
        except BoundaryViolation as v:
            await self._reject(send, v)
            return
        await self.app(scope, self._replay(body), send)

    # ---- WebSocket: the handshake is an HTTP GET with the same headers, so
    #      it gets the same checks. Body hash must be of the empty body. ----
    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            headers = self._collect(scope)
            ts = self._verify_signature(scope, headers, "GET")
            self._verify_body_integrity(headers, b"")
            self._claim_nonce(headers, ts)
        except BoundaryViolation as v:
            self._record(v)
            # ASGI: close before accept => server answers the handshake 403.
            msg = await receive()
            if msg.get("type") == "websocket.connect":
                await send({"type": "websocket.close", "code": 1008})
            return
        await self.app(scope, receive, send)

    # ---- BOOK I: only what this vantage can honestly own ----------------
    def _collect(self, scope: Scope) -> Dict[bytes, bytes]:
        raw: List[Tuple[bytes, bytes]] = scope.get("headers", [])
        if sum(len(k) + len(v) for k, v in raw) > self.max_header_size:
            raise BoundaryViolation("II_EXTENT", "header block too large", 431)

        out: Dict[bytes, bytes] = {}
        counts: Dict[bytes, int] = {}
        for k, v in raw:
            lk = k.lower()
            counts[lk] = counts.get(lk, 0) + 1
            if lk in _SENSITIVE_SINGLETON and counts[lk] > 1:
                raise BoundaryViolation("I_AMBIGUITY", f"duplicate {lk!r}", 400)
            if lk == b"content-length" and not (v.isdigit() and v.isascii()):
                # wire grammar DIGIT+ ; rejects +, _, spaces, unicode digits
                raise BoundaryViolation("I_AMBIGUITY", "non-numeric Content-Length", 400)
            out[lk] = v

        # Defense-in-depth only: the server already framed this request; the
        # real smuggling surface (frontend<->server) is invisible here.
        if b"content-length" in out and b"transfer-encoding" in out:
            raise BoundaryViolation("I_AMBIGUITY", "CL+TE present", 400)

        host = _parse_host(out.get(b"host", b""))
        if not host or host not in self.allowed_hosts:
            raise BoundaryViolation("I_AMBIGUITY", f"unroutable host {host!r}", 421)
        return out

    # ---- BOOK III window + BOOK IV signature + coverage -----------------
    def _verify_signature(self, scope: Scope, h: Dict[bytes, bytes], method_s: str) -> float:
        ts_raw = h.get(b"x-request-timestamp")
        nonce = h.get(b"x-request-nonce")
        sig = h.get(b"x-request-signature")
        chash = h.get(b"x-content-sha256")
        signed_raw = h.get(b"x-request-signed-headers")
        if not (ts_raw and nonce and sig and chash) or signed_raw is None:
            raise BoundaryViolation("IV_LEAKAGE", "unsigned request", 401)

        # Strict-parse the declaration first (Book I), then enforce the
        # server's coverage floor (Book IV), then verify the HMAC.
        signed_names = _parse_signed_headers(signed_raw)
        declared = set(signed_names)
        if not self.required_signed_headers.issubset(declared):
            missing = sorted(self.required_signed_headers - declared)
            raise BoundaryViolation("IV_LEAKAGE", f"required headers unsigned: {missing}", 401)
        uncovered = sorted((set(h) & self.must_sign_if_present) - declared)
        if uncovered:
            # Present, acted-on, and outside the signed set. The HMAC over
            # the declared set would still verify — this check, not the
            # signature, is what catches an injected decision header.
            raise BoundaryViolation("IV_LEAKAGE", f"decision headers unsigned: {uncovered}", 401)
        # A declared header may not ride in duplicated: _collect collapsed
        # it last-wins, but a downstream may read the first value.
        counts: Dict[bytes, int] = {}
        for k, _v in scope.get("headers", []):
            lk = k.lower()
            counts[lk] = counts.get(lk, 0) + 1
        for name in signed_names:
            if counts.get(name, 0) > 1:
                raise BoundaryViolation("I_AMBIGUITY", f"duplicate signed header {name!r}", 400)

        # Strict grammars before any numeric interpretation.
        if not _TS_RE.fullmatch(ts_raw):
            raise BoundaryViolation("I_AMBIGUITY", "malformed timestamp", 400)
        ts = float(ts_raw.decode("ascii"))
        if not math.isfinite(ts):  # unreachable under _TS_RE; kept as a belt
            raise BoundaryViolation("I_AMBIGUITY", "malformed timestamp", 400)
        if not _NONCE_RE.fullmatch(nonce):
            raise BoundaryViolation("I_AMBIGUITY", "malformed nonce", 400)

        # FRESHNESS window: bounds the replay horizon AND the nonce-cache size.
        if abs(time.time() - ts) > self.freshness_window_sec:
            raise BoundaryViolation("III_FRESHNESS", "timestamp outside window", 401)

        try:
            method = method_s.encode("ascii")
            authority = h.get(b"host", b"").strip().lower()
            authority.decode("ascii")
        except (UnicodeEncodeError, UnicodeDecodeError):
            raise BoundaryViolation("I_AMBIGUITY", "non-ascii method/host", 400)
        qs = scope.get("query_string", b"")
        if isinstance(qs, str):
            qs = qs.encode("utf-8")
        canonical = _build_canonical(
            method=method, authority=authority,
            root_path=scope.get("root_path", "").encode("utf-8"),
            raw_path=_scope_raw_path(scope), query=qs, ts_raw=ts_raw,
            nonce=nonce, chash=chash, signed_raw=signed_raw,
            signed_names=signed_names, headers=h,
        )
        expected = hmac.new(self.signing_key, canonical, hashlib.sha256).hexdigest().encode("ascii")
        # Grammar check is on attacker-supplied shape only (public info);
        # the comparison against the secret-derived value is constant-time.
        if not _SIG_RE.fullmatch(sig) or not hmac.compare_digest(sig, expected):
            raise BoundaryViolation("IV_LEAKAGE", "bad signature", 401)
        return ts

    # ---- BOOK II: measure the magnitude, don't trust the label ----------
    async def _drain_bounded(self, receive: Receive) -> bytes:
        buf = bytearray()
        more = True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                raise BoundaryViolation("II_EXTENT", "client disconnected", 400)
            buf += msg.get("body", b"")
            more = msg.get("more_body", False)
            if len(buf) > self.max_body_size:
                # Abort as soon as the REAL body exceeds the cap, regardless of
                # any Content-Length claim (or its absence under chunked).
                raise BoundaryViolation("II_EXTENT", "body exceeds cap", 413)
        return bytes(buf)

    # ---- BOOK IV binds BOOK II: signed claim must equal measured reality -
    def _verify_body_integrity(self, h: Dict[bytes, bytes], body: bytes) -> None:
        claimed = h[b"x-content-sha256"]  # presence guaranteed by _verify_signature
        actual = hashlib.sha256(body).hexdigest().encode("ascii")
        if not hmac.compare_digest(claimed, actual):
            raise BoundaryViolation("IV_LEAKAGE", "body hash mismatch", 401)

    # ---- BOOK III: single-use. Claimed LAST, so a rejected request does not
    #      burn a nonce the legitimate client still needs. -----------------
    def _claim_nonce(self, h: Dict[bytes, bytes], ts: float) -> None:
        if not self._nonces.check_and_add(h[b"x-request-nonce"], ts + self.freshness_window_sec):
            raise BoundaryViolation("III_FRESHNESS", "replayed nonce", 401)

    def _replay(self, body: bytes) -> Receive:
        sent = False

        async def receive() -> Dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        return receive

    # ---- BOOK IV: generic surface; internals logged, never returned ------
    def _record(self, v: BoundaryViolation) -> str:
        rid = secrets.token_hex(8)
        log.warning("boundary reject id=%s book=%s detail=%s", rid, v.book, v.detail)
        if self.on_reject is not None:
            self.on_reject(v)
        return rid

    async def _reject(self, send: Send, v: BoundaryViolation) -> None:
        rid = self._record(v)
        # Client sees a STANDARD status plus an opaque id — never the book or
        # the detail string.
        body = json.dumps({"error": "request_rejected", "request_id": rid}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": v.status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"connection", b"close"),
            ],
        })
        await send({"type": "http.response.body", "body": body})


# =====================================================================
# ATTACK HARNESS — drive the target from the adversary's side and report,
# per attack, whether the defense HELD for the right reason, held for the
# wrong reason, or a payload reached the app.
# =====================================================================
if __name__ == "__main__":
    import asyncio
    import sys

    logging.basicConfig(level=logging.ERROR, format="  [target-log] %(message)s")

    KEY = b"load-me-from-config-or-a-kms"          # the real signing key
    WRONG_KEY = b"attacker-never-obtained-this-key"  # the outsider's guess
    HOST = "api.example.com"
    SMALL = b'{"hello":"world"}'
    BIG = b"x" * (2 * 1024 * 1024)                 # 2 MiB > 1 MiB cap

    # ---- TARGET app: reports what it saw so the harness can tell a real
    #      penetration from a rejection, and check body fidelity. ---------
    async def target_app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await receive()  # websocket.connect
            await send({"type": "websocket.accept"})
            await send({"type": "websocket.send", "text": json.dumps({"reached_app": True})})
            await send({"type": "websocket.close", "code": 1000})
            return
        chunks = bytearray()
        more = True
        while more:
            m = await receive()
            chunks += m.get("body", b"")
            more = m.get("more_body", False)
        payload = json.dumps({
            "reached_app": True,
            "body_sha256": hashlib.sha256(chunks).hexdigest(),
        }).encode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": payload})

    last_violation: Dict[str, Optional[BoundaryViolation]] = {"v": None}

    target = StructuralBoundaryMiddleware(
        app=target_app, allowed_hosts={HOST}, signing_key=KEY,
        on_reject=lambda v: last_violation.__setitem__("v", v),
    )

    # ---- attacker's signer: may use the real KEY (authenticated insider who
    #      still must not be able to smuggle/replay/swap) or WRONG_KEY (the
    #      outsider who cannot forge at all). ------------------------------
    def forge(method, path, body, *, host=HOST, nonce=None, ts=None,
              extra=None, qs: bytes = b"", declare=None, key=KEY,
              raw_path: Optional[bytes] = None, root_path: bytes = b""):
        ts = ts or f"{time.time():.6f}"
        nonce = nonce or secrets.token_hex(16).encode("ascii")
        extra = list(extra or [])
        chash = hashlib.sha256(body).hexdigest().encode("ascii")
        if declare is None:
            signed_names = sorted({b"host"} | {k.lower() for k, _ in extra})
        else:
            signed_names = list(declare)
        signed_raw = b";".join(signed_names)
        values: Dict[bytes, bytes] = {
            b"host": host.encode(),
            b"x-request-timestamp": ts.encode(),
            b"x-request-nonce": nonce,
            b"x-content-sha256": chash,
        }
        for k, v in extra:
            values[k.lower()] = v
        canonical = _build_canonical(
            method=method.encode(), authority=host.encode().strip().lower(),
            root_path=root_path,
            raw_path=raw_path if raw_path is not None else path.encode(),
            query=qs, ts_raw=ts.encode(), nonce=nonce,
            chash=chash, signed_raw=signed_raw,
            signed_names=_parse_signed_headers(signed_raw), headers=values,
        )
        sig = hmac.new(key, canonical, hashlib.sha256).hexdigest().encode("ascii")
        hdrs = [
            (b"host", host.encode()),
            (b"x-request-timestamp", ts.encode()),
            (b"x-request-nonce", nonce),
            (b"x-content-sha256", chash),
            (b"x-request-signed-headers", signed_raw),
            (b"x-request-signature", sig),
        ]
        return hdrs + extra

    def with_value(hdrs, name, value):
        return [(k, value if k == name else v) for k, v in hdrs]

    def make_receive(body: bytes, chunk: int = 65536) -> Receive:
        parts = [body[i:i + chunk] for i in range(0, len(body), chunk)] or [b""]

        async def receive() -> Dict[str, Any]:
            if parts:
                p = parts.pop(0)
                return {"type": "http.request", "body": p, "more_body": bool(parts)}
            return {"type": "http.request", "body": b"", "more_body": False}

        return receive

    def ws_receive() -> Receive:
        msgs = [{"type": "websocket.connect"}]

        async def receive() -> Dict[str, Any]:
            return msgs.pop(0) if msgs else {"type": "websocket.disconnect", "code": 1000}

        return receive

    Result = Tuple[Any, bool, Optional[BoundaryViolation], Optional[str]]

    async def fire(scope: Scope, receive: Receive) -> Result:
        """Returns (status, reached_app, violation, app_body_sha256)."""
        cap: Dict[str, Any] = {}
        last_violation["v"] = None

        async def send(m):
            t = m["type"]
            if t == "http.response.start":
                cap["status"] = m["status"]
            elif t == "http.response.body":
                try:
                    cap["body"] = json.loads(m["body"].decode())
                except Exception:
                    cap["body"] = m["body"].decode()
            elif t == "websocket.accept":
                cap["status"] = "ws-ok"
            elif t == "websocket.send":
                cap["body"] = json.loads(m["text"])
            elif t == "websocket.close" and "status" not in cap:
                cap["status"] = f"ws-{m.get('code')}"

        await target(scope, receive, send)
        body = cap.get("body")
        reached = isinstance(body, dict) and body.get("reached_app") is True
        sha = body.get("body_sha256") if isinstance(body, dict) else None
        return cap.get("status"), reached, last_violation["v"], sha

    # ---- attack registry -------------------------------------------------
    # expect = (book, detail-substring) for attacks; None for controls.
    ATTACKS: List[Tuple[str, str, Optional[Tuple[str, str]], Optional[bytes],
                        Callable[[], Awaitable[Result]]]] = []

    def attack(book: str, name: str, expect: Tuple[str, str]):
        def deco(fn):
            ATTACKS.append((book, name, expect, None, fn))
            return fn
        return deco

    def control(name: str, body: Optional[bytes]):
        def deco(fn):
            ATTACKS.append(("-- CONTROL", name, None, body, fn))
            return fn
        return deco

    def http(method, path, headers, *, qs=None, raw_path=None):
        s = {"type": "http", "method": method, "path": path, "headers": headers,
             "raw_path": raw_path if raw_path is not None else path.encode()}
        if qs is not None:
            s["query_string"] = qs
        return s

    def ws(path, headers):
        return {"type": "websocket", "path": path, "raw_path": path.encode(),
                "headers": headers}

    # ===== BOOK I — AMBIGUITY: make the edge and the app disagree =========
    # Every Book I attack starts from a VALID signed request, so the only
    # thing that can stop it is the ambiguity check it targets.

    @attack("I  AMBIGUITY", "duplicate Host, hope for last-wins",
            ("I_AMBIGUITY", "duplicate b'host'"))
    async def _():
        h = forge("GET", "/", b"") + [(b"host", b"evil.example.com")]
        return await fire(http("GET", "/", h), make_receive(b""))

    @attack("I  AMBIGUITY", "CL + TE together (desync)",
            ("I_AMBIGUITY", "CL+TE present"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL, extra=[
            (b"content-length", b"17"), (b"transfer-encoding", b"chunked"),
        ])
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "non-numeric Content-Length",
            ("I_AMBIGUITY", "non-numeric Content-Length"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL, extra=[(b"content-length", b"17x")])
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "unsorted signed-headers list",
            ("I_AMBIGUITY", "not sorted"))
    async def _():
        h = with_value(forge("POST", "/v1/thing", SMALL),
                       b"x-request-signed-headers", b"x-forwarded-for;host")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "self-referential signed-headers list",
            ("I_AMBIGUITY", "self-referential"))
    async def _():
        h = with_value(forge("POST", "/v1/thing", SMALL),
                       b"x-request-signed-headers", b"host;x-request-signature")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "duplicate signed header ride-along",
            ("I_AMBIGUITY", "duplicate signed header"))
    async def _():
        h = forge("POST", "/v1/act", SMALL, extra=[(b"x-forwarded-for", b"1.1.1.1")])
        h = h + [(b"x-forwarded-for", b"2.2.2.2")]  # second value nobody signed
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "NaN timestamp to slip the window",
            ("I_AMBIGUITY", "malformed timestamp"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL, ts="nan")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "non-canonical timestamp '1_7..'/'1e9'",
            ("I_AMBIGUITY", "malformed timestamp"))
    async def _():
        t = str(int(time.time()))
        h = forge("POST", "/v1/thing", SMALL, ts=t[0] + "_" + t[1:])
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "percent-encoded path under captured sig",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        # Captured: /files/a/b. Deliver /files/a%2Fb — ASGI decodes both to
        # path '/files/a/b', but raw_path (and any raw-path router) differs.
        captured = forge("GET", "/files/a/b", b"")
        return await fire(http("GET", "/files/a/b", captured, raw_path=b"/files/a%2Fb"),
                          make_receive(b""))

    # ===== BOOK II — EXTENT: lie about magnitude ==========================

    @attack("II EXTENT   ", "oversized body, honest small CL claim",
            ("II_EXTENT", "body exceeds cap"))
    async def _():
        h = forge("POST", "/v1/upload", BIG, extra=[(b"content-length", b"17")])
        return await fire(http("POST", "/v1/upload", h), make_receive(BIG))

    @attack("II EXTENT   ", "chunked (TE), no CL, unbounded body",
            ("II_EXTENT", "body exceeds cap"))
    async def _():
        h = forge("POST", "/v1/upload", BIG) + [(b"transfer-encoding", b"chunked")]
        return await fire(http("POST", "/v1/upload", h), make_receive(BIG))

    @attack("II EXTENT   ", "oversized header block (signed)",
            ("II_EXTENT", "header block too large"))
    async def _():
        h = forge("GET", "/", b"", extra=[(b"x-filler", b"A" * 9000)])
        return await fire(http("GET", "/", h), make_receive(b""))

    # ===== BOOK III — FRESHNESS: move the request through time ============

    @attack("III FRESHNESS", "replay a captured valid request",
            ("III_FRESHNESS", "replayed nonce"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL)
        first = await fire(http("POST", "/v1/thing", h), make_receive(SMALL))
        if not first[1]:
            return first  # original didn't land: replay test is meaningless
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("III FRESHNESS", "back-dated timestamp",
            ("III_FRESHNESS", "outside window"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL, ts=f"{time.time() - 10_000:.6f}")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("III FRESHNESS", "post-dated timestamp",
            ("III_FRESHNESS", "outside window"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL, ts=f"{time.time() + 10_000:.6f}")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    # ===== BOOK IV — LEAKAGE / COVERAGE: forge, swap, inject ==============

    @attack("IV LEAKAGE ", "forge a signature without the key",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        h = forge("POST", "/v1/thing", SMALL, key=WRONG_KEY)
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "body swap (sign A, deliver B)",
            ("IV_LEAKAGE", "body hash mismatch"))
    async def _():
        a, b = b"approved=false", b"approved=true!"
        h = forge("POST", "/v1/act", a)                 # valid sig over A
        return await fire(http("POST", "/v1/act", h), make_receive(b))

    @attack("IV LEAKAGE ", "query swap under a valid signature",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        h = forge("POST", "/v1/act", SMALL, qs=b"approved=false")
        return await fire(http("POST", "/v1/act", h, qs=b"approved=true"),
                          make_receive(SMALL))

    @attack("IV LEAKAGE ", "port swap under a valid signature",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        # Signed for :443, delivered to :8443 (e.g. an internal admin port).
        captured = forge("POST", "/v1/act", SMALL, host=f"{HOST}:443")
        h = with_value(captured, b"host", f"{HOST}:8443".encode())
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV COVERAGE", "inject unsigned decision header",
            ("IV_LEAKAGE", "decision headers unsigned"))
    async def _():
        captured = forge("POST", "/v1/act", SMALL)      # declares host only
        h = captured + [(b"x-http-method-override", b"DELETE")]
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV COVERAGE", "inject unsigned Forwarded (RFC 7239)",
            ("IV_LEAKAGE", "decision headers unsigned"))
    async def _():
        captured = forge("POST", "/v1/act", SMALL)
        h = captured + [(b"forwarded", b"for=10.0.0.1;proto=https")]
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV COVERAGE", "inject unsigned Authorization",
            ("IV_LEAKAGE", "decision headers unsigned"))
    async def _():
        captured = forge("POST", "/v1/act", SMALL)
        h = captured + [(b"authorization", b"Bearer stolen-admin-token")]
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV COVERAGE", "downgrade: declare host, send Cookie",
            ("IV_LEAKAGE", "decision headers unsigned"))
    async def _():
        h = forge("POST", "/v1/act", SMALL,
                  extra=[(b"cookie", b"session=abc")], declare=[b"host"])
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "tamper a declared header's value",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        h = with_value(
            forge("POST", "/v1/act", SMALL, extra=[(b"x-http-method-override", b"GET")]),
            b"x-http-method-override", b"DELETE",
        )
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "truncated / wrong-length signature",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        h = with_value(forge("POST", "/v1/thing", SMALL),
                       b"x-request-signature", b"0" * 10)
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "canonical-collision signature reuse",
            ("IV_LEAKAGE", "bad signature"))
    async def _():
        # Capture a valid sig for (path='/a\nb', query='c'); try to reuse it for
        # (path='/a', query='b\nc') — identical under a newline-join canonical,
        # distinct under length-prefixing. The captured sig must not verify.
        captured = forge("POST", "/a\nb", SMALL, qs=b"c")
        return await fire(http("POST", "/a", captured, qs=b"b\nc"),
                          make_receive(SMALL))

    @attack("IV LEAKAGE ", "WebSocket: skip HTTP checks entirely",
            ("IV_LEAKAGE", "unsigned request"))
    async def _():
        return await fire(ws("/admin", [(b"host", HOST.encode())]), ws_receive())

    @attack("IV LEAKAGE ", "WebSocket: unroutable Host",
            ("I_AMBIGUITY", "unroutable host"))
    async def _():
        return await fire(ws("/admin", [(b"host", b"evil.com")]), ws_receive())

    @attack("IV LEAKAGE ", "WebSocket: replay a captured handshake",
            ("III_FRESHNESS", "replayed nonce"))
    async def _():
        h = forge("GET", "/stream", b"")
        first = await fire(ws("/stream", h), ws_receive())
        if not first[1]:
            return first
        return await fire(ws("/stream", h), ws_receive())

    # ===== CONTROLS: the requests that SHOULD reach the app ===============

    @control("legitimate signed request", SMALL)
    async def _():
        h = forge("POST", "/v1/thing", SMALL)
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @control("legitimate signed request, chunked body", SMALL * 5000)
    async def _():
        body = SMALL * 5000  # ~85 KB, crosses several 64 KiB receive chunks
        h = forge("POST", "/v1/thing", body)
        return await fire(http("POST", "/v1/thing", h), make_receive(body))

    @control("legitimate signed WebSocket handshake", None)
    async def _():
        h = forge("GET", "/stream", b"")
        return await fire(ws("/stream", h), ws_receive())

    # ---- runner + red-team report ---------------------------------------
    async def main() -> int:
        # Injectivity, demonstrated not asserted.
        old_a = b"\n".join([b"/a\nb", b"c"])
        old_b = b"\n".join([b"/a", b"b\nc"])
        new_a = _lp_join([b"/a\nb", b"c"])
        new_b = _lp_join([b"/a", b"b\nc"])

        # Lifespan must still pass through untouched.
        lifespan_seen: List[str] = []

        async def ls_app(scope, receive, send):
            lifespan_seen.append(scope["type"])

        await StructuralBoundaryMiddleware(app=ls_app, allowed_hosts={HOST},
                                           signing_key=KEY)({"type": "lifespan"}, None, None)

        print("=" * 86)
        print("STRUCTURAL BOUNDARY — ATTACK HARNESS v5   (target: in-process middleware)")
        print(f"canonical injective: {new_a != new_b}   "
              f"(newline-join would collide: {old_a == old_b})   "
              f"lifespan passthrough: {lifespan_seen == ['lifespan']}")
        print("=" * 86)
        print(f"{'BOOK':<13} {'ATTACK':<42} {'STATUS':>7}  VERDICT")
        print("-" * 86)

        held = wrong = bypass = control_ok = control_broken = 0
        findings: List[str] = []
        current_book = None

        for book, name, expect, ctrl_body, fn in ATTACKS:
            if book != current_book:
                if current_book is not None:
                    print()
                current_book = book
            status, reached, v, sha = await fn()
            if expect is not None:
                if reached:
                    verdict = "BYPASS  <-- finding"
                    bypass += 1
                    findings.append(f"{book.strip()} / {name}: reached the app")
                elif v is not None and v.book == expect[0] and expect[1] in v.detail:
                    verdict = "held"
                    held += 1
                else:
                    got = f"{v.book}: {v.detail}" if v else "no violation recorded"
                    verdict = f"WRONG REASON ({got})"
                    wrong += 1
                    findings.append(f"{book.strip()} / {name}: blocked by '{got}', "
                                    f"expected {expect[0]} '{expect[1]}'")
            else:
                intact = ctrl_body is None or sha == hashlib.sha256(ctrl_body).hexdigest()
                if reached and intact:
                    verdict = "ok (expected)"
                    control_ok += 1
                else:
                    why = "body altered" if reached else f"rejected: {v.detail if v else '?'}"
                    verdict = f"BROKEN ({why})  <-- false positive"
                    control_broken += 1
                    findings.append(f"CONTROL / {name}: {why}")
            print(f"{book:<13} {name:<42} {str(status):>7}  {verdict}")

        if lifespan_seen != ["lifespan"]:
            findings.append("lifespan scope was not passed through")
        if not (new_a != new_b and old_a == old_b):
            findings.append("canonical injectivity demonstration failed")

        print("-" * 86)
        print(f"RESULT: {held + wrong + bypass} attacks  |  {held} held  |  "
              f"{wrong} wrong reason  |  {bypass} bypass")
        print(f"        control: {control_ok} ok, {control_broken} broken")
        if findings:
            print("\nFINDINGS:")
            for f in findings:
                print(f"  - {f}")
        else:
            print("\nNo findings: every attack was blocked by the check it targets,"
                  " and every control passed intact.")
        print("=" * 86)
        return 1 if findings else 0

    sys.exit(asyncio.run(main()))
