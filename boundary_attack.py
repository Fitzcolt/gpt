"""
Structural boundary ATTACK harness — v4: probing the four boundaries.

The adversary's mirror of the defensive middleware. Same four books, read from
the attacker's side of the wire: each book names a boundary the middleware
CLAIMS to hold, and this harness mounts the concrete payloads that try to cross
it. It drives the middleware IN-PROCESS — the target is constructed below and
called directly through ASGI, not reached over a socket — and reports, per
attack, whether the defense HELD or the payload reached the application (a
bypass / finding).

The four books as attack surfaces:

  BOOK I  — AMBIGUITY (what):     make the edge and the app disagree about the
        request. Duplicate a trusted header and hope for last-wins collapse;
        send CL+TE together for a desync; smuggle a non-numeric length or a
        NaN timestamp past a permissive parse; feed a malformed or
        self-referential signed-headers list. The middleware's move is to
        refuse the ambiguity at the grammar, not resolve it.
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
        body or the query under it; inject an unsigned decision header a
        captured HMAC still verifies around; downgrade coverage by declaring
        less than you send; exploit a non-injective canonical to reuse one
        signature for two different requests. The defense is a constant-time
        compare over a length-prefixed canonical, a server-side coverage floor,
        and a body-hash bind.

A legitimate signed request is included as a CONTROL: it SHOULD reach the app,
which is how the harness distinguishes a real bypass from the one request that
is supposed to get through. Any other attack that reaches the app is a finding.

Scope, stated plainly: everything here targets the StructuralBoundaryMiddleware
instance built in __main__. This is a self-test / red-team harness for that
middleware — code you own — not a client for arbitrary servers. Nothing here
opens a network connection, and the payloads are shaped to this middleware's
own SBv4 scheme, not a generic protocol. Point it at your own target.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import secrets
import time
from typing import Any, Awaitable, Callable, Dict, List, Tuple

Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]

log = logging.getLogger("structural_boundary")

# Headers we make a trust decision on: a duplicate is an ambiguity we refuse,
# not collapse last-wins.
_SENSITIVE_SINGLETON = (
    b"host",
    b"content-length",
    b"x-request-timestamp",
    b"x-request-nonce",
    b"x-request-signature",
    b"x-content-sha256",
    b"x-request-signed-headers",
)

# Decision headers that must be signed WHENEVER PRESENT. An unsigned one is
# an input the downstream will act on that the signer never saw — the exact
# scenario-13 shape. Extend per deployment: any header your app/framework
# treats as authoritative belongs here (or in required_signed_headers).
_DEFAULT_MUST_SIGN_IF_PRESENT = frozenset({
    b"content-length",
    b"content-type",
    b"cookie",
    b"range",
    b"x-forwarded-for",
    b"x-forwarded-host",
    b"x-forwarded-proto",
    b"x-http-method-override",
    b"x-method-override",
    b"x-original-url",
    b"x-rewrite-url",
})

# The signed-headers list may never name the signature itself or the list
# itself: self-reference is not coverage.
_SELF_REFERENTIAL = frozenset({b"x-request-signature", b"x-request-signed-headers"})

_TOKEN_RE = re.compile(rb"[a-z0-9!#$%&'*+\-.^_`|~]+")

# Domain separator: v4 signatures can never be confused with an earlier
# scheme's, even if every other field coincides.
_SCHEME = b"SBv4"


def _lp_join(fields: List[bytes]) -> bytes:
    """Length-prefixed join: injective by construction.

    b"\\n".join is NOT injective when a field may contain b"\\n" — the field
    boundary is information the encoding destroys. Emitting 'len:field' for
    each field preserves the boundary exactly, for any field bytes.
    """
    return b"".join(str(len(f)).encode("ascii") + b":" + f for f in fields)


def _parse_signed_headers(raw: bytes) -> List[bytes]:
    """Strict grammar for X-Request-Signed-Headers (Book I).

    Lowercase RFC tokens, ';'-separated, sorted, unique, no empty entries,
    no self-reference. Anything else is malformed — same strict-parse genus
    as the NaN timestamp and the digit-only Content-Length: reject at the
    grammar, don't let a permissive parse downstream guess.
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
    host: bytes,
    path: bytes,
    query: bytes,
    ts_raw: bytes,
    nonce: bytes,
    chash: bytes,
    signed_raw: bytes,
    signed_names: List[bytes],
    headers: Dict[bytes, bytes],
) -> bytes:
    """The one canonical construction, shared by signer and verifier.

    Fields: scheme | method | parsed-host | path | query | ts | nonce |
    body-hash | signed-list-raw | (name | presence | value) per declared
    header, in declared (sorted) order. Presence is its own field so a
    missing header and a present-but-empty one encode differently.
    Path and query are separate fields; no '?'-gluing.
    """
    fields: List[bytes] = [_SCHEME, method, host, path, query, ts_raw, nonce,
                            chash, signed_raw]
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


class BoundaryViolation(Exception):
    def __init__(self, book: str, detail: str, status_code: int) -> None:
        self.book = book
        self.detail = detail
        self.status_code = status_code
        super().__init__(f"[{book}] {detail}")


def _parse_host(raw: bytes) -> str:
    """Host minus port, IPv6-safe. '[::1]:443' -> '::1', 'h:80' -> 'h'."""
    s = raw.decode("latin1").strip().lower()
    if s.startswith("["):  # IPv6 literal
        end = s.find("]")
        return s[1:end] if end != -1 else s
    return s.split(":", 1)[0]


class _NonceCache:
    """Per-process replay guard. PRODUCTION: replace with a shared atomic
    store so the check is global, not per-worker."""

    def __init__(self) -> None:
        self._seen: Dict[bytes, float] = {}

    def check_and_add(self, nonce: bytes, expires_at: float) -> bool:
        now = time.time()
        for n in [n for n, exp in self._seen.items() if exp <= now]:
            del self._seen[n]  # opportunistic eviction
        if nonce in self._seen:
            return False
        self._seen[nonce] = expires_at
        return True


class StructuralBoundaryMiddleware:
    """TARGET UNDER TEST. The attack harness in __main__ drives this.

    Unchanged from the defensive build — the point of an attack harness is to
    probe the real thing, not a weakened stand-in. If an attack below reaches
    the app, the finding is against THIS code as written.
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        allowed_hosts: set[str],
        signing_key: bytes,
        max_header_size: int = 8192,
        max_body_size: int = 1_048_576,
        freshness_window_sec: float = 300.0,
        required_signed_headers=_norm_header_set({b"host"}),
        must_sign_if_present=None,
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
        # server sets its floor. A client that declares less is rejected no
        # matter how valid its HMAC is over what it chose to declare.
        self.required_signed_headers = _norm_header_set(required_signed_headers)
        self.must_sign_if_present = (
            _DEFAULT_MUST_SIGN_IF_PRESENT if must_sign_if_present is None
            else _norm_header_set(must_sign_if_present)
        )
        self._nonces = _NonceCache()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            headers = self._collect(scope)              # BOOK I + header EXTENT
            self._verify_signature(scope, headers)      # BOOK III (window) + IV (sig)
            body = await self._drain_bounded(receive)   # BOOK II (measure, don't trust)
            self._verify_body_integrity(headers, body)  # BOOK IV binds BOOK II
            self._claim_nonce(headers)                  # BOOK III (anti-replay, last)
        except BoundaryViolation as v:
            await self._reject(send, v)
            return
        await self.app(scope, self._replay(body), send)

    # ---- BOOK I: only what this vantage can honestly own ----------------
    def _collect(self, scope: Scope) -> Dict[bytes, bytes]:
        raw: List[Tuple[bytes, bytes]] = scope.get("headers", [])
        if sum(len(k) + len(v) for k, v in raw) > self.max_header_size:
            raise BoundaryViolation("II_EXTENT", "header block too large", 431)

        out: Dict[bytes, bytes] = {}
        counts: Dict[bytes, int] = {}
        cl_found = te_found = False
        for k, v in raw:
            lk = k.lower()
            counts[lk] = counts.get(lk, 0) + 1
            if lk in _SENSITIVE_SINGLETON and counts[lk] > 1:
                raise BoundaryViolation("I_AMBIGUITY", f"duplicate {lk!r}", 400)
            if lk == b"content-length":
                cl_found = True
                if not v.isdigit():  # wire grammar DIGIT+ ; rejects +, _, spaces
                    raise BoundaryViolation("I_AMBIGUITY", "non-numeric Content-Length", 400)
            if lk == b"transfer-encoding":
                te_found = True
            out[lk] = v

        # Defense-in-depth only: the server already framed this request; the
        # real smuggling surface (frontend<->server) is invisible here.
        if cl_found and te_found:
            raise BoundaryViolation("I_AMBIGUITY", "CL+TE present", 400)

        host = _parse_host(out.get(b"host", b""))
        if not host or host not in self.allowed_hosts:
            raise BoundaryViolation("I_AMBIGUITY", f"unroutable host {host!r}", 421)
        return out

    # ---- BOOK III window + BOOK IV signature + coverage -----------------
    def _verify_signature(self, scope: Scope, h: Dict[bytes, bytes]) -> None:
        ts_raw = h.get(b"x-request-timestamp")
        nonce = h.get(b"x-request-nonce")
        sig = h.get(b"x-request-signature")
        chash = h.get(b"x-content-sha256")
        signed_raw = h.get(b"x-request-signed-headers")
        # Signing mandatory here (fail-closed default), and v4 makes the
        # signed-headers declaration part of 'signed': no declaration =
        # unsigned. Deployment knob: some sign only mutating methods.
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
        # it last-wins, but a downstream may read the first value. Signing
        # the collapse would bind a value nobody necessarily acts on.
        counts: Dict[bytes, int] = {}
        for k, _v in scope.get("headers", []):
            lk = k.lower()
            counts[lk] = counts.get(lk, 0) + 1
        for name in signed_names:
            if counts.get(name, 0) > 1:
                raise BoundaryViolation("I_AMBIGUITY", f"duplicate signed header {name!r}", 400)
        try:
            ts = float(ts_raw.decode("ascii"))
        except ValueError:
            raise BoundaryViolation("I_AMBIGUITY", "malformed timestamp", 400)
        # float() accepts 'nan'/'inf'; NaN would slip the window check below
        # because every comparison with NaN is False. Reject non-finite.
        if not math.isfinite(ts):
            raise BoundaryViolation("I_AMBIGUITY", "malformed timestamp", 400)

        # FRESHNESS window: bounds the replay horizon AND the nonce-cache size.
        if abs(time.time() - ts) > self.freshness_window_sec:
            raise BoundaryViolation("III_FRESHNESS", "timestamp outside window", 401)

        # Timestamp+nonce are INSIDE the signed material, so they are not naked
        # — you cannot bump them without the key. Symmetric HMAC = SigV4-class,
        # request-scoped shared secret. Swap to Ed25519 for true principal auth
        # (a server-side key read then cannot forge).
        # Path and query are SEPARATE canonical fields: ASGI 'path' excludes
        # the query, so ?approved=false -> ?approved=true must be its own
        # bound field, not a '?'-glued suffix.
        try:
            method = scope.get("method", "").encode("ascii")
            host = _parse_host(h.get(b"host", b"")).encode("ascii")
        except UnicodeEncodeError:
            raise BoundaryViolation("I_AMBIGUITY", "non-ascii method/host", 400)
        path = scope.get("path", "").encode("utf-8")
        qs = scope.get("query_string", b"")
        if isinstance(qs, str):
            qs = qs.encode("utf-8")
        canonical = _build_canonical(
            method=method, host=host, path=path, query=qs, ts_raw=ts_raw,
            nonce=nonce, chash=chash, signed_raw=signed_raw,
            signed_names=signed_names, headers=h,
        )
        expected = hmac.new(self.signing_key, canonical, hashlib.sha256).hexdigest().encode("ascii")
        if not hmac.compare_digest(sig, expected):  # constant-time: no timing channel
            raise BoundaryViolation("IV_LEAKAGE", "bad signature", 401)

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
    def _claim_nonce(self, h: Dict[bytes, bytes]) -> None:
        ts = float(h[b"x-request-timestamp"].decode("ascii"))
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
    async def _reject(self, send: Send, v: BoundaryViolation) -> None:
        rid = secrets.token_hex(8)
        log.warning("boundary reject id=%s book=%s detail=%s", rid, v.book, v.detail)
        # Client sees a STANDARD status (413/421/401 carry semantics CDNs and
        # clients act on) plus an opaque id — never the book or the detail
        # string. Collapse to a single 400 if you want zero differentiation,
        # at the cost of those semantics.
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
# per attack, whether the defense HELD or a payload reached the app.
# =====================================================================
if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.WARNING, format="  [target-log] %(message)s")

    KEY = b"load-me-from-config-or-a-kms"          # the real signing key
    WRONG_KEY = b"attacker-never-obtained-this-key"  # the outsider's guess
    HOST = "api.example.com"
    SMALL = b'{"hello":"world"}'
    BIG = b"x" * (2 * 1024 * 1024)                 # 2 MiB > 1 MiB cap

    # ---- TARGET app: sets reached_app=True so the harness can tell a real
    #      penetration from a rejection. -----------------------------------
    async def target_app(scope: Scope, receive: Receive, send: Send) -> None:
        chunks = bytearray()
        more = True
        while more:
            m = await receive()
            chunks += m.get("body", b"")
            more = m.get("more_body", False)
        payload = json.dumps({"reached_app": True, "body_bytes": len(chunks)}).encode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": payload})

    target = StructuralBoundaryMiddleware(
        app=target_app, allowed_hosts={HOST}, signing_key=KEY,
    )

    # ---- attacker's signer: may use the real KEY (authenticated insider who
    #      still must not be able to smuggle/replay/swap) or WRONG_KEY (the
    #      outsider who cannot forge at all). ------------------------------
    def forge(method, path, body, *, host=HOST, nonce=None, ts=None,
              extra=None, qs: bytes = b"", declare=None, key=KEY):
        ts = ts or str(time.time())
        nonce = nonce or secrets.token_bytes(16)
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
            method=method.encode(),
            host=_parse_host(host.encode()).encode("ascii"),
            path=path.encode(), query=qs, ts_raw=ts.encode(), nonce=nonce,
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

    async def fire(scope: Scope, receive: Receive) -> Tuple[int, bool]:
        cap: Dict[str, Any] = {}

        async def send(m):
            if m["type"] == "http.response.start":
                cap["status"] = m["status"]
            elif m["type"] == "http.response.body":
                try:
                    cap["body"] = json.loads(m["body"].decode())
                except Exception:
                    cap["body"] = m["body"].decode()

        await target(scope, receive, send)
        reached = isinstance(cap.get("body"), dict) and cap["body"].get("reached_app") is True
        return cap.get("status"), reached

    # ---- attack registry -------------------------------------------------
    ATTACKS: List[Tuple[str, str, bool, Callable[[], Awaitable[Tuple[int, bool]]]]] = []

    def attack(book: str, name: str, expect_blocked: bool = True):
        def deco(fn):
            ATTACKS.append((book, name, expect_blocked, fn))
            return fn
        return deco

    def http(method, path, headers, *, qs=None):
        s = {"type": "http", "method": method, "path": path, "headers": headers}
        if qs is not None:
            s["query_string"] = qs
        return s

    # ===== BOOK I — AMBIGUITY: make the edge and the app disagree =========

    @attack("I  AMBIGUITY", "duplicate Host, hope for last-wins")
    async def _():
        return await fire(http("GET", "/", [
            (b"host", HOST.encode()), (b"host", b"evil.example.com"),
        ]), make_receive(b""))

    @attack("I  AMBIGUITY", "CL + TE together (desync)")
    async def _():
        h = forge("POST", "/v1/thing", SMALL, extra=[
            (b"content-length", b"17"), (b"transfer-encoding", b"chunked"),
        ])
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "non-numeric Content-Length")
    async def _():
        h = forge("POST", "/v1/thing", SMALL, extra=[(b"content-length", b"17x")])
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "unsorted signed-headers list")
    async def _():
        h = with_value(forge("POST", "/v1/thing", SMALL),
                       b"x-request-signed-headers", b"x-forwarded-for;host")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "self-referential signed-headers list")
    async def _():
        h = with_value(forge("POST", "/v1/thing", SMALL),
                       b"x-request-signed-headers", b"host;x-request-signature")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "duplicate signed header ride-along")
    async def _():
        h = forge("POST", "/v1/act", SMALL, extra=[(b"x-forwarded-for", b"1.1.1.1")])
        h = h + [(b"x-forwarded-for", b"2.2.2.2")]  # second value nobody signed
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("I  AMBIGUITY", "NaN timestamp to slip the window")
    async def _():
        h = forge("POST", "/v1/thing", SMALL, ts="nan")
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    # ===== BOOK II — EXTENT: lie about magnitude ==========================

    @attack("II EXTENT   ", "oversized body, honest small CL claim")
    async def _():
        h = forge("POST", "/v1/upload", BIG, extra=[(b"content-length", b"17")])
        return await fire(http("POST", "/v1/upload", h), make_receive(BIG))

    @attack("II EXTENT   ", "chunked, no CL, unbounded body")
    async def _():
        h = forge("POST", "/v1/upload", BIG)  # authenticated; no length at all
        return await fire(http("POST", "/v1/upload", h), make_receive(BIG))

    @attack("II EXTENT   ", "oversized header block")
    async def _():
        return await fire(http("GET", "/", [
            (b"host", HOST.encode()), (b"x-filler", b"A" * 9000),
        ]), make_receive(b""))

    # ===== BOOK III — FRESHNESS: move the request through time ============

    @attack("III FRESHNESS", "replay a captured valid request")
    async def _():
        n = secrets.token_bytes(16)
        h = forge("POST", "/v1/thing", SMALL, nonce=n)
        await fire(http("POST", "/v1/thing", h), make_receive(SMALL))   # 1st: legit
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))  # replay

    @attack("III FRESHNESS", "back-dated timestamp")
    async def _():
        h = forge("POST", "/v1/thing", SMALL, ts=str(time.time() - 10_000))
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("III FRESHNESS", "post-dated timestamp")
    async def _():
        h = forge("POST", "/v1/thing", SMALL, ts=str(time.time() + 10_000))
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    # ===== BOOK IV — LEAKAGE / COVERAGE: forge, swap, inject ==============

    @attack("IV LEAKAGE ", "forge a signature without the key")
    async def _():
        h = forge("POST", "/v1/thing", SMALL, key=WRONG_KEY)
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "body swap (sign A, deliver B)")
    async def _():
        a, b = b"approved=false", b"approved=true!"
        h = forge("POST", "/v1/act", a)                 # valid sig over A
        return await fire(http("POST", "/v1/act", h), make_receive(b))

    @attack("IV LEAKAGE ", "query swap under a valid signature")
    async def _():
        h = forge("POST", "/v1/act", SMALL, qs=b"approved=false")
        return await fire(http("POST", "/v1/act", h, qs=b"approved=true"),
                          make_receive(SMALL))

    @attack("IV COVERAGE", "inject unsigned decision header")
    async def _():
        captured = forge("POST", "/v1/act", SMALL)      # declares host only
        h = captured + [(b"x-http-method-override", b"DELETE")]
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV COVERAGE", "downgrade: declare host, send Cookie")
    async def _():
        h = forge("POST", "/v1/act", SMALL,
                  extra=[(b"cookie", b"session=abc")], declare=[b"host"])
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "tamper a declared header's value")
    async def _():
        h = with_value(
            forge("POST", "/v1/act", SMALL, extra=[(b"x-http-method-override", b"GET")]),
            b"x-http-method-override", b"DELETE",
        )
        return await fire(http("POST", "/v1/act", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "truncated / wrong-length signature")
    async def _():
        h = with_value(forge("POST", "/v1/thing", SMALL),
                       b"x-request-signature", b"0" * 10)
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    @attack("IV LEAKAGE ", "canonical-collision signature reuse")
    async def _():
        # Capture a valid sig for (path='/a\nb', query='c'); try to reuse it for
        # (path='/a', query='b\nc') — identical under a newline-join canonical,
        # distinct under length-prefixing. The captured sig must not verify.
        captured = forge("POST", "/a\nb", SMALL, qs=b"c")
        return await fire(http("POST", "/a", captured, qs=b"b\nc"),
                          make_receive(SMALL))

    # ===== CONTROL: the one request that SHOULD reach the app =============

    @attack("-- CONTROL ", "legitimate signed request", expect_blocked=False)
    async def _():
        h = forge("POST", "/v1/thing", SMALL)
        return await fire(http("POST", "/v1/thing", h), make_receive(SMALL))

    # ---- runner + red-team report ---------------------------------------
    async def main() -> None:
        # Injectivity, demonstrated not asserted: the newline-join canonical
        # collides on the collision attack's field pair; length-prefix doesn't.
        old_a = b"\n".join([b"/a\nb", b"c"])
        old_b = b"\n".join([b"/a", b"b\nc"])
        new_a = _lp_join([b"/a\nb", b"c"])
        new_b = _lp_join([b"/a", b"b\nc"])

        print("=" * 78)
        print("STRUCTURAL BOUNDARY — ATTACK HARNESS   (target: in-process middleware)")
        print(f"canonical injective: {new_a != new_b}   "
              f"(newline-join would collide: {old_a == old_b})")
        print("=" * 78)
        print(f"{'BOOK':<13} {'ATTACK':<42} {'STATUS':>6}  VERDICT")
        print("-" * 78)

        held = bypass = control_ok = control_broken = 0
        findings: List[str] = []
        current_book = None

        for book, name, expect_blocked, fn in ATTACKS:
            if book != current_book:
                if current_book is not None:
                    print()
                current_book = book
            status, reached = await fn()
            if expect_blocked:
                if reached:
                    verdict, bypass = "BYPASS  <-- finding", bypass + 1
                    findings.append(f"{book.strip()} / {name}")
                else:
                    verdict, held = "held", held + 1
            else:  # control
                if reached:
                    verdict, control_ok = "ok (expected)", control_ok + 1
                else:
                    verdict, control_broken = "BROKEN  <-- false positive", control_broken + 1
            print(f"{book:<13} {name:<42} {str(status):>6}  {verdict}")

        print("-" * 78)
        attacks_total = held + bypass
        print(f"RESULT: {attacks_total} attacks  |  {held} held  |  {bypass} bypass")
        print(f"        control: {control_ok} ok, {control_broken} broken")
        if findings:
            print("\nFINDINGS (attack reached the app):")
            for f in findings:
                print(f"  - {f}")
        else:
            print("\nNo bypass: every attack was blocked and the control passed.")
        print("=" * 78)

    asyncio.run(main())
