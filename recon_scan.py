#!/usr/bin/env python3
"""
recon_scan.py - Non-destructive web reconnaissance for AUTHORIZED assessments.

This tool gathers information about web hosts you are contracted to test. It is
deliberately PASSIVE/non-destructive: it sends ordinary HEAD/GET requests, reads
responses, and reports. It does NOT fuzz inputs, send request-smuggling or
desync payloads, brute-force credentials, upload anything, or try to exploit.
Recon only. Anything offensive is a deliberate, separately-scoped follow-up a
human decides on per finding - not something a scanner should fire blindly.

What it collects, per in-scope host:
  * DNS resolution + whether the IP is public/private/reserved
  * HTTP and HTTPS liveness: status, redirect chain, server/powered-by banners
  * Security-header audit (HSTS, CSP, X-Frame-Options, ...) with what's missing
  * Cookie flags (Secure / HttpOnly / SameSite)
  * TLS: negotiated version, cert subject/issuer/expiry/SANs, validity
  * Benign discovery files: robots.txt, sitemap.xml, security.txt, humans.txt
  * Lightweight technology fingerprint from banners/cookies

SCOPE IS ENFORCED. The tool will only contact hosts you explicitly place in
scope (a hostname, or a *.example.com wildcard). A redirect that leaves scope is
reported and NOT followed. You must pass --authorized to confirm you have
written permission to test the targets; that assertion is yours to make and to
be able to prove.

Stdlib only - no third-party packages required.

Examples:
  python3 recon_scan.py --authorized app.example.com api.example.com
  python3 recon_scan.py --authorized --scope-file scope.txt --json out.json
  python3 recon_scan.py --authorized --scope '*.example.com' www.example.com \\
      --delay 1.0 --paths
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import socket
import ssl
import sys
import threading
import time
from http.client import HTTPConnection, HTTPSConnection
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

__version__ = "1.0"
USER_AGENT = f"recon-scan/{__version__} (authorized security assessment)"

# Security response headers we audit for presence, with a one-line note on why
# each matters. Absence is informational, not proof of a vulnerability.
SECURITY_HEADERS: Dict[str, str] = {
    "strict-transport-security": "HSTS: forces HTTPS, blocks SSL-strip downgrade",
    "content-security-policy": "CSP: mitigates XSS / data injection",
    "x-frame-options": "clickjacking defense (superseded by CSP frame-ancestors)",
    "x-content-type-options": "stops MIME sniffing (expect: nosniff)",
    "referrer-policy": "controls Referer leakage to third parties",
    "permissions-policy": "restricts powerful browser features",
    "cross-origin-opener-policy": "process isolation (Spectre-class defense)",
}

# Benign, read-only discovery files. These are published for clients to read;
# requesting them is not intrusive. This is NOT a content-brute-force wordlist.
DISCOVERY_PATHS: List[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
    "/.well-known/change-password",
]

# Header/cookie banners -> technology guesses. Heuristic only.
FINGERPRINTS: List[Tuple[str, str]] = [
    ("x-powered-by", "declared via X-Powered-By"),
    ("x-aspnet-version", "ASP.NET"),
    ("x-drupal-cache", "Drupal"),
    ("x-generator", "declared via X-Generator"),
    ("x-shopify-stage", "Shopify"),
    ("via", "proxy/CDN in path (Via)"),
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "AWS CloudFront"),
    ("x-served-by", "Fastly/Varnish"),
    ("x-vercel-id", "Vercel"),
]

_print_lock = threading.Lock()


class RateLimiter:
    """Global minimum spacing between outbound requests, across all workers."""

    def __init__(self, delay: float) -> None:
        self._delay = max(0.0, delay)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self._delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next = now + self._delay


class Scope:
    """Explicit allowlist of testable hosts. Exact names and *.domain wildcards."""

    def __init__(self, entries: List[str]) -> None:
        self.exact: set[str] = set()
        self.wildcards: List[str] = []  # suffixes like ".example.com"
        for raw in entries:
            e = raw.strip().lower().rstrip(".")
            if not e:
                continue
            if e.startswith("*."):
                self.wildcards.append(e[1:])  # ".example.com"
            else:
                self.exact.add(e)

    def __bool__(self) -> bool:
        return bool(self.exact or self.wildcards)

    def contains(self, host: str) -> bool:
        h = host.strip().lower().rstrip(".")
        if h in self.exact:
            return True
        for suffix in self.wildcards:
            if h.endswith(suffix) and h != suffix.lstrip("."):
                return True
            if h == suffix.lstrip("."):  # apex also covered by its wildcard
                return True
        return False


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_link_local:
        return "link-local"
    if addr.is_reserved or addr.is_multicast:
        return "reserved"
    return "public"


def resolve(host: str) -> Tuple[List[str], Optional[str]]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return [], f"DNS failure: {e}"
    ips = sorted({i[4][0] for i in infos})
    return ips, None


def _make_unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_info(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Negotiated TLS version + cert details + validity. Connects even to invalid
    certs (to report them), but only parses the cert chain on a verified handshake."""
    out: Dict[str, Any] = {"valid": None, "version": None, "cert": None, "error": None}
    # Pass 1: strict verification to learn validity and (if valid) read the cert.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["valid"] = True
                out["version"] = ss.version()
                cert = ss.getpeercert()
                out["cert"] = _summarize_cert(cert)
        return out
    except ssl.SSLCertVerificationError as e:
        out["valid"] = False
        out["error"] = f"cert verification failed: {e.verify_message or e}"
    except (ssl.SSLError, socket.timeout, OSError) as e:
        out["error"] = f"TLS connect error: {e}"
        return out
    # Pass 2: invalid cert - still record the negotiated version (no cert parse).
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with _make_unverified_ctx().wrap_socket(sock, server_hostname=host) as ss:
                out["version"] = ss.version()
    except (ssl.SSLError, socket.timeout, OSError):
        pass
    return out


def _summarize_cert(cert: Dict[str, Any]) -> Dict[str, Any]:
    def flatten(seq: Any) -> str:
        parts = []
        for rdn in seq or ():
            for k, v in rdn:
                parts.append(f"{k}={v}")
        return ", ".join(parts)

    sans = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=dt.timezone.utc)
            days_left = (exp - dt.datetime.now(dt.timezone.utc)).days
        except ValueError:
            pass
    return {
        "subject": flatten(cert.get("subject")),
        "issuer": flatten(cert.get("issuer")),
        "not_after": not_after,
        "days_until_expiry": days_left,
        "subject_alt_names": sans,
    }


def http_fetch(
    scheme: str,
    host: str,
    port: int,
    path: str,
    *,
    method: str,
    timeout: float,
    limiter: RateLimiter,
    max_body: int = 65536,
) -> Dict[str, Any]:
    """One request. Returns status, headers (list, duplicates preserved), body snippet.
    Never raises for HTTP-level problems; network errors are returned in 'error'."""
    limiter.wait()
    conn = None
    try:
        if scheme == "https":
            conn = HTTPSConnection(host, port, timeout=timeout, context=_make_unverified_ctx())
        else:
            conn = HTTPConnection(host, port, timeout=timeout)
        conn.request(
            method,
            path or "/",
            headers={"Host": host, "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
        )
        resp = conn.getresponse()
        body = b""
        if method != "HEAD":
            body = resp.read(max_body)
        return {
            "status": resp.status,
            "reason": resp.reason,
            "headers": resp.getheaders(),  # list[tuple], preserves duplicate Set-Cookie
            "body": body,
            "error": None,
        }
    except (socket.timeout, OSError, ssl.SSLError) as e:
        return {"status": None, "reason": None, "headers": [], "body": b"", "error": str(e)}
    finally:
        if conn is not None:
            conn.close()


def header_get(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def header_all(headers: List[Tuple[str, str]], name: str) -> List[str]:
    name = name.lower()
    return [v for k, v in headers if k.lower() == name]


def follow_redirects(
    url: str, scope: Scope, limiter: RateLimiter, timeout: float, max_hops: int
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Walk redirects, staying in scope. Returns (hops, out_of_scope_target_or_None)."""
    hops: List[Dict[str, Any]] = []
    seen: set[str] = set()
    current = url
    for _ in range(max_hops + 1):
        if current in seen:
            break
        seen.add(current)
        parts = urlsplit(current)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        r = http_fetch(parts.scheme, host, port, path, method="GET",
                       timeout=timeout, limiter=limiter)
        hop = {
            "url": current,
            "status": r["status"],
            "server": header_get(r["headers"], "server"),
            "location": header_get(r["headers"], "location"),
            "error": r["error"],
            "_headers": r["headers"],
            "_body": r["body"],
        }
        hops.append(hop)
        if r["status"] and 300 <= r["status"] < 400 and hop["location"]:
            nxt = urlsplit(hop["location"])
            if not nxt.scheme:  # relative redirect
                current = urlunsplit((parts.scheme, parts.netloc, nxt.path or "/", nxt.query, ""))
                continue
            nhost = nxt.hostname or ""
            if not scope.contains(nhost):
                return hops, hop["location"]  # stop: leaves scope
            current = hop["location"]
            continue
        break
    return hops, None


def audit_headers(headers: List[Tuple[str, str]]) -> Dict[str, Any]:
    present, missing = {}, []
    for h, why in SECURITY_HEADERS.items():
        val = header_get(headers, h)
        if val is not None:
            present[h] = val
        else:
            missing.append({"header": h, "why": why})
    return {"present": present, "missing": missing}


def audit_cookies(headers: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    cookies = []
    for raw in header_all(headers, "set-cookie"):
        segs = [s.strip() for s in raw.split(";")]
        attrs = {s.split("=", 1)[0].strip().lower(): (s.split("=", 1)[1].strip()
                                                       if "=" in s else "")
                 for s in segs[1:]}
        name = segs[0].split("=", 1)[0].strip() if segs else ""
        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite"),
        })
    return cookies


def fingerprint(headers: List[Tuple[str, str]]) -> List[str]:
    out = []
    for h, label in FINGERPRINTS:
        val = header_get(headers, h)
        if val is not None:
            out.append(f"{label}: {val}" if "declared" in label else label)
    return out


def scan_host(spec: Dict[str, Any], args: argparse.Namespace, scope: Scope,
              limiter: RateLimiter) -> Dict[str, Any]:
    host = spec["host"]
    probes: List[Tuple[str, int]] = spec["probes"]
    result: Dict[str, Any] = {"host": host, "label": spec["label"], "dns": {},
                              "schemes": {}, "discovery": {}, "notes": []}

    ips, dns_err = resolve(host)
    if dns_err:
        result["dns"] = {"error": dns_err}
        result["notes"].append(dns_err)
        return result
    classes = {ip: classify_ip(ip) for ip in ips}
    result["dns"] = {"addresses": ips, "classes": classes}

    nonpublic = {ip: c for ip, c in classes.items() if c != "public"}
    if nonpublic and not args.allow_private:
        msg = (f"resolves to non-public IP(s) {nonpublic}; skipped. "
               "Use --allow-private for internal-scope engagements.")
        result["notes"].append(msg)
        return result

    for scheme, port in probes:
        default_port = 443 if scheme == "https" else 80
        netloc = host if port == default_port else f"{host}:{port}"
        key = scheme if port == default_port else f"{scheme}:{port}"
        base = f"{scheme}://{netloc}"
        hops, oos = follow_redirects(base + "/", scope, limiter, args.timeout, args.max_redirects)
        if not hops:
            continue
        final = hops[-1]
        entry: Dict[str, Any] = {
            "reachable": final["status"] is not None,
            "final_url": final["url"],
            "status": final["status"],
            "redirect_chain": [{"url": h["url"], "status": h["status"], "location": h["location"]}
                               for h in hops],
            "server": final["server"],
            "error": final["error"],
        }
        if oos:
            entry["left_scope"] = oos
            result["notes"].append(f"{key}: redirect left scope -> {oos} (not followed)")
        if final["status"] is not None:
            entry["security_headers"] = audit_headers(final["_headers"])
            entry["cookies"] = audit_cookies(final["_headers"])
            entry["fingerprint"] = fingerprint(final["_headers"])
        if scheme == "https":
            entry["tls"] = tls_info(host, port, args.timeout)
        result["schemes"][key] = entry

    # Benign discovery files (over the first reachable probe).
    live = next(((scheme, port) for scheme, port in probes
                 if result["schemes"].get(
                     scheme if port == (443 if scheme == "https" else 80)
                     else f"{scheme}:{port}", {}).get("reachable")), None)
    if live and args.paths:
        live_scheme, port = live
        for p in DISCOVERY_PATHS:
            r = http_fetch(live_scheme, host, port, p, method="GET",
                           timeout=args.timeout, limiter=limiter)
            if r["status"] in (200, 204):
                snippet = r["body"][:200].decode("utf-8", "replace").strip()
                result["discovery"][p] = {"status": r["status"], "preview": snippet}
    return result


def print_report(results: List[Dict[str, Any]]) -> None:
    with _print_lock:
        for r in results:
            print("=" * 78)
            print(f"HOST: {r['host']}")
            dns = r.get("dns", {})
            if dns.get("error"):
                print(f"  DNS: {dns['error']}")
            elif dns.get("addresses"):
                for ip in dns["addresses"]:
                    print(f"  DNS: {ip} ({dns['classes'][ip]})")
            for note in r.get("notes", []):
                print(f"  NOTE: {note}")
            for scheme, e in r.get("schemes", {}).items():
                if not e.get("reachable"):
                    if e.get("error"):
                        print(f"  [{scheme}] unreachable: {e['error']}")
                    continue
                print(f"  [{scheme}] {e['status']} -> {e['final_url']}"
                      + (f"  server={e['server']}" if e.get("server") else ""))
                if len(e.get("redirect_chain", [])) > 1:
                    for h in e["redirect_chain"][:-1]:
                        print(f"        redirect {h['status']} -> {h['location']}")
                tls = e.get("tls")
                if tls:
                    v = tls.get("version") or "?"
                    if tls.get("valid") is True and tls.get("cert"):
                        c = tls["cert"]
                        print(f"        TLS {v}  cert OK  issuer=[{c['issuer']}]  "
                              f"expires {c['not_after']} ({c['days_until_expiry']}d)")
                        if c["subject_alt_names"]:
                            print(f"        SANs: {', '.join(c['subject_alt_names'][:8])}"
                                  + (" ..." if len(c['subject_alt_names']) > 8 else ""))
                    elif tls.get("valid") is False:
                        print(f"        TLS {v}  CERT INVALID: {tls.get('error')}")
                    elif tls.get("error"):
                        print(f"        TLS: {tls['error']}")
                fp = e.get("fingerprint") or []
                if fp:
                    print(f"        tech: {'; '.join(fp)}")
                missing = e.get("security_headers", {}).get("missing", [])
                if missing:
                    print(f"        missing security headers: "
                          f"{', '.join(m['header'] for m in missing)}")
                for ck in e.get("cookies", []):
                    flags = []
                    if not ck["secure"]:
                        flags.append("no Secure")
                    if not ck["httponly"]:
                        flags.append("no HttpOnly")
                    if not ck["samesite"]:
                        flags.append("no SameSite")
                    if flags:
                        print(f"        cookie '{ck['name']}': {', '.join(flags)}")
            if r.get("discovery"):
                for path, d in r["discovery"].items():
                    print(f"  found {path} ({d['status']})")
        print("=" * 78)


def parse_target(raw: str) -> Optional[Dict[str, Any]]:
    """Accept 'host', 'host:port', or a full URL. Returns a spec:
    {host, label, probes=[(scheme, port), ...]}. None for empty input."""
    t = raw.strip()
    if not t:
        return None
    if "://" in t:
        u = urlsplit(t)
        host = (u.hostname or "").lower().rstrip(".")
        scheme = u.scheme if u.scheme in ("http", "https") else "https"
        port = u.port or (443 if scheme == "https" else 80)
        return {"host": host, "label": t, "probes": [(scheme, port)]}
    # host or host:port  (guard IPv6 '[::1]:443' minimally)
    host, _, port_s = t.rpartition(":")
    if host and port_s.isdigit():
        host = host.strip("[]").lower().rstrip(".")
        port = int(port_s)
        return {"host": host, "label": t, "probes": [("https", port), ("http", port)]}
    host = t.strip("[]").lower().rstrip(".")
    return {"host": host, "label": t, "probes": [("https", 443), ("http", 80)]}


def load_scope(args: argparse.Namespace) -> Tuple[List[Dict[str, Any]], Scope]:
    raw_targets: List[str] = list(args.targets)
    explicit_scope: List[str] = list(args.scope)
    if args.scope_file:
        with open(args.scope_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    explicit_scope.append(line)

    specs: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_targets:
        spec = parse_target(raw)
        if spec and spec["host"] and spec["label"] not in seen:
            seen.add(spec["label"])
            specs.append(spec)

    # Strict mode: if you declared a scope, targets must fall inside it (catches
    # typos). Convenience mode: with no explicit scope, the targets you named ARE
    # the scope - your assertion of authorization.
    if explicit_scope:
        scope = Scope(explicit_scope)
    else:
        scope = Scope([s["host"] for s in specs])
    return specs, scope


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Non-destructive web recon for AUTHORIZED assessments.",
        epilog="You are responsible for having written authorization for every target.",
    )
    p.add_argument("targets", nargs="*", help="hostnames or URLs to scan")
    p.add_argument("--scope", action="append", default=[],
                   help="extra in-scope entry (hostname or *.domain); repeatable")
    p.add_argument("--scope-file", help="file of in-scope hosts, one per line (# comments ok)")
    p.add_argument("--authorized", action="store_true",
                   help="REQUIRED: assert you have written permission to test these targets")
    p.add_argument("--allow-private", action="store_true",
                   help="permit targets resolving to private/reserved IPs (internal engagements)")
    p.add_argument("--paths", action="store_true",
                   help="also fetch benign discovery files (robots.txt, security.txt, ...)")
    p.add_argument("--delay", type=float, default=0.5,
                   help="minimum seconds between requests, globally (default 0.5)")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (default 10)")
    p.add_argument("--max-redirects", type=int, default=5, help="max redirect hops (default 5)")
    p.add_argument("--workers", type=int, default=4, help="concurrent hosts (default 4)")
    p.add_argument("--json", metavar="FILE", help="write full results as JSON to FILE")
    p.add_argument("--version", action="version", version=f"recon-scan {__version__}")
    args = p.parse_args(argv)

    specs, scope = load_scope(args)
    if not specs:
        p.error("no targets given")
    if not args.authorized:
        p.error("refusing to scan without --authorized (assert written permission to test)")
    for s in specs:
        if not scope.contains(s["host"]):
            p.error(f"target {s['label']!r} (host {s['host']!r}) is not in the "
                    "declared scope; add it to --scope/--scope-file or remove the target")

    order = {s["label"]: i for i, s in enumerate(specs)}
    sys.stderr.write(
        f"recon-scan {__version__}: {len(specs)} target(s), scope-guarded, "
        f"delay={args.delay}s. Recon only - no exploitation.\n"
    )

    limiter = RateLimiter(args.delay)
    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(scan_host, s, args, scope, limiter): s for s in specs}
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:  # keep one bad host from killing the run
                s = futs[fut]
                results.append({"host": s["host"], "label": s["label"],
                                "notes": [f"scan error: {e}"],
                                "dns": {}, "schemes": {}, "discovery": {}})

    results.sort(key=lambda r: order.get(r.get("label", ""), 0))
    print_report(results)

    if args.json:
        serializable = []
        for r in results:
            rc = json.loads(json.dumps(r, default=lambda o: o.decode("utf-8", "replace")
                                       if isinstance(o, bytes) else str(o)))
            for e in rc.get("schemes", {}).values():
                e.pop("_headers", None)
                e.pop("_body", None)
            serializable.append(rc)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
        sys.stderr.write(f"wrote {args.json}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
