# recon_scan

A **non-destructive** web reconnaissance scanner for **authorized** penetration
tests. Stdlib-only Python 3 (no dependencies).

It gathers information with ordinary HEAD/GET requests and reports. It does **not**
fuzz inputs, send request-smuggling/desync payloads, brute-force, upload, or try
to exploit anything. Recon is the first phase; any offensive follow-up is a
separate, per-finding decision a human makes against an explicitly scoped target.

## What it collects per host

- DNS resolution and whether each IP is public / private / reserved
- HTTP + HTTPS liveness: status, full redirect chain, `Server` / `X-Powered-By` banners
- Security-header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, …) — what's **missing**
- Cookie flags: `Secure` / `HttpOnly` / `SameSite`
- TLS: negotiated version, certificate subject/issuer/expiry/SANs, validity
- Benign discovery files (`--paths`): `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`
- Heuristic technology fingerprint from banners/cookies (Cloudflare, Vercel, ASP.NET, …)

## Safety model

- **`--authorized` is mandatory.** It is your assertion that you hold written
  permission to test the targets. Only scan what your engagement's rules of
  engagement cover.
- **Scope is enforced.** If you pass `--scope`/`--scope-file`, every target must
  fall inside it (typos are rejected). With no explicit scope, the targets you
  name *are* the scope.
- **Redirects that leave scope are reported, not followed** — so you never
  accidentally crawl a CDN, linked third party, or auth provider.
- **Private/reserved IPs are skipped** unless you pass `--allow-private` (for
  internal engagements).
- **Polite by default:** a global request delay (`--delay`, default 0.5s) and
  a scanner-identifying `User-Agent`.

## Usage

```bash
# Basic: one or more hosts (they become the scope)
python3 recon_scan.py --authorized app.example.com api.example.com

# Explicit scope file (strict: targets must be inside it)
python3 recon_scan.py --authorized --scope-file scope.txt --paths --json out.json

# Wildcard scope + specific targets, slower rate
python3 recon_scan.py --authorized --scope '*.example.com' www.example.com --delay 1.0

# Non-standard port, or a full URL
python3 recon_scan.py --authorized staging.example.com:8443
python3 recon_scan.py --authorized https://example.com/
```

`scope.txt` is one entry per line; `#` comments allowed; `*.example.com` wildcards supported.

## Flags

| Flag | Meaning |
|------|---------|
| `--authorized` | **required** — assert written permission to test |
| `--scope` / `--scope-file` | declare in-scope hosts (strict matching) |
| `--allow-private` | permit targets on private/reserved IPs |
| `--paths` | also fetch benign discovery files |
| `--delay` | global min seconds between requests (default 0.5) |
| `--timeout` | per-request timeout (default 10) |
| `--max-redirects` | max redirect hops (default 5) |
| `--workers` | concurrent hosts (default 4) |
| `--json FILE` | write full structured results |

## Scope and legality

You are responsible for having explicit, written authorization for every target.
Scanning systems you are not authorized to test may be illegal. This tool makes
no attempt to hide its activity and identifies itself in its `User-Agent`.
