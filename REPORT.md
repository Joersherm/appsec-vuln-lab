# AppSec Assessment Report — OWASP Juice Shop (local lab)

**Target:** OWASP Juice Shop `bkimminich/juice-shop:v17.3.0`, run in Docker, bound to
`http://localhost:3001` (localhost only).
**Assessor:** Joseph Sherman
**Engagement type:** Self-directed lab against an intentionally vulnerable application.
**Scope:** The single local instance above. No third-party systems were touched.

---

## 1. Executive summary

This assessment identified **six vulnerabilities** in the target spanning five OWASP
Top 10 (2021) categories, including a **critical** SQL injection that permits full
authentication bypass and administrator takeover. Each issue was reproduced manually,
remediated with a targeted source-code change against the Juice Shop source, and paired
with an automated regression script that fails against the vulnerable build and passes
against the patched one.

The most serious issues (VL-01 SQLi, VL-02 IDOR) stem from trusting user input in
security-sensitive code paths — the query layer and the authorization layer
respectively. The remaining findings reflect weak cryptographic and recovery choices
and an over-exposed file endpoint. All are addressed by the fixes in `fixes/`.

## 2. Findings overview

| ID | Title | OWASP 2021 | Severity | CVSS | Status |
|----|-------|-----------|----------|------|--------|
| [VL-01](findings/01-sqli-login-auth-bypass.md) | SQL injection in login → auth bypass | A03 Injection | **Critical** | 9.8 | Fixed |
| [VL-02](findings/02-idor-basket-access.md) | IDOR on shopping baskets | A01 Broken Access Control | High | 6.5 | Fixed |
| [VL-03](findings/03-dom-xss-search.md) | DOM-based XSS in product search | A03 Injection (XSS) | Medium | 6.1 | Fixed |
| [VL-04](findings/04-weak-password-reset.md) | Unthrottled security-question reset | A07 Auth Failures | High | 7.5 | Fixed |
| [VL-05](findings/05-ftp-sensitive-file-exposure.md) | `/ftp` exposure + null-byte bypass | A05 Misconfiguration | High | 7.5 | Fixed |
| [VL-06](findings/06-unsalted-md5-password-hash.md) | Unsalted MD5 password storage | A02 Cryptographic Failures | High | 7.5 | Fixed |

**Severity distribution:** 1 Critical · 4 High · 1 Medium.

## 3. Methodology

1. **Recon** — mapped the SPA and its REST API surface (`/rest/*`, `/api/*`) and the
   static `/ftp` route.
2. **Assess** — manually exploited each issue against the local instance, capturing the
   request/response evidence summarized in each `findings/` write-up.
3. **Fix** — patched the responsible source files in a fork of Juice Shop `v17.3.0`;
   diffs and rationale live in `fixes/`.
4. **Verify** — authored one Python regression script per finding (`scripts/`) with a
   strict exit-code contract (0 patched / 1 vulnerable / 2 unreachable).
5. **Report** — this document.

## 4. Remediation summary

| ID | Root cause | Fix |
|----|-----------|-----|
| VL-01 | Raw SQL string concatenation of `email` | Parameterized `bind` query |
| VL-02 | No ownership check on basket id | Compare basket `UserId` to JWT identity |
| VL-03 | `bypassSecurityTrustHtml` on user input | Render as text / `sanitize()` |
| VL-04 | No rate limit on reset; weak knowledge factor | Rate limit + lockout; prefer OOB token |
| VL-05 | Null byte trimmed after extension check | Reject null byte; validate resolved path |
| VL-06 | Unsalted MD5 password hashing | bcrypt (per-user salt + work factor) |

Cross-cutting recommendations: add a restrictive `Content-Security-Policy`; rate-limit
all authentication endpoints; adopt parameterized queries and an output-encoding
standard project-wide; keep confidential files out of any publicly served directory.

## 5. Retest results

The vulnerable baseline was run **live** on 2026-11-17 against OWASP Juice Shop
`v17.3.0` in Docker at `http://localhost:3002` (port `3002` was used because `3001` was
occupied by an unrelated service). **All six findings reproduced** —
`python3 scripts/run_all.py` reported `0 passed, 6 vulnerable, 0 skipped`. Evidence is
in `screenshots/` (suite output, raw HTTP proof, and the live app).

The exploits were corroborated independently by the application's own challenge tracker,
which registered **Login Admin** (VL-01), **View Basket** (VL-02), **Poison Null Byte**
and **Confidential Document** (VL-05), and **Password Strength** (VL-01/06) — visible in
`screenshots/app-home.png`.

The **patched ("after") column is pending**: it requires applying `fixes/` to a Juice
Shop fork, rebuilding, and re-running the suite (expected `6 passed`). The scripts'
exit-code contract makes this a single `run_all.py` invocation.

### Retest table

| ID | Vulnerable build (verified live) | Patched build | Evidence |
|----|----------------------------------|---------------|----------|
| VL-01 | **FAIL** — `' OR 1=1--` returns an `admin` (id 1) JWT | _pending rebuild_ | `retest-vulnerable.png`, `raw-http-evidence.txt`, `app-home.png` |
| VL-02 | **FAIL** — read baskets 1 & 2 (other users) | _pending rebuild_ | `retest-vulnerable.png` |
| VL-03 | **FAIL** — `bypassSecurityTrustHtml` sink present in `main.js` | _pending rebuild_ | `retest-vulnerable.png` |
| VL-04 | **FAIL** — 15 wrong reset answers, no `429` | _pending rebuild_ | `retest-vulnerable.png` |
| VL-05 | **FAIL** — `%2500.md` served `package.json.bak` | _pending rebuild_ | `retest-vulnerable.png`, `vl05-ftp-exposure.png` |
| VL-06 | **FAIL** — stored hash == `md5(password)` | _pending rebuild_ | `retest-vulnerable.png`, `raw-http-evidence.txt` |

### Reproducing / completing the patched run

```bash
# Vulnerable baseline (already captured):
docker run -d --name juice -p 127.0.0.1:3002:3000 bkimminich/juice-shop:v17.3.0
export JUICE_URL=http://localhost:3002 TEST_EMAIL=... TEST_PASSWORD=...
python3 scripts/run_all.py            # -> 6 vulnerable

# Patched build (to complete the "after" column):
#   apply fixes/ to a juice-shop v17.3.0 fork, rebuild, run it on the same URL, then:
python3 scripts/run_all.py            # expect -> 6 passed
```

## 6. Disclaimer

All testing described here targets a local, intentionally vulnerable application (OWASP
Juice Shop) running only on `localhost`. No systems owned by third parties were
accessed or tested. Payloads and fixes are provided for defensive and educational
purposes.
