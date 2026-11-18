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

Both runs were executed **live** on 2026-11-17.

- **Before (stock):** `bkimminich/juice-shop:v17.3.0` at `http://localhost:3002` →
  `python3 scripts/run_all.py` reported **`0 passed, 6 vulnerable, 0 skipped`**.
- **After (patched):** a fork with `fixes/juice-shop-v17.3.0-fixes.patch` applied, built
  into an image and run at `http://localhost:3003` → **`6 passed, 0 vulnerable,
  0 skipped`**.

Side-by-side evidence: `screenshots/retest-before-after.png`. The stock exploits were
also corroborated by Juice Shop's own challenge tracker (Login Admin, View Basket,
Poison Null Byte, Confidential Document, Password Strength) in `screenshots/app-home.png`.
Legitimate login still works on the patched build (admin/admin123 → HTTP 200), confirming
the scrypt migration preserved authentication.

### Retest table

| ID | Before — stock (3002) | After — patched (3003) | Evidence |
|----|------------------------|------------------------|----------|
| VL-01 | **FAIL** — `' OR 1=1--` returns an `admin` (id 1) JWT | **PASS** — injection → HTTP 401, no token | `retest-before-after.png`, `raw-http-evidence.txt` |
| VL-02 | **FAIL** — read baskets 1 & 2 (other users) | **PASS** — cross-user reads refused | `retest-before-after.png` |
| VL-03 | **FAIL** — live `<iframe>` injected into DOM | **PASS** — payload sanitized, no live element | `retest-before-after.png` |
| VL-04 | **FAIL** — 15 wrong reset answers, no `429` | **PASS** — endpoint throttles (HTTP 429) | `retest-before-after.png` |
| VL-05 | **FAIL** — `%2500.md` served `package.json.bak` | **PASS** — null-byte refused (HTTP 403) | `retest-before-after.png`, `vl05-ftp-exposure.png` |
| VL-06 | **FAIL** — stored hash == `md5(password)` | **PASS** — stored as `scrypt$…` | `retest-before-after.png` |

### Reproducing

```bash
# Before (stock):
docker run -d --name juice -p 127.0.0.1:3002:3000 bkimminich/juice-shop:v17.3.0
JUICE_URL=http://localhost:3002 TEST_EMAIL=... TEST_PASSWORD=... python3 scripts/run_all.py  # 6 vulnerable

# After (patched):
git clone --depth 1 --branch v17.3.0 https://github.com/juice-shop/juice-shop.git && cd juice-shop
git apply /path/to/fixes/juice-shop-v17.3.0-fixes.patch
docker build -t juice-patched:v17.3.0 . && docker run -d -p 127.0.0.1:3003:3000 juice-patched:v17.3.0
JUICE_URL=http://localhost:3003 TEST_EMAIL=... TEST_PASSWORD=... python3 scripts/run_all.py  # 6 passed
```

> Build note: Juice Shop's Dockerfile uses the EOL `node:20-buster` base; two lines need
> a one-time tweak (point apt at `archive.debian.org`, drop the optional SBOM step) for
> the image to build today. This does not affect the application code or the fixes.

## 6. Disclaimer

All testing described here targets a local, intentionally vulnerable application (OWASP
Juice Shop) running only on `localhost`. No systems owned by third parties were
accessed or tested. Payloads and fixes are provided for defensive and educational
purposes.
