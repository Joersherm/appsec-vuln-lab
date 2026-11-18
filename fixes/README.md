# Fixes

One remediation document per finding. Each contains a unified diff against the upstream
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) source (tag `v17.3.0`, the
image used in this lab), the rationale, defense-in-depth notes, and the regression
command that proves it.

| Fix | Finding | File(s) changed | Technique |
|-----|---------|-----------------|-----------|
| [01](01-sqli-login-auth-bypass.md) | VL-01 SQLi login | `routes/login.ts` | Parameterized query (`bind`) |
| [02](02-idor-basket-access.md) | VL-02 IDOR basket | `routes/basket.ts` | Ownership check from JWT |
| [03](03-dom-xss-search.md) | VL-03 DOM XSS | `frontend/.../search-result.component.*` | Remove `bypassSecurityTrustHtml`; escape |
| [04](04-weak-password-reset.md) | VL-04 weak reset | `server.ts`, `routes/resetPassword.ts` | Rate limit + constant-time compare |
| [05](05-ftp-sensitive-file-exposure.md) | VL-05 `/ftp` exposure | `routes/fileServer.ts` | Reject null byte; validate resolved path |
| [06](06-unsalted-md5-password-hash.md) | VL-06 MD5 hashing | `lib/insecurity.ts`, `models/user.ts` | bcrypt (salt + work factor) |

## Applying the fixes

`juice-shop-v17.3.0-fixes.patch` is the **actual** unified diff produced from a
`v17.3.0` checkout (7 files, all six findings). Apply it to a fork and build:

```bash
# 1. Clone the pinned source and apply the patch
git clone --depth 1 --branch v17.3.0 https://github.com/juice-shop/juice-shop.git
cd juice-shop
git apply /path/to/appsec-vuln-lab/fixes/juice-shop-v17.3.0-fixes.patch

# 2a. Build & run a patched Docker image (recommended — uses the pinned Node 20 toolchain)
docker build -t juice-patched:v17.3.0 .
docker run -d --name juice-patched -p 127.0.0.1:3002:3000 juice-patched:v17.3.0

#    ...or 2b. build locally (needs Node 18–22; postinstall builds frontend + server)
#    npm install && npm start

# 3. Re-run the regression suite against the patched instance
JUICE_URL=http://localhost:3002 python3 /path/to/appsec-vuln-lab/scripts/run_all.py
#    expect: 6 passed, 0 vulnerable
```

> This exact flow was executed for the retest in [`../REPORT.md`](../REPORT.md#5-retest-results):
> the patched image reports **6/6 PASS** where the stock image reports 6/6 vulnerable.
> The per-fix Markdown files show each change in isolation with rationale.
