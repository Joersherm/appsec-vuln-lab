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

The diffs are written against upstream file paths so they can be applied to a fork:

```bash
# 1. Fork / clone the pinned source
git clone --branch v17.3.0 https://github.com/juice-shop/juice-shop.git
cd juice-shop && git switch -c fixes

# 2. Apply each change (diffs here are illustrative/representative of the upstream
#    code; reconcile against the exact lines in your checkout, then commit per fix).

# 3. Rebuild and run the patched instance on the lab port
npm install
npm run build
PORT=3000 npm start   # map/expose as http://localhost:3001 to match the lab

# 4. Re-run the regression suite against the patched instance
python3 ../appsec-vuln-lab/scripts/run_all.py
```

> The diffs reflect the vulnerable patterns these Juice Shop versions are known for;
> line numbers and surrounding context may differ slightly by sub-version. Treat them
> as the intended change, and verify behaviour with the regression scripts rather than
> by line match alone.
