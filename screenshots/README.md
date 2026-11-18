# Screenshots & evidence

Evidence captured from **live** runs on 2026-11-17: the stock OWASP Juice Shop `v17.3.0`
(Docker, `http://localhost:3002`) and a **patched** build of the same version
(`http://localhost:3003`). The stock build reproduces all six findings; the patched
build blocks all six.

| File | Shows |
|------|-------|
| `retest-before-after.png` | **Primary evidence** — suite output side by side: stock = 6 VULNERABLE, patched = 6 PASS. |
| `retest-vulnerable.png` | Full stock `run_all.py` output + raw HTTP exploit proof for VL-01/05/06. |
| `app-home.png` | The running target, with the app's own "challenge solved" banners corroborating the exploits: **Login Admin** (VL-01), **View Basket** (VL-02), **Poison Null Byte** + **Confidential Document** (VL-05), **Password Strength** (VL-01/06). |
| `vl05-ftp-exposure.png` | Confidential `/ftp/acquisitions.md` served to an anonymous browser. |
| `retest-vulnerable.txt` / `retest-patched.txt` | Plain-text suite output, before and after. |
| `raw-http-evidence.txt` | Plain-text raw `curl` exploit requests/responses. |

## Corroboration

The exploits were independently confirmed three ways:

1. **Regression suite** — `run_all.py` reports 6/6 VULNERABLE.
2. **Raw HTTP** — e.g. SQLi `' OR 1=1--` returns an `admin` (id 1) JWT; the null-byte
   request serves `package.json.bak`; the admin login token's `data.password`
   (`0192023a...b500`) equals `md5("admin123")`.
3. **The app's own challenge tracker** fired for the corresponding Juice Shop
   challenges (visible in `app-home.png`).

## Patched (after) — captured

The patched build (fork + `fixes/juice-shop-v17.3.0-fixes.patch`, built into an image and
run on `:3003`) blocks all six findings — see the right-hand column of
`retest-before-after.png` and `retest-patched.txt`. VL-03 is verified behaviorally: the
suite renders the search page in headless Chrome and confirms the injected `<iframe>`
element is present in the stock DOM but sanitized away on the patched build.
