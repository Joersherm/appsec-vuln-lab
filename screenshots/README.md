# Screenshots & evidence

Evidence captured from a **live** run of the lab against OWASP Juice Shop `v17.3.0`
(Docker, `http://localhost:3002`) on 2026-11-17. This is the **vulnerable baseline**:
all six findings reproduce.

| File | Shows |
|------|-------|
| `retest-vulnerable.png` | Full `scripts/run_all.py` output — all 6 findings report **VULNERABLE** — plus raw HTTP exploit evidence for VL-01/05/06. |
| `app-home.png` | The running target. Note the app's own "challenge solved" banners corroborating the exploits: **Login Admin** (VL-01), **View Basket** (VL-02), **Poison Null Byte** + **Confidential Document** (VL-05), **Password Strength** (VL-01/06). |
| `vl05-ftp-exposure.png` | Confidential `/ftp/acquisitions.md` served to an anonymous browser ("This document is confidential! Do not distribute!"). |
| `retest-vulnerable.txt` | Plain-text copy of the suite output. |
| `raw-http-evidence.txt` | Plain-text copy of the raw `curl` exploit requests/responses. |

## Corroboration

The exploits were independently confirmed three ways:

1. **Regression suite** — `run_all.py` reports 6/6 VULNERABLE.
2. **Raw HTTP** — e.g. SQLi `' OR 1=1--` returns an `admin` (id 1) JWT; the null-byte
   request serves `package.json.bak`; the admin login token's `data.password`
   (`0192023a...b500`) equals `md5("admin123")`.
3. **The app's own challenge tracker** fired for the corresponding Juice Shop
   challenges (visible in `app-home.png`).

## Patched (after) captures — pending

The "after" pair for each finding (exploit blocked on a patched build) is produced by
applying `fixes/` to a Juice Shop fork, rebuilding, and re-running `run_all.py` (expect
6/6 PASS). The VL-03 DOM-XSS `alert()` firing is best captured interactively, since a
headless screenshot can't show a JavaScript dialog; the suite proves the
`bypassSecurityTrustHtml` sink is present/absent instead.
