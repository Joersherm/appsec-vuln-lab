# Screenshots

Supporting evidence for findings and fixes. Capture these during the live retest (the
lab instance was not running at authoring time, so this folder is a placeholder).

Suggested captures, one before/after pair per finding:

| File (suggested) | Shows |
|------------------|-------|
| `vl01-sqli-before.png` / `vl01-sqli-after.png` | login with `' OR 1=1--` → token vs. 401 |
| `vl02-idor-before.png` / `vl02-idor-after.png` | reading another user's basket vs. 401 |
| `vl03-xss-before.png` / `vl03-xss-after.png` | `alert('xss')` firing vs. inert escaped text |
| `vl04-reset-before.png` / `vl04-reset-after.png` | unlimited wrong answers vs. 429 |
| `vl05-ftp-before.png` / `vl05-ftp-after.png` | `%2500.md` serving a backup vs. 403 |
| `vl06-hash-before.png` / `vl06-hash-after.png` | stored MD5 vs. bcrypt `$2b$...` |

Also useful: a terminal capture of `python3 scripts/run_all.py` against the vulnerable
build (all FAIL) and against the patched build (all PASS).
