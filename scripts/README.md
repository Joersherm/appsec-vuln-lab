# Regression scripts

One Python script per finding that reproduces the exploit and asserts whether the
target is **vulnerable** or **patched**. Standard library only — no `pip install`.

## Exit-code contract

| Code | Meaning | When |
|------|---------|------|
| `0` | **PASS** | exploit is blocked → app is patched |
| `1` | **FAIL** | exploit succeeds → app is vulnerable |
| `2` | **SKIP** | app unreachable / prerequisite missing |

So a script "fails against the vulnerable app and passes against the patched one," as
the project methodology requires.

## Running

```bash
# whole suite
python3 scripts/run_all.py

# one finding
python3 scripts/test_01_sqli_login.py
```

## Configuration (environment variables)

| Var | Default | Used by | Purpose |
|-----|---------|---------|---------|
| `JUICE_URL` | `http://localhost:3001` | all | base URL of the lab instance |
| `TEST_EMAIL` | `testuser@local.test` | 02, 04 | local throwaway account |
| `TEST_PASSWORD` | *(unset)* | 02 | password for the above (kept out of git) |

VL-06 needs no admin token: it reads the stored hash from the login JWT the app issues
to the probe user itself.

VL-03 needs a Chrome/Chromium binary to render the DOM (set `CHROME`, or it tries common
install paths). If none is found it SKIPs rather than guessing. Everything else is
pure standard library.

Credentials are **not** committed. Export them from your local notes before running the
checks that need them, e.g.:

```bash
export TEST_PASSWORD='...'            # from notes/test-credentials.md (git-ignored)
python3 scripts/test_02_idor_basket.py
```

## Scripts

| Script | Finding | What it asserts |
|--------|---------|-----------------|
| `test_01_sqli_login.py` | VL-01 | `' OR 1=1--` does not authenticate |
| `test_02_idor_basket.py` | VL-02 | can't read another user's basket by id |
| `test_03_dom_xss_search.py` | VL-03 | injected `<iframe>` sanitized out of the rendered DOM (headless Chrome) |
| `test_04_password_reset_bruteforce.py` | VL-04 | reset endpoint throttles (429) |
| `test_05_ftp_null_byte.py` | VL-05 | `%2500.md` null-byte bypass refused |
| `test_06_password_hash.py` | VL-06 | stored password is bcrypt, not unsalted MD5 |

> Live status: the lab instance was not running when these were authored, so the suite
> is **ready to run** rather than executed. Bring the container up (see repo README),
> export the env vars, and run `run_all.py`; capture the before/after output and
> screenshots into `screenshots/` and the retest table in `REPORT.md`.
