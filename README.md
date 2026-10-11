# AppSec Vulnerability Assessment & Remediation Lab

A hands-on security assessment of [OWASP Juice Shop](https://owasp-juice.shop/), an
intentionally vulnerable web application. This project identifies real OWASP Top 10
vulnerabilities, exploits them in a local lab, patches the vulnerable source code, and
proves each fix with an automated regression script.

**Scope:** All testing is performed exclusively against a local, intentionally
vulnerable instance of Juice Shop running in Docker on `localhost`. Nothing in this
repo is intended for use against any system you do not own or have explicit permission
to test.

## Target application

| | |
|---|---|
| App | [OWASP Juice Shop](https://owasp-juice.shop/) (`bkimminich/juice-shop`) |
| Run via | Docker |
| Local URL | `http://localhost:3001` |
| Source | https://github.com/juice-shop/juice-shop |

### Running it locally

```bash
docker run -d --name juice -p 127.0.0.1:3001:3000 bkimminich/juice-shop:v17.3.0
```

Then open http://localhost:3001.

> Note: port `3000` is the documented default for Juice Shop, but it's mapped to
> `3001` here to avoid a conflict with another local dev server. Adjust the port if
> your own environment differs.

A local test account was registered manually through the app's own registration form
to explore the app as a normal user before testing began. Credentials for that account
are kept out of version control (see `.gitignore`) since it's a throwaway test account
— to follow along, just register your own via **Not yet a customer?** on the login
page.

## Repo structure

```
findings/     One write-up per vulnerability found (description, repro steps, impact, severity)
fixes/        Patched source code / diffs for each finding, one branch or commit per fix
scripts/      Python regression scripts that reproduce each exploit and confirm it's blocked
screenshots/  Supporting evidence for findings and fixes
REPORT.md     Final assessment report (summary, findings table, remediation, retest results)
```

## Methodology

1. **Recon** — map the app's structure and API surface.
2. **Assess** — identify and manually exploit 5–6 vulnerabilities spanning different
   OWASP Top 10 categories (e.g. SQL injection, XSS, broken access control, broken
   authentication, sensitive data exposure).
3. **Fix** — patch each vulnerability in a fork of the Juice Shop source.
4. **Verify** — write a Python script per exploit that fails against the vulnerable
   app and passes against the patched one.
5. **Report** — summarize findings and remediation in a short assessment report.

## Status

Setup complete — local instance running, test account created, environment explored.
Findings in progress.

## Disclaimer

All testing in this repository was performed against a local, intentionally
vulnerable application (OWASP Juice Shop) running only on `localhost`. No systems
owned by third parties were accessed or tested.

## License

MIT — see [LICENSE](LICENSE).
