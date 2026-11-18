# Fix 01 — Parameterize the login query (VL-01, SQLi)

**Finding:** `findings/01-sqli-login-auth-bypass.md`
**File:** `routes/login.ts`
**Approach:** replace raw string concatenation with a bound/parameterized query so the
`email` input is always treated as data, never SQL.

## Patch (actual, from `juice-shop-v17.3.0-fixes.patch`)

Look the user up by email with a **bound parameter**, then verify the password in code
(this also enables the scrypt migration in Fix 06, since the password can no longer be
compared as an MD5 string inside the query):

```diff
--- a/routes/login.ts
+++ b/routes/login.ts
@@ return (req, res, next) =>
-    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }) // vuln-code-snippet vuln-line ...
-      .then((authenticatedUser) => {
-        const user = utils.queryResultToJson(authenticatedUser)
-        if (user.data?.id && user.data.totpSecret !== '') {
+    models.sequelize.query('SELECT * FROM Users WHERE email = $email AND deletedAt IS NULL', { bind: { email: req.body.email || '' }, model: UserModel, plain: true }) // VL-01: parameterized query, no string concatenation
+      .then((authenticatedUser) => {
+        const user = utils.queryResultToJson(authenticatedUser)
+        const passwordValid = Boolean(user.data?.id) && security.comparePassword(req.body.password || '', (user.data as any)?.password ?? '') // VL-01/VL-06: verify password in code
+        if (passwordValid && user.data.totpSecret !== '') {
@@ (the subsequent branch)
-        } else if (user.data?.id) {
+        } else if (passwordValid) {
           afterLogin(user, res, next)
         } else {
           res.status(401).send(res.__('Invalid email or password.'))
```

## Why this works

With `bind`, the driver sends the SQL text and the parameter values separately; the
`email` value `' OR 1=1--` is compared as a literal string and matches no row, so the
endpoint returns `401`. No input can alter the query structure. The password is then
checked in application code via a constant-time `comparePassword`, so a found row still
can't authenticate without the correct password.

## Defense in depth

- Validate `email` against an email format (and length) before the data layer.
- Keep the generic "Invalid email or password." message to avoid user enumeration.

## Verify

```bash
python3 scripts/test_01_sqli_login.py        # PASS (exit 0) only when patched
```
