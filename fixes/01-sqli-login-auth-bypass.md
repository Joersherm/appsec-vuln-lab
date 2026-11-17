# Fix 01 — Parameterize the login query (VL-01, SQLi)

**Finding:** `findings/01-sqli-login-auth-bypass.md`
**File:** `routes/login.ts`
**Approach:** replace raw string concatenation with a bound/parameterized query so the
`email` input is always treated as data, never SQL.

## Patch

```diff
--- a/routes/login.ts
+++ b/routes/login.ts
@@ login(req, res, next)
-  models.sequelize.query(
-    `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
-    { model: UserModel, plain: true }
-  )
+  models.sequelize.query(
+    'SELECT * FROM Users WHERE email = $email AND password = $password AND deletedAt IS NULL',
+    {
+      bind: {
+        email: req.body.email || '',
+        password: security.hash(req.body.password || '')
+      },
+      model: UserModel,
+      plain: true
+    }
+  )
     .then((authenticatedUser) => {
       const user = utils.queryResultToJson(authenticatedUser)
       if (!user.data?.id) {
         return res.status(401).send(res.__('Invalid email or password.'))
       }
       // ... issue JWT as before ...
     })
     .catch((error: Error) => next(error))
```

## Why this works

With `bind`, the driver sends the SQL text and the parameter values separately; the
`email` value `' OR 1=1--` is compared as a literal string and matches no row, so the
endpoint returns `401`. No input can alter the query structure.

## Defense in depth

- Validate `email` against an email format (and length) before the data layer.
- Keep the generic "Invalid email or password." message to avoid user enumeration.

## Verify

```bash
python3 scripts/test_01_sqli_login.py        # PASS (exit 0) only when patched
```
