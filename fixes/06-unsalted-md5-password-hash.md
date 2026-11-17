# Fix 06 — Hash passwords with bcrypt (VL-06, cryptographic failure)

**Finding:** `findings/06-unsalted-md5-password-hash.md`
**Files:** `lib/insecurity.ts` (hashing primitives), `models/user.ts` (hash on save/compare)
**Approach:** replace unsalted MD5 with **bcrypt** (per-user salt + work factor) and use
an async, constant-time verify.

## Patch

```diff
--- a/lib/insecurity.ts
+++ b/lib/insecurity.ts
@@
-import crypto from 'node:crypto'
+import crypto from 'node:crypto'
+import bcrypt from 'bcryptjs'
@@
-export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
+const BCRYPT_ROUNDS = 12
+
+// New, salted, adaptive password hashing.
+export const hashPassword = (data: string) => bcrypt.hashSync(data, BCRYPT_ROUNDS)
+export const comparePassword = (data: string, stored: string) => bcrypt.compareSync(data, stored)
+
+// Retained only for non-password, legacy uses; never use for passwords.
+export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

```diff
--- a/models/user.ts
+++ b/models/user.ts
@@ init(sequelize)
       password: {
         type: DataTypes.STRING,
         set (clearTextPassword: string) {
-          this.setDataValue('password', security.hash(clearTextPassword))
+          this.setDataValue('password', security.hashPassword(clearTextPassword))
         }
       },
```

```diff
--- a/routes/login.ts
+++ b/routes/login.ts
@@
-  // password compared inside the SQL query via security.hash(...)
+  // Look the user up by email only (parameterized — see Fix 01), then verify the
+  // password in code with bcrypt:
+  //   const ok = user && security.comparePassword(req.body.password || '', user.password)
+  //   if (!ok) return res.status(401).send(res.__('Invalid email or password.'))
```

> Dependency: `npm install bcryptjs` (pure-JS, no native build) or `bcrypt`.

## Why this works

bcrypt embeds a unique salt per hash and a tunable cost factor, so two users with the
same password get different hashes and offline cracking is many orders of magnitude
slower than MD5. Stored values start with `$2a$`/`$2b$` and never equal `md5(password)`.

## Migration

Re-hash on next successful login: if a stored value looks like legacy MD5
(`/^[a-f0-9]{32}$/`), verify against MD5 once, and on success immediately re-save the
password (triggering the bcrypt setter), then remove the legacy path.

## Verify

```bash
python3 scripts/test_06_password_hash.py     # PASS (exit 0) only when patched
```
