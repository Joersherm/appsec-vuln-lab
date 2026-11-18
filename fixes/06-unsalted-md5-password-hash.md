# Fix 06 — Replace unsalted MD5 with a salted adaptive hash (VL-06)

**Finding:** `findings/06-unsalted-md5-password-hash.md`
**Files:** `lib/insecurity.ts` (hashing primitives), `models/user.ts` (hash on save),
`routes/login.ts` (verify in code — shared with Fix 01)
**Approach:** replace unsalted MD5 with a **per-user-salted, adaptive** hash. The
implemented patch uses Node's built-in `crypto.scryptSync` (memory-hard, no new
dependency, constant-time verify); **bcrypt** or **argon2id** are equally valid choices.

## Patch (actual, from `juice-shop-v17.3.0-fixes.patch`)

```diff
--- a/lib/insecurity.ts
+++ b/lib/insecurity.ts
@@
-export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
+// VL-06: salted, adaptive password hashing via scrypt (replaces unsalted md5 for passwords).
+const SCRYPT_KEYLEN = 64
+export const hashPassword = (data: string): string => {
+  const salt = crypto.randomBytes(16)
+  const derived = crypto.scryptSync(data, salt, SCRYPT_KEYLEN)
+  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`
+}
+export const comparePassword = (data: string, stored: string): boolean => {
+  try {
+    const [scheme, saltHex, hashHex] = (stored ?? '').split('$')
+    if (scheme !== 'scrypt' || !saltHex || !hashHex) return false
+    const derived = crypto.scryptSync(data, Buffer.from(saltHex, 'hex'), SCRYPT_KEYLEN)
+    const expected = Buffer.from(hashHex, 'hex')
+    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected)
+  } catch { return false }
+}
+// Legacy md5 hash retained only for non-password uses (e.g. order ids), never for passwords.
+export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

```diff
--- a/models/user.ts
+++ b/models/user.ts
@@ password setter
-          this.setDataValue('password', security.hash(clearTextPassword)) // vuln-code-snippet vuln-line weakPasswordChallenge
+          this.setDataValue('password', security.hashPassword(clearTextPassword)) // VL-06: scrypt instead of unsalted md5
```

Login then verifies the password in code with `security.comparePassword(...)` rather
than inside the SQL query — see Fix 01, whose parameterized rewrite makes this change.

## Why this works

scrypt derives each hash from a **unique random salt** and is **memory-hard**, so two
users with the same password get different stored values and offline cracking is many
orders of magnitude slower than MD5. Stored values are `scrypt$<salt>$<hash>` and never
equal `md5(password)`. Verification uses `crypto.timingSafeEqual`. Using the Node
built-in avoids adding a dependency (and the Dockerfile swallows `build:server`
failures, so keeping `tsc` dependency-clean was important here).

## Migration

Re-hash on next successful login: if a stored value looks like legacy MD5
(`/^[a-f0-9]{32}$/`), verify against MD5 once, and on success immediately re-save the
password (triggering the bcrypt setter), then remove the legacy path.

## Verify

```bash
python3 scripts/test_06_password_hash.py     # PASS (exit 0) only when patched
```
