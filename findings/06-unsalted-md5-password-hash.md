# Finding 06 — Passwords stored with unsalted MD5

| | |
|---|---|
| **ID** | VL-06 |
| **OWASP Top 10 (2021)** | A02:2021 – Cryptographic Failures |
| **CWE** | CWE-916: Use of Password Hash With Insufficient Computational Effort; CWE-759: Use of a One-Way Hash without a Salt |
| **Severity** | **High** |
| **CVSS 3.1** | 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) (impact realised on data disclosure) |
| **Affected component** | Password hashing → `lib/insecurity.ts`, `models/user.ts` |
| **Status** | Open → Fixed (see `fixes/06-unsalted-md5-password-hash.md`) |

## Summary

User passwords are hashed with a single round of **unsalted MD5**. MD5 is fast and
broken for password storage: without a salt, identical passwords produce identical
hashes (enabling rainbow-table lookups and cross-account correlation), and the whole
password set can be cracked offline almost instantly if the `Users` table is ever
disclosed (e.g. via Finding 01's SQL injection).

## Affected code (vulnerable)

`lib/insecurity.ts`:

```ts
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

Used directly to store and compare passwords, with no per-user salt and no work factor.

## Reproduction

Target: local lab instance at `http://localhost:3001`.

1. Obtain a `Users` row (for example via Finding 01, or any admin-level data read). The
   stored `password` for a user whose password is `admin123` is:

   ```
   0192023a7bbd73250516f069df18b500   # == md5("admin123")
   ```

2. **Vulnerable result:** confirm the stored hash equals unsalted MD5 of the plaintext:

   ```bash
   python3 -c "import hashlib; print(hashlib.md5(b'admin123').hexdigest())"
   # 0192023a7bbd73250516f069df18b500  -> matches the stored value
   ```

   Any leaked hash is reversible via a lookup table in milliseconds.

3. **Patched result:** stored values are bcrypt hashes (prefix `$2a$`/`$2b$`), are
   different for two users sharing a password (unique salts), and do **not** match the
   MD5 of the plaintext.

The regression script `scripts/test_06_password_hash.py` registers a user and inspects
the stored hash format (and that it is not the MD5 of the chosen password).

## Impact

- On any disclosure of the user table, the entire password corpus is recoverable
  almost immediately, enabling account takeover and credential-stuffing against the
  users' other services (password reuse).

## Remediation

Replace MD5 with a **memory-hard / adaptive** password hash — **bcrypt** (used in the
fix), `scrypt`, or `argon2id` — with a per-user salt and an appropriate work factor.
Hash on registration/change and verify with the algorithm's constant-time `compare`.
Plan a migration that re-hashes on next successful login. See
`fixes/06-unsalted-md5-password-hash.md`.

## References

- OWASP Top 10 A02:2021; OWASP Password Storage Cheat Sheet
- CWE-916, CWE-759, CWE-327
