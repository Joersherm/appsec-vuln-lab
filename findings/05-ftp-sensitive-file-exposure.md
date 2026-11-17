# Finding 05 — Sensitive file exposure via `/ftp` and poison-null-byte traversal

| | |
|---|---|
| **ID** | VL-05 |
| **OWASP Top 10 (2021)** | A05:2021 – Security Misconfiguration (with A01 – Broken Access Control) |
| **CWE** | CWE-548: Exposure of Information Through Directory Listing; CWE-158: Improper Neutralization of Null Byte |
| **Severity** | **High** |
| **CVSS 3.1** | 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Affected component** | `/ftp` static route + download filter → `routes/fileServer.ts`, `server.ts` |
| **Status** | Open → Fixed (see `fixes/05-ftp-sensitive-file-exposure.md`) |

## Summary

The application exposes an `/ftp` directory of server files to anonymous users. A
download filter is supposed to restrict access to `.md` and `.pdf` files only, but the
check inspects the filename *after* a URL-encoded null byte (`%00`, double-encoded as
`%2500`), so appending `%2500.md` to a forbidden filename bypasses the extension
allow-list and discloses backup/source files.

## Affected code (vulnerable)

`routes/fileServer.ts` only rejects a request when the *literal* path doesn't end in an
allowed extension, and it decodes `%00` such that `package.json.bak%2500.md` passes the
`.md` check but resolves on disk to `package.json.bak`:

```ts
const file = req.params.file
if (file.includes('/')) { res.status(403); return }
if (endsWithAllowlistedFileType(file)) {        // sees ".md"
  file = security.cutOffPoisonNullByte(file)    // but then trims at the null byte
  res.sendFile(path.resolve('ftp/', file))      // serves package.json.bak
}
```

## Reproduction

Target: local lab instance at `http://localhost:3001`.

1. **Direct confidential file** (no filter needed — it is a `.md`):

   ```bash
   curl -s http://localhost:3001/ftp/acquisitions.md | head
   ```
   Returns a document marked confidential.

2. **Allow-list bypass** to reach a non-`.md`/`.pdf` backup file:

   ```bash
   curl -s "http://localhost:3001/ftp/package.json.bak%2500.md" | head
   ```

3. **Vulnerable result:** step 2 returns `200` with the contents of
   `package.json.bak` even though `.bak` is not an allowed type — the `%2500` null byte
   truncates the name after the extension check.

4. **Patched result:** step 2 returns `403`/`404`; only genuine `.md`/`.pdf` files are
   served and the null byte is rejected rather than trimmed.

The regression script `scripts/test_05_ftp_null_byte.py` automates both the direct and
bypass checks.

## Impact

- Disclosure of confidential business documents and server-side backup/source files
  (`package.json.bak`, coupon/key material, etc.).
- Leaked dependency and configuration data aids further targeted attacks.

## Remediation

- Do not expose an `/ftp` directory of server files to anonymous users; if a download
  area is required, serve it from a dedicated, vetted location with authz.
- **Reject** requests containing null bytes (`%00`/`%2500`) outright instead of
  trimming them, and validate the *final, decoded, resolved* path against the
  allow-list (canonicalize, then check extension) before `sendFile`.
- Confirm resolved paths stay within the intended base directory.

See `fixes/05-ftp-sensitive-file-exposure.md`.

## References

- OWASP Top 10 A05:2021; OWASP Path Traversal / File Upload guidance
- CWE-548, CWE-158, CWE-22
