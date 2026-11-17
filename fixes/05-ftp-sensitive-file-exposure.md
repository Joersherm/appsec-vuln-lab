# Fix 05 — Reject null bytes and validate the resolved path (VL-05)

**Finding:** `findings/05-ftp-sensitive-file-exposure.md`
**File:** `routes/fileServer.ts`
**Approach:** reject any request containing a null byte instead of trimming it, then
canonicalize the path and validate the *final* extension and base directory before
serving.

## Patch

```diff
--- a/routes/fileServer.ts
+++ b/routes/fileServer.ts
@@
 import path from 'node:path'
 import { type Request, type Response, type NextFunction } from 'express'

 export function servePublicFiles () {
   return ({ params, query }: Request, res: Response, next: NextFunction) => {
     const file = params.file

-    if (!file.includes('/')) {
-      verify(file, res, next)
-    } else {
-      res.status(403)
-      next(new Error('File names cannot contain forward slashes!'))
-    }
+    // Reject traversal and null bytes outright (no trimming).
+    if (file.includes('/') || file.includes('\\') || file.includes('%00') || file.includes('\0')) {
+      res.status(403)
+      return next(new Error('Illegal file name.'))
+    }
+    verify(file, res, next)
   }
 }

-function verify (file: string, res: Response, next: NextFunction) {
-  if (file && (endsWithAllowlistedFileType(file))) {
-    file = security.cutOffPoisonNullByte(file)   // <-- removed: this enabled the bypass
-    res.status(200)
-    res.sendFile(path.resolve('ftp/', file))
-  } else {
-    res.status(403)
-    next(new Error('Only .md and .pdf files are allowed!'))
-  }
-}
+function verify (file: string, res: Response, next: NextFunction) {
+  const base = path.resolve('ftp/')
+  const resolved = path.resolve(base, file)
+  const ok =
+    file &&
+    endsWithAllowlistedFileType(resolved) &&          // check the FINAL resolved name
+    (resolved === base + path.sep + path.basename(resolved)) &&  // no nesting/traversal
+    resolved.startsWith(base + path.sep)              // stays inside ftp/
+  if (ok) {
+    res.status(200)
+    res.sendFile(resolved)
+  } else {
+    res.status(403)
+    next(new Error('Only .md and .pdf files are allowed!'))
+  }
+}
```

## Why this works

`package.json.bak%2500.md` now fails at the first gate (it contains `%00` after
decoding / the literal check), so the null-byte truncation trick is gone. Even if a
name slipped through, the allow-list is applied to the **canonicalized** path and the
resolved file is required to live directly inside `ftp/`, so `.bak`/source files are
never served.

## Defense in depth

- Don't expose server files to anonymous users at all; gate any download area behind
  authz and keep only genuinely public docs there.
- Remove confidential files (`acquisitions.md`, backups) from the public directory.

## Verify

```bash
python3 scripts/test_05_ftp_null_byte.py     # PASS (exit 0) only when patched
```
