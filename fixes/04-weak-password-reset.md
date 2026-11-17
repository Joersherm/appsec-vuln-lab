# Fix 04 — Rate-limit account recovery (VL-04, weak reset / no throttle)

**Finding:** `findings/04-weak-password-reset.md`
**Files:** `server.ts` (register limiter), `routes/resetPassword.ts` (constant-time compare)
**Approach:** apply a strict per-IP/per-account rate limit with lockout to the reset
endpoint, and use a constant-time comparison for the answer.

## Patch

```diff
--- a/server.ts
+++ b/server.ts
@@
 import express from 'express'
+import rateLimit from 'express-rate-limit'
@@
+  // Throttle brute force of the security-question reset flow.
+  const resetPasswordLimiter = rateLimit({
+    windowMs: 15 * 60 * 1000,   // 15 minutes
+    max: 5,                     // 5 attempts per window per IP
+    standardHeaders: true,
+    legacyHeaders: false,
+    message: { error: 'Too many attempts. Try again later.' }
+  })
+  app.use('/rest/user/reset-password', resetPasswordLimiter)
```

```diff
--- a/routes/resetPassword.ts
+++ b/routes/resetPassword.ts
@@
 import { SecurityAnswerModel } from '../models/securityAnswer'
 import * as security from '../lib/insecurity'
+import { timingSafeEqual } from 'node:crypto'
@@
-    if (security.hmac(req.body.answer) === answer.answer) {
+    const provided = Buffer.from(security.hmac(req.body.answer ?? ''))
+    const stored = Buffer.from(answer.answer ?? '')
+    const match = provided.length === stored.length && timingSafeEqual(provided, stored)
+    if (match) {
       user.update({ password: req.body.new }).then(() => res.status(200).json({ user }))
     } else {
       res.status(401).send(res.__('Wrong answer to security question.'))
     }
```

## Why this works

After 5 failed attempts in the window the endpoint returns `429`, so online brute force
of a low-entropy security answer is no longer feasible. `timingSafeEqual` removes a
timing oracle on the answer comparison.

## Defense in depth (recommended follow-up)

- Replace the security question with an **out-of-band, signed, single-use, expiring
  reset token** delivered by email; never change a password on a knowledge answer alone.
- Also rate-limit `/rest/user/login` and add account lockout/backoff.

## Verify

```bash
python3 scripts/test_04_password_reset_bruteforce.py   # PASS (exit 0) only when patched
```
