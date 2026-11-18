# Fix 04 — Tighten account-recovery rate limiting (VL-04)

**Finding:** `findings/04-weak-password-reset.md`
**File:** `server.ts`
**Approach:** Juice Shop `v17.3.0` already mounts a rate limiter on the reset endpoint,
but it is ineffective: the cap is **100** attempts per 15 minutes (far too high to stop
targeted brute force of one account's low-entropy answer) **and** it keys on the
`X-Forwarded-For` header, which the client can spoof to get a fresh bucket per request.
The fix lowers the cap and keys on the real TCP peer address.

## Patch (actual, from `juice-shop-v17.3.0-fixes.patch`)

```diff
--- a/server.ts
+++ b/server.ts
@@ Rate limiting
   app.use('/rest/user/reset-password', rateLimit({
     windowMs: 5 * 60 * 1000,
-    max: 100,
-    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip } // vuln-code-snippet vuln-line resetPasswordMortyChallenge
+    max: 5, // VL-04: strict cap to stop online brute force of low-entropy security answers
+    keyGenerator: (req: any) => req.socket?.remoteAddress ?? req.ip // VL-04: key on the real TCP peer, not the spoofable X-Forwarded-For header
   }))
```

## Why this works

With a cap of 5 per window the endpoint returns `429` after a handful of wrong answers,
so online brute force of a guessable security answer is no longer feasible. Keying on
the socket peer address (not the attacker-controlled `X-Forwarded-For` header) closes
the per-request bypass — rotating the header no longer resets the counter.

## Defense in depth (recommended follow-up)

- Replace the security question with an **out-of-band, signed, single-use, expiring
  reset token** delivered by email; never change a password on a knowledge answer alone.
- Compare the submitted answer in constant time (`crypto.timingSafeEqual`) to remove any
  timing oracle.
- Also rate-limit `/rest/user/login` and add account lockout/backoff.

## Verify

```bash
python3 scripts/test_04_password_reset_bruteforce.py   # PASS (exit 0) only when patched
```
