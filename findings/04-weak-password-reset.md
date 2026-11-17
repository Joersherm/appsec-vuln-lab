# Finding 04 — Weak account recovery (unthrottled security-question reset)

| | |
|---|---|
| **ID** | VL-04 |
| **OWASP Top 10 (2021)** | A07:2021 – Identification and Authentication Failures |
| **CWE** | CWE-640: Weak Password Recovery Mechanism; CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **Severity** | **High** |
| **CVSS 3.1** | 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) |
| **Affected component** | `POST /rest/user/reset-password` → `routes/resetPassword.ts` |
| **Status** | Open → Fixed (see `fixes/04-weak-password-reset.md`) |

## Summary

Account recovery is gated solely by a knowledge-based **security question**. The reset
endpoint accepts unlimited attempts with no rate limiting, lockout, or delay, and the
security answers are low-entropy, guessable values (e.g. a pet's name). An attacker who
knows or brute-forces the answer can set a new password for any account and take it
over — no access to the account's email is required.

## Affected code (vulnerable)

`routes/resetPassword.ts` validates the answer and immediately rewrites the password,
with no attempt counter or throttle:

```ts
SecurityAnswerModel.findOne({ where: { UserId: user.id } }).then((answer) => {
  if (security.hmac(req.body.answer) === answer.answer) {
    user.update({ password: req.body.new }).then(() => res.status(200).json({ user }))
  } else {
    res.status(401).send(res.__('Wrong answer to security question.'))
  }
})
```

The endpoint can be called as fast as the network allows, enabling offline-style
online brute force of the answer.

## Reproduction

Target: local lab instance at `http://localhost:3001`.

1. Pick a victim email. Repeatedly submit candidate answers:

   ```bash
   for ans in fluffy rex bella max charlie testanswer123; do
     curl -s -o /dev/null -w "%{http_code} $ans\n" \
       -X POST http://localhost:3001/rest/user/reset-password \
       -H 'Content-Type: application/json' \
       -d "{\"email\":\"testuser@local.test\",\"answer\":\"$ans\",\"new\":\"Pwned!2026\",\"repeat\":\"Pwned!2026\"}"
   done
   ```

2. **Vulnerable result:** every wrong guess returns `401` instantly with no lockout; a
   correct guess returns `200` and the account password is changed. Hundreds/thousands
   of guesses per minute are accepted.

3. **Patched result:** after a small number of failed attempts the endpoint returns
   `429 Too Many Requests` (and/or enforces an increasing delay / temporary lock),
   making online brute force infeasible.

The regression script `scripts/test_04_password_reset_bruteforce.py` sends a burst of
wrong answers and asserts the server begins throttling.

## Impact

- Full account takeover of any user whose security answer is guessable or known.
- No email access required, so the legitimate owner receives no reset notification.

## Remediation

- **Rate-limit and lock** the reset endpoint per account and per source IP
  (e.g. `express-rate-limit`), with exponential backoff.
- Treat security questions as a weak secondary factor at best; prefer a signed,
  expiring, single-use reset **token delivered out-of-band** (email).
- Return a generic response and constant-time comparison to avoid oracle behaviour.

See `fixes/04-weak-password-reset.md`.

## References

- OWASP Top 10 A07:2021; OWASP Forgot Password & Authentication Cheat Sheets
- CWE-640, CWE-307
