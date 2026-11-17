# Finding 02 — Broken access control (IDOR) on shopping baskets

| | |
|---|---|
| **ID** | VL-02 |
| **OWASP Top 10 (2021)** | A01:2021 – Broken Access Control |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key (IDOR) |
| **Severity** | **High** |
| **CVSS 3.1** | 6.5 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| **Affected component** | `GET /rest/basket/:id` → `routes/basket.ts` |
| **Status** | Open → Fixed (see `fixes/02-idor-basket-access.md`) |

## Summary

The basket retrieval endpoint looks up a basket purely by the `:id` path parameter and
returns it without checking that the basket belongs to the authenticated user. Any
logged-in user can read any other user's basket (and its contents) by iterating the
numeric id — a classic Insecure Direct Object Reference.

## Affected code (vulnerable)

`routes/basket.ts` retrieves the basket by primary key only:

```ts
export function retrieveBasket () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id
    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, /* ... */ }] })
      .then((basket) => {
        res.json(utils.queryResultToJson(basket))
      }).catch(next)
  }
}
```

There is no comparison between the basket's `UserId` and the id encoded in the
caller's JWT.

## Reproduction

Target: local lab instance at `http://localhost:3001`.

1. Register/login as the low-privilege test user to obtain a JWT (`token`).
2. Request a basket id that is **not** yours (e.g. `1`, the admin's):

   ```bash
   curl -s http://localhost:3001/rest/basket/1 \
     -H "Authorization: Bearer $TOKEN"
   ```

3. **Vulnerable result:** HTTP `200` with the full contents of basket `1`, including
   products another user added — even though the request was authenticated as a
   different user.

4. **Patched result:** HTTP `401`/`403` when the basket's owner id does not match the
   authenticated user id; your own basket still returns `200`.

The regression script `scripts/test_02_idor_basket.py` automates this check.

## Impact

- Horizontal privilege escalation: read any user's basket by id enumeration.
- Discloses other users' shopping activity and product selections.
- Same pattern typically extends to modifying others' baskets if write endpoints share
  the flaw.

## Remediation

Enforce an **ownership check** in `retrieveBasket`: resolve the caller's user id from
the verified JWT and reject the request when it does not match the basket's `UserId`.
See `fixes/02-idor-basket-access.md`. Prefer deriving the basket from the session/token
rather than trusting a client-supplied id at all.

## References

- OWASP Top 10 A01:2021 – Broken Access Control
- OWASP Insecure Direct Object Reference Prevention Cheat Sheet
- CWE-639, CWE-284
