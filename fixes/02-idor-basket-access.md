# Fix 02 — Enforce basket ownership (VL-02, IDOR)

**Finding:** `findings/02-idor-basket-access.md`
**File:** `routes/basket.ts`
**Approach:** resolve the caller's user id from the verified JWT and reject any request
for a basket the caller does not own.

## Patch

```diff
--- a/routes/basket.ts
+++ b/routes/basket.ts
@@
 import { type Request, type Response, type NextFunction } from 'express'
 import { BasketModel } from '../models/basket'
 import { ProductModel } from '../models/product'
+import * as security from '../lib/insecurity'
 import * as utils from '../lib/utils'

 export function retrieveBasket () {
   return (req: Request, res: Response, next: NextFunction) => {
     const id = req.params.id
-    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
-      .then((basket) => {
-        res.json(utils.queryResultToJson(basket))
-      }).catch(next)
+    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
+      .then((basket) => {
+        if (!basket) { return res.status(404).json({ error: 'Basket not found.' }) }
+        // Ownership check: the basket's UserId must match the authenticated user.
+        const loggedInUser = security.authenticatedUsers.from(req)
+        if (!loggedInUser || Number(basket.UserId) !== Number(loggedInUser.data.id)) {
+          return res.status(401).json({ error: 'Access denied.' })
+        }
+        res.json(utils.queryResultToJson(basket))
+      }).catch(next)
   }
 }
```

## Why this works

The basket is still fetched by id, but it is only returned when its `UserId` equals the
id carried in the request's verified JWT (`security.authenticatedUsers.from(req)`).
Enumerating another user's basket id now yields `401`. A missing basket yields `404`
without leaking ownership.

## Defense in depth

- Better still: ignore the client-supplied `:id` entirely and look the basket up by the
  authenticated user id, so the object reference is never attacker-controlled.
- Apply the same ownership check to all basket mutation endpoints.

## Verify

```bash
python3 scripts/test_02_idor_basket.py       # PASS (exit 0) only when patched
```
