#!/usr/bin/env python3
"""VL-02 regression: IDOR on GET /rest/basket/:id.

Logs in as the low-privilege test user, then requests baskets that are very likely
owned by OTHER users (ids 1 and 2). A patched app must refuse baskets the caller does
not own.

  Vulnerable -> 200 with another user's basket contents.
  Patched    -> 401/403/404 for baskets the caller does not own.

Set TEST_EMAIL / TEST_PASSWORD env vars to the local throwaway account (kept out of
git). Defaults match notes/test-credentials.md but are not committed here.
"""
import os
import common as c

EMAIL = os.environ.get("TEST_EMAIL", "testuser@local.test")
PASSWORD = os.environ.get("TEST_PASSWORD", "")


def test():
    if not PASSWORD:
        return c.UNREACHABLE, ("set TEST_PASSWORD (and TEST_EMAIL) to the local test "
                               "account to run this check")
    token, lr = c.login(EMAIL, PASSWORD)
    if not token:
        return c.UNREACHABLE, (f"could not log in as {EMAIL} (HTTP {lr.status}); "
                               "create the account or fix credentials")
    auth = {"Authorization": f"Bearer {token}"}

    leaked = []
    for other_id in (1, 2):
        r = c.get(f"/rest/basket/{other_id}", headers=auth)
        j = r.json()
        owner = None
        if isinstance(j, dict):
            data = j.get("data", j)
            owner = data.get("UserId") if isinstance(data, dict) else None
        if r.status == 200 and isinstance(j, dict) and "data" in (j if isinstance(j, dict) else {}):
            leaked.append((other_id, owner, r.status))

    if leaked:
        details = ", ".join(f"basket {bid} (UserId={owner})" for bid, owner, _ in leaked)
        return c.FAIL, f"read baskets not owned by the caller: {details}"
    return c.PASS, "cross-user basket reads were refused (no ownership bypass)."


if __name__ == "__main__":
    c.main("VL-02 IDOR basket access", test)
