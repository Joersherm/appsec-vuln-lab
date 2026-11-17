#!/usr/bin/env python3
"""VL-01 regression: SQL injection auth bypass on POST /rest/user/login.

Exploit: an `email` of `' OR 1=1--` should NOT authenticate anyone.
  Vulnerable -> returns 200 + a JWT (auth bypass).
  Patched    -> returns 401, no token.
"""
import common as c


def test():
    payload = {"email": "' OR 1=1--", "password": "not-the-password"}
    r = c.post("/rest/user/login", data=payload)
    j = r.json() or {}
    token = (j.get("authentication") or {}).get("token") if isinstance(j, dict) else None

    if r.status == 200 and token:
        return c.FAIL, (
            "injection `' OR 1=1--` logged in and received a JWT "
            f"(HTTP {r.status}). The login query is not parameterized."
        )
    # Also confirm a known-good admin-targeting payload is rejected.
    r2 = c.post("/rest/user/login",
                data={"email": "admin@juice-sh.op'--", "password": "x"})
    j2 = r2.json() or {}
    token2 = (j2.get("authentication") or {}).get("token") if isinstance(j2, dict) else None
    if r2.status == 200 and token2:
        return c.FAIL, f"admin-targeting injection succeeded (HTTP {r2.status})."

    return c.PASS, f"injection rejected (HTTP {r.status}/{r2.status}, no token issued)."


if __name__ == "__main__":
    c.main("VL-01 SQLi login auth bypass", test)
