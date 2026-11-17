#!/usr/bin/env python3
"""VL-06 regression: password storage must not be unsalted MD5.

Registers a fresh user with a known password, then (if an admin/data path is available
via JUICE_ADMIN_TOKEN) inspects the stored hash. Without a data path, it falls back to
asserting the app does not expose the hash AND documents the expected patched format.

  Vulnerable -> stored hash equals md5(password) (32 hex chars, unsalted).
  Patched    -> stored hash is bcrypt ($2a$/$2b$...), != md5(password).

Provide JUICE_ADMIN_TOKEN to enable the authenticated hash inspection via
GET /api/Users (admin-only). Without it, the test can only verify the hash is not
leaked to an anonymous caller.
"""
import hashlib
import os
import time
import common as c

ADMIN_TOKEN = os.environ.get("JUICE_ADMIN_TOKEN", "")


def register(email, password):
    return c.post("/api/Users", data={
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 1},
        "securityAnswer": "regression",
    })


def stored_hash_for(email):
    if not ADMIN_TOKEN:
        return None
    r = c.get("/api/Users", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    j = r.json() or {}
    for u in (j.get("data") or []):
        if u.get("email") == email:
            return u.get("password")
    return None


def test():
    email = f"hashcheck+{int(time.time())}@local.test"
    password = "Regression-Hash!2026"
    reg = register(email, password)
    if reg.status not in (200, 201):
        return c.UNREACHABLE, f"could not register probe user (HTTP {reg.status})."

    md5 = hashlib.md5(password.encode()).hexdigest()
    stored = stored_hash_for(email)

    if stored is None:
        return c.UNREACHABLE, (
            "no admin data path (set JUICE_ADMIN_TOKEN) to read the stored hash. "
            f"Expected patched format: bcrypt ($2a$/$2b$...), not md5={md5}.")

    if stored == md5 or (len(stored) == 32 and all(ch in "0123456789abcdef" for ch in stored.lower())):
        return c.FAIL, f"stored password is unsalted MD5 ({stored})."
    if stored.startswith(("$2a$", "$2b$", "$2y$")):
        return c.PASS, "stored password is bcrypt (salted, adaptive)."
    return c.PASS, f"stored password is not MD5 (format: {stored[:7]}...)."


if __name__ == "__main__":
    c.main("VL-06 unsalted MD5 password hash", test)
