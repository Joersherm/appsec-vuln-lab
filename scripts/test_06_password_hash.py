#!/usr/bin/env python3
"""VL-06 regression: password storage must not be unsalted MD5.

Registers a fresh user with a known password, logs in, and reads the stored password
hash straight out of the login JWT payload (Juice Shop embeds the full user record,
including the password hash, in the token). Then checks the hash's format.

  Vulnerable -> stored hash equals md5(password): 32 hex chars, unsalted.
  Patched    -> stored hash is bcrypt ($2a$/$2b$...), != md5(password).

No admin token needed: the hash is exposed in the token the app issues to the user
itself. (That the hash is in the JWT at all is a related exposure; this test asserts
specifically on the hashing algorithm.)
"""
import base64
import hashlib
import json
import time
import common as c


def register(email, password):
    return c.post("/api/Users", data={
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 1},
        "securityAnswer": "regression",
    })


def hash_from_token(token: str):
    """Decode the JWT payload (middle segment, base64url) and return data.password."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # pad
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return (payload.get("data") or {}).get("password")
    except (ValueError, IndexError, TypeError):
        return None


def test():
    email = f"hashcheck+{int(time.time())}@local.test"
    password = "Regression-Hash!2026"
    reg = register(email, password)
    if reg.status not in (200, 201):
        return c.UNREACHABLE, f"could not register probe user (HTTP {reg.status})."

    token, lr = c.login(email, password)
    if not token:
        return c.UNREACHABLE, f"could not log in as probe user (HTTP {lr.status})."

    stored = hash_from_token(token)
    md5 = hashlib.md5(password.encode()).hexdigest()
    if stored is None:
        return c.UNREACHABLE, "login token did not expose a password field to inspect."

    is_md5_shape = len(stored) == 32 and all(ch in "0123456789abcdef" for ch in stored.lower())
    if stored == md5 or is_md5_shape:
        matches = " (== md5(password))" if stored == md5 else ""
        return c.FAIL, f"stored password is unsalted MD5: {stored}{matches}."
    if stored.startswith(("$2a$", "$2b$", "$2y$")):
        return c.PASS, "stored password is bcrypt (salted, adaptive)."
    return c.PASS, f"stored password is not MD5 (format: {stored[:7]}...)."


if __name__ == "__main__":
    c.main("VL-06 unsalted MD5 password hash", test)
