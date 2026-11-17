#!/usr/bin/env python3
"""VL-05 regression: /ftp exposure + poison-null-byte allow-list bypass.

Checks the allow-list bypass: requesting a non-.md/.pdf backup file through a
double-encoded null byte (`%2500.md`) must NOT return its contents.

  Vulnerable -> `GET /ftp/package.json.bak%2500.md` returns 200 with backup contents.
  Patched    -> that request returns 403/404; only genuine .md/.pdf files are served.

Also reports (informational) whether confidential `acquisitions.md` is anonymously
readable, since the directory itself should ideally not be public.
"""
import common as c

BYPASS_PATH = "/ftp/package.json.bak%2500.md"


def looks_like_backup(text: str) -> bool:
    t = text.lower()
    return ('"dependencies"' in t) or ('"name"' in t and '"version"' in t)


def test():
    r = c.get(BYPASS_PATH)
    if r.status == 200 and looks_like_backup(r.text):
        return c.FAIL, (f"null-byte bypass served a backup file via {BYPASS_PATH} "
                        f"(HTTP 200, {len(r.body)} bytes).")

    # Informational: is the confidential doc anonymously reachable?
    info = c.get("/ftp/acquisitions.md")
    note = ""
    if info.status == 200 and info.body:
        note = (" NOTE: /ftp/acquisitions.md is still anonymously readable — consider "
                "removing confidential files from the public dir (see fix 05).")

    if r.status in (403, 404) or not looks_like_backup(r.text):
        return c.PASS, f"null-byte bypass refused (HTTP {r.status}).{note}"
    return c.FAIL, f"unexpected response to bypass attempt (HTTP {r.status})."


if __name__ == "__main__":
    c.main("VL-05 /ftp null-byte bypass", test)
