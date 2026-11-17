"""Shared helpers for the Juice Shop regression scripts.

Standard library only (urllib) so the suite runs with a bare Python 3 — no pip install.

Exit-code convention used by every test script:
    0  PASS       exploit is BLOCKED  -> app is patched
    1  FAIL       exploit SUCCEEDS    -> app is vulnerable
    2  UNREACHABLE app did not respond (lab instance not running)
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("JUICE_URL", "http://localhost:3001").rstrip("/")

PASS, FAIL, UNREACHABLE = 0, 1, 2

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class Response:
    def __init__(self, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body or b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None


def request(method: str, path: str, *, data=None, headers=None, timeout=10) -> Response:
    """Perform an HTTP request. `path` may be absolute or relative to BASE_URL.

    Raises ConnectionError if the host cannot be reached (caller maps this to
    UNREACHABLE).
    """
    url = path if path.startswith("http") else f"{BASE_URL}{path}"
    hdrs = {"User-Agent": "appsec-vuln-lab-regression/1.0"}
    if headers:
        hdrs.update(headers)

    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body = data.encode()
        else:
            body = data

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            return Response(resp.status, dict(resp.headers), resp.read())
    except urllib.error.HTTPError as e:  # non-2xx is still a valid response for us
        return Response(e.code, dict(e.headers or {}), e.read())
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
        raise ConnectionError(f"could not reach {url}: {e}") from e


def get(path, **kw):
    return request("GET", path, **kw)


def post(path, **kw):
    return request("POST", path, **kw)


def looks_like_juiceshop() -> bool:
    """Best-effort check that BASE_URL is actually a Juice Shop instance, so the suite
    doesn't report a misleading PASS against some unrelated service on the same port."""
    try:
        v = get("/rest/admin/application-version", timeout=5)
        j = v.json()
        if isinstance(j, dict) and j.get("version"):
            return True
    except ConnectionError:
        raise
    except Exception:
        pass
    try:
        root = get("/", timeout=5)
        return "juice shop" in root.text.lower()
    except ConnectionError:
        raise
    except Exception:
        return False


def login(email: str, password: str):
    """Return (token, response). token is None on failure."""
    r = post("/rest/user/login", data={"email": email, "password": password})
    token = None
    j = r.json()
    if isinstance(j, dict):
        token = (j.get("authentication") or {}).get("token")
    return token, r


def result(name: str, code: int, detail: str) -> int:
    label = {PASS: "PASS", FAIL: "FAIL", UNREACHABLE: "SKIP"}[code]
    verdict = {
        PASS: "patched (exploit blocked)",
        FAIL: "VULNERABLE (exploit succeeded)",
        UNREACHABLE: "app unreachable",
    }[code]
    print(f"[{label}] {name}: {verdict}")
    if detail:
        print(f"       {detail}")
    return code


def run(name: str, fn):
    """Wrap a test function; handle unreachable host uniformly. `fn` returns
    (code, detail)."""
    try:
        if not looks_like_juiceshop():
            return result(name, UNREACHABLE,
                          f"{BASE_URL} does not look like a Juice Shop instance "
                          "(no version endpoint / title). Start the lab container first.")
        code, detail = fn()
    except ConnectionError as e:
        return result(name, UNREACHABLE, str(e))
    return result(name, code, detail)


def main(name: str, fn):
    sys.exit(run(name, fn))
