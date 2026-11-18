#!/usr/bin/env python3
"""VL-03 regression: DOM-based XSS in product search.

The sink is client-side, so this renders the search page in a headless browser and
inspects the resulting DOM. The payload is an empty `<iframe>` carrying a marker class
(no script, no dialog — so it never blocks headless). `<iframe>` is a tag Angular's HTML
sanitizer removes entirely, so:

  Vulnerable -> the search term is trusted as raw HTML; the live `<iframe class=MARKER>`
                element survives into the rendered DOM.
  Patched    -> the iframe is stripped (or escaped to inert text); the live element with
                the marker is absent.

Needs a Chromium/Chrome binary (set CHROME, or common install paths are tried). If none
is found the test SKIPs rather than guessing.
"""
import os
import shutil
import subprocess
import tempfile
from urllib.parse import quote
import common as c

PROBE = "XSSPROBE37"
PAYLOAD = f'<iframe class="{PROBE}"></iframe>'

CHROME_CANDIDATES = [
    os.environ.get("CHROME", ""),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome") or "",
    shutil.which("chromium") or "",
    shutil.which("chromium-browser") or "",
]


def find_chrome():
    for p in CHROME_CANDIDATES:
        if p and os.path.exists(p):
            return p
    return None


def dump_dom(chrome, url):
    with tempfile.TemporaryDirectory() as prof:
        out = subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
             f"--user-data-dir={prof}", "--virtual-time-budget=8000",
             "--dump-dom", url],
            capture_output=True, text=True, timeout=60,
        )
        return out.stdout or ""


def test():
    chrome = find_chrome()
    if not chrome:
        return c.UNREACHABLE, "no Chrome/Chromium found (set CHROME) to render the DOM."

    url = f"{c.BASE_URL}/#/search?q={quote(PAYLOAD)}"
    dom = dump_dom(chrome, url)
    if not dom:
        return c.UNREACHABLE, "headless render produced no DOM."

    # A live <iframe class="XSSPROBE37"> element in the serialized DOM means the search
    # term was trusted as raw HTML. Escaped text would serialize as &lt;iframe and not
    # match this; a stripped element is simply absent.
    live_element = f'<iframe class="{PROBE}"' in dom or f"<iframe class={PROBE}" in dom
    if live_element:
        return c.FAIL, ("search term rendered as raw HTML — live "
                        f'<iframe class="{PROBE}"> element present in the DOM.')
    return c.PASS, "payload sanitized (no live injected element in the rendered DOM)."


if __name__ == "__main__":
    c.main("VL-03 DOM XSS in search", test)
