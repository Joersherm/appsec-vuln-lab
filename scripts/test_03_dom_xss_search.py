#!/usr/bin/env python3
"""VL-03 regression: DOM-based XSS in product search.

The sink is client-side (`bypassSecurityTrustHtml` in the Angular bundle), so this
script checks two server-observable signals:

  1. The product search API does NOT reflect the raw payload unescaped into an
     HTML/JS response (a server-side reflection would be an extra, clearer flaw).
  2. The built frontend bundle no longer binds the search term via the
     `bypassSecurityTrustHtml` sink.

Full in-browser execution proof is captured as a screenshot during live retest.

  Vulnerable -> main JS bundle still contains the bypassSecurityTrustHtml sink.
  Patched    -> sink removed (or term rendered via interpolation/sanitize()).
"""
import re
import common as c

PAYLOAD = '<iframe src="javascript:alert(`xss`)">'


def find_main_bundle():
    r = c.get("/")
    if r.status != 200:
        return None
    m = re.findall(r'(?:src=")(main[.\w-]*\.js)"?', r.text)
    return m[0] if m else "main.js"


def test():
    # (1) search API should not echo the raw payload back verbatim in a doc response
    from urllib.parse import quote
    r = c.get("/rest/products/search?q=" + quote(PAYLOAD))
    api_reflects = PAYLOAD in r.text

    # (2) inspect the main JS bundle for the sink
    bundle = find_main_bundle()
    sink_present = None
    if bundle:
        b = c.get(f"/{bundle}")
        if b.status == 200:
            sink_present = "bypassSecurityTrustHtml" in b.text

    if sink_present is True:
        return c.FAIL, (f"frontend bundle {bundle} still uses bypassSecurityTrustHtml "
                        "— the DOM-XSS sink for the search term is present.")
    if api_reflects:
        return c.FAIL, "search API reflects the raw HTML payload unescaped."
    if sink_present is None and bundle is None:
        return c.UNREACHABLE, "could not locate the main JS bundle to inspect the sink."
    return c.PASS, (f"sink absent from {bundle or 'bundle'} and payload not reflected "
                    "unescaped.")


if __name__ == "__main__":
    c.main("VL-03 DOM XSS in search", test)
