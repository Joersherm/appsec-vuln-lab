# Fix 03 — Stop bypassing sanitization on the search term (VL-03, XSS)

**Finding:** `findings/03-dom-xss-search.md`
**File:** `frontend/src/app/search-result/search-result.component.ts` (+ template)
**Approach:** never call `bypassSecurityTrustHtml` on user input; render the search term
as text so Angular's contextual auto-escaping applies.

## Patch

```diff
--- a/frontend/src/app/search-result/search-result.component.ts
+++ b/frontend/src/app/search-result/search-result.component.ts
@@
-    this.route.queryParams.subscribe((queryParam: Params) => {
-      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam.q)
-      this.filterTable()
-    })
+    this.route.queryParams.subscribe((queryParam: Params) => {
+      // Keep the raw term as a plain string; do NOT mark it as trusted HTML.
+      this.searchValue = queryParam.q ?? ''
+      this.filterTable()
+    })
```

```diff
--- a/frontend/src/app/search-result/search-result.component.html
+++ b/frontend/src/app/search-result/search-result.component.html
@@
-      <span [innerHTML]="searchValue"></span>
+      <span>{{ searchValue }}</span>
```

If markup genuinely must be rendered, sanitize instead of bypassing:

```ts
import { DomSanitizer, SecurityContext } from '@angular/platform-browser'
// ...
this.searchValue = this.sanitizer.sanitize(SecurityContext.HTML, queryParam.q ?? '') ?? ''
```

## Why this works

Interpolation (`{{ }}`) and `sanitize(SecurityContext.HTML, …)` escape/strip dangerous
constructs, so `<iframe src="javascript:…">` is rendered as inert text and no script
runs. `bypassSecurityTrustHtml` was the sink that disabled this protection.

## Defense in depth

- Ship a `Content-Security-Policy` (`default-src 'self'`, no `unsafe-inline` script).
- Audit the codebase for other `bypassSecurityTrust*` calls on untrusted data.

## Verify

```bash
python3 scripts/test_03_dom_xss_search.py    # PASS (exit 0) only when patched
```

> Note: the script verifies this **behaviorally** — it renders `/#/search?q=<iframe…>`
> in headless Chrome and checks whether the injected `<iframe>` survives into the DOM
> (vulnerable) or is sanitized away (patched). Confirmed live: present on the stock
> build, absent on the patched build.
