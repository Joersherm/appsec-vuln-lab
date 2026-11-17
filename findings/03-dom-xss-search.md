# Finding 03 — DOM-based XSS in product search

| | |
|---|---|
| **ID** | VL-03 |
| **OWASP Top 10 (2021)** | A03:2021 – Injection (Cross-Site Scripting) |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Severity** | **Medium** |
| **CVSS 3.1** | 6.1 (`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`) |
| **Affected component** | Search result header → `frontend/src/app/search-result/search-result.component.ts` |
| **Status** | Open → Fixed (see `fixes/03-dom-xss-search.md`) |

## Summary

The search results page echoes the raw search term back into the DOM through Angular's
`bypassSecurityTrustHtml`, which explicitly disables the framework's built-in output
sanitization. A crafted `q` parameter is rendered as live HTML, allowing script
execution in the victim's browser (DOM-based XSS).

## Affected code (vulnerable)

`frontend/src/app/search-result/search-result.component.ts`:

```ts
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
// ...
// template: <h1 ...><span [innerHTML]="searchValue"></span></h1>
```

Binding attacker-controlled text to `[innerHTML]` after `bypassSecurityTrustHtml`
defeats Angular's contextual auto-escaping.

## Reproduction

Target: local lab instance at `http://localhost:3001`.

1. Open a search URL whose `q` value contains an HTML payload that fires without
   needing inline `<script>` (which the browser won't execute via `innerHTML`):

   ```
   http://localhost:3001/#/search?q=<iframe src="javascript:alert(`xss`)">
   ```

2. **Vulnerable result:** the `<iframe>` is injected into the results header and the
   `javascript:` URI executes — `alert('xss')` fires in the page origin.

3. **Patched result:** the payload is rendered as inert, escaped text (`&lt;iframe ...`)
   and no script executes.

Because this is DOM-based, the payload executes client-side from the URL fragment. The
regression script `scripts/test_03_dom_xss_search.py` verifies the server-side
contract that supports it (that the raw term is reflected without encoding) and checks
the built asset no longer contains the `bypassSecurityTrustHtml` sink.

## Impact

- Arbitrary JavaScript in a victim's session when they open a crafted link.
- Session/JWT theft (token is reachable from `localStorage`), action-on-behalf-of the
  victim, UI redressing, credential phishing within a trusted origin.

## Remediation

Do **not** bypass sanitization for user input. Bind the search term as plain text
(interpolation `{{ searchValue }}` or a `textContent` binding), and if HTML is truly
required, pass it through Angular's `DomSanitizer.sanitize(SecurityContext.HTML, …)`
instead of `bypassSecurityTrustHtml`. See `fixes/03-dom-xss-search.md`. Add a
`Content-Security-Policy` that forbids inline script as defense in depth.

## References

- OWASP Top 10 A03:2021 – Injection
- OWASP XSS Prevention Cheat Sheet; Angular Security Guide (Sanitization)
- CWE-79
