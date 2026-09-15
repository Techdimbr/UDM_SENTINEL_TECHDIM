## 2024-05-14 - [Content Security Policy & Subresource Integrity]
**Vulnerability:** External CDN scripts were used without integrity checks, and no Content Security Policy (CSP) was present, opening up potential XSS risks and script tampering for the charting functionalities.
**Learning:** Adding CSP headers using FastAPI middleware and including the integrity attribute on third-party scripts loaded in `static/index.html` are effective defense-in-depth measures against script tampering and XSS without affecting application logic.
**Prevention:** Always verify CDN scripts using the `integrity` and `crossorigin` attributes, and include a robust Content Security Policy using web application middlewares.
