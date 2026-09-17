
## 2024-09-17 - Added Security Headers Middleware
**Vulnerability:** Missing security headers (X-Frame-Options, X-Content-Type-Options, HSTS, CSP, etc.) leaves the application vulnerable to clickjacking, MIME-type sniffing, cross-site scripting (XSS), and unencrypted data transmission downgrades.
**Learning:** By default, FastAPI/Starlette does not include these headers. An explicit HTTP middleware function must be added to inject them into every response in order to achieve defense-in-depth on the API.
**Prevention:** Always implement a security header middleware or use libraries like `secure` or `starlette.middleware.base.BaseHTTPMiddleware` when bootstrapping a new FastAPI project.
