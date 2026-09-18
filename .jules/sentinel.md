## 2026-09-18 - [Missing HTTP Security Headers]
**Vulnerability:** Foundational HTTP security headers (like `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `X-XSS-Protection`) were missing from FastAPI responses.
**Learning:** FastAPI does not include these security headers by default. They must be added manually via middleware or at the web server (Nginx/Traefik) level.
**Prevention:** Always add a global middleware (e.g. `@app.middleware("http")`) to append security headers early in the development lifecycle for FastAPI applications.
