# Changelog

## Unreleased

### Security

- Remediated CVE-2026-48710 by pinning Starlette 1.3.1. This release contains
  the upstream malformed `Host` header fix introduced in Starlette 1.0.1 and
  later fixes for StaticFiles path validation, URL authority parsing, and form
  parser resource limits.
- Added the stable HTTPX2 test-client dependency required by Starlette 1.3.1.
  FastAPI remains at 0.136.3 because its published dependency metadata
  officially supports Starlette 1.3.1 (`starlette>=0.46.0`); Kaya's existing
  Pydantic Settings 2.14.2, HTTPX 0.28.1, and Uvicorn 0.34.0 pins remain within
  their declared compatibility constraints.
- Added direct and trusted-reverse-proxy regression coverage for authentication,
  authorisation, module access, CSRF, redirects, WebSockets, static files, file
  uploads, and malformed or manipulated `Host` headers.
