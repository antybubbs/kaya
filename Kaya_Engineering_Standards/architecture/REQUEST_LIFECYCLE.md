# Request Lifecycle

## Normal request flow

A typical request follows this sequence:

1. The reverse proxy forwards the request to Kaya.
2. Trusted proxy handling determines the effective scheme and client address.
3. Session middleware validates the signed session cookie.
4. Global middleware applies host validation, security headers, metrics and audit context.
5. The router resolves the endpoint.
6. Authentication and module-access checks identify the user and permitted operation.
7. Input is validated and normalised.
8. The route calls a service or focused domain helper.
9. Database work is completed transactionally.
10. A template, redirect, file or JSON response is returned.
11. Audit and performance information is finalised.
12. Security and cache headers are attached to the response.

## Middleware requirements

Middleware must have one clearly defined purpose.

A middleware component must not:

- silently swallow application exceptions;
- open a database session without guaranteed closure;
- mutate security-sensitive headers based on untrusted forwarded values;
- perform expensive work for static assets unless required;
- write secrets or bearer identifiers into logs.

Middleware order must be tested when behaviour depends on request state created by another middleware.

## Redirects

Use `303 See Other` after successful form submissions so refresh does not repeat a mutation.

Redirect targets derived from user input must be restricted to safe local paths. Do not redirect to arbitrary schemes or hosts.

## JSON endpoints

Interactive JSON endpoints must apply the same authentication, module access and role checks as their related HTML pages.

An endpoint used by polling must return a clear status that distinguishes:

- success with current data;
- success with stale data;
- temporarily unavailable;
- permission denied;
- invalid request.

## Exceptions

Expected domain failures should use typed or clearly named exceptions translated at the route boundary.

Unexpected exceptions should:

- be logged with a request identifier;
- produce a generic user-facing response;
- preserve transaction rollback;
- avoid exposing stack traces in production.

## Audit handling

A request-level audit event is not a substitute for a meaningful domain audit event.

For example, `POST /users/4/delete` records that a request occurred, but a domain audit event should record that a particular account was deleted, by whom, and with sensitive fields excluded.
