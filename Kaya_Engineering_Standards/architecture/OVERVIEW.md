# Kaya Architecture Overview

## Application style

Kaya is a modular, server-rendered FastAPI application.

The main process provides:

- HTTP routing;
- Jinja-rendered pages;
- JSON endpoints used by interactive pages;
- signed session handling;
- authentication and authorisation;
- SQLAlchemy-backed persistence;
- security middleware;
- audit recording;
- long-running monitoring and maintenance services.

## Primary layers

### HTTP layer

Routers under `app/routers/` own URL structure, request parsing and response construction.

Routes should remain thin. They may:

- load the authenticated user;
- validate request shape;
- call service functions;
- translate expected domain errors into HTTP responses;
- choose and populate templates.

They should not contain large reusable workflows.

### Service layer

Services under `app/services/` own reusable application behaviour, integrations and background operations.

Examples include session handling, network monitoring history, Secure Send cleanup, trusted client IP resolution, HA monitoring and audit context.

A service must expose clear inputs and outputs and avoid hidden dependence on global request state unless its role specifically requires request context.

### Persistence layer

SQLAlchemy sessions are created through the database session module. Models represent persisted state.

Transactions should be scoped to one logical operation. Service functions should either:

- accept a session from the caller; or
- clearly own session creation and closure.

Do not mix both approaches unpredictably.

### Presentation layer

Jinja templates render the primary interface. Static JavaScript adds interaction and live updates.

Templates must receive prepared display data. They must not query the database or determine access rights.

## Application startup

The FastAPI application is configured in `app/main.py`.

Startup and shutdown own background task lifecycle. A background service must be registered explicitly and must support cancellation or clean shutdown.

The application also configures:

- session middleware;
- trusted proxy and client IP behaviour;
- security headers;
- request and performance metrics;
- audit request context;
- mounted static assets;
- router registration.

Middleware order is significant and must be reviewed when adding or moving middleware.

## Module boundaries

A module is not necessarily a Python package today, but each module should maintain a clear boundary across:

- router;
- service functions;
- models;
- templates;
- static assets;
- tests;
- module registration and access rules.

New development should reduce cross-module imports where practical. Shared behaviour belongs in a shared service rather than one module importing another module's route internals.

## Integrations

External systems are untrusted and unreliable.

All integration code must:

- use explicit connection and read timeouts;
- validate returned data;
- handle unavailable and malformed responses;
- avoid exposing credentials in errors;
- distinguish current, stale and failed state;
- be testable without requiring the live external system.

## Architectural change control

A significant change to these layers requires an ADR and an update to this document.
