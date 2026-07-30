# Authorisation and Module Access

## Model

Kaya uses two related controls:

1. **Global role** determines broad action capability, such as administrative, editing or viewing rights.
2. **Module access** determines which modules the user can enter and invoke.

A user must pass both checks.

## Server-side enforcement

Every protected route and endpoint must enforce authorisation server-side.

Hiding a navigation item, button or form control improves usability but does not enforce access.

## Service-layer protection

Security-sensitive services should require an explicit actor or permission context when they can be called from multiple routes or jobs.

A service must not infer that a caller is authorised merely because a route normally checks access.

## Administrative access

Administrative functions must require the administrator role in addition to module access where relevant.

The application must protect against removing or disabling the last usable administrator account unless an explicit recovery path exists.

## Viewer and editor behaviour

Viewer access must not allow state changes through alternate methods, direct URLs, JSON endpoints or import functions.

Editor access should be limited to domain editing and must not imply Site Administration, user management, security configuration or unrestricted secret access.

## Module-disabled state

When a module is disabled:

- navigation must be removed;
- direct page access must be denied or return not found according to the shared pattern;
- JSON endpoints must be denied;
- background tasks should stop or become inactive where appropriate;
- existing data must be retained unless explicitly deleted by an authorised action.

## Shared and public links

A shared link is a separate authorisation mechanism and must be intentionally designed.

Shared links must:

- use high-entropy, non-sequential tokens;
- support revocation;
- avoid exposing bearer tokens in audit logs;
- define expiry or explicit non-expiry;
- restrict displayed data to the intended view;
- avoid granting access to normal authenticated routes;
- support an additional PIN or passcode when the feature requires it.

## Testing matrix

For protected behaviour, tests should cover:

- anonymous user;
- authenticated user without module access;
- viewer;
- editor;
- administrator;
- disabled module;
- revoked shared link;
- malformed or guessed shared token.
