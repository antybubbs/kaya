# Dashboard Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

The Dashboard is the authenticated landing page for Kaya. It gives the user a high-level operational entry point into the application.

## Routes

- `/dashboard`

## Models Used

- User/session context
- Compute summary data from compute models

## Workflows

- Authenticated user opens dashboard after login.
- Dashboard renders server-side using current application context and available compute summary data.

## Permissions

- Requires any authenticated user.

## Dependencies

- Auth/session state
- Compute summary service/data where available

## Edge Cases And Risks

- Dashboard usefulness depends on available module data.
- Compute summary values depend on background polling and/or agent check-ins.
