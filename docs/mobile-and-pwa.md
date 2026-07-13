# Mobile and PWA implementation

Kaya uses a shared responsive layer in `app/static/css/responsive.css`. Desktop styling remains in the existing application and module stylesheets; the responsive layer is loaded last so module-specific fixed widths cannot reintroduce mobile overflow.

## Reviewed coverage

- Global authenticated shell, account menu, permissions-aware navigation, demo banner, login and setup
- Dashboard widgets, controls, manager dialog, live refresh and touch reordering
- Infrastructure: rack manager/detail, backup manager, asset manager/detail/forms, Compute Manager and workload/host views
- Remote Manager: host rail, session workspace, SSH/RDP panels, settings and recordings
- Networking: VLAN/IP lists/details/forms, IP/WAN Monitor, DNS dashboard/tables/forms, Domain Manager
- Security and licence list/detail/forms
- Documentation and Runbook Manager editor/detail/list views
- Team users and user forms
- Data import/export, custom fields and categories
- Site Administration, settings, audit logs and About views

Wide data tables retain their full desktop columns and are placed in keyboard-focusable, horizontally scrollable regions on narrow screens. This avoids hiding operational fields while containing overflow to the table panel.

## PWA security model

- The service worker only handles same-origin `GET` requests.
- Navigations always use the network. If the network fails, only the generic offline page is shown.
- Authenticated HTML, API responses, uploads, remote sessions, WebSockets and mutations are never placed in the service-worker cache.
- Existing application middleware sends `Cache-Control: no-store` for non-static responses, including authenticated pages and logout.
- Versioned static URLs use cache-first behavior. A new worker does not activate over the current page until the user selects **Refresh** in the update notice.
- No infrastructure mutation is queued for replay.

## Deployment notes

- Installability requires HTTPS, except on browser-recognized localhost origins.
- The manifest and service worker are served at application scope, including when `ROOT_PATH` is configured behind a reverse proxy.
- Reverse proxies must forward the configured path prefix to Kaya and must not rewrite `/service-worker.js` to a different origin.
- The service worker deliberately provides no authenticated offline mode; Kaya requires a live connection for current infrastructure information.

## Responsive verification checklist

Review at 320, 375, 390, 430, 768 and 1024 CSS pixels, plus a normal desktop width:

- Drawer open/close, overlay, Escape, link-close and expandable navigation
- Login/logout, account menu, active navigation and permission-specific links
- Search/Add toolbars, forms, validation, selects, uploads, table filters/settings and horizontal table scrolling
- Dashboard refresh, offline/online state, widget dialog, keyboard ordering and touch move controls
- Remote host rail, SSH/RDP launch/workspace, settings and recordings
- Manifest, icon and service-worker responses; install prompt; offline fallback; user-triggered worker update
- Confirm that logout/authenticated HTML are unavailable offline and are never present in service-worker caches

Installed standalone mode should be checked on target Android Chrome and iOS Safari devices because OS-level installation UI and safe-area behavior cannot be fully emulated by server-side tests.
