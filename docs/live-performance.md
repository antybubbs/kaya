# Live Performance diagnostics

Administrators can open **About → Live Performance**. The page and its JSON API use Kaya's existing `admin` role; other users do not receive the link and are denied server-side.

Diagnostics are off by default. The switch is persisted in the existing `RemoteManagerSetting` table and is restored during application startup. Captured data is a process-local ring buffer containing at most 300 recent request samples; it is intentionally not a database history and is cleared on process restart. In multi-worker or multi-replica deployments, each process has its own window, so the page must be interpreted as the process serving the request.

When enabled, Kaya retains timestamp, method, normalized route, status, request duration, SQL count/time, template time, external-call count/time, process RSS, and dashboard widget timing names/durations. Query strings, request/response bodies, cookies, authorization or other secret headers, credentials, parameters, form fields, and personal content are not retained. Numeric and UUID path segments are represented as `{id}`.

The page calculates averages, interpolated p95, slowest request, SQL and external-call summaries, and supports route, status, and slow-only filtering. Optional live refresh polls every three seconds, pauses while hidden, and excludes its own page/API/toggle/clear requests from the sample window. Clear removes samples only; it does not disable collection. Disable diagnostics after troubleshooting to avoid the small per-request timing and bounded-buffer overhead.

Timing categories are diagnostic labels: under 300 ms normal, 300–500 ms noticeable, 500–1000 ms slow, and over 1000 ms very slow. They are not health or security decisions. Dashboard snapshot widget timings are instrumentation only; widget execution remains sequential and unchanged.
