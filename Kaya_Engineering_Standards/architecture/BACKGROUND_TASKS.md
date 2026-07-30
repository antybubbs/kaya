# Background Services

## Current pattern

Kaya runs several monitoring, polling, cleanup, version-check and high-availability loops from the application process.

This pattern is acceptable while the operational limits are understood and documented.

## Required lifecycle

Every background service must:

- start exactly once per intended process;
- retain a task handle;
- handle cancellation;
- close network and database resources;
- log startup, failure and shutdown;
- avoid terminating permanently after one recoverable exception;
- expose enough state to diagnose whether it is running.

## Failure isolation

One failed service must not stop unrelated services.

The outer loop should catch expected operational failures, record them, apply bounded delay or backoff and continue.

Do not use a broad exception handler that loses the traceback or creates a tight failure loop.

## Scheduling

Intervals must be configurable where operationally useful and must have safe minimums.

Use monotonic time for intervals. Avoid cumulative drift when task timing matters.

## Concurrency

A background service must define whether overlap is allowed.

Where overlap is unsafe, use an application-level lock, database lease or another explicit mechanism. Do not assume a single worker unless deployment documentation enforces it.

## Multi-worker warning

Application-started loops run once per process. Running multiple Uvicorn/Gunicorn workers may therefore duplicate monitoring and reconciliation work.

Until Kaya introduces an external worker architecture or leader election, deployment documentation must specify the supported worker model for installations using in-process background services.

## Database sessions

Open sessions for the shortest practical scope. Always close them in `finally` blocks or context managers.

Do not retain a SQLAlchemy session across sleep intervals.

## External calls

All external calls require connection and read timeouts. Retries must be bounded and should use backoff for repeated failures.

## Health and freshness

A service should record:

- last start;
- last successful cycle;
- last failure;
- current state;
- relevant error summary;
- next expected cycle where useful.

The UI must not display historical success as current health when the service has stopped.
