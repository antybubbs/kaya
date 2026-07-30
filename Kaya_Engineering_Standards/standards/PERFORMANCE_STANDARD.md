# Performance Standard

## Principle

Kaya should remain responsive on modest self-hosted hardware while monitoring and retaining operational data.

## Request performance

Avoid external network calls in page-rendering paths where cached or previously collected data can be used.

Every external call requires a timeout.

Slow operations should expose progress or run outside the request when appropriate.

## Database queries

Watch for:

- N+1 relationship loading;
- repeated settings queries;
- loading full history when only a summary is shown;
- unbounded list pages;
- sorting on unindexed columns;
- repeated commits.

Use pagination for growing lists.

Use aggregate queries for dashboards rather than loading all rows into Python.

## Middleware

Global middleware runs on nearly every request and must remain efficient.

Avoid repeated database loading of settings when a safe short-lived cache or request-shared context is suitable. Any cache must have a clear invalidation rule.

Static assets should bypass unnecessary database and audit work.

## Monitoring

Polling frequency must balance freshness and system cost.

A page with multiple live components should share summary requests where practical rather than opening independent high-frequency polling loops.

Browser polling must stop or reduce when the page is hidden where appropriate.

## History retention

Operational history grows continuously.

Every high-volume history model should define:

- expected write rate;
- indexes;
- retention;
- aggregation strategy;
- maximum query window;
- pagination.

## Templates and static assets

Avoid shipping large scripts globally for one module.

Static assets should be cached with versioned or immutable URLs.

Do not place large encoded assets inline in templates.

## Measurements

Performance changes should be based on measurements.

Useful measures include:

- server request duration;
- database query count and duration;
- page transfer size;
- browser render and interaction timing;
- background cycle duration;
- task backlog or missed cycles.

## Regression thresholds

The project should introduce agreed CI or review thresholds for critical routes as repeatable benchmarks become available.

Until then, changes to dashboards, middleware and high-volume history queries require explicit review of likely query and polling impact.
