# Phase 12A cleanup isolation

Disposable validation must use an explicit run-scoped project name such as
`kaya_phase10_<run>` or `kaya_phase12a_<run>`. The shared resource helper
validates that identity, rejects protected names, and removes only resources
whose Docker Compose project label and run-scoped name match. Cleanup uses
`docker compose down --remove-orphans` without volume deletion, followed by
the helper's exact container/volume/network cleanup. Missing manifests do not
permit wildcard deletion.

Protected deployment names include `kaya_phase6_postgres_secret`,
`kaya_postgres_data`, and `kaya_postgres_secret`. External or unknown
resources are preserved. A fixed protected name in a disposable Compose
configuration must fail preflight.

The Phase 12 incident occurred when an early overlay left the fixed
`kaya_phase6_postgres_secret` mount from the base Compose file active and
`docker compose -p phase12fresh2 ... down -v --remove-orphans` removed it.
That volume contained PostgreSQL deployment secret files, not database data.
Its labels and secret contents are unavailable. Kaya does not guess or
recreate them and does not rotate credentials automatically. Operators of an
affected deployment must retrieve the original secret from an authorized
surviving mount/backup or use the explicit supported credential-rotation
procedure.

Phase 7–11 finalizers now use the same exact project-label/prefix cleanup
model. Their fixed container names were removed where necessary, including
the Phase 8 restore container. The Phase 12A workflow separately validates a
protected sentinel and cross-phase cleanup collision.
