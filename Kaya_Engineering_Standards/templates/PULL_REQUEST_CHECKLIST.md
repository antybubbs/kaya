# Pull Request Checklist

## Summary

- [ ] The change has a clear, focused purpose.
- [ ] Existing patterns and relevant standards were reviewed.

## Correctness

- [ ] Expected and failure paths are handled.
- [ ] Existing behaviour is preserved unless intentionally changed.

## Security

- [ ] Input is validated.
- [ ] Authorisation is enforced server-side.
- [ ] Secrets and sensitive data are not logged or exposed.
- [ ] CSRF, XSS, SSRF, file and redirect risks were considered where relevant.

## Data and compatibility

- [ ] Database changes include safe migration handling.
- [ ] Existing installations have an upgrade path.
- [ ] Destructive behaviour is explicit and recoverable where practical.

## Quality

- [ ] Relevant tests were added or updated.
- [ ] Tests were actually run and the command/result is recorded.
- [ ] Logging and auditing are appropriate.
- [ ] Performance impact was considered.

## UI

- [ ] Light and dark mode checked.
- [ ] Responsive layout checked.
- [ ] Keyboard and accessibility checked.
- [ ] Empty, loading, stale and error states are clear.

## Documentation

- [ ] User and engineering documentation updated.
- [ ] ADR added when required.
