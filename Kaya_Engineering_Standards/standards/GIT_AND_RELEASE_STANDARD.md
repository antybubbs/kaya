# Git and Release Standard

## Branching

Use focused branches from the current main branch.

Do not combine unrelated work into one branch.

## Commits

Commits should be coherent and buildable where practical.

Use imperative, descriptive subjects.

Do not include generated attribution that misrepresents authorship or review.

## Pull requests

Pull requests should remain draft until the implementation, tests and documentation are ready for review.

A PR must describe security, data, deployment and compatibility impact.

## Review

At least one informed review is recommended for security-sensitive or architectural changes, even when the primary implementation is AI-assisted.

Review comments should identify concrete risk or required behaviour.

## Versioning

Kaya releases should follow the repository's chosen semantic versioning approach.

- patch: compatible fixes;
- minor: compatible features;
- major: incompatible changes.

Pre-1.0 releases may move quickly, but breaking changes still require documentation and migration care.

## Release checks

Before release:

- tests pass;
- dependency vulnerabilities are reviewed;
- migrations are tested;
- version references are consistent;
- Docker image builds;
- upgrade path is documented;
- release notes are complete;
- backup and rollback implications are understood.

## Tags and artefacts

A release tag must correspond to the code and artefacts published for that version.

The application must not report a version that does not match the checked-out or packaged release.

## Security releases

Security fixes should minimise disclosure before a patched release is available.

Release notes should explain impact and required user action without publishing unnecessary exploitation guidance.
