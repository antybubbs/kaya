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

Kaya uses a Development -> Release Candidate -> Stable lifecycle for new public
versions. Active development remains on the repository's development branch
(currently the `dev*` branch family; the planned logical branch is `dev`).

- Development builds use immutable tags `vX.Y.Z-dev.N` and are GitHub prereleases.
- Release candidates use immutable tags `vX.Y.Z-rc.N` and are GitHub prereleases.
- Stable releases use `vX.Y.Z` and are normal GitHub releases.

The release flow is:

```text
dev -> vX.Y.Z-dev.N -> vX.Y.Z-rc.N -> RC validation -> Dev -> Main -> vX.Y.Z
```

An RC that fails validation is never edited or reused. Fixes return to the
development branch and produce the next RC number. Stable promotion must not
add functional changes after RC approval. If functional code changes, the RC
must be rejected, the fix must return through Development, and a new RC must
be tested.

The public updater remains stable-only. Prerelease tags must not become the
Docker `latest` image or be treated as mandatory upgrade steps. Only a
published, non-draft, non-prerelease `vX.Y.Z` release may publish `latest`.
Development and RC images receive only their version-specific tags.

Release notes may be brief and internal for Development builds, should identify
the validation scope for RCs, and must be polished public notes for Stable. The
final Stable wording may be completed during RC validation without changing
the tested application source.

Release creation is an owner-controlled operation. Coding agents must read the
current release phase, must not independently promote Development to `main`,
and must not create a stable release unless explicitly instructed. Before
stable promotion, the approved RC tag and the promotion source tree must be
compared; any functional difference requires a new RC. Required Dev -> Main
checks, including tests, lint/type/security checks and Docker/workflow checks,
must pass before recommending promotion.

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

## Mandatory completion standard for all Kaya development work

Do not consider a task complete merely because the requested feature works or the automated tests pass.

Kaya uses GitHub CodeQL and security checks as part of the Dev → Main promotion process. We are currently seeing too many issues discovered only at that stage.

Your responsibility is to catch these problems before handing the work back.

Before declaring any task complete

You must:

Review the complete diff for the work you have performed.
Run all relevant:
unit tests
integration tests
linting
formatting checks
type checking
security/static-analysis tooling already available in the repository
Examine every changed security boundary for CodeQL-style vulnerabilities.

This includes, where relevant:

SQL/query construction
command execution and subprocess use
shell injection
path traversal
arbitrary file access
unsafe archive/file extraction
SSRF
unsafe URL handling or redirects
XSS / unsafe HTML generation
template injection
untrusted input reaching sensitive APIs
authentication and authorisation bypasses
CSRF
insecure session/token handling
secret exposure
passwords/tokens appearing in logs
weak or inappropriate cryptography
insecure randomness
unsafe deserialisation
overly permissive CORS or network access
filesystem permissions
race conditions affecting security-sensitive operations
exception messages leaking sensitive information

Review both backend and frontend code.

CodeQL

Where the repository provides a practical way to run CodeQL or equivalent analysis locally, run it.

If CodeQL itself cannot reasonably be executed in the development environment, that is not a reason to ignore this requirement.

Perform a manual security/data-flow review of the changed code before handing the task back.

Pay particular attention to:

source → transformation → sink

Do not only inspect the line likely to be flagged. Trace where the data originates, how it is validated, and where it ultimately reaches a sensitive operation.

Do not suppress findings to get a green build

Never:

add CodeQL suppression comments merely to make the alert disappear
weaken validation
disable a security check
exclude files from analysis
catch and ignore exceptions hiding the underlying problem

unless there is a genuine, documented false positive and the reasoning is clearly explained.

Fix the underlying issue instead.

Existing security controls

Do not weaken existing Kaya security behaviour while implementing unrelated work.

This particularly applies to:

Remote Manager trust controls
RDP certificate verification
SSH host identity verification
authentication
authorisation
CSRF
rate limiting
encryption
session management
audit logging
secure uploads
secret handling
Final response

Before saying the task is complete, report:

what changed
tests/checks run
whether they passed
security-sensitive areas reviewed
any CodeQL/static-analysis checks run
any remaining concern or limitation

If you have not completed the security review, explicitly say the work is not yet ready for Dev → Main promotion.

The objective is that Dev → Main should confirm the quality of the work, not be the first point at which obvious CodeQL/security problems are discovered.
