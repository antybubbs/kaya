# Coding Standards

## Python version and style

Use the Python version declared by the project. Code must be compatible with the supported runtime in Docker and CI.

Follow PEP 8 where it improves readability, but repository conventions and automated formatting take precedence.

## Naming

Use descriptive names.

- functions and variables: `snake_case`;
- classes: `PascalCase`;
- constants: `UPPER_SNAKE_CASE`;
- module keys and URL slugs: stable lowercase values following existing Kaya conventions.

Avoid vague names such as `data`, `thing`, `temp`, `handler2` or `process_item` when a domain name is available.

## Functions

A function should perform one coherent task.

Long functions are not automatically wrong, but a function should be split when it mixes request handling, authorisation, database writes, external calls and presentation preparation.

Prefer explicit parameters over reading mutable globals.

## Type hints

Public service functions and non-trivial helpers should use type hints.

Do not add inaccurate hints merely to satisfy appearance. Use `Optional` or union types where `None` is valid.

## Imports

Group standard-library, third-party and application imports.

Avoid wildcard imports.

Avoid circular imports by improving boundaries rather than moving imports inside functions without explanation. A local import is acceptable where it deliberately avoids optional or startup-heavy dependencies.

## Exceptions

Catch the narrowest useful exception.

Do not use:

```python
except Exception:
    pass
```

Unexpected exceptions should retain traceback information in logs.

Expected domain failures should use clear exception types or result objects.

## Async and blocking work

FastAPI async handlers must not perform long blocking network or filesystem operations directly.

Use an async client, a thread boundary or a background workflow as appropriate.

Do not mark a function `async` when it contains no asynchronous work solely for consistency.

## Database code

Use SQLAlchemy parameterisation. Do not construct SQL using user-provided string interpolation.

Session ownership must be obvious.

Commit once per logical transaction where practical. Roll back on failure.

## Configuration

Read configuration through the approved settings layer.

Do not scatter direct `os.environ` calls through routes and services.

New configuration must have:

- a documented name;
- validation;
- a safe default where possible;
- deployment documentation.

## Security-sensitive helpers

Cryptography, token generation, password hashing, client IP resolution, CSRF and permission checks must use shared approved helpers.

Do not create module-specific alternatives.

## Comments and docstrings

Comments should explain why, risk or non-obvious constraints.

Do not narrate straightforward code.

Public services and security-sensitive helpers should have concise docstrings describing behaviour, inputs, outputs and important failure modes.

## Dead code

Remove unused code rather than commenting it out.

Feature flags may retain inactive paths only when they are intentional, tested and documented.

## Duplication

Before copying a block, decide whether the underlying rule is shared.

Three similar lines are often clearer than a premature abstraction. Three independent implementations of permission or encryption logic are not acceptable.

## File size

There is no arbitrary maximum file length. A file should be split when it contains multiple unrelated responsibilities or becomes difficult to navigate and test.

## Linting and formatting

The repository should adopt and enforce an agreed formatter, linter and import checker through CI. Tooling changes require a focused pull request and documentation update.
