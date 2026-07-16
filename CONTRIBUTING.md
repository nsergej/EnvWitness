# Contributing to EnvWitness

Thank you for improving diagnostic evidence for everyone. Contributions are welcome across code, collectors, rule design, documentation, accessibility, packaging, and security research.

## Before You Start

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Search existing issues and discussions before opening a proposal.
- Use a public issue for ordinary behavior changes.
- Use GitHub private vulnerability reporting for security-sensitive work.
- Keep pull requests focused on one coherent outcome.

## Development Setup

Python 3.11 or newer and Git are required.

```bash
git clone https://github.com/envwitness/envwitness.git
cd envwitness
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux and macOS
source .venv/bin/activate
```

Install all development tools:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[development]"
```

## Quality Gate

Run the same checks as continuous integration:

```bash
ruff format --check src tests examples scripts
ruff check src tests examples scripts
mypy src
pytest
bandit -c pyproject.toml -r src
python -m build
```

On Windows, `scripts/verify.ps1` runs the complete local gate. On Linux and macOS, use `scripts/verify.sh`.

## Design Rules

1. Minimize collection before adding redaction.
2. Never persist a pre-redaction value.
3. Never hash discarded secret material.
4. Use argument vectors; do not introduce `shell=True`.
5. Keep external plugins disabled until explicitly configured.
6. Put domain rules in `domain`, use-case coordination in `application`, adapters in `infrastructure`, and transport concerns in `presentation`.
7. Document every public API and every configuration field.
8. Add tests for success, invalid input, resource limits, and security boundaries.

## Pull Requests

Pull requests must include:

- a concise problem statement;
- the chosen behavior and rejected alternatives when the decision is non-obvious;
- tests that would fail before the change;
- documentation for public behavior;
- a `CHANGELOG.md` entry under `Unreleased` when users will notice the change.

Use conventional commit subjects when practical:

```text
feat: add JVM runtime collector plugin
fix: reject duplicate ZIP members before extraction
docs: clarify stored-value digest semantics
```

## Compatibility

Schema `1.x` readers must reject unknown major versions and preserve all documented `1.0` invariants. Breaking CLI, archive, plugin, or REST changes require a major release and a migration document.

## Licensing

By submitting a contribution, you agree that it is licensed under the Apache License 2.0.
