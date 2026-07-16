# Python API

EnvWitness is CLI-first. The package root exposes a deliberately small stable Python API:

```python
from envwitness import Capsule, ComparisonReport, EvidenceFact, __version__
```

## `EvidenceFact`

An immutable observation with a semantic `key`, JSON `value`, `collector`, human-readable `source`, UTC `captured_at`, `sensitivity`, stored-value `digest`, and redaction audit fields.

Use `EvidenceFact.create(...)` to calculate the digest from the stored value. Direct construction validates that a supplied digest matches.

## `Capsule`

An immutable schema `1.0` manifest containing unique facts, optional command metadata, redaction summary, plugin names, and integrity metadata.

- `unsigned_payload()` returns the JSON-compatible payload covered by integrity.
- `expected_manifest_digest()` returns its SHA-256 digest.
- `seal()` returns a new capsule carrying that digest.
- `verify_integrity()` returns whether the stored digest matches.

## `ComparisonReport`

An immutable result containing ordered semantic differences, deterministic diagnostic hints, capsule identifiers, creation time, and an `identical` flag.

## Compatibility policy

Only names exported from `envwitness.__all__` are covered by semantic-version compatibility. Application and infrastructure modules are documented for contributors but may evolve between minor releases. The `.evw` schema and process plugin protocol have separate compatibility commitments documented in [Architecture Decisions](decisions.md).

All public functions and classes carry Google-style docstrings and are checked by Ruff during continuous integration.
