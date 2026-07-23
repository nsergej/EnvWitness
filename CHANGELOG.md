# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

No unreleased changes.

## [1.0.1] - 2026-07-23

### Fixed

- kept the CodeQL `init` and `analyze` actions on the same immutable `v4.37.3`
  revision so Dependabot updates cannot leave the workflow with incompatible
  action configuration versions;
- derived the FastAPI application version from the package version instead of
  maintaining a second hard-coded value.

### Changed

- updated `actions/checkout` to `v7.0.1` and `actions/setup-python` to `v7.0.0`;
- expanded the supported Rich range to `<16` and the development-only mypy
  range to `<3`.

## [1.0.0] - 2026-07-17

### Added

- immutable provenance-carrying evidence model and schema `1.0`;
- global deterministic secret redaction with auditable rule counts;
- cross-platform system, Git, environment, runtime, and file fingerprint collectors;
- bounded command capture without shell interpretation;
- self-verifying `.evw` archives with ZIP safety checks;
- semantic working-versus-failing comparison and deterministic diagnostic hints;
- strict YAML configuration, JSON and Markdown export, and verified JSON import;
- out-of-process language-neutral collector plugin protocol;
- Typer CLI, loopback FastAPI service, OpenAPI schema, and local dashboard;
- explicit two-key telemetry consent and a disabled-by-default package-index updater interface;
- Windows, Linux, and macOS CI, security scanning, Docker runtime, and release automation;
- an automated branch-aware test suite with a required coverage threshold above 85 percent.

### Security

- executable discovery excludes implicit current-directory lookup and executes resolved absolute paths;
- subprocess output is bounded while streaming, and process trees are terminated on timeout or cancellation with Windows Job Objects and POSIX process groups;
- command arguments, working-directory metadata, project metadata, provenance, nested JSON keys, home-directory paths, and display controls pass through redaction before persistence;
- Markdown renderers prevent raw HTML, code-span, table, and Unicode display-control injection;
- archive and JSON readers reject duplicate keys, non-finite values, encrypted or duplicate members, decompression overflows, report mismatches, symlink swaps, and path-to-handle identity changes;
- the loopback API validates Host headers against DNS rebinding, bounds capsule names, proves canonical storage containment, hides filesystem paths in errors, and rejects reparse-point redirection;
- plugin processes use strict JSON, bounded streams, sanitized errors, and deterministic cleanup;
- telemetry uses one bounded worker and rechecks consent before delivery;
- release and continuous-integration Actions are pinned to verified immutable commit identifiers.

### Operations

- source and GitHub Release installation documentation for the initial public release;
- reproducible release assets: wheel, source distribution, SPDX SBOM, SHA-256 checksums, and GitHub build provenance attestations;
- Python 3.11, 3.12, and 3.13 coverage on Windows, Linux, and macOS, cross-platform wheel smoke tests, and a Linux container smoke test;
- Docker Compose runs a one-shot capture job compatible with the loopback-only API security model;
- package-index installation and updater documentation state that PyPI distribution is not part of the 1.0 release.

[Unreleased]: https://github.com/nsergej/EnvWitness/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/nsergej/EnvWitness/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/nsergej/EnvWitness/releases/tag/v1.0.0
