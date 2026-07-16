# EnvWitness 1.0 Security Audit

Audit date: 2026-07-17  
Reviewed revision: `645fca1ec5b11248ba565d32f52ee9ab8320dfb7`  
Remediated release: `v1.0.0`

## Scope

The review covered every runtime Python module, the CLI and REST API, capsule archive parsing, Markdown rendering, collectors, subprocess ownership, plugin execution, telemetry consent, update checks, Docker packaging, GitHub Actions, examples, and release metadata. The threat model treats project contents and imported capsules as untrusted, plugins and custom redaction expressions as explicitly trusted local configuration, and the loopback dashboard as browser-reachable through DNS rebinding unless the `Host` header is validated.

Review methods included full-file static analysis, synthetic secret canaries, real CLI/API workflows, malformed archive cases, Windows executable-resolution probes, descendant-process tests, bounded-output stress tests, dependency and source scanners, and responsive browser checks.

## Findings And Resolution

| Severity | Finding | Resolution in 1.0.0 |
|---|---|---|
| High | Git discovery could execute `git.exe` from an untrusted current directory on Windows. | Executables are resolved only from trusted system search paths before launch. |
| High | Default runtime probes could execute `python.exe` or `git.exe` from an untrusted current directory on Windows. | Runtime probes use the same trusted executable resolver and reject unsafe resolution. |
| Medium | Command arguments bypassed redaction and could persist credentials in a capsule. | Command metadata, arguments, working directories, and outputs pass through the redactor before persistence. |
| Medium | Fact provenance metadata bypassed redaction and could retain secrets from runtime probe commands. | Redaction now recursively covers values, sources, keys, and nested metadata. |
| Medium | Runtime probe output was fully buffered before its 64 KiB retention limit. | A shared asynchronous process runner drains streams incrementally with fixed byte limits. |
| Medium | Git query output was fully buffered before its 1 MiB retention limit. | Git collection uses the bounded streaming process runner. |
| Medium | A descendant inheriting output pipes could keep capture alive after its parent timed out. | POSIX process groups and Windows kill-on-close Job Objects terminate descendants and bound reader shutdown. |
| Medium | An allowlisted file could be replaced between path validation and content read. | Files are opened first, validated from the handle, bounded during read, and checked against the path identity. |
| Medium | The loopback read API accepted arbitrary `Host` headers, enabling browser DNS-rebinding access. | Loopback hosts are normalized and allowlisted by ASGI middleware before route dispatch. |
| Low | Capsule fields could inject active Markdown or raw HTML into `CAPSULE.md`. | Rendered values escape Markdown delimiters, HTML, controls, and code-span boundaries. |
| Low | Compared fact values could escape Markdown code spans in exported reports. | Comparison rendering uses the same safe display encoding. |
| Low | Capsule verification authenticated `manifest.json` but did not compare the embedded report. | Readers require valid UTF-8 `CAPSULE.md` and compare it with deterministic rendering of the verified manifest. |
| Low | A queued telemetry event could be sent after consent was withdrawn. | One bounded worker rechecks persisted consent immediately before delivery and drops queued events after revocation. |
| Hardening | A pathological custom redaction expression could consume excessive CPU. | Configuration rejects backreferences, excessive nesting, ambiguous repeated groups, and unsafe repetition bounds. This is defense in depth because custom expressions are trusted local configuration. |
| Hardening | An explicitly enabled plugin could emit unbounded output or leave a child process behind. | Plugin streams are bounded, cancellation owns process cleanup, JSON is parsed strictly, and secret-bearing stderr is not exposed. Plugins remain trusted executable code. |

No known finding in this review remains open in the release worktree. Capsule digests detect accidental or malicious mutation but are not digital signatures and do not prove who created an archive.

## Verification Evidence

The release worktree passed the following local checks:

- 159 tests passed and 2 Windows symlink tests were skipped because the current account lacks symlink privileges.
- Ruff formatting and linting passed.
- strict mypy passed for 22 source files.
- Bandit reported no issues.
- pip-audit reported no known dependency vulnerabilities.
- Repository structure, examples, Markdown links, assets, workflow pins, and release metadata passed the repository validator.
- Wheel and source distribution builds completed successfully.
- actionlint accepted every GitHub Actions workflow.

A real CLI round trip captured two capsules, verified and compared them, exported and imported one capsule, and confirmed that a synthetic command-line secret and the current home-directory path were absent from raw archive bytes. A 128 MiB subprocess-output stress case retained only the configured 1 KiB and 2 KiB stream limits with approximately 0.81 MiB measured Python peak memory. A Windows timeout canary returned after approximately 1.19 seconds and left no live descendant.

The dashboard was exercised at desktop and 390 by 844 mobile viewports. It produced no JavaScript errors or page-level horizontal overflow. REST checks confirmed a 400 response for an untrusted `Host` and a 401 response for a malformed Unicode bearer token.

Docker was not available on the audit workstation. The release therefore validates the container with the GitHub Actions build and smoke-test job before publication.

## Reproduce

Run the complete local quality gate from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Run the dashboard with an explicit mutation token:

```powershell
$env:ENVWITNESS_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
.\.venv\Scripts\envwitness.exe serve --config .\examples\configs\minimal.yml --project-root .
```

Security reports should follow the private process in [SECURITY.md](../SECURITY.md).
