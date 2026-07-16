# Roadmap

The roadmap prioritizes trust, useful daily workflows, and ecosystem reach. Dates are intentionally omitted; releases ship when acceptance criteria and security review are complete.

## 1.0 - Evidence capsules

- Cross-platform system, Git, environment, lockfile, file, runtime, and command evidence.
- Global deterministic redaction and post-redaction integrity.
- Safe `.evw` archives, JSON/Markdown import and export, semantic comparison, and diagnostic hints.
- CLI, loopback REST API, local dashboard, process plugin protocol, opt-in telemetry, and update policy.

## 1.1 - Authenticated evidence

- Capsule signatures backed by Windows CNG, macOS Keychain, and Linux secret-service integrations.
- Maintainer trust policies and signature status in CLI, API, and dashboard.
- Reproducible signature test vectors and a documented key-rotation procedure.

## 1.2 - First-party collectors

- Independently versioned Docker, Kubernetes, Node.js, Java, .NET, and database plugins.
- Plugin conformance runner and compatibility fixtures.
- Signed plugin release manifests and provenance attestations.

## 1.3 - Team baselines

- Local baseline collections with privacy-preserving aggregation.
- Machine-readable issue-template integration.
- CI matrix comparison and artifact annotations.

## 2.0 - Diagnostic rule packs

- Versioned, declarative hint rules with deterministic scoring.
- Offline rule-pack installation and signature verification.
- Stable migration tools for capsule schema 2.0.

## Non-goals

- Cloud storage or automatic capsule upload in the core project.
- Remote command execution.
- Full machine inventory or asset management.
- Claims that regular-expression redaction can identify every secret.

See [Project Management](project-management.md) for release-ready issue specifications.
