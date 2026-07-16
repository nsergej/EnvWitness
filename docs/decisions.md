# Architecture Decision Records

## ADR-001: Structured facts instead of collected files

**Status:** Accepted

Every observation is represented by a stable semantic key, JSON value, provenance, sensitivity classification, capture time, and digest. File hashes and explicitly approved file contents become facts. This makes comparison independent of archive layout and gives every disclosed value a reason for existing.

## ADR-002: Redact before persistence

**Status:** Accepted

Collectors return in-memory raw facts. One deterministic redactor runs across all built-in and plugin facts before a capsule is created. Archives, logs, telemetry, and reports never receive pre-redaction values.

## ADR-003: Hash stored values only

**Status:** Accepted

The digest of a fact covers its post-redaction value. A digest of discarded secret material could become an offline guessing oracle for weak passwords, internal hostnames, or short tokens.

## ADR-004: Out-of-process plugins

**Status:** Accepted

Plugins are executable processes with a versioned JSON standard-input/standard-output contract. This keeps the core language-neutral, avoids dependency conflicts, and supports strict time and output limits. Plugins remain trusted local code and require explicit enablement.

## ADR-005: ZIP container with constrained members

**Status:** Accepted

The `.evw` format is ZIP for ubiquitous tooling, but schema `1.0` accepts only `manifest.json` and `CAPSULE.md`. Readers reject traversal, encryption, duplicate entries, unknown entries, oversized archives, and excessive expanded size.

## ADR-006: Loopback-only API

**Status:** Accepted

The configuration schema accepts only `127.0.0.1`, `localhost`, or `::1`. All state-changing endpoints require a bearer token from an environment variable. Exposing evidence over a network requires a separately designed authentication and transport model.

## ADR-007: Two-key telemetry consent

**Status:** Accepted

Telemetry requires local user consent plus project configuration with an HTTPS endpoint. Either control disables delivery. Events use a hardcoded allowlist and contain no stable installation identifier.
