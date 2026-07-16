# Project Management

This document is the source for the initial GitHub labels, issues, milestones, and project board. Each issue is independently deliverable and includes observable acceptance criteria. The definitions below are prepared content, not a claim that the corresponding GitHub objects already exist.

## Labels

| Label | Color | Purpose |
| --- | --- | --- |
| `area: capture` | `0e8a16` | Collectors and command execution. |
| `area: privacy` | `b60205` | Redaction and disclosure controls. |
| `area: plugins` | `5319e7` | Process protocol and ecosystem. |
| `area: dashboard` | `1d76db` | Browser interface and API. |
| `area: packaging` | `006b75` | Installation, Docker, and releases. |
| `type: bug` | `d73a4a` | Reproducible incorrect behavior. |
| `type: feature` | `a2eeef` | New user-facing behavior. |
| `type: security` | `d93f0b` | Security hardening. |
| `good first issue` | `7057ff` | Small, documented contributor entry point. |
| `help wanted` | `008672` | Maintainer-approved external contribution. |

## Milestones

| Milestone | Goal | Included issues |
| --- | --- | --- |
| `v1.1 Authenticated Evidence` | Verify who sealed a capsule. | 1, 2, 3 |
| `v1.2 First-party Plugins` | Cover common runtime and infrastructure drift. | 4, 5, 6, 7 |
| `v1.3 Team Baselines` | Make comparison a repeatable team workflow. | 8, 9 |
| `Contributor Experience` | Reduce contribution and support friction. | 10, 11, 12 |

## Prepared issues

### 1. Add operating-system keystore abstraction

**Labels:** `type: security`, `area: packaging`
**Milestone:** `v1.1 Authenticated Evidence`

Define a port for creating and retrieving a local signing key without exporting private material. Implement capability discovery for Windows, macOS, and Linux. Acceptance: unsupported systems fail closed; integration tests use temporary test providers; the threat model documents key scope and recovery.

### 2. Sign and verify capsule manifests

**Labels:** `type: security`, `area: privacy`
**Milestone:** `v1.1 Authenticated Evidence`

Add detached Ed25519 signatures over the canonical manifest digest. Acceptance: unsigned 1.0 capsules remain readable; invalid signatures are distinct from digest failures; CLI and API expose signer identity and verification state; test vectors are language-neutral.

### 3. Add dashboard signature states

**Labels:** `type: feature`, `area: dashboard`
**Milestone:** `v1.1 Authenticated Evidence`

Show verified, unsigned, unknown signer, and invalid states without using color alone. Acceptance: keyboard and screen-reader semantics are tested; mobile layout remains free of horizontal overflow; browser screenshots cover every state.

### 4. Publish Docker collector plugin

**Labels:** `type: feature`, `area: plugins`, `help wanted`
**Milestone:** `v1.2 First-party Plugins`

Collect client/server versions, context name hash, and daemon capability flags without container names or environment values. Acceptance: Linux, Windows client, rootless, daemon-unavailable, and timeout fixtures pass the conformance suite.

### 5. Publish Kubernetes context plugin

**Labels:** `type: feature`, `area: plugins`
**Milestone:** `v1.2 First-party Plugins`

Report client version and redacted context shape without cluster URLs, tokens, certificate material, namespaces, or user names. Acceptance: no network call occurs unless explicitly configured; fixtures cover malformed kubeconfig and multiple contexts.

### 6. Publish Node.js dependency plugin

**Labels:** `type: feature`, `area: plugins`, `good first issue`
**Milestone:** `v1.2 First-party Plugins`

Report Node.js/package-manager versions, package-manager mode, and lockfile metadata. Acceptance: npm, pnpm, Yarn classic, and Yarn modern fixtures pass on all supported operating systems.

### 7. Build plugin conformance runner

**Labels:** `type: feature`, `area: plugins`
**Milestone:** `v1.2 First-party Plugins`

Create `envwitness plugins validate COMMAND...` with protocol, namespace, timeout, output, and secret-canary checks. Acceptance: JSON and human reports are available; failure exit codes are stable; the example plugin passes.

### 8. Compare capsule collections

**Labels:** `type: feature`, `area: capture`
**Milestone:** `v1.3 Team Baselines`

Compare one candidate against several known-good capsules and distinguish invariant drift from expected fleet variance. Acceptance: scoring is deterministic; raw evidence remains local; reports explain sample size and confidence limitations.

### 9. Generate GitHub issue form snippets

**Labels:** `type: feature`, `area: packaging`, `good first issue`
**Milestone:** `v1.3 Team Baselines`

Add a command that emits a reviewed issue-form section for requesting capsules. Acceptance: generated YAML passes GitHub schema validation; copy explains privacy review and version requirements; no repository write occurs without an explicit output path.

### 10. Add shell completion packages

**Labels:** `type: feature`, `area: packaging`, `good first issue`
**Milestone:** `Contributor Experience`

Document and test completion for PowerShell, Bash, Zsh, and Fish. Acceptance: generated scripts install to user-selected paths and never modify shell profiles automatically.

### 11. Add archive compatibility corpus

**Labels:** `type: security`, `area: packaging`, `help wanted`
**Milestone:** `Contributor Experience`

Create small valid and hostile `.evw` fixtures for traversal, duplicate entries, compression limits, invalid UTF-8, unknown fields, and digest mismatch. Acceptance: provenance for generated fixtures is documented and all rejection cases have stable error categories.

### 12. Localize human-readable reports

**Labels:** `type: feature`, `good first issue`
**Milestone:** `Contributor Experience`

Introduce message catalogs for rendered CLI and Markdown text while keeping keys, JSON, and protocol fields stable. Acceptance: English remains complete; one second locale demonstrates extraction and fallback; no translated string changes archive integrity semantics.

## Starter issues

Issues 6, 9, 10, and 12 are sized for first-time contributors and point to existing examples or test patterns.

## Project board

Create a table-style GitHub Project named `EnvWitness Roadmap` with these fields:

| Field | Values |
| --- | --- |
| Status | Triage, Ready, In progress, Review, Done |
| Priority | Critical, High, Normal, Low |
| Target | 1.1, 1.2, 1.3, Contributor Experience |
| Area | Capture, Privacy, Plugins, Dashboard, Packaging |

Views:

- `Roadmap`: grouped by Target, sorted by Priority.
- `Current`: Target 1.1, grouped by Status.
- `Contributors`: `good first issue` or `help wanted`, grouped by Area.
- `Security`: `type: security`, sorted by Priority.

Automation moves newly added issues to Triage, pull requests to In progress, reviews to Review, and merged pull requests to Done.
