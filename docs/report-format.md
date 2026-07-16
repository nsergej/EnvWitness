# Capsule and Report Format

An `.evw` file is a constrained ZIP archive. Writers in schema `1.0` emit `manifest.json` and `CAPSULE.md`; readers reject unknown, absolute, traversing, duplicate, encrypted, or oversized members. `manifest.json` is the authoritative machine-readable document.

## Archive limits

| Boundary | Limit |
| --- | ---: |
| Compressed `.evw` size | 25 MiB |
| Total expanded member size | 50 MiB |
| Allowed member names | `manifest.json`, `CAPSULE.md` |

Archives are read without extracting members to the file system. Writes use a temporary sibling followed by atomic replacement, and an existing symbolic-link destination is rejected.

## Manifest fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Format compatibility identifier, exactly `1.0`. |
| `capsule_identifier` | Random capsule identifier used in comparisons and API responses. |
| `created_at` | UTC creation timestamp. |
| `tool_version` | EnvWitness version that created the manifest. |
| `project_name` | Operator-visible project label. |
| `project_root_label` | Non-absolute label for the captured root; the user home is stored as `home-directory`. |
| `facts` | Ordered evidence records with provenance, sensitivity, redaction audit, and digest. |
| `command` | Optional redacted command metadata and outcome. |
| `redaction` | Counts of scanned/redacted facts, replacements, and triggered rules. |
| `plugins` | Enabled plugin collector names represented in the capture. |
| `integrity` | SHA-256 algorithm identifier and digest of the canonical unsigned manifest. |

Each fact contains `key`, JSON `value`, `collector`, `source`, `captured_at`, `sensitivity`, `digest`, `redacted`, and `redaction_rules`. The fact digest covers only the canonical stored value after redaction.

## Canonical integrity

EnvWitness serializes the unsigned manifest as UTF-8 JSON with sorted object keys, no insignificant whitespace, and stable UTC/enum conversion, then calculates SHA-256. A fact digest uses the same canonical representation for its stored value.

These are unkeyed digests. They detect corruption and modification that was not followed by resealing. A person able to edit a capsule can recompute them, so schema `1.0` provides no author identity, signature, hardware attestation, or chain of custody.

## Markdown report

`CAPSULE.md` is a human-readable projection generated from the manifest. Use `envwitness inspect FILE.evw --format markdown` or `envwitness export FILE.evw FILE.md --format markdown` to render from a verified manifest. Treat Markdown from an untrusted capsule as untrusted text and use a viewer that disables raw HTML and remote content.

## JSON export and import

JSON export writes the complete manifest. Import validates strict schema `1.0`, every fact digest, and manifest integrity before creating a new `.evw` container. Unknown fields and modified values are rejected; import never invents replacement digests.

## Compatibility

Schema `1.x` preserves the documented `1.0` invariants. A future incompatible archive layout or integrity model requires a new major schema and migration documentation. Public Python objects and plugin messages have separate compatibility policies documented in [Architecture Decisions](decisions.md).
