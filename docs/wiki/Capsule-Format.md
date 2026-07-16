# Capsule Format

An `.evw` file is a constrained ZIP archive with exactly two members:

- `manifest.json`: strict schema `1.0`, fact digests, and manifest integrity.
- `CAPSULE.md`: a human-readable review document generated from the same capsule.

Readers validate archive size, expanded size, paths, duplicate names, encryption, known members, JSON schema, every fact digest, and manifest integrity. The digest covers post-redaction values, not discarded secret material.

Use `envwitness verify FILE.evw` before processing a capsule from another person.
