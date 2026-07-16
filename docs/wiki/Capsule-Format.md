# Capsule Format

An `.evw` file written by EnvWitness 1.0 is a constrained ZIP archive with two known members:

- `manifest.json`: strict schema `1.0`, fact digests, and manifest integrity.
- `CAPSULE.md`: a human-readable review document generated from the same capsule.

Readers validate archive size, expanded size, paths, duplicate names, encryption, known members, JSON schema, every fact digest, and manifest integrity. The digest covers post-redaction values, not discarded secret material. It detects changes not followed by resealing; it is not a signature or proof of origin.

Use `envwitness verify FILE.evw` before processing a capsule from another person.

The complete field and compatibility reference is in [Capsule and Report Format](../report-format.md).
