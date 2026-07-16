# Privacy Guide

EnvWitness is privacy-first, not privacy-infallible. Treat every capsule, exported report, comparison, and verbose log as potentially sensitive until a person has reviewed it.

## Collected by default

- operating-system family and release, machine architecture, Python version, locale, and timezone;
- environment variable names, never values unless an exact value allowlist contains the name;
- Git availability, repository state, branch, commit, dirty flag, and changed-path count, without remote URLs, patch bodies, or changed path names;
- SHA-256 hashes of recognized dependency and lock files, without their content;
- configured runtime probe availability and bounded version output;
- when a command is supplied, its redacted arguments, bounded standard output and error, exit code, timing, timeout state, and truncation state.

The capsule also stores a project display name, a non-absolute root label, timestamps, tool version, collector provenance, sensitivity classes, redaction counters, and ordinary integrity digests. Capturing the home directory uses the label `home-directory`, and native or slash-normalized home path prefixes are redacted from persisted text and command metadata.

## Never enabled implicitly

- environment values;
- arbitrary file contents;
- external plugins;
- telemetry;
- automatic update checks or installation;
- capsule upload or remote sharing.

File contents and environment values require exact allowlists. Plugins require an explicit command and `enabled: true`. Plugins are trusted local executables with the current user's permissions; the JSON protocol is a data boundary, not a sandbox.

## Redaction

Built-in rules target private key blocks, authorization headers, common credential assignments, credential-bearing URLs, JWT-shaped values, recognizable provider token formats, unsafe terminal control characters, and the current home-directory path. Custom rules can add organization-specific patterns. Redaction runs before facts, project metadata, command metadata, reports, or archives are persisted.

Unknown encodings, proprietary token formats, business-sensitive identifiers, source snippets, and secrets split across fields may survive. Do not use redaction as the only disclosure control.

## Telemetry

Telemetry requires both local consent and `telemetry.enabled: true` with an HTTPS endpoint. Events are limited to allowlisted counts, operating-system family, tool version, plugin count, redacted fact count, and whether a command was captured. Capsules, command text, paths, project names, fact values, and stable installation identifiers are excluded.

Disable consent with:

```bash
envwitness telemetry disable
```

## Review checklist

1. Run `envwitness verify FILE.evw`.
2. Run `envwitness inspect FILE.evw --format markdown` and read the complete result.
3. Search exports and logs for organization names, usernames, paths, URLs, ticket identifiers, source fragments, credentials, and personal data.
4. Confirm every allowlisted environment value and file content is necessary for the recipient.
5. Share through an access-controlled channel with an explicit retention period.
6. Revoke or rotate any credential that may have been exposed; deleting a public attachment is not sufficient.

## Data location and deletion

CLI output is written only to the destination selected by the operator. The local API stores capsules under its configured project-relative storage directory, defaulting to `.envwitness/capsules`. Delete capsules and exports with normal operating-system tools after the support case ends. EnvWitness does not maintain a remote copy.
