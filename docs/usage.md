# Usage Guide

EnvWitness captures a bounded diagnostic snapshot, removes recognized secrets before persistence, seals the stored manifest with ordinary SHA-256 digests, and compares snapshots by semantic key.

## 1. Create and review configuration

```bash
envwitness init --output envwitness.yml
```

Review every allowlist and plugin command before capture. Environment values, file contents, plugins, telemetry, and automatic update policy are disabled unless explicitly configured.

## 2. Capture a baseline

Run this in a working checkout:

```bash
envwitness capture --config envwitness.yml --project-root . --output working.evw
```

Capture the failing command directly, without a shell:

```bash
envwitness capture --config envwitness.yml --output failing.evw -- python -m pytest tests/test_login.py
```

Everything after `--` becomes the command argument vector. Avoid placing secrets on command lines. EnvWitness applies redaction to stored arguments and command output, but process arguments may still be visible to the local operating system while the command runs.

## 3. Verify and inspect

```bash
envwitness verify failing.evw
envwitness inspect failing.evw --format summary
envwitness inspect failing.evw --format markdown
envwitness export failing.evw failing.json --format json
```

Verification checks archive limits, schema, fact digests, and manifest integrity. These unkeyed digests detect changes that were not followed by resealing; they do not prove who created the capsule. Inspect all output before sharing.

## 4. Compare environments

```bash
envwitness compare working.evw failing.evw --format markdown --output difference.md
```

The first capsule is the known-working baseline. EnvWitness orders semantic differences and derives deterministic hints. Hints are diagnostic starting points, not automated root-cause proof.

## 5. Import and export

```bash
envwitness export failing.evw failing.json --format json
envwitness import failing.json restored.evw
```

Import accepts a complete, already sealed schema `1.0` manifest. Editing exported JSON invalidates its digest; import does not silently reseal modified evidence.

## Local dashboard and API

Set a high-entropy token before starting the service:

```powershell
$env:ENVWITNESS_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
envwitness serve --config envwitness.yml --project-root .
```

Open `http://127.0.0.1:8765`. The service is loopback-only. Do not expose it through a reverse proxy, SSH forwarding, Docker port publishing, or a public tunnel. Read endpoints intentionally have no bearer-token requirement; capture requires the configured token.

## Docker capture

```bash
docker compose -f docker/compose.yml run --build --rm envwitness
```

This creates `envwitness-capture.evw` in the mounted project. The container is a one-shot CLI environment, not a dashboard host. See [Docker](../docker/README.md).

## Exit codes and logs

Successful commands return `0`; validated runtime and integrity failures return `1`; invalid CLI syntax returns `2`. Use `--verbose` for diagnostic standard-error logging or `--json-logs` for one JSON object per line. Logs can contain paths and operational metadata, so review them before attaching them to a public issue.
