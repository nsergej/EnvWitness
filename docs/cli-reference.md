# CLI Reference

All commands support `--help`. Global `--verbose` enables diagnostic logs and `--json-logs` emits one structured JSON object per standard-error line.

| Command | Purpose |
| --- | --- |
| `envwitness version` | Print the installed version. |
| `envwitness init` | Atomically create a strict YAML configuration. |
| `envwitness capture` | Collect, redact, seal, and write a capsule. |
| `envwitness verify` | Validate archive safety, schema, fact digests, and manifest integrity. |
| `envwitness inspect` | Render a verified capsule as a table, JSON, or Markdown. |
| `envwitness compare` | Compare a working baseline with a candidate capsule. |
| `envwitness export` | Export verified JSON or readable Markdown. |
| `envwitness import` | Validate exported JSON and rebuild a capsule. |
| `envwitness serve` | Run the loopback REST API and dashboard. |
| `envwitness telemetry` | Enable, disable, or inspect explicit consent. |
| `envwitness plugins example` | Print protocol 1.0 request and response samples. |
| `envwitness update` | Check or install a stable PyPI release. |

## Capture

```console
envwitness capture [--config PATH] [--project-root PATH] [--output PATH] [-- COMMAND...]
```

Everything after `--` is passed as a direct argument vector. Command standard output, standard error, exit status, timing, and truncation metadata become redacted evidence.

## Inspect and verify

```console
envwitness verify capture.evw
envwitness inspect capture.evw --format summary
envwitness inspect capture.evw --format json
envwitness inspect capture.evw --format markdown
```

## Compare

```console
envwitness compare working.evw failing.evw --format markdown
envwitness compare working.evw failing.evw --format json --output report.json
```

The first capsule is always the known-working baseline. Differences and diagnostic hints are deterministic for the same two manifests.

## Import and export

```console
envwitness export capture.evw capture.json --format json
envwitness export capture.evw capture.md --format markdown
envwitness import capture.json restored.evw
```

JSON import verifies all existing digests; it does not reseal modified data.

## Service

```console
envwitness serve --config envwitness.yml --project-root .
```

The service remains attached to the terminal and uses the configured loopback host and port.

## Updates

```console
envwitness update check --config envwitness.yml
envwitness update install --version 1.0.1 --config envwitness.yml
```

The explicit install command accepts only a normalized stable version. Automatic policy is documented in [Configuration Reference](configuration.md#updates).

## Exit behavior

Successful commands return `0`. Runtime, configuration, integrity, import, plugin, and update failures return `1` with a safe message. Invalid command syntax uses Typer's standard exit code `2`.
