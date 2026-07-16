# Troubleshooting

## Capture cannot find the project root

Pass an existing directory with `--project-root`. EnvWitness resolves it before collectors start.

## A runtime probe is missing

Use argument-vector YAML syntax and ensure the executable is on `PATH`:

```yaml
runtime_probes:
  - name: node
    command: [node, --version]
```

## Mutation API returns 503

Set the configured token environment variable before starting `envwitness serve`, then restart the service.

## Capsule verification fails

Do not import and reseal modified JSON. Capture again from the source environment or retrieve the original archive. Integrity failures are intentional.

## A plugin fails

Confirm `enabled: true`, run its configured command directly with a protocol request, and check timeout and output limits. `envwitness plugins example --name NAME` prints a complete exchange.

## A value was redacted unexpectedly

Inspect `redaction.rules_triggered` in JSON output. Narrow the relevant custom expression, capture again, and review the new capsule. Built-in secret rules cannot be disabled.
