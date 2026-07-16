# Plugin Authoring

EnvWitness plugins are standalone executables that exchange one JSON request and one JSON response. They can be written in any language, do not import EnvWitness internals, and are enabled explicitly in YAML.

## Contract

EnvWitness starts the configured argument vector with the project root as the working directory. Standard input receives:

```json
{
  "protocol_version": "1.0",
  "project_root": "/absolute/project/path",
  "maximum_output_bytes": 1048576,
  "metadata": {}
}
```

The plugin must write exactly one UTF-8 JSON document to standard output:

```json
{
  "protocol_version": "1.0",
  "facts": [
    {
      "key": "plugin.container-runtime.version",
      "value": "27.5.1",
      "source": "container runtime version command",
      "sensitivity": "public"
    }
  ]
}
```

Response fields are strict; unknown fields are rejected. At most 500 facts are accepted. Every key must begin with `plugin.<configured-name>.`, be unique within the response, and match `[a-z0-9][a-z0-9_.-]*`.

## Sensitivity

Use the narrowest honest classification:

| Value | Meaning |
| --- | --- |
| `public` | Safe product or runtime metadata. |
| `internal` | Operational context that should stay inside an organization. |
| `sensitive` | Data requiring explicit review before sharing. |
| `secret` | Must never persist; replaced completely by the global redactor. |

All string values pass through built-in and custom redaction after the plugin exits.

## Failure behavior

- Write diagnostics to standard error and return a nonzero exit code.
- Return no partial JSON on failure.
- Finish within the configured timeout.
- Keep output below `maximum_output_bytes` from the plugin configuration.
- Never prompt for input or start a background process.

## Configuration

```yaml
plugins:
  - name: runtime-inventory
    command: [python, examples/plugins/runtime_inventory.py]
    enabled: true
    timeout_seconds: 10
    maximum_output_bytes: 65536
```

Run a complete protocol sample with:

```console
envwitness plugins example --name runtime-inventory
```

The working Python implementation is [`examples/plugins/runtime_inventory.py`](../examples/plugins/runtime_inventory.py), and [`examples/configs/plugin.yml`](../examples/configs/plugin.yml) enables it.

## Compatibility

Protocol `1.0` is stable for the EnvWitness 1.x series. Additive core fields will not be sent to a 1.0 plugin because strict consumers may reject them. A future incompatible envelope will use a new protocol version.

## Security checklist

- Treat `project_root` as untrusted input and resolve child paths beneath it.
- Use direct process argument vectors, not concatenated shell commands.
- Bound every file, process, and network operation.
- Avoid network access unless the plugin's purpose and documentation require it.
- Never return credentials, complete environment dumps, source file contents, or user identity by default.
- Document provenance precisely enough for a reviewer to reproduce the fact.
