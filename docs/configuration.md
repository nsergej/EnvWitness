# Configuration Reference

EnvWitness reads a strict YAML document. Unknown keys, invalid types, absolute disclosure paths, unsafe API bindings, and untrusted update endpoints are rejected before capture starts.

Generate the complete default document with:

```console
envwitness init --output envwitness.yml
```

## Root fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `schema_version` | string | `"1.0"` | Configuration schema. Only `1.0` is accepted. |
| `project_name` | string | project directory name | Display name, at most 120 characters. |
| `capture` | mapping | documented below | Collection and command limits. |
| `redaction` | mapping | documented below | Additional global redaction rules. |
| `plugins` | sequence | `[]` | Explicitly configured process plugins. |
| `api` | mapping | documented below | Loopback service settings. |
| `telemetry` | mapping | disabled | Aggregate telemetry policy. |
| `updates` | mapping | disabled | Manual and automatic package update policy. |

## `capture`

| Field | Type | Default | Constraint |
| --- | --- | --- | --- |
| `command_timeout_seconds` | integer | `300` | 1 through 86,400. |
| `maximum_output_bytes` | integer | `1048576` | 4 KiB through 16 MiB, per captured stream. |
| `include_environment_names` | boolean | `true` | Includes names only; values remain excluded. |
| `environment_value_allowlist` | string sequence | `[]` | Exact variable names; wildcards are not expanded. |
| `file_content_allowlist` | string sequence | `[]` | Relative project paths without parent traversal. |
| `runtime_probes` | sequence | Python and Git | Argument-vector commands with a 1 through 30 second timeout. |

Runtime probe example:

```yaml
runtime_probes:
  - name: node
    command: [node, --version]
    timeout_seconds: 5
```

Commands are executed directly without a shell. A missing probe executable becomes evidence; it does not abort the whole capture.

## `redaction`

`custom_rules` is a sequence of named regular expressions. Each expression is compiled while loading configuration and runs after all built-in and plugin collectors complete.

```yaml
redaction:
  custom_rules:
    - name: internal-incident
      pattern: "INC-[0-9]{8}"
```

Names must use lowercase letters, digits, and hyphens. Patterns are limited to 256 characters. Review expressions for pathological backtracking before deployment.

## `plugins`

| Field | Type | Default | Constraint |
| --- | --- | --- | --- |
| `name` | string | required | Unique lowercase namespace. |
| `command` | string sequence | required | Direct process argument vector, at most 32 items. |
| `enabled` | boolean | `false` | Must be true before the process can run. |
| `timeout_seconds` | integer | `10` | 1 through 120. |
| `maximum_output_bytes` | integer | `262144` | 1 KiB through 4 MiB. |

Plugins are trusted local executables, not a sandbox. See [Plugin Authoring](plugin-authoring.md).

## `api`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `127.0.0.1` | Only `127.0.0.1`, `localhost`, or `::1`. |
| `port` | integer | `8765` | 1,024 through 65,535. |
| `token_environment_variable` | string | `ENVWITNESS_API_TOKEN` | Environment variable holding the mutation bearer token. |
| `storage_directory` | string | `.envwitness/capsules` | Project-relative capsule store. |

The bearer token is read once when the service starts. Restart the service after rotating it.

## `telemetry`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Project-side telemetry switch. |
| `endpoint` | string | empty | HTTPS event collector endpoint. |

Delivery additionally requires `envwitness telemetry enable`. Either switch being off makes the client inert.

## `updates`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `automatic_check` | boolean | `false` | Check the fixed package-index endpoint when `capture` or `serve` starts and the interval is due. |
| `automatic_install` | boolean | `false` | Install the exact discovered stable version. Requires automatic checks. |
| `metadata_url` | string | canonical PyPI URL | Fixed to `https://pypi.org/pypi/envwitness/json`. |
| `check_interval_hours` | integer | `24` | 1 through 720. |

The last successful automatic check is stored at `~/.config/envwitness/updates.json`. Update failures are logged and never block capture or service startup. EnvWitness 1.0 is distributed only through GitHub Releases, so this updater cannot discover 1.0 and should remain disabled. The fields are retained for configuration compatibility with a possible future package-index release.

## Complete example

See [`examples/configs/minimal.yml`](../examples/configs/minimal.yml) and [`examples/configs/plugin.yml`](../examples/configs/plugin.yml). Both are loaded by automated tests to prevent documentation drift.
