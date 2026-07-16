# REST API Reference

Start the local service with `envwitness serve --config envwitness.yml`. OpenAPI is available at `/api/openapi.json` and interactive documentation at `/api/docs`.

The API binds only to a loopback address. JSON request models reject unknown properties.

## Authentication

`POST /api/v1/capture` requires:

```http
Authorization: Bearer <value of ENVWITNESS_API_TOKEN>
```

The environment variable name is configurable. A missing server-side token returns `503`; a missing or incorrect bearer token returns `401`.

## Operations

### `GET /healthz`

Returns `200` without touching storage.

```json
{"status":"ok"}
```

### `GET /api/v1/capsules`

Lists archives that pass schema and integrity verification. Invalid files are omitted.

```json
{
  "capsules": [
    {
      "name": "working.evw",
      "capsule_identifier": "ew-0123456789abcdef01234567",
      "project_name": "payments-api",
      "created_at": "2026-07-16T12:00:00Z",
      "fact_count": 24,
      "redacted_fact_count": 1,
      "command_exit_code": 0
    }
  ]
}
```

### `GET /api/v1/capsules/{capsule_name}`

Returns the complete verified manifest. Names must end in `.evw` and contain only letters, digits, dot, underscore, and hyphen. Missing or invalid capsules return `404`.

### `POST /api/v1/capture`

Creates a capsule under the configured storage directory. Status is `201`.

```json
{
  "command": ["python", "-m", "pytest"],
  "output_name": "failure.evw"
}
```

`command` defaults to an empty array and accepts at most 256 arguments. `output_name` is 1 through 120 characters and must be a safe `.evw` basename.

Response:

```json
{
  "name": "failure.evw",
  "capsule_identifier": "ew-0123456789abcdef01234567",
  "fact_count": 24,
  "redacted_fact_count": 1
}
```

Collection failures return `422` with a safe `detail` message.

### `POST /api/v1/compare`

Compares two verified stored capsules and does not mutate state.

```json
{
  "baseline": "working.evw",
  "candidate": "failure.evw"
}
```

The response is a `ComparisonReport`: baseline and candidate identifiers, UTC creation time, ordered `differences`, ordered `hints`, and `identical`. Missing or invalid capsules return `404`.

## Example

```bash
curl http://127.0.0.1:8765/api/v1/capsules
curl -X POST http://127.0.0.1:8765/api/v1/compare \
  -H "Content-Type: application/json" \
  -d '{"baseline":"working.evw","candidate":"failure.evw"}'
```

The bundled browser interface uses these same endpoints; there is no separate privileged backend.
