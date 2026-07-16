# REST API Reference

Start the local service with `envwitness serve --config envwitness.yml`. OpenAPI is available at `/api/openapi.json` and interactive documentation at `/api/docs`.

The API binds only to a loopback address. JSON request models reject unknown properties. Host validation accepts only the configured loopback host and local loopback aliases; a rejected `Host` header returns `400`.

## Authentication

`POST /api/v1/capture` requires:

```http
Authorization: Bearer <value of ENVWITNESS_API_TOKEN>
```

The environment variable name is configurable. A missing server-side token returns `503`; a missing or incorrect bearer token returns `401`.

The read and comparison endpoints intentionally do not require a token because the server is local-only. Anyone able to access the listening process can read capsule metadata and manifests. Do not expose the service through a reverse proxy, tunnel, port forward, or container port mapping.

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

## Limits and validation

| Input | Boundary |
| --- | --- |
| Capture command | At most 256 direct arguments; no shell interpretation. |
| Output name | 1 to 120 characters, safe `.evw` basename only. |
| Capsule names | Letters, digits, dot, underscore, and hyphen; `.evw` suffix required. |
| Storage | Fixed project-relative directory; traversal and absolute paths are rejected. |
| Archive reads | 25 MiB compressed and 50 MiB expanded, with known members only. |
| Request models | Unknown JSON properties are rejected. |

## Error responses

FastAPI validation failures return `422` with structured validation details. Authentication failures return `401` and `WWW-Authenticate: Bearer`; an unset mutation token returns `503`; a missing or invalid stored capsule returns `404`; unsafe capsule basenames return `400`. Internal exception details and absolute storage paths are not part of the API contract.

## OpenAPI integration

Retrieve the machine-readable schema from:

```bash
curl --fail http://127.0.0.1:8765/api/openapi.json --output envwitness-openapi.json
```

Clients should treat additional response fields in minor versions as compatible and must not send unknown request fields. The stable Python API is documented separately in [Python API](python-api.md).
