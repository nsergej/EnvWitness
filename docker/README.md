# Docker

Build the CLI image:

```console
docker build -f docker/Dockerfile -t envwitness:1.0.0 .
```

Run a one-shot capture with the current project mounted at `/workspace`:

```console
docker run --rm --read-only --tmpfs /tmp \
  --user 10001:10001 \
  -v "$PWD:/workspace" \
  envwitness:1.0.0 capture --project-root /workspace --output /workspace/capture.evw
```

Run the dashboard:

```console
export ENVWITNESS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose -f docker/compose.yml up --build
```

Set `ENVWITNESS_PROJECT_PATH` when the inspected project is not the repository root. Bind-mounted project permissions must allow UID `10001` to create `.envwitness/capsules`; use a pre-created writable directory on restrictive Linux hosts.
