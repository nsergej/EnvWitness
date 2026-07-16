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

The image uses a digest-pinned official Python base, runs as UID and GID `10001`, has no Linux capabilities under the supplied Compose policy, and contains Git so the default Git and runtime probes work. Dependabot proposes base-image digest updates. The mounted directory must permit UID `10001` to create the output file.

Run the same one-shot workflow with Docker Compose:

```console
docker compose -f docker/compose.yml run --build --rm envwitness
```

The default output is `envwitness-capture.evw`. Set `ENVWITNESS_OUTPUT` to another safe basename and `ENVWITNESS_PROJECT_PATH` when the inspected project is not the repository root:

```console
ENVWITNESS_PROJECT_PATH=/path/to/project ENVWITNESS_OUTPUT=incident-42.evw docker compose -f docker/compose.yml run --build --rm envwitness
```

On PowerShell:

```powershell
$env:ENVWITNESS_PROJECT_PATH = "C:\source\project"
$env:ENVWITNESS_OUTPUT = "incident-42.evw"
docker compose -f docker/compose.yml run --build --rm envwitness
```

The dashboard is intentionally not published from this container. EnvWitness only permits loopback API binding, and a process bound to container loopback is not safely reachable through Docker port publishing. Run `envwitness serve` on the host when the local dashboard is needed.
