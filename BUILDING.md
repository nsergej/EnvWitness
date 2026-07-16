# Building EnvWitness

This guide covers a clean development environment, the complete quality gate, package creation, wheel installation, and the container build. EnvWitness supports CPython 3.11, 3.12, and 3.13.

## Prerequisites

- CPython 3.11, 3.12, or 3.13
- Git
- Docker Engine with Docker Compose v2 for container verification
- PowerShell 7 or Windows PowerShell on Windows

## Development environment

```bash
git clone https://github.com/nsergej/EnvWitness.git
cd EnvWitness
python -m venv .venv
```

Activate the environment on PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[development]"
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[development]"
```

## Complete quality gate

PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Linux or macOS:

```bash
./scripts/verify.sh
```

The gate checks formatting, lint rules, strict typing, tests and branch coverage, Bandit findings, repository structure, examples, dependency vulnerabilities, and wheel/source-distribution builds. A failure in any command stops the script.

## Build and install the wheel

```bash
python -m build
python -m venv .wheel-smoke
```

PowerShell:

```powershell
.\.wheel-smoke\Scripts\python.exe -m pip install (Get-ChildItem .\dist\*.whl | Select-Object -First 1).FullName
.\.wheel-smoke\Scripts\envwitness.exe version
```

Linux or macOS:

```bash
.wheel-smoke/bin/python -m pip install dist/*.whl
.wheel-smoke/bin/envwitness version
```

## Container build

```bash
docker build -f docker/Dockerfile -t envwitness:local .
docker run --rm envwitness:local --help
```

The runtime image uses a non-root UID/GID of `10001` and includes Git for the default probes. The supplied Compose service drops all Linux capabilities and enables `no-new-privileges`. See [docker/README.md](docker/README.md) for the one-shot capture command and bind-mount permissions.

## Release artifacts

Pushing a version tag matching `v<package-version>` starts `.github/workflows/release.yml`. The workflow repeats the quality and security checks, builds a wheel and source distribution, installs the wheel in a clean virtual environment, generates an SPDX JSON SBOM and SHA-256 checksums, records GitHub build provenance attestations, and creates a GitHub Release from `release/<tag>.md`.

The workflow does not publish to PyPI and does not claim that the Git tag is cryptographically signed. A maintainer must review the tag, release notes, and successful CI result before pushing the tag.
