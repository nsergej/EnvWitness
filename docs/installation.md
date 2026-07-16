# Installation

EnvWitness 1.0 is distributed through GitHub Releases and source tags. There is no EnvWitness 1.0 package on PyPI.

## Install the release wheel

With `pipx`:

```bash
pipx install https://github.com/nsergej/EnvWitness/releases/download/v1.0.0/envwitness-1.0.0-py3-none-any.whl
envwitness version
```

With `uv`:

```bash
uv tool install https://github.com/nsergej/EnvWitness/releases/download/v1.0.0/envwitness-1.0.0-py3-none-any.whl
envwitness version
```

The URL becomes available when the corresponding GitHub Release is published. For development before that release, use a local checkout.

## Verify a downloaded artifact

Download the wheel and `SHA256SUMS` from the same GitHub Release. On PowerShell:

```powershell
$expected = (Select-String -Path .\SHA256SUMS -Pattern "envwitness-1.0.0-py3-none-any.whl").Line.Split()[0]
$actual = (Get-FileHash .\envwitness-1.0.0-py3-none-any.whl -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "EnvWitness wheel checksum mismatch" }
```

On Linux:

```bash
grep ' envwitness-1.0.0-py3-none-any.whl$' SHA256SUMS | sha256sum --check -
```

On macOS:

```bash
grep ' envwitness-1.0.0-py3-none-any.whl$' SHA256SUMS | shasum --algorithm 256 --check -
```

GitHub records build provenance for the release distributions. With an authenticated GitHub CLI:

```bash
gh attestation verify envwitness-1.0.0-py3-none-any.whl --repo nsergej/EnvWitness
```

Checksums detect accidental download corruption. GitHub attestations associate an artifact with the repository workflow identity. Neither mechanism makes an unreviewed capsule trustworthy.

## Install an exact Git tag

```bash
pipx install "git+https://github.com/nsergej/EnvWitness.git@v1.0.0"
```

For a stronger reproducibility policy, install the verified release wheel by its checksum instead of resolving a tag at installation time.

## Install from a local checkout

```bash
git clone https://github.com/nsergej/EnvWitness.git
cd EnvWitness
python -m venv .venv
python -m pip install -e .
```

Activate `.venv` or invoke its `envwitness` executable directly. Contributors should install `.[development]` and follow [BUILDING.md](../BUILDING.md).

## Upgrade and uninstall

Install a reviewed newer release wheel URL with `pipx install --force URL`, or uninstall with:

```bash
pipx uninstall envwitness
```

The package-index updater exposed by the 1.0 CLI is retained for configuration compatibility but cannot discover EnvWitness until an official PyPI package exists. Automatic checks and installs are disabled by default.
