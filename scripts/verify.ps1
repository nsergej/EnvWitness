[CmdletBinding()]
param(
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $Python) {
    $VirtualPython = Join-Path $RepositoryRoot ".venv\Scripts\python.exe"
    $Python = if (Test-Path -LiteralPath $VirtualPython) { $VirtualPython } else { "python" }
}

Push-Location $RepositoryRoot
try {
    & $Python -m ruff format --check src tests examples scripts
    & $Python -m ruff check src tests examples scripts
    & $Python -m mypy src
    & $Python -m pytest
    & $Python -m bandit -c pyproject.toml -r src
    & $Python scripts/validate_repository.py
    & $Python -m build
    & $Python -m pip_audit
}
finally {
    Pop-Location
}
