[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironment = Join-Path $RepositoryRoot ".venv"

if (-not (Test-Path -LiteralPath (Join-Path $VirtualEnvironment "Scripts\python.exe"))) {
    & $Python -m venv $VirtualEnvironment
}

$VirtualPython = Join-Path $VirtualEnvironment "Scripts\python.exe"
& $VirtualPython -m pip install --upgrade pip
& $VirtualPython -m pip install -e "$RepositoryRoot[development]"
Write-Output "Development environment ready: $VirtualEnvironment"
