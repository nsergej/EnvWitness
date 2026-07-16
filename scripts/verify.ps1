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

function Invoke-PythonStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $Python @Arguments
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        throw "$Name failed with exit code $ExitCode."
    }
}

Push-Location $RepositoryRoot
try {
    Invoke-PythonStep -Name "Ruff format check" -Arguments @("-m", "ruff", "format", "--check", "src", "tests", "examples", "scripts")
    Invoke-PythonStep -Name "Ruff lint" -Arguments @("-m", "ruff", "check", "src", "tests", "examples", "scripts")
    Invoke-PythonStep -Name "Mypy" -Arguments @("-m", "mypy", "src")
    Invoke-PythonStep -Name "Pytest" -Arguments @("-m", "pytest")
    Invoke-PythonStep -Name "Bandit" -Arguments @("-m", "bandit", "-c", "pyproject.toml", "-r", "src")
    Invoke-PythonStep -Name "Repository validation" -Arguments @("scripts/validate_repository.py")
    Invoke-PythonStep -Name "Package build" -Arguments @("-m", "build")
    Invoke-PythonStep -Name "Dependency audit" -Arguments @("-m", "pip_audit")
}
finally {
    Pop-Location
}
