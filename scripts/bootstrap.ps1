[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironment = Join-Path $RepositoryRoot ".venv"

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    & $Executable @Arguments
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        throw "$Name failed with exit code $ExitCode."
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $VirtualEnvironment "Scripts\python.exe"))) {
    Invoke-CheckedCommand -Executable $Python -Arguments @("-m", "venv", $VirtualEnvironment) -Name "Virtual environment creation"
}

$VirtualPython = Join-Path $VirtualEnvironment "Scripts\python.exe"
Invoke-CheckedCommand -Executable $VirtualPython -Arguments @("-m", "pip", "install", "--upgrade", "pip") -Name "Pip upgrade"
Invoke-CheckedCommand -Executable $VirtualPython -Arguments @("-m", "pip", "install", "-e", "$RepositoryRoot[development]") -Name "Development dependency installation"
Write-Output "Development environment ready: $VirtualEnvironment"
