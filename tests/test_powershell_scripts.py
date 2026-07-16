from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="PowerShell scripts target Windows")


def write_failing_command(path: Path, call_log: Path) -> None:
    """Create a deterministic command that records one invocation and fails."""
    path.write_text(
        f'@echo off\necho %*>>"{call_log}"\nexit /b 23\n',
        encoding="utf-8",
    )


def run_powershell(
    script: Path, python_command: Path, working_directory: Path
) -> subprocess.CompletedProcess[str]:
    """Run one PowerShell script with an intentionally failing Python command."""
    executable = shutil.which("powershell.exe")
    if executable is None:
        pytest.skip("Windows PowerShell is unavailable")
    return subprocess.run(  # noqa: S603
        (
            executable,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Python",
            str(python_command),
        ),
        cwd=working_directory,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_verify_script_stops_after_first_failed_command(tmp_path: Path) -> None:
    """Require the verification gate to propagate its first native failure."""
    repository_root = Path(__file__).resolve().parents[1]
    call_log = tmp_path / "verify-calls.txt"
    failing_command = tmp_path / "failing-python.cmd"
    write_failing_command(failing_command, call_log)

    completed_process = run_powershell(
        repository_root / "scripts" / "verify.ps1",
        failing_command,
        repository_root,
    )

    assert completed_process.returncode != 0
    calls = call_log.read_text(encoding="utf-8").splitlines()
    assert calls == ["-m ruff format --check src tests examples scripts"]
    assert "Ruff format check failed with exit code 23" in completed_process.stderr


def test_bootstrap_script_stops_when_venv_creation_fails(tmp_path: Path) -> None:
    """Require bootstrap to avoid reporting success after Python fails."""
    temporary_scripts = tmp_path / "scripts"
    temporary_scripts.mkdir()
    source_script = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap.ps1"
    bootstrap_script = temporary_scripts / "bootstrap.ps1"
    bootstrap_script.write_text(source_script.read_text(encoding="utf-8"), encoding="utf-8")
    call_log = tmp_path / "bootstrap-calls.txt"
    failing_command = tmp_path / "failing-python.cmd"
    write_failing_command(failing_command, call_log)

    completed_process = run_powershell(bootstrap_script, failing_command, tmp_path)

    assert completed_process.returncode != 0
    calls = call_log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 1
    assert calls[0].startswith("-m venv ")
    assert "Virtual environment creation failed with exit code 23" in completed_process.stderr
    assert "Development environment ready" not in completed_process.stdout
