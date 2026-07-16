from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from envwitness.application.ports import CaptureContext
from envwitness.domain.errors import CaptureError
from envwitness.infrastructure.collectors import (
    AsyncCommandRunner,
    EnvironmentCollector,
    FileFingerprintCollector,
    GitCollector,
    RuntimeCollector,
    SystemCollector,
)
from envwitness.infrastructure.config import RuntimeProbeConfiguration


def context(project_root: Path, **overrides: object) -> CaptureContext:
    values: dict[str, object] = {
        "project_root": project_root,
        "maximum_output_bytes": 4_096,
    }
    values.update(overrides)
    return CaptureContext(**values)  # type: ignore[arg-type]


def test_system_collector_excludes_identity(project_directory: Path) -> None:
    facts = asyncio.run(SystemCollector().collect(context(project_directory)))
    keys = {fact.key for fact in facts}
    assert "system.operating_system" in keys
    assert "system.hostname" not in keys
    assert "system.username" not in keys


def test_environment_collector_only_reads_allowlisted_value(
    project_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VISIBLE_SETTING", "diagnostic")
    monkeypatch.setenv("HIDDEN_SECRET", "must-not-appear")
    facts = asyncio.run(
        EnvironmentCollector(include_names=True).collect(
            context(project_directory, environment_value_allowlist=("VISIBLE_SETTING",))
        )
    )
    values = {fact.key: fact.value for fact in facts}
    assert values["environment.value.visible.setting"] == "diagnostic"
    assert "must-not-appear" not in str(values)


def test_file_collector_hashes_and_reads_allowlist(project_directory: Path) -> None:
    configuration_file = project_directory / "diagnostic.yml"
    configuration_file.write_text("mode: test\n", encoding="utf-8")
    facts = asyncio.run(
        FileFingerprintCollector().collect(
            context(project_directory, file_content_allowlist=("diagnostic.yml",))
        )
    )
    values = {fact.key: fact.value for fact in facts}
    assert len(str(values["file.hash.pyproject.toml"])) == 64
    assert str(values["file.content.diagnostic.yml"]).strip() == "mode: test"


def test_file_collector_rejects_binary_allowlist(project_directory: Path) -> None:
    binary_file = project_directory / "binary.dat"
    binary_file.write_bytes(b"before\x00after")
    with pytest.raises(CaptureError, match="binary"):
        asyncio.run(
            FileFingerprintCollector().collect(
                context(project_directory, file_content_allowlist=("binary.dat",))
            )
        )


def test_file_collector_rejects_path_identity_change(
    project_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed_file = project_directory / "diagnostic.yml"
    replacement_file = project_directory / "replacement.yml"
    allowed_file.write_text("mode: original\n", encoding="utf-8")
    replacement_file.write_text("mode: replacement\n", encoding="utf-8")
    original_resolve = Path.resolve

    def resolve_with_changed_identity(path: Path, strict: bool = False) -> Path:
        if path == allowed_file:
            return original_resolve(replacement_file, strict=strict)
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve_with_changed_identity)
    with pytest.raises(CaptureError, match="changed while"):
        asyncio.run(
            FileFingerprintCollector().collect(
                context(project_directory, file_content_allowlist=("diagnostic.yml",))
            )
        )


def test_runtime_collector_reports_available_and_missing(project_directory: Path) -> None:
    probes = (
        RuntimeProbeConfiguration(name="python", command=(sys.executable, "--version")),
        RuntimeProbeConfiguration(name="missing", command=("envwitness-no-such-runtime",)),
    )
    facts = asyncio.run(RuntimeCollector(probes).collect(context(project_directory)))
    values = {fact.key: fact.value for fact in facts}
    assert values["runtime.python.available"] is True
    assert str(values["runtime.python.version"]).startswith("Python")
    assert values["runtime.missing.available"] is False


def test_command_runner_success_and_truncation(project_directory: Path) -> None:
    runner = AsyncCommandRunner()
    result = asyncio.run(
        runner.run(
            (
                sys.executable,
                "-c",
                "import sys; print('x' * 10000); print('error', file=sys.stderr)",
            ),
            project_directory,
            5,
            4_096,
        )
    )
    assert result.execution.exit_code == 0
    assert result.execution.output_truncated is True
    assert len(result.standard_output.encode()) == 4_096
    assert "error" in result.standard_error


def test_command_runner_timeout(project_directory: Path) -> None:
    result = asyncio.run(
        AsyncCommandRunner().run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            project_directory,
            1,
            4_096,
        )
    )
    assert result.execution.timed_out is True
    assert result.execution.exit_code == -1


def test_command_runner_missing_executable(project_directory: Path) -> None:
    with pytest.raises(CaptureError, match="Cannot start"):
        asyncio.run(
            AsyncCommandRunner().run(
                ("envwitness-no-such-command",),
                project_directory,
                1,
                4_096,
            )
        )


def test_git_collector_reports_unavailable(
    project_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_executable(*_args: object, **_kwargs: object) -> str:
        raise FileNotFoundError

    monkeypatch.setattr(
        "envwitness.infrastructure.collectors.resolve_executable",
        unavailable_executable,
    )
    facts = asyncio.run(GitCollector().collect(context(project_directory)))
    values = {fact.key: fact.value for fact in facts}
    assert values == {"git.available": False}


@pytest.mark.skipif(shutil.which("git") is None, reason="Git executable is unavailable")
def test_git_collector_reads_repository_state(project_directory: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=project_directory, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.test"], cwd=project_directory, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=project_directory, check=True)
    subprocess.run(["git", "add", "pyproject.toml"], cwd=project_directory, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=project_directory, check=True)
    facts = asyncio.run(GitCollector().collect(context(project_directory)))
    values = {fact.key: fact.value for fact in facts}
    assert values["git.repository"] is True
    assert values["git.dirty"] is False
    assert len(str(values["git.commit"])) == 40
