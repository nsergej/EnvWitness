from __future__ import annotations

import sys
from pathlib import Path

from typer.testing import CliRunner

from envwitness.infrastructure.archive import ZipCapsuleRepository
from envwitness.infrastructure.telemetry import ConsentStore
from envwitness.infrastructure.updater import UpdateStatus
from envwitness.presentation.cli import _default_capsule_path, _format_url_host, app

RUNNER = CliRunner()


def test_version_command() -> None:
    result = RUNNER.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "EnvWitness 1.0.1" in result.stdout


def test_capture_help_documents_trailing_command() -> None:
    result = RUNNER.invoke(app, ["capture", "--help"])
    assert result.exit_code == 0
    assert "COMMAND" in result.stdout
    assert "after --" in result.stdout


def test_ipv6_dashboard_host_is_bracketed() -> None:
    assert _format_url_host("::1") == "[::1]"


def test_default_capsule_path_cannot_escape_through_project_name() -> None:
    assert _default_capsule_path("../../customer project") == Path("customer-project.evw")


def test_cli_capture_verify_export_and_import(project_directory: Path, tmp_path: Path) -> None:
    configuration_path = tmp_path / "envwitness.yml"
    initialize = RUNNER.invoke(app, ["init", "--output", str(configuration_path)])
    assert initialize.exit_code == 0

    capsule_path = tmp_path / "cli.evw"
    capture = RUNNER.invoke(
        app,
        [
            "capture",
            "--config",
            str(configuration_path),
            "--project-root",
            str(project_directory),
            "--output",
            str(capsule_path),
            "--",
            sys.executable,
            "-c",
            "print('captured command')",
        ],
    )
    assert capture.exit_code == 0
    assert capsule_path.exists()
    assert ZipCapsuleRepository().read(capsule_path).command.exit_code == 0

    verify = RUNNER.invoke(app, ["verify", str(capsule_path)])
    assert verify.exit_code == 0
    assert "Verified" in verify.stdout

    json_path = tmp_path / "cli.json"
    export = RUNNER.invoke(
        app,
        ["export", str(capsule_path), str(json_path), "--format", "json"],
    )
    assert export.exit_code == 0
    imported_path = tmp_path / "imported.evw"
    import_result = RUNNER.invoke(
        app,
        ["import", str(json_path), str(imported_path)],
    )
    assert import_result.exit_code == 0
    assert imported_path.exists()


def test_cli_rejects_invalid_format(sample_capsule, tmp_path: Path) -> None:
    capsule_path = ZipCapsuleRepository().write(sample_capsule, tmp_path / "sample.evw")
    result = RUNNER.invoke(app, ["inspect", str(capsule_path), "--format", "xml"])
    assert result.exit_code == 1
    assert "Format must be" in result.stderr


def test_cli_inspect_compare_and_plugin_example(sample_capsule, tmp_path: Path) -> None:
    baseline = ZipCapsuleRepository().write(sample_capsule, tmp_path / "baseline.evw")
    candidate = ZipCapsuleRepository().write(sample_capsule, tmp_path / "candidate.evw")

    inspect_json = RUNNER.invoke(app, ["inspect", str(baseline), "--format", "json"])
    inspect_markdown = RUNNER.invoke(app, ["inspect", str(baseline), "--format", "markdown"])
    compare_json = RUNNER.invoke(
        app,
        ["compare", str(baseline), str(candidate), "--format", "json"],
    )
    comparison_path = tmp_path / "comparison.md"
    compare_file = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline),
            str(candidate),
            "--output",
            str(comparison_path),
        ],
    )
    plugin_example = RUNNER.invoke(app, ["plugins", "example", "--name", "sample"])

    assert inspect_json.exit_code == 0
    assert "capsule_identifier" in inspect_json.stdout
    assert inspect_markdown.exit_code == 0
    assert "# EnvWitness report" in inspect_markdown.stdout
    assert compare_json.exit_code == 0
    assert '"identical": true' in compare_json.stdout
    assert compare_file.exit_code == 0
    assert comparison_path.exists()
    assert plugin_example.exit_code == 0
    assert "plugin.sample.version" in plugin_example.stdout


def test_cli_telemetry_commands(tmp_path: Path, monkeypatch) -> None:
    consent_path = tmp_path / "consent.json"
    monkeypatch.setattr("envwitness.presentation.cli.default_consent_path", lambda: consent_path)

    initial = RUNNER.invoke(app, ["telemetry", "status"])
    enabled = RUNNER.invoke(app, ["telemetry", "enable"])
    status = RUNNER.invoke(app, ["telemetry", "status"])
    disabled = RUNNER.invoke(app, ["telemetry", "disable"])

    assert "disabled" in initial.stdout
    assert enabled.exit_code == 0
    assert "enabled" in status.stdout
    assert disabled.exit_code == 0
    assert ConsentStore(consent_path).is_enabled() is False


def test_cli_update_check(monkeypatch) -> None:
    monkeypatch.setattr(
        "envwitness.infrastructure.updater.PyPiUpdater.check",
        lambda self: UpdateStatus("1.0.0", "1.1.0", True),
    )
    result = RUNNER.invoke(app, ["update", "check"])
    assert result.exit_code == 0
    assert "1.1.0" in result.stdout
