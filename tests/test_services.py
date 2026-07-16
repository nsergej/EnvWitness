from __future__ import annotations

import asyncio
import sys
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from envwitness.application.ports import CaptureContext, CollectedFact, CommandResult
from envwitness.application.services import CaptureRequest, CaptureService, default_project_label
from envwitness.domain.errors import CaptureError
from envwitness.domain.models import Sensitivity, utc_now
from envwitness.infrastructure.archive import ZipCapsuleRepository
from envwitness.infrastructure.collectors import AsyncCommandRunner
from envwitness.infrastructure.redaction import DeterministicRedactor


class StaticCollector:
    def __init__(self, key: str, value: object = "value") -> None:
        self._key = key
        self._value = value

    @property
    def name(self) -> str:
        return "static"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        return [
            CollectedFact(
                key=self._key,
                value=self._value,
                collector=self.name,
                source=context.project_root.name,
                sensitivity=Sensitivity.PUBLIC,
                captured_at=utc_now(),
            )
        ]


class BlockingCommandRunner:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def run(
        self,
        arguments: tuple[str, ...],
        working_directory: Path,
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> CommandResult:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")


class FailingCollector:
    def __init__(self, command_runner: BlockingCommandRunner) -> None:
        self._command_runner = command_runner

    @property
    def name(self) -> str:
        return "failing"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        await self._command_runner.started.wait()
        raise RuntimeError("collector failed")


def service(*collectors: StaticCollector) -> CaptureService:
    return CaptureService(
        collectors=collectors,
        redactor=DeterministicRedactor(),
        command_runner=AsyncCommandRunner(),
        repository=ZipCapsuleRepository(),
        tool_version="1.0.0",
    )


def test_capture_service_end_to_end(project_directory: Path, tmp_path: Path) -> None:
    github_token_canary = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "captured.evw",
        project_name="fixture",
        command=(sys.executable, "-c", f"print({github_token_canary!r})"),
        maximum_output_bytes=4_096,
    )
    capsule, destination = asyncio.run(service(StaticCollector("sample.fact")).capture(request))
    assert destination.exists()
    assert capsule.verify_integrity()
    assert capsule.redaction.facts_redacted >= 1
    output = next(fact for fact in capsule.facts if fact.key == "command.standard_output")
    assert "ghp_" not in str(output.value)


def test_capture_service_rejects_duplicate_keys(project_directory: Path, tmp_path: Path) -> None:
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "duplicate.evw",
        project_name="fixture",
        maximum_output_bytes=4_096,
    )
    with pytest.raises(CaptureError, match="duplicate"):
        asyncio.run(
            service(StaticCollector("same.key"), StaticCollector("same.key")).capture(request)
        )


def test_capture_request_rejects_invalid_limits(project_directory: Path, tmp_path: Path) -> None:
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "invalid.evw",
        project_name="fixture",
        maximum_output_bytes=10,
    )
    with pytest.raises(CaptureError, match="Maximum output"):
        request.validate()


def test_capture_request_rejects_other_invalid_inputs(
    project_directory: Path,
    tmp_path: Path,
) -> None:
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "invalid.evw",
        project_name="fixture",
        maximum_output_bytes=4_096,
    )

    with pytest.raises(CaptureError, match="Project root"):
        replace(request, project_root=tmp_path / "missing").validate()
    with pytest.raises(CaptureError, match="Project name"):
        replace(request, project_name=" ").validate()
    with pytest.raises(CaptureError, match="Command timeout"):
        replace(request, command_timeout_seconds=0).validate()
    with pytest.raises(CaptureError, match="more than 256"):
        replace(request, command=("argument",) * 257).validate()
    with pytest.raises(CaptureError, match="null bytes"):
        replace(request, command=("argument\x00value",)).validate()


def test_default_project_label_hides_home_directory_name() -> None:
    assert default_project_label(Path.home()) == "home-directory"


def test_capture_service_cancels_command_when_collection_fails(
    project_directory: Path,
    tmp_path: Path,
) -> None:
    command_runner = BlockingCommandRunner()
    capture_service = CaptureService(
        collectors=(FailingCollector(command_runner),),
        redactor=DeterministicRedactor(),
        command_runner=command_runner,
        repository=ZipCapsuleRepository(),
        tool_version="1.0.0",
    )
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "failed.evw",
        project_name="fixture",
        command=(sys.executable, "-c", "print('never finishes')"),
        maximum_output_bytes=4_096,
    )

    with pytest.raises(CaptureError, match="Evidence collection failed"):
        asyncio.run(capture_service.capture(request))

    assert command_runner.cancelled is True
    assert not (tmp_path / "failed.evw").exists()


def test_capture_service_redacts_persisted_command_arguments(
    project_directory: Path,
    tmp_path: Path,
) -> None:
    option_secret = "plain-option-secret-canary"
    query_secret = "plain-query-secret-canary"
    command = (
        sys.executable,
        "-c",
        "print('ok')",
        "--token",
        option_secret,
        f"https://user:password@example.test/path?api_key={query_secret}&mode=check",
    )
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "arguments.evw",
        project_name="fixture",
        command=command,
        maximum_output_bytes=4_096,
    )

    capsule, destination = asyncio.run(service(StaticCollector("sample.fact")).capture(request))

    assert capsule.command is not None
    persisted = capsule.model_dump_json()
    assert option_secret not in persisted
    assert query_secret not in persisted
    assert "user:password" not in persisted
    assert str(Path.home()).casefold() not in persisted.casefold()
    assert "[REDACTED:command-argument]" in capsule.command.arguments
    assert capsule.command.working_directory == project_directory.name
    with zipfile.ZipFile(destination) as archive:
        archived_content = archive.read("manifest.json") + archive.read("CAPSULE.md")
    assert option_secret.encode() not in archived_content
    assert query_secret.encode() not in archived_content


def test_capture_service_redacts_sensitive_project_metadata(
    project_directory: Path,
    tmp_path: Path,
) -> None:
    request = CaptureRequest(
        project_root=project_directory,
        destination=tmp_path / "metadata.evw",
        project_name="client_secret=synthetic-project-secret",
        maximum_output_bytes=4_096,
    )

    capsule, _ = asyncio.run(service(StaticCollector("sample.fact")).capture(request))

    serialized = capsule.model_dump_json()
    assert "synthetic-project-secret" not in serialized
    assert capsule.project_name == "client_secret=[REDACTED:sensitive-assignment]"
