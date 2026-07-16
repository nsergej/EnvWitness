from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from envwitness.application.ports import CaptureContext, CollectedFact
from envwitness.application.services import CaptureRequest, CaptureService
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
    assert capsule.redaction.facts_redacted == 1
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
