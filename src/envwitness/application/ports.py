"""Abstract ports implemented by the EnvWitness infrastructure layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from envwitness.domain.models import (
    Capsule,
    CommandExecution,
    EvidenceFact,
    RedactionSummary,
    Sensitivity,
)


class CollectedFact(BaseModel):
    """Unsealed collector output awaiting the global redaction pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=180, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    value: JsonValue
    collector: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=500)
    sensitivity: Sensitivity
    captured_at: datetime


@dataclass(frozen=True, slots=True)
class CaptureContext:
    """Non-secret context shared with built-in and external collectors."""

    project_root: Path
    maximum_output_bytes: int
    environment_value_allowlist: tuple[str, ...] = ()
    file_content_allowlist: tuple[str, ...] = ()
    runtime_commands: tuple[tuple[str, ...], ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Raw output and validated metadata returned by a command runner."""

    execution: CommandExecution
    standard_output: str
    standard_error: str


class EvidenceCollector(Protocol):
    """Collect one coherent category of diagnostic evidence."""

    @property
    def name(self) -> str:
        """Return the stable collector identifier."""

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Collect facts without persisting or transmitting them."""


class CommandRunner(Protocol):
    """Execute an argument vector without invoking a shell."""

    async def run(
        self,
        arguments: tuple[str, ...],
        working_directory: Path,
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> CommandResult:
        """Run a command and return bounded output plus timing metadata."""


class EvidenceRedactor(Protocol):
    """Transform collected facts into disclosure-safe stored facts."""

    def redact(
        self,
        facts: list[CollectedFact],
    ) -> tuple[list[EvidenceFact], RedactionSummary]:
        """Redact every value and return an auditable summary."""


class CapsuleRepository(Protocol):
    """Persist and retrieve self-verifying evidence capsules."""

    def write(self, capsule: Capsule, destination: Path) -> Path:
        """Write a sealed capsule atomically to its destination."""

    def read(self, source: Path, *, verify: bool = True) -> Capsule:
        """Load a capsule and optionally enforce its integrity record."""


class TelemetrySink(Protocol):
    """Receive privacy-minimized events when explicit consent is enabled."""

    def record(self, event_name: str, properties: dict[str, int | str | bool]) -> None:
        """Record one aggregate event without affecting the primary operation."""
