"""Validated domain models for evidence, capsules, and comparisons."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


class Sensitivity(StrEnum):
    """Classification applied to every captured fact."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    # This is sensitivity vocabulary, never credential material.
    SECRET = "secret"  # nosec B105


class DifferenceKind(StrEnum):
    """Supported semantic difference categories."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class DifferenceSeverity(StrEnum):
    """Operator-facing importance assigned to a semantic difference."""

    INFORMATION = "information"
    WARNING = "warning"
    CRITICAL = "critical"


def canonical_json(value: Any) -> bytes:
    """Serialize a value into stable UTF-8 JSON bytes.

    Args:
        value: JSON-compatible data to serialize.

    Returns:
        Stable bytes with sorted keys and no insignificant whitespace.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def digest_value(value: Any) -> str:
    """Return a SHA-256 digest for the stored representation of a value.

    The digest intentionally covers the value after redaction. EnvWitness never
    stores a digest of discarded secret material because low-entropy secrets can
    otherwise be recovered with an offline guessing attack.

    Args:
        value: JSON-compatible value whose integrity must be protected.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(canonical_json(value)).hexdigest()


def utc_now() -> datetime:
    """Return a timezone-aware current UTC timestamp."""
    return datetime.now(UTC)


def has_unsafe_control_characters(value: str) -> bool:
    """Return whether text contains control or invisible formatting characters."""
    return any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)


def _json_default(value: Any) -> str:
    """Convert supported non-JSON values for canonical serialization."""
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return value.value
    raise TypeError(f"Unsupported canonical JSON value: {type(value).__name__}")


class EvidenceFact(BaseModel):
    """One provenance-carrying observation stored in a capsule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=180, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    value: JsonValue
    collector: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    source: str = Field(min_length=1, max_length=500)
    captured_at: datetime
    sensitivity: Sensitivity
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    redacted: bool = False
    redaction_rules: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        """Ensure the fact digest protects exactly the stored value."""
        expected_digest = digest_value(self.value)
        if self.digest != expected_digest:
            raise ValueError("Evidence fact digest does not match the stored value")
        if self.redacted and not self.redaction_rules:
            raise ValueError("A redacted fact must name at least one redaction rule")
        if not self.redacted and self.redaction_rules:
            raise ValueError("An unredacted fact cannot list redaction rules")
        return self

    @classmethod
    def create(
        cls,
        *,
        key: str,
        value: JsonValue,
        collector: str,
        source: str,
        sensitivity: Sensitivity,
        captured_at: datetime | None = None,
        redacted: bool = False,
        redaction_rules: tuple[str, ...] = (),
    ) -> EvidenceFact:
        """Create a fact and calculate the digest of its stored value.

        Args:
            key: Stable semantic key used when comparing capsules.
            value: JSON-compatible value after any required redaction.
            collector: Identifier of the collector that produced the fact.
            source: Human-readable provenance such as a command or file path.
            sensitivity: Disclosure classification of the stored value.
            captured_at: Optional explicit capture time, primarily for imports.
            redacted: Whether content was replaced by a redaction rule.
            redaction_rules: Names of rules that modified the value.

        Returns:
            Fully validated evidence fact.
        """
        return cls(
            key=key,
            value=value,
            collector=collector,
            source=source,
            captured_at=captured_at or utc_now(),
            sensitivity=sensitivity,
            digest=digest_value(value),
            redacted=redacted,
            redaction_rules=redaction_rules,
        )


class CommandExecution(BaseModel):
    """Result and timing metadata for an optional captured command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    arguments: tuple[str, ...] = Field(min_length=1, max_length=256)
    working_directory: str = Field(min_length=1, max_length=500)
    started_at: datetime
    finished_at: datetime
    duration_milliseconds: int = Field(ge=0)
    exit_code: int
    timed_out: bool = False
    output_truncated: bool = False

    @model_validator(mode="after")
    def validate_timing(self) -> Self:
        """Reject command metadata whose finish time precedes its start."""
        if self.finished_at < self.started_at:
            raise ValueError("Command finish time cannot precede its start time")
        return self


class RedactionSummary(BaseModel):
    """Auditable summary of privacy transformations applied before storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    facts_scanned: int = Field(ge=0)
    facts_redacted: int = Field(ge=0)
    replacements: int = Field(ge=0)
    rules_triggered: dict[str, int] = Field(default_factory=dict)


class CapsuleIntegrity(BaseModel):
    """Integrity metadata for a sealed capsule manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str = Field(default="sha256", pattern=r"^sha256$")
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class Capsule(BaseModel):
    """Versioned, self-verifying diagnostic evidence capsule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    capsule_identifier: str = Field(
        min_length=16,
        max_length=80,
        pattern=r"^[a-z0-9-]+$",
    )
    created_at: datetime
    tool_version: str = Field(min_length=1, max_length=50)
    project_name: str = Field(min_length=1, max_length=120)
    project_root_label: str = Field(min_length=1, max_length=200)
    facts: tuple[EvidenceFact, ...]
    command: CommandExecution | None = None
    redaction: RedactionSummary
    plugins: tuple[str, ...] = ()
    integrity: CapsuleIntegrity | None = None

    @field_validator("project_name", "project_root_label")
    @classmethod
    def project_labels_are_display_safe(cls, value: str) -> str:
        """Reject control characters from labels shown by terminal and web clients."""
        if has_unsafe_control_characters(value):
            raise ValueError("Project labels cannot contain control characters")
        return value

    @field_validator("facts")
    @classmethod
    def facts_have_unique_keys(cls, facts: tuple[EvidenceFact, ...]) -> tuple[EvidenceFact, ...]:
        """Require one authoritative value for each semantic fact key."""
        keys = [fact.key for fact in facts]
        if len(keys) != len(set(keys)):
            raise ValueError("Capsule facts must have unique keys")
        return facts

    def unsigned_payload(self) -> dict[str, Any]:
        """Return the canonical manifest payload used for integrity sealing."""
        return self.model_dump(mode="json", exclude={"integrity"})

    def expected_manifest_digest(self) -> str:
        """Calculate the expected digest for the unsigned manifest payload."""
        return hashlib.sha256(canonical_json(self.unsigned_payload())).hexdigest()

    def seal(self) -> Capsule:
        """Return an immutable copy carrying a current manifest digest."""
        integrity = CapsuleIntegrity(manifest_digest=self.expected_manifest_digest())
        return self.model_copy(update={"integrity": integrity})

    def verify_integrity(self) -> bool:
        """Return whether the stored integrity record matches the manifest."""
        if self.integrity is None:
            return False
        return self.integrity.manifest_digest == self.expected_manifest_digest()


class FactDifference(BaseModel):
    """Semantic difference between a baseline and candidate fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    kind: DifferenceKind
    severity: DifferenceSeverity
    baseline_value: JsonValue | None = None
    candidate_value: JsonValue | None = None
    explanation: str


class DiagnosticHint(BaseModel):
    """Deterministic diagnostic suggestion derived from one or more differences."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    priority: int = Field(ge=1, le=100)
    title: str
    explanation: str
    related_keys: tuple[str, ...]


class ComparisonReport(BaseModel):
    """Complete semantic comparison of two verified capsules."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline_capsule_identifier: str
    candidate_capsule_identifier: str
    created_at: datetime
    differences: tuple[FactDifference, ...]
    hints: tuple[DiagnosticHint, ...]
    identical: bool
