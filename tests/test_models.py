from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from envwitness.domain.models import (
    Capsule,
    CommandExecution,
    EvidenceFact,
    RedactionSummary,
    Sensitivity,
    canonical_json,
    digest_value,
    utc_now,
)


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"second": 2, "first": 1}) == canonical_json({"first": 1, "second": 2})


def test_digest_is_for_stored_value() -> None:
    assert digest_value("stored") != digest_value("discarded")


def test_fact_rejects_tampered_digest(sample_fact: EvidenceFact) -> None:
    payload = sample_fact.model_dump()
    payload["digest"] = "0" * 64
    with pytest.raises(ValidationError, match="digest does not match"):
        EvidenceFact.model_validate(payload)


def test_fact_requires_rule_when_redacted() -> None:
    with pytest.raises(ValidationError, match="must name"):
        EvidenceFact.create(
            key="command.standard_error",
            value="[REDACTED]",
            collector="command",
            source="stderr",
            sensitivity=Sensitivity.SENSITIVE,
            redacted=True,
        )


def test_command_rejects_reverse_timing() -> None:
    now = utc_now()
    with pytest.raises(ValidationError, match="finish time"):
        CommandExecution(
            arguments=("python", "--version"),
            working_directory="project",
            started_at=now,
            finished_at=now - timedelta(seconds=1),
            duration_milliseconds=1,
            exit_code=0,
        )


def test_capsule_seal_detects_tampering(sample_capsule: Capsule) -> None:
    assert sample_capsule.verify_integrity()
    tampered = sample_capsule.model_copy(update={"project_name": "changed"})
    assert not tampered.verify_integrity()


def test_capsule_rejects_duplicate_fact_keys(sample_fact: EvidenceFact) -> None:
    with pytest.raises(ValidationError, match="unique keys"):
        Capsule(
            capsule_identifier="ew-0123456789abcdef",
            created_at=utc_now(),
            tool_version="1.0.0",
            project_name="sample",
            project_root_label="sample",
            facts=(sample_fact, sample_fact),
            redaction=RedactionSummary(
                facts_scanned=2,
                facts_redacted=0,
                replacements=0,
            ),
        )
