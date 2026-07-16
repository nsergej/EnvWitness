from __future__ import annotations

from envwitness.application.ports import CollectedFact
from envwitness.domain.models import Sensitivity, utc_now
from envwitness.infrastructure.config import RedactionRuleConfiguration
from envwitness.infrastructure.redaction import DeterministicRedactor


def collected(value: object, *, sensitivity: Sensitivity = Sensitivity.SENSITIVE) -> CollectedFact:
    return CollectedFact(
        key="command.standard_output",
        value=value,
        collector="command",
        source="stdout",
        sensitivity=sensitivity,
        captured_at=utc_now(),
    )


def test_redacts_built_in_secret_patterns() -> None:
    github_token_canary = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
    value = {
        "token": github_token_canary,
        "authorization": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "url": "https://user:password@example.test/path",
        "assignment": "client_secret=hunter2",
    }
    facts, summary = DeterministicRedactor().redact([collected(value)])
    rendered = str(facts[0].value)
    assert "ghp_" not in rendered
    assert "hunter2" not in rendered
    assert "password@example" not in rendered
    assert facts[0].redacted is True
    assert summary.facts_redacted == 1
    assert summary.replacements == 4


def test_secret_classification_always_discards_value() -> None:
    facts, summary = DeterministicRedactor().redact(
        [collected("unrecognized weak secret", sensitivity=Sensitivity.SECRET)]
    )
    assert facts[0].value == "[REDACTED:secret-classification]"
    assert facts[0].redaction_rules == ("secret-classification",)
    assert summary.rules_triggered == {"secret-classification": 1}


def test_custom_redaction_rule() -> None:
    redactor = DeterministicRedactor(
        (RedactionRuleConfiguration(name="ticket", pattern=r"INC-[0-9]{8}"),)
    )
    facts, _ = redactor.redact([collected(["INC-12345678", "visible"])])
    assert facts[0].value == ["[REDACTED:ticket]", "visible"]


def test_clean_value_keeps_original_digest() -> None:
    facts, summary = DeterministicRedactor().redact([collected("ordinary output")])
    assert facts[0].value == "ordinary output"
    assert facts[0].redacted is False
    assert summary.replacements == 0
