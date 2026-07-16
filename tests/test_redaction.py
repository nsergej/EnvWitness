from __future__ import annotations

from pathlib import Path

import pytest

from envwitness.application.ports import CollectedFact
from envwitness.domain.errors import CaptureError
from envwitness.domain.models import Sensitivity, utc_now
from envwitness.infrastructure.config import RedactionRuleConfiguration
from envwitness.infrastructure.redaction import DeterministicRedactor


def collected(
    value: object,
    *,
    sensitivity: Sensitivity = Sensitivity.SENSITIVE,
    key: str = "command.standard_output",
    collector: str = "command",
    source: str = "stdout",
) -> CollectedFact:
    return CollectedFact(
        key=key,
        value=value,
        collector=collector,
        source=source,
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


def test_home_directory_is_redacted_from_persisted_text() -> None:
    home_directory = str(Path.home().resolve(strict=True))

    facts, summary = DeterministicRedactor().redact([collected(f"runtime={home_directory}")])

    assert home_directory.casefold() not in str(facts[0].value).casefold()
    assert "home-directory" in facts[0].redaction_rules
    assert summary.replacements == 1


def test_terminal_control_character_is_redacted() -> None:
    facts, summary = DeterministicRedactor().redact([collected("safe\x1b[31munsafe")])

    assert "\x1b" not in str(facts[0].value)
    assert "control-character" in facts[0].redaction_rules
    assert summary.replacements == 1


def test_unicode_format_character_is_redacted() -> None:
    facts, summary = DeterministicRedactor().redact([collected("safe\u202eunsafe")])

    assert "\u202e" not in str(facts[0].value)
    assert "format-character" in facts[0].redaction_rules
    assert summary.replacements == 1


def test_redacts_source_and_nested_mapping_keys_deterministically() -> None:
    first_token = "ghp_" + "a" * 24
    second_token = "ghp_" + "b" * 24
    first_value = {second_token: "second", first_token: "first", "visible": "kept"}
    second_value = {"visible": "kept", first_token: "first", second_token: "second"}
    source = f"plugin output from {first_token}"

    first_facts, first_summary = DeterministicRedactor().redact(
        [collected(first_value, source=source)]
    )
    second_facts, _ = DeterministicRedactor().redact([collected(second_value, source=source)])

    assert first_facts[0].value == second_facts[0].value
    assert first_facts[0].value == {
        "[REDACTED:github-token]": "first",
        "[REDACTED:github-token]#2": "second",
        "visible": "kept",
    }
    assert first_token not in first_facts[0].source
    assert first_facts[0].redacted is True
    assert first_summary.replacements == 3


@pytest.mark.parametrize("field", ["key", "collector"])
def test_rejects_secret_bearing_semantic_identifiers(field: str) -> None:
    token = "ghp_" + "c" * 24
    arguments = {field: token}
    fact = collected("value", **arguments)

    with pytest.raises(CaptureError, match="contains sensitive material"):
        DeterministicRedactor().redact([fact])


def test_redacts_contextual_command_arguments() -> None:
    option_secret = "option-secret-canary"
    query_secret = "query-secret-canary"
    arguments = [
        "tool",
        "--password",
        option_secret,
        "--client_secret=inline-secret-canary",
        f"https://user:pass@example.test/path?token={query_secret}&mode=check",
    ]

    facts, summary = DeterministicRedactor().redact(
        [
            collected(
                arguments,
                key="envwitness.command.arguments",
                sensitivity=Sensitivity.INTERNAL,
            )
        ]
    )

    rendered = str(facts[0].value)
    assert option_secret not in rendered
    assert "inline-secret-canary" not in rendered
    assert query_secret not in rendered
    assert "user:pass" not in rendered
    assert "mode=check" in rendered
    assert summary.replacements == 4


@pytest.mark.parametrize("value", ["not-a-list", ["tool", 1]])
def test_rejects_invalid_command_argument_metadata(value: object) -> None:
    with pytest.raises(CaptureError, match="list of strings"):
        DeterministicRedactor().redact(
            [
                collected(
                    value,
                    key="envwitness.command.arguments",
                    sensitivity=Sensitivity.INTERNAL,
                )
            ]
        )


def test_redacts_ipv6_url_with_invalid_port_without_leaking_credentials() -> None:
    arguments = ["tool", "https://user:pass@[::1]:invalid/path?mode=check"]

    facts, summary = DeterministicRedactor().redact(
        [
            collected(
                arguments,
                key="envwitness.command.arguments",
                sensitivity=Sensitivity.INTERNAL,
            )
        ]
    )

    rendered = str(facts[0].value)
    assert "user:pass" not in rendered
    assert "@[::1]" in rendered
    assert "mode=check" in rendered
    assert summary.replacements == 1


def test_rejects_invalid_collector_identifier() -> None:
    with pytest.raises(CaptureError, match="valid semantic identifier"):
        DeterministicRedactor().redact([collected("value", collector="Invalid Collector")])
