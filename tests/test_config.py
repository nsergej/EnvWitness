from __future__ import annotations

from pathlib import Path

import pytest

from envwitness.domain.errors import ConfigurationError
from envwitness.infrastructure.config import (
    EnvWitnessConfiguration,
    load_configuration,
    write_default_configuration,
)


def test_safe_defaults() -> None:
    configuration = load_configuration(None)
    assert configuration.telemetry.enabled is False
    assert configuration.updates.automatic_install is False
    assert configuration.api.host == "127.0.0.1"


def test_default_configuration_round_trip(tmp_path: Path) -> None:
    path = write_default_configuration(tmp_path / "envwitness.yml")
    configuration = load_configuration(path)
    assert len(configuration.capture.runtime_probes) == 2
    with pytest.raises(ConfigurationError, match="Refusing to overwrite"):
        write_default_configuration(path)


def test_unknown_configuration_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yml"
    path.write_text("unknown: true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Extra inputs"):
        load_configuration(path)


def test_traversing_file_allowlist_is_rejected() -> None:
    with pytest.raises(ValueError, match="inside the project"):
        EnvWitnessConfiguration.model_validate(
            {"capture": {"file_content_allowlist": ["../secret.txt"]}}
        )


def test_non_https_telemetry_endpoint_is_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        EnvWitnessConfiguration.model_validate(
            {"telemetry": {"enabled": True, "endpoint": "http://example.test"}}
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https:///events",
        "https://user:password@example.test/events",
        "https://example.test/events#fragment",
        "https://example.test/events#",
        "https://example.test\\@attacker.test/events",
    ],
)
def test_ambiguous_telemetry_endpoints_are_rejected(endpoint: str) -> None:
    with pytest.raises(ValueError, match="Telemetry endpoint"):
        EnvWitnessConfiguration.model_validate({"telemetry": {"endpoint": endpoint}})


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(a|aa)+$",
        r"(?:[A-Za-z]+\s?)*$",
        r"(secret){1,1001}",
        r"(secret)\1",
    ],
)
def test_dangerous_custom_redaction_regex_is_rejected(pattern: str) -> None:
    with pytest.raises(ValueError, match="Redaction expression"):
        EnvWitnessConfiguration.model_validate(
            {"redaction": {"custom_rules": [{"name": "unsafe", "pattern": pattern}]}}
        )


def test_bounded_custom_redaction_regex_remains_supported() -> None:
    configuration = EnvWitnessConfiguration.model_validate(
        {"redaction": {"custom_rules": [{"name": "ticket", "pattern": r"INC-[0-9]{8}"}]}}
    )
    assert configuration.redaction.custom_rules[0].pattern == r"INC-[0-9]{8}"


def test_non_loopback_api_binding_is_rejected() -> None:
    with pytest.raises(ValueError, match="String should match pattern"):
        EnvWitnessConfiguration.model_validate({"api": {"host": "0.0.0.0"}})


def test_project_name_with_control_character_is_rejected() -> None:
    with pytest.raises(ValueError, match="control characters"):
        EnvWitnessConfiguration.model_validate({"project_name": "project\x1b[31m"})
