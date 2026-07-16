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


def test_non_loopback_api_binding_is_rejected() -> None:
    with pytest.raises(ValueError, match="String should match pattern"):
        EnvWitnessConfiguration.model_validate({"api": {"host": "0.0.0.0"}})
