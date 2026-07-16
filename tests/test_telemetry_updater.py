from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from envwitness.domain.errors import ConfigurationError, UpdateError
from envwitness.infrastructure.telemetry import AggregateTelemetryClient, ConsentStore
from envwitness.infrastructure.updater import (
    AutomaticUpdateCoordinator,
    PyPiUpdater,
    UpdateStatus,
)


def test_consent_store_defaults_disabled_and_round_trips(tmp_path: Path) -> None:
    store = ConsentStore(tmp_path / "consent.json")
    assert store.is_enabled() is False
    store.set_enabled(True)
    assert store.is_enabled() is True
    store.set_enabled(False)
    assert store.is_enabled() is False


def test_telemetry_requires_https(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="HTTPS"):
        AggregateTelemetryClient(
            consent_store=ConsentStore(tmp_path / "consent.json"),
            endpoint="http://example.test",
            tool_version="1.0.0",
        )


def test_telemetry_is_inert_without_consent(tmp_path: Path, monkeypatch) -> None:
    delivery = Mock()
    monkeypatch.setattr(AggregateTelemetryClient, "_deliver", delivery)
    client = AggregateTelemetryClient(
        consent_store=ConsentStore(tmp_path / "consent.json"),
        endpoint="https://example.test/events",
        tool_version="1.0.0",
    )
    client.record("capture_completed", {"fact_count": 10})
    delivery.assert_not_called()


def test_telemetry_delivers_only_allowlisted_properties(tmp_path: Path, monkeypatch) -> None:
    consent_store = ConsentStore(tmp_path / "consent.json")
    consent_store.set_enabled(True)
    delivered = []

    class ImmediateThread:
        def __init__(self, *, target, args, **options) -> None:
            self.target = target
            self.args = args

        def start(self) -> None:
            self.target(*self.args)

    monkeypatch.setattr("threading.Thread", ImmediateThread)
    monkeypatch.setattr(
        AggregateTelemetryClient,
        "_deliver",
        lambda self, payload: delivered.append(payload),
    )
    client = AggregateTelemetryClient(
        consent_store=consent_store,
        endpoint="https://example.test/events",
        tool_version="1.0.0",
    )
    client.record(
        "capture_completed",
        {"fact_count": 10, "project_name": "must-not-leave"},
    )
    assert delivered[0]["properties"] == {"fact_count": 10}
    client.record("unapproved_event", {"fact_count": 10})
    assert len(delivered) == 1


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        return False

    def read(self, maximum_bytes: int = -1) -> bytes:
        return self._payload[:maximum_bytes]


def test_update_check_uses_normalized_versions(monkeypatch) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse({"info": {"version": "1.2.0"}}),
    )
    status = PyPiUpdater(
        current_version="1.0.0",
        metadata_url="https://pypi.org/pypi/envwitness/json",
    ).check()
    assert status.update_available is True
    assert status.latest_version == "1.2.0"


def test_updater_rejects_untrusted_metadata_url() -> None:
    with pytest.raises(UpdateError, match="canonical"):
        PyPiUpdater(current_version="1.0.0", metadata_url="https://example.test/data")


def test_updater_rejects_prerelease_install() -> None:
    updater = PyPiUpdater(
        current_version="1.0.0",
        metadata_url="https://pypi.org/pypi/envwitness/json",
    )
    with pytest.raises(UpdateError, match="stable"):
        updater.install("2.0.0rc1")


def test_updater_installs_exact_version(monkeypatch) -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    runner = Mock(return_value=completed)
    monkeypatch.setattr("subprocess.run", runner)
    updater = PyPiUpdater(
        current_version="1.0.0",
        metadata_url="https://pypi.org/pypi/envwitness/json",
    )
    updater.install("1.2.3")
    command = runner.call_args.args[0]
    assert "envwitness==1.2.3" in command
    assert runner.call_args.kwargs["timeout"] == 300


def test_updater_reports_installer_failure(monkeypatch) -> None:
    completed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="installation failed"
    )
    monkeypatch.setattr("subprocess.run", lambda *arguments, **options: completed)
    updater = PyPiUpdater(
        current_version="1.0.0",
        metadata_url="https://pypi.org/pypi/envwitness/json",
    )
    with pytest.raises(UpdateError, match="installation failed"):
        updater.install("1.2.3")


def test_automatic_update_checks_once_per_interval(tmp_path: Path) -> None:
    updater = Mock()
    updater.check.return_value = UpdateStatus("1.0.0", "1.0.0", False)
    coordinator = AutomaticUpdateCoordinator(
        updater=updater,
        state_path=tmp_path / "updates.json",
    )
    checked_at = datetime(2026, 7, 16, 12, tzinfo=UTC)

    first = coordinator.run(
        automatic_check=True,
        automatic_install=False,
        interval_hours=24,
        now=checked_at,
    )
    second = coordinator.run(
        automatic_check=True,
        automatic_install=False,
        interval_hours=24,
        now=checked_at + timedelta(hours=23),
    )

    assert first.checked is True
    assert second.checked is False
    updater.check.assert_called_once_with()


def test_automatic_update_installs_discovered_stable_version(tmp_path: Path) -> None:
    updater = Mock()
    updater.check.return_value = UpdateStatus("1.0.0", "1.2.0", True)
    coordinator = AutomaticUpdateCoordinator(
        updater=updater,
        state_path=tmp_path / "updates.json",
    )

    result = coordinator.run(
        automatic_check=True,
        automatic_install=True,
        interval_hours=24,
    )

    assert result.installed_version == "1.2.0"
    updater.install.assert_called_once_with("1.2.0")


def test_automatic_update_is_inert_without_opt_in(tmp_path: Path) -> None:
    updater = Mock()
    result = AutomaticUpdateCoordinator(
        updater=updater,
        state_path=tmp_path / "updates.json",
    ).run(
        automatic_check=False,
        automatic_install=False,
        interval_hours=24,
    )
    assert result.checked is False
    updater.check.assert_not_called()


def test_automatic_update_recovers_from_malformed_state(tmp_path: Path) -> None:
    state_path = tmp_path / "updates.json"
    state_path.write_text("not-json", encoding="utf-8")
    updater = Mock()
    updater.check.return_value = UpdateStatus("1.0.0", "1.0.0", False)

    result = AutomaticUpdateCoordinator(updater=updater, state_path=state_path).run(
        automatic_check=True,
        automatic_install=False,
        interval_hours=24,
    )

    assert result.checked is True
    assert "last_checked_at" in json.loads(state_path.read_text(encoding="utf-8"))
