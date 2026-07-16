from __future__ import annotations

import threading
import urllib.error
from pathlib import Path

import pytest

from envwitness.domain.errors import ConfigurationError
from envwitness.infrastructure.telemetry import AggregateTelemetryClient, ConsentStore


class _TelemetryResponse:
    def __enter__(self) -> _TelemetryResponse:
        return self

    def __exit__(self, *arguments: object) -> bool:
        return False

    def read(self, maximum_bytes: int = -1) -> bytes:
        return b""[:maximum_bytes]


def test_disabled_telemetry_does_not_start_a_worker(tmp_path: Path) -> None:
    client = AggregateTelemetryClient(
        consent_store=ConsentStore(tmp_path / "consent.json"),
        endpoint="https://example.test/events",
        tool_version="1.0.0",
    )
    client.record("capture_completed", {"fact_count": 1})
    assert client._worker is None
    client.close()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https:///events",
        "https://user@example.test/events",
        "https://example.test/events#fragment",
    ],
)
def test_telemetry_client_rejects_ambiguous_endpoint(
    endpoint: str,
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError, match="Telemetry endpoint"):
        AggregateTelemetryClient(
            consent_store=ConsentStore(tmp_path / "consent.json"),
            endpoint=endpoint,
            tool_version="1.0.0",
        )


def test_telemetry_uses_one_worker_and_rechecks_revoked_consent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consent_store = ConsentStore(tmp_path / "consent.json")
    consent_store.set_enabled(True)
    first_delivery_started = threading.Event()
    release_first_delivery = threading.Event()
    delivered: list[dict[str, object]] = []

    def deliver(self: AggregateTelemetryClient, payload: dict[str, object]) -> None:
        delivered.append(payload)
        first_delivery_started.set()
        release_first_delivery.wait(1)

    monkeypatch.setattr(AggregateTelemetryClient, "_deliver", deliver)
    client = AggregateTelemetryClient(
        consent_store=consent_store,
        endpoint="https://example.test/events",
        tool_version="1.0.0",
    )
    client.record("capture_completed", {"fact_count": 1})
    assert first_delivery_started.wait(1)
    first_worker = client._worker
    client.record("capture_completed", {"fact_count": 2})
    assert client._worker is first_worker
    consent_store.set_enabled(False)
    release_first_delivery.set()
    client.close()

    assert len(delivered) == 1


def test_telemetry_worker_posts_allowlisted_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consent_store = ConsentStore(tmp_path / "consent.json")
    consent_store.set_enabled(True)
    requests: list[tuple[object, float]] = []

    def open_request(request: object, timeout: float) -> _TelemetryResponse:
        requests.append((request, timeout))
        return _TelemetryResponse()

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    client = AggregateTelemetryClient(
        consent_store=consent_store,
        endpoint="https://example.test/events",
        tool_version="1.0.0",
    )
    client.record("capture_completed", {"fact_count": 4})
    client.close()

    assert len(requests) == 1
    assert requests[0][1] == 2


def test_telemetry_network_failure_never_escapes_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consent_store = ConsentStore(tmp_path / "consent.json")
    consent_store.set_enabled(True)

    def fail_request(request: object, timeout: float) -> _TelemetryResponse:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr("urllib.request.urlopen", fail_request)
    client = AggregateTelemetryClient(
        consent_store=consent_store,
        endpoint="https://example.test/events",
        tool_version="1.0.0",
    )
    client.record("capture_completed", {"fact_count": 4})
    client.close()
