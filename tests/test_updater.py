from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from envwitness.domain.errors import UpdateError
from envwitness.infrastructure.updater import (
    AutomaticUpdateCoordinator,
    PyPiUpdater,
    UpdateStatus,
)


class _MetadataResponse:
    def __init__(self, version: str) -> None:
        self._payload = json.dumps({"info": {"version": version}}).encode("utf-8")

    def __enter__(self) -> _MetadataResponse:
        return self

    def __exit__(self, *arguments: object) -> bool:
        return False

    def read(self, maximum_bytes: int = -1) -> bytes:
        return self._payload[:maximum_bytes]


@pytest.mark.parametrize("latest_version", ["2.0.0rc1", "2.0.0.dev1", "2.0.0+local"])
def test_update_check_ignores_non_stable_metadata(
    latest_version: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: _MetadataResponse(latest_version),
    )
    status = PyPiUpdater(
        current_version="1.0.0",
        metadata_url="https://pypi.org/pypi/envwitness/json",
    ).check()
    assert status.update_available is False


def test_future_update_timestamp_is_due(tmp_path: Path) -> None:
    current_time = datetime(2026, 7, 16, 12, tzinfo=UTC)
    state_path = tmp_path / "updates.json"
    state_path.write_text(
        json.dumps(
            {
                "last_checked_at": (current_time + timedelta(days=365))
                .isoformat()
                .replace("+00:00", "Z")
            }
        ),
        encoding="utf-8",
    )
    updater = Mock()
    updater.check.return_value = UpdateStatus("1.0.0", "1.0.0", False)

    result = AutomaticUpdateCoordinator(updater=updater, state_path=state_path).run(
        automatic_check=True,
        automatic_install=False,
        interval_hours=24,
        now=current_time,
    )

    assert result.checked is True
    updater.check.assert_called_once_with()


def test_active_update_lock_skips_without_waiting(tmp_path: Path) -> None:
    state_path = tmp_path / "updates.json"
    state_path.with_name("updates.json.lock").write_text("active", encoding="ascii")
    updater = Mock()

    result = AutomaticUpdateCoordinator(updater=updater, state_path=state_path).run(
        automatic_check=True,
        automatic_install=False,
        interval_hours=24,
    )

    assert result.checked is False
    updater.check.assert_not_called()


def test_state_directory_failure_is_wrapped(tmp_path: Path) -> None:
    non_directory = tmp_path / "not-a-directory"
    non_directory.write_text("file", encoding="utf-8")
    updater = Mock()
    updater.check.return_value = UpdateStatus("1.0.0", "1.0.0", False)

    with pytest.raises(UpdateError, match="update state lock"):
        AutomaticUpdateCoordinator(
            updater=updater,
            state_path=non_directory / "updates.json",
        ).run(
            automatic_check=True,
            automatic_install=False,
            interval_hours=24,
        )
