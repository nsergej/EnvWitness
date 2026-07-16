"""Explicit-consent, privacy-minimized aggregate telemetry delivery."""

from __future__ import annotations

import contextlib
import json
import logging
import platform
import threading
import urllib.error
import urllib.request
from pathlib import Path

from envwitness.domain.errors import ConfigurationError

LOGGER = logging.getLogger(__name__)


class ConsentStore:
    """Persist an explicit telemetry choice separately from project configuration."""

    def __init__(self, path: Path) -> None:
        """Initialize the store at an operator-visible local path."""
        self._path = path

    def set_enabled(self, enabled: bool) -> None:
        """Atomically store the explicit consent state with restrictive permissions."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self._path.with_suffix(".temporary")
        try:
            temporary_path.write_text(
                json.dumps({"telemetry_enabled": enabled}, indent=2) + "\n",
                encoding="utf-8",
            )
            with contextlib.suppress(OSError):
                temporary_path.chmod(0o600)
            temporary_path.replace(self._path)
        except OSError as error:
            temporary_path.unlink(missing_ok=True)
            raise ConfigurationError(f"Cannot persist telemetry consent: {error}") from error

    def is_enabled(self) -> bool:
        """Return true only when a valid stored choice explicitly enables telemetry."""
        if not self._path.exists():
            return False
        try:
            raw_data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
        return isinstance(raw_data, dict) and raw_data.get("telemetry_enabled") is True


class AggregateTelemetryClient:
    """Send allowlisted aggregate events without identifiers or captured evidence."""

    _ALLOWED_EVENT_NAMES = frozenset({"capture_completed", "comparison_completed"})
    _ALLOWED_PROPERTY_NAMES = frozenset(
        {
            "fact_count",
            "plugin_count",
            "redacted_fact_count",
            "command_captured",
            "difference_count",
        }
    )

    def __init__(
        self,
        *,
        consent_store: ConsentStore,
        endpoint: str,
        tool_version: str,
    ) -> None:
        """Initialize a client that remains inert without both consent and endpoint."""
        if endpoint and not endpoint.startswith("https://"):
            raise ConfigurationError("Telemetry endpoint must use HTTPS")
        self._consent_store = consent_store
        self._endpoint = endpoint
        self._tool_version = tool_version

    def record(self, event_name: str, properties: dict[str, int | str | bool]) -> None:
        """Validate and deliver one aggregate event on a non-blocking daemon thread."""
        if not self._consent_store.is_enabled() or not self._endpoint:
            return
        if event_name not in self._ALLOWED_EVENT_NAMES:
            LOGGER.warning("telemetry_event_rejected", extra={"event_name": event_name})
            return
        safe_properties = {
            key: value
            for key, value in properties.items()
            if key in self._ALLOWED_PROPERTY_NAMES and isinstance(value, (int, bool))
        }
        payload = {
            "event": event_name,
            "properties": safe_properties,
            "operating_system": platform.system().lower(),
            "tool_version": self._tool_version,
        }
        delivery_thread = threading.Thread(
            target=self._deliver,
            args=(payload,),
            name="envwitness-telemetry",
            daemon=True,
        )
        delivery_thread.start()

    def _deliver(self, payload: dict[str, object]) -> None:
        """POST one bounded JSON event and suppress non-critical network failures."""
        encoded_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - endpoint is HTTPS-validated
            self._endpoint,
            data=encoded_payload,
            headers={"Content-Type": "application/json", "User-Agent": "EnvWitness"},
            method="POST",
        )
        try:
            # Configuration validation permits HTTPS telemetry endpoints only.
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                request,
                timeout=2,
            ) as response:
                response.read(1)
        except (OSError, urllib.error.URLError):
            LOGGER.debug("telemetry_delivery_failed", exc_info=True)


def default_consent_path() -> Path:
    """Return the cross-platform per-user consent document path."""
    return Path.home() / ".config" / "envwitness" / "consent.json"
