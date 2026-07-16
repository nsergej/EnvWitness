"""Explicit-consent, privacy-minimized aggregate telemetry delivery."""

from __future__ import annotations

import contextlib
import json
import logging
import platform
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from uuid import uuid4

from envwitness.domain.errors import ConfigurationError
from envwitness.infrastructure.config import validate_telemetry_endpoint

LOGGER = logging.getLogger(__name__)


class ConsentStore:
    """Persist an explicit telemetry choice separately from project configuration."""

    def __init__(self, path: Path) -> None:
        """Initialize the store at an operator-visible local path."""
        self._path = path

    def set_enabled(self, enabled: bool) -> None:
        """Atomically store the explicit consent state with restrictive permissions."""
        temporary_path = self._path.with_name(f".{self._path.name}.{uuid4().hex}.temporary")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
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


@dataclass(slots=True)
class _QueuedTelemetryEvent:
    """One validated event and its short submission acknowledgement."""

    payload: dict[str, object]
    completed: Event


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
    _MAXIMUM_QUEUED_EVENTS = 32
    _SUBMISSION_WAIT_SECONDS = 0.05

    def __init__(
        self,
        *,
        consent_store: ConsentStore,
        endpoint: str,
        tool_version: str,
    ) -> None:
        """Initialize a client that remains inert without both consent and endpoint."""
        try:
            validated_endpoint = validate_telemetry_endpoint(endpoint)
        except ValueError as error:
            raise ConfigurationError(str(error)) from error
        self._consent_store = consent_store
        self._endpoint = validated_endpoint
        self._tool_version = tool_version
        self._queue: Queue[_QueuedTelemetryEvent] = Queue(maxsize=self._MAXIMUM_QUEUED_EVENTS)
        self._state_lock = Lock()
        self._stop_requested = Event()
        self._worker: Thread | None = None
        self._closed = False
        self._drain_on_close = True

    def record(self, event_name: str, properties: dict[str, int | str | bool]) -> None:
        """Validate and enqueue one aggregate event for the bounded worker."""
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
        payload: dict[str, object] = {
            "event": event_name,
            "properties": safe_properties,
            "operating_system": platform.system().lower(),
            "tool_version": self._tool_version,
        }
        queued_event = _QueuedTelemetryEvent(payload=payload, completed=Event())
        with self._state_lock:
            if self._closed:
                return
            try:
                self._queue.put_nowait(queued_event)
            except Full:
                LOGGER.debug("telemetry_queue_full")
                return
            if self._worker is None:
                self._worker = Thread(
                    target=self._worker_loop,
                    name="envwitness-telemetry",
                    daemon=True,
                )
                self._worker.start()
        queued_event.completed.wait(self._SUBMISSION_WAIT_SECONDS)

    def close(self, *, drain: bool = True, timeout_seconds: float = 2.5) -> None:
        """Stop accepting events and give the single worker bounded time to drain."""
        if timeout_seconds < 0:
            raise ValueError("Telemetry close timeout cannot be negative")
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._drain_on_close = drain
            self._stop_requested.set()
            worker = self._worker
        if not drain:
            self._discard_pending_events()
        if worker is None:
            return
        worker.join(timeout_seconds)
        if worker.is_alive():
            self._drain_on_close = False
            self._discard_pending_events()
            worker.join(0.1)
            if worker.is_alive():
                LOGGER.debug("telemetry_worker_close_timed_out")

    def _worker_loop(self) -> None:
        """Deliver queued events serially until an explicit close completes."""
        while True:
            if self._stop_requested.is_set() and (not self._drain_on_close or self._queue.empty()):
                return
            try:
                queued_event = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                if self._consent_store.is_enabled():
                    self._deliver(queued_event.payload)
            finally:
                queued_event.completed.set()
                self._queue.task_done()

    def _discard_pending_events(self) -> None:
        """Discard queued, not-yet-sent events during a non-draining close."""
        while True:
            try:
                queued_event = self._queue.get_nowait()
            except Empty:
                return
            queued_event.completed.set()
            self._queue.task_done()

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
        except (OSError, ValueError, urllib.error.URLError):
            LOGGER.debug("telemetry_delivery_failed", exc_info=True)


def default_consent_path() -> Path:
    """Return the cross-platform per-user consent document path."""
    return Path.home() / ".config" / "envwitness" / "consent.json"
