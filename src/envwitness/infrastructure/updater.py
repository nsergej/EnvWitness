"""Explicit and optionally automated package update checks through PyPI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from packaging.version import InvalidVersion, Version

from envwitness.domain.errors import UpdateError

_STALE_LOCK_AGE = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class UpdateStatus:
    """Result of comparing the installed package with trusted metadata."""

    current_version: str
    latest_version: str
    update_available: bool


@dataclass(frozen=True, slots=True)
class AutomaticUpdateResult:
    """Outcome of one automatic update policy evaluation."""

    checked: bool
    installed_version: str | None = None


class UpdateClient(Protocol):
    """Operations required by the automatic update coordinator."""

    def check(self) -> UpdateStatus:
        """Return the current release status."""
        ...

    def install(self, version: str) -> None:
        """Install one exact stable release."""
        ...


class PyPiUpdater:
    """Check and install exact EnvWitness releases from the canonical package index."""

    def __init__(self, *, current_version: str, metadata_url: str) -> None:
        """Initialize the updater with a trusted metadata URL."""
        if metadata_url != "https://pypi.org/pypi/envwitness/json":
            raise UpdateError("Updater metadata must use the canonical PyPI endpoint")
        self._current_version = current_version
        self._metadata_url = metadata_url

    def check(self) -> UpdateStatus:
        """Fetch bounded release metadata and compare normalized versions."""
        request = urllib.request.Request(  # noqa: S310 - URL is an exact trusted constant
            self._metadata_url,
            headers={"Accept": "application/json", "User-Agent": "EnvWitness update checker"},
        )
        try:
            # Construction accepts the exact canonical PyPI HTTPS endpoint only.
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                request,
                timeout=5,
            ) as response:
                raw_payload = response.read(1_048_577)
        except (OSError, urllib.error.URLError) as error:
            raise UpdateError(f"Update check failed: {error}") from error
        if len(raw_payload) > 1_048_576:
            raise UpdateError("Update metadata exceeds the 1 MiB safety limit")
        try:
            payload = json.loads(raw_payload)
            latest_version = str(payload["info"]["version"])
            current = Version(self._current_version)
            latest = Version(latest_version)
        except (json.JSONDecodeError, KeyError, TypeError, InvalidVersion) as error:
            raise UpdateError(f"Invalid update metadata: {error}") from error
        return UpdateStatus(
            current_version=self._current_version,
            latest_version=latest_version,
            update_available=_is_stable_version(latest) and latest > current,
        )

    def install(self, version: str) -> None:
        """Install one exact validated release using the active Python interpreter."""
        try:
            normalized_version = Version(version)
        except InvalidVersion as error:
            raise UpdateError(f"Invalid requested version: {version}") from error
        if not _is_stable_version(normalized_version):
            raise UpdateError("Automatic installation accepts stable releases only")
        command = (
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            f"envwitness=={normalized_version}",
        )
        try:
            # The executable and package name are fixed; only a normalized version varies.
            completed_process = subprocess.run(  # noqa: S603  # nosec B603
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise UpdateError(f"Update installation failed: {error}") from error
        if completed_process.returncode != 0:
            error_text = completed_process.stderr[-4_096:]
            raise UpdateError(f"Package installer failed: {error_text}")


class AutomaticUpdateCoordinator:
    """Apply an explicit, rate-limited automatic update policy."""

    def __init__(self, *, updater: UpdateClient, state_path: Path) -> None:
        """Initialize the coordinator with an updater and local state path."""
        self._updater = updater
        self._state_path = state_path

    def run(
        self,
        *,
        automatic_check: bool,
        automatic_install: bool,
        interval_hours: int,
        now: datetime | None = None,
    ) -> AutomaticUpdateResult:
        """Check when due and optionally install an exact stable release.

        A failed or malformed state document is treated as missing state. The
        successful check timestamp is persisted before installation so a package
        manager failure cannot trigger a network request on every CLI invocation.
        """
        if automatic_install and not automatic_check:
            raise UpdateError("Automatic installation requires automatic checks")
        if not automatic_check:
            return AutomaticUpdateResult(checked=False)
        if not 1 <= interval_hours <= 720:
            raise UpdateError("Update check interval must be between 1 and 720 hours")

        current_time = (now or datetime.now(UTC)).astimezone(UTC)
        lock_path = self._state_path.with_name(f"{self._state_path.name}.lock")
        with _try_update_lock(lock_path, current_time) as lock_acquired:
            if not lock_acquired or not self._is_due(current_time, interval_hours):
                return AutomaticUpdateResult(checked=False)

            status = self._updater.check()
            self._write_state(current_time)
            if automatic_install and status.update_available:
                try:
                    discovered_version = Version(status.latest_version)
                except InvalidVersion as error:
                    raise UpdateError("Updater returned an invalid release version") from error
                if not _is_stable_version(discovered_version):
                    raise UpdateError("Automatic installation accepts stable releases only")
                self._updater.install(status.latest_version)
                return AutomaticUpdateResult(
                    checked=True,
                    installed_version=status.latest_version,
                )
            return AutomaticUpdateResult(checked=True)

    def _is_due(self, current_time: datetime, interval_hours: int) -> bool:
        """Return whether the persisted successful check is outside the interval."""
        if not self._state_path.is_file():
            return True
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
            raw_timestamp = payload["last_checked_at"]
            if not isinstance(raw_timestamp, str):
                return True
            last_checked = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            if last_checked.tzinfo is None:
                return True
            normalized_last_checked = last_checked.astimezone(UTC)
            if normalized_last_checked > current_time:
                return True
            return current_time - normalized_last_checked >= timedelta(hours=interval_hours)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, ValueError, TypeError):
            return True

    def _write_state(self, checked_at: datetime) -> None:
        """Persist one successful check timestamp using an atomic replacement."""
        temporary_path = self._state_path.with_name(
            f".{self._state_path.name}.{os.getpid()}.{uuid4().hex}.temporary"
        )
        payload = {"last_checked_at": checked_at.isoformat().replace("+00:00", "Z")}
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self._state_path)
        except OSError as error:
            temporary_path.unlink(missing_ok=True)
            raise UpdateError(f"Cannot persist update check state: {error}") from error


def _is_stable_version(version: Version) -> bool:
    """Return whether a normalized version represents a public stable release."""
    return not version.is_prerelease and not version.is_devrelease and version.local is None


@contextmanager
def _try_update_lock(lock_path: Path, current_time: datetime) -> Iterator[bool]:
    """Acquire a cross-process lock atomically without waiting for another command."""
    lock_token = uuid4().hex
    file_descriptor: int | None = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        _remove_stale_lock(lock_path, current_time)
    except OSError as error:
        raise UpdateError(f"Cannot acquire update state lock: {error}") from error
    try:
        file_descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.write(file_descriptor, lock_token.encode("ascii"))
    except FileExistsError:
        yield False
        return
    except OSError as error:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
                lock_path.unlink(missing_ok=True)
        raise UpdateError(f"Cannot acquire update state lock: {error}") from error

    try:
        yield True
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        with suppress(OSError, UnicodeError):
            if lock_path.read_text(encoding="ascii") == lock_token:
                lock_path.unlink(missing_ok=True)


def _remove_stale_lock(lock_path: Path, current_time: datetime) -> None:
    """Remove a lock left behind by a process that exceeded all updater timeouts."""
    try:
        initial_status = lock_path.stat()
    except FileNotFoundError:
        return
    lock_age = current_time.timestamp() - initial_status.st_mtime
    if lock_age <= _STALE_LOCK_AGE.total_seconds():
        return
    try:
        confirmed_status = lock_path.stat()
        if (
            confirmed_status.st_mtime_ns == initial_status.st_mtime_ns
            and confirmed_status.st_size == initial_status.st_size
        ):
            lock_path.unlink(missing_ok=True)
    except FileNotFoundError:
        return


def default_update_state_path() -> Path:
    """Return the cross-platform per-user automatic update state path."""
    return Path.home() / ".config" / "envwitness" / "updates.json"
