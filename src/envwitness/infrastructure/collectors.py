"""Cross-platform built-in collectors and bounded subprocess execution."""

from __future__ import annotations

import asyncio
import hashlib
import locale
import os
import platform
import re
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from envwitness.application.ports import CaptureContext, CollectedFact, CommandResult
from envwitness.domain.errors import CaptureError
from envwitness.domain.models import CommandExecution, Sensitivity, utc_now
from envwitness.infrastructure.config import RuntimeProbeConfiguration
from envwitness.infrastructure.processes import resolve_executable, run_bounded_process

DEFAULT_FINGERPRINT_FILES = (
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "composer.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
)


def _collected_fact(
    *,
    key: str,
    value: str | int | bool | list[str] | dict[str, str],
    collector: str,
    source: str,
    sensitivity: Sensitivity,
) -> CollectedFact:
    """Create a timestamped raw fact with consistent capture semantics."""
    return CollectedFact(
        key=key,
        value=value,
        collector=collector,
        source=source,
        sensitivity=sensitivity,
        captured_at=utc_now(),
    )


def _safe_key_fragment(value: str) -> str:
    """Convert a name or relative path into a stable semantic-key fragment."""
    normalized = re.sub(r"[^a-z0-9]+", ".", value.lower()).strip(".")
    if not normalized:
        return "unnamed"
    return normalized[:120]


class SystemCollector:
    """Collect non-identifying operating system and interpreter facts."""

    @property
    def name(self) -> str:
        """Return the stable collector identifier."""
        return "system"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Collect portable system facts without hostname or user identity."""
        del context
        locale_name = locale.getlocale()[0] or "unknown"
        return [
            _collected_fact(
                key="system.operating_system",
                value=platform.system() or "unknown",
                collector=self.name,
                source="platform.system",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="system.release",
                value=platform.release() or "unknown",
                collector=self.name,
                source="platform.release",
                sensitivity=Sensitivity.INTERNAL,
            ),
            _collected_fact(
                key="system.architecture",
                value=platform.machine() or "unknown",
                collector=self.name,
                source="platform.machine",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="system.python",
                value=platform.python_version(),
                collector=self.name,
                source="platform.python_version",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="system.locale",
                value=locale_name,
                collector=self.name,
                source="locale.getlocale",
                sensitivity=Sensitivity.INTERNAL,
            ),
            _collected_fact(
                key="system.timezone",
                value=datetime.now().astimezone().tzname() or "unknown",
                collector=self.name,
                source="local timezone name",
                sensitivity=Sensitivity.INTERNAL,
            ),
        ]


class EnvironmentCollector:
    """Collect environment names and only explicitly allowlisted values."""

    def __init__(self, *, include_names: bool = True) -> None:
        """Configure whether variable names are included as one aggregate fact."""
        self._include_names = include_names

    @property
    def name(self) -> str:
        """Return the stable collector identifier."""
        return "environment"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Collect names by default and allowlisted values by exact key match."""
        facts: list[CollectedFact] = []
        if self._include_names:
            facts.append(
                _collected_fact(
                    key="environment.variable_names",
                    value=sorted(os.environ),
                    collector=self.name,
                    source="process environment keys only",
                    sensitivity=Sensitivity.INTERNAL,
                )
            )
        for variable_name in context.environment_value_allowlist:
            if variable_name not in os.environ:
                continue
            facts.append(
                _collected_fact(
                    key=f"environment.value.{_safe_key_fragment(variable_name)}",
                    value=os.environ[variable_name],
                    collector=self.name,
                    source=f"explicitly allowlisted environment variable {variable_name}",
                    sensitivity=Sensitivity.SENSITIVE,
                )
            )
        return facts


class GitCollector:
    """Collect source identity without remote URLs, author data, or patch content."""

    @property
    def name(self) -> str:
        """Return the stable collector identifier."""
        return "git"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Collect commit, branch, and dirty state when the project uses Git."""
        try:
            executable = resolve_executable("git", working_directory=context.project_root)
        except (FileNotFoundError, ValueError):
            return [
                _collected_fact(
                    key="git.available",
                    value=False,
                    collector=self.name,
                    source="executable discovery",
                    sensitivity=Sensitivity.PUBLIC,
                )
            ]
        maximum_output_bytes = min(context.maximum_output_bytes, 1_048_576)
        inside = await self._git(
            executable,
            context.project_root,
            maximum_output_bytes,
            "rev-parse",
            "--is-inside-work-tree",
        )
        if inside.strip().lower() != "true":
            return [
                _collected_fact(
                    key="git.available",
                    value=True,
                    collector=self.name,
                    source="git rev-parse",
                    sensitivity=Sensitivity.PUBLIC,
                ),
                _collected_fact(
                    key="git.repository",
                    value=False,
                    collector=self.name,
                    source="git rev-parse --is-inside-work-tree",
                    sensitivity=Sensitivity.PUBLIC,
                ),
            ]
        branch, commit, status = await asyncio.gather(
            self._git(
                executable,
                context.project_root,
                maximum_output_bytes,
                "branch",
                "--show-current",
            ),
            self._git(executable, context.project_root, maximum_output_bytes, "rev-parse", "HEAD"),
            self._git(
                executable,
                context.project_root,
                maximum_output_bytes,
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
            ),
        )
        changed_count = sum(1 for line in status.splitlines() if line.strip())
        return [
            _collected_fact(
                key="git.available",
                value=True,
                collector=self.name,
                source="executable discovery",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="git.repository",
                value=True,
                collector=self.name,
                source="git rev-parse --is-inside-work-tree",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="git.branch",
                value=branch.strip() or "detached",
                collector=self.name,
                source="git branch --show-current",
                sensitivity=Sensitivity.INTERNAL,
            ),
            _collected_fact(
                key="git.commit",
                value=commit.strip(),
                collector=self.name,
                source="git rev-parse HEAD",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="git.dirty",
                value=changed_count > 0,
                collector=self.name,
                source="git status --porcelain=v1",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key="git.changed_path_count",
                value=changed_count,
                collector=self.name,
                source="count of git status entries; paths excluded",
                sensitivity=Sensitivity.PUBLIC,
            ),
        ]

    async def _git(
        self,
        executable: str,
        project_root: Path,
        maximum_output_bytes: int,
        *arguments: str,
    ) -> str:
        """Run one bounded Git query without shell interpretation."""
        result = await run_bounded_process(
            (executable, "-c", "core.quotepath=false", *arguments),
            working_directory=project_root,
            timeout_seconds=5,
            maximum_standard_output_bytes=maximum_output_bytes,
            maximum_standard_error_bytes=4_096,
            terminate_on_output_limit=True,
        )
        if result.timed_out or result.return_code != 0:
            return ""
        output = result.standard_output.decode("utf-8", errors="replace")
        if result.standard_output_truncated:
            return output + "\n__envwitness_output_truncated__"
        return output


class FileFingerprintCollector:
    """Hash dependency inputs and disclose explicitly allowlisted text files."""

    @property
    def name(self) -> str:
        """Return the stable collector identifier."""
        return "file"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Collect root-level lockfile hashes and approved bounded text content."""
        facts: list[CollectedFact] = []
        for file_name in DEFAULT_FINGERPRINT_FILES:
            candidate = context.project_root / file_name
            if not candidate.is_file():
                continue
            digest = await asyncio.to_thread(
                self._hash_project_file,
                context.project_root,
                file_name,
                33_554_432,
            )
            facts.append(
                _collected_fact(
                    key=f"file.hash.{_safe_key_fragment(file_name)}",
                    value=digest,
                    collector=self.name,
                    source=f"SHA-256 of project file {file_name}",
                    sensitivity=Sensitivity.PUBLIC,
                )
            )
        for configured_path in context.file_content_allowlist:
            content = await asyncio.to_thread(
                self._read_project_text_file,
                context.project_root,
                configured_path,
                context.maximum_output_bytes,
            )
            facts.append(
                _collected_fact(
                    key=f"file.content.{_safe_key_fragment(configured_path)}",
                    value=content,
                    collector=self.name,
                    source=f"explicitly allowlisted project file {configured_path}",
                    sensitivity=Sensitivity.SENSITIVE,
                )
            )
        return facts

    @staticmethod
    def _hash_project_file(
        project_root: Path,
        configured_path: str,
        maximum_bytes: int,
    ) -> str:
        """Hash a verified project file while enforcing a streaming size limit."""
        digest = hashlib.sha256()
        bytes_read = 0
        with FileFingerprintCollector._open_verified_project_file(
            project_root,
            configured_path,
        ) as file_handle:
            while chunk := file_handle.read(min(65_536, maximum_bytes - bytes_read + 1)):
                bytes_read += len(chunk)
                if bytes_read > maximum_bytes:
                    raise CaptureError(
                        f"Fingerprint file exceeds {maximum_bytes} bytes: {configured_path}"
                    )
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _open_verified_project_file(project_root: Path, configured_path: str) -> BinaryIO:
        """Open first, then verify containment and path-to-handle identity."""
        relative_path = Path(configured_path)
        if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts:
            raise CaptureError(f"Allowed file path is invalid: {configured_path}")
        resolved_root = project_root.resolve(strict=True)
        candidate = project_root / relative_path
        try:
            file_handle = candidate.open("rb")
        except OSError as error:
            raise CaptureError(f"Cannot open project file: {configured_path}") from error
        try:
            resolved_candidate = candidate.resolve(strict=True)
            resolved_candidate.relative_to(resolved_root)
            handle_status = os.fstat(file_handle.fileno())
            path_status = resolved_candidate.stat()
        except (OSError, RuntimeError, ValueError) as error:
            file_handle.close()
            raise CaptureError(
                f"Allowed file escapes the project root: {configured_path}"
            ) from error
        if not stat.S_ISREG(handle_status.st_mode) or not stat.S_ISREG(path_status.st_mode):
            file_handle.close()
            raise CaptureError(f"Allowed path is not a regular file: {configured_path}")
        if (handle_status.st_dev, handle_status.st_ino) != (
            path_status.st_dev,
            path_status.st_ino,
        ):
            file_handle.close()
            raise CaptureError(f"Allowed file changed while it was being opened: {configured_path}")
        return file_handle

    @staticmethod
    def _read_project_text_file(
        project_root: Path,
        configured_path: str,
        maximum_bytes: int,
    ) -> str:
        """Read bounded UTF-8 text and reject binary or undecodable content."""
        with FileFingerprintCollector._open_verified_project_file(
            project_root,
            configured_path,
        ) as file_handle:
            raw_content = file_handle.read(maximum_bytes + 1)
        if len(raw_content) > maximum_bytes:
            raise CaptureError(f"Allowed file exceeds the output limit: {configured_path}")
        if b"\x00" in raw_content:
            raise CaptureError(f"Allowed file appears to be binary: {configured_path}")
        try:
            return raw_content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CaptureError(f"Allowed file is not UTF-8 text: {configured_path}") from error


class RuntimeCollector:
    """Run explicitly configured, short-lived runtime version probes."""

    def __init__(self, probes: tuple[RuntimeProbeConfiguration, ...]) -> None:
        """Store validated runtime probes."""
        self._probes = probes

    @property
    def name(self) -> str:
        """Return the stable collector identifier."""
        return "runtime"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Execute probes concurrently and report availability plus bounded output."""
        results = await asyncio.gather(*(self._probe(probe, context) for probe in self._probes))
        return [fact for result in results for fact in result]

    async def _probe(
        self,
        probe: RuntimeProbeConfiguration,
        context: CaptureContext,
    ) -> list[CollectedFact]:
        """Run one probe without shell interpretation or inherited standard input."""
        available_key = f"runtime.{probe.name}.available"
        try:
            executable = resolve_executable(
                probe.command[0],
                working_directory=context.project_root,
            )
        except (FileNotFoundError, ValueError):
            return [
                _collected_fact(
                    key=available_key,
                    value=False,
                    collector=self.name,
                    source=f"executable discovery for {probe.command[0]}",
                    sensitivity=Sensitivity.PUBLIC,
                )
            ]
        result = await run_bounded_process(
            (executable, *probe.command[1:]),
            working_directory=context.project_root,
            timeout_seconds=probe.timeout_seconds,
            maximum_standard_output_bytes=context.maximum_output_bytes,
            maximum_standard_error_bytes=context.maximum_output_bytes,
            terminate_on_output_limit=True,
        )
        if result.timed_out:
            output = "probe timed out"
        else:
            combined_output = result.standard_output + result.standard_error
            output = (
                combined_output[: context.maximum_output_bytes]
                .decode("utf-8", errors="replace")
                .strip()
            )
            if result.output_limit_exceeded:
                output += " [output truncated]"
        return [
            _collected_fact(
                key=available_key,
                value=True,
                collector=self.name,
                source=f"executable discovery for {probe.command[0]}",
                sensitivity=Sensitivity.PUBLIC,
            ),
            _collected_fact(
                key=f"runtime.{probe.name}.version",
                value=output,
                collector=self.name,
                source="argument-vector probe: " + " ".join(probe.command),
                sensitivity=Sensitivity.PUBLIC,
            ),
        ]


class AsyncCommandRunner:
    """Execute a command with bounded output, timeout, and no shell."""

    async def run(
        self,
        arguments: tuple[str, ...],
        working_directory: Path,
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> CommandResult:
        """Run a process and drain both output streams without unbounded buffering."""
        started_at = datetime.now(UTC)
        monotonic_start = time.monotonic()
        try:
            result = await run_bounded_process(
                arguments,
                working_directory=working_directory,
                timeout_seconds=timeout_seconds,
                maximum_standard_output_bytes=maximum_output_bytes,
                maximum_standard_error_bytes=maximum_output_bytes,
            )
        except (FileNotFoundError, OSError, ValueError) as error:
            raise CaptureError(f"Cannot start captured command: {error}") from error
        finished_at = datetime.now(UTC)
        duration_milliseconds = max(0, round((time.monotonic() - monotonic_start) * 1_000))
        execution = CommandExecution(
            arguments=arguments,
            working_directory=working_directory.name,
            started_at=started_at,
            finished_at=finished_at,
            duration_milliseconds=duration_milliseconds,
            exit_code=result.return_code,
            timed_out=result.timed_out,
            output_truncated=result.output_limit_exceeded,
        )
        return CommandResult(
            execution=execution,
            standard_output=result.standard_output.decode("utf-8", errors="replace"),
            standard_error=result.standard_error.decode("utf-8", errors="replace"),
        )
