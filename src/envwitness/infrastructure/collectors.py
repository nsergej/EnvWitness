"""Cross-platform built-in collectors and bounded subprocess execution."""

from __future__ import annotations

import asyncio
import hashlib
import locale
import os
import platform
import re
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

from envwitness.application.ports import CaptureContext, CollectedFact, CommandResult
from envwitness.domain.errors import CaptureError
from envwitness.domain.models import CommandExecution, Sensitivity, utc_now
from envwitness.infrastructure.config import RuntimeProbeConfiguration

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
        if shutil.which("git") is None:
            return [
                _collected_fact(
                    key="git.available",
                    value=False,
                    collector=self.name,
                    source="executable discovery",
                    sensitivity=Sensitivity.PUBLIC,
                )
            ]
        inside = await self._git(context.project_root, "rev-parse", "--is-inside-work-tree")
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
            self._git(context.project_root, "branch", "--show-current"),
            self._git(context.project_root, "rev-parse", "HEAD"),
            self._git(context.project_root, "status", "--porcelain=v1", "--untracked-files=normal"),
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

    async def _git(self, project_root: Path, *arguments: str) -> str:
        """Run one bounded Git query without shell interpretation."""
        process = await asyncio.create_subprocess_exec(
            "git",
            "-c",
            "core.quotepath=false",
            *arguments,
            cwd=project_root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            standard_output, _ = await asyncio.wait_for(process.communicate(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()
            return ""
        if process.returncode != 0:
            return ""
        return standard_output[:1_048_576].decode("utf-8", errors="replace")


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
            digest = await asyncio.to_thread(self._hash_file, candidate, 33_554_432)
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
            candidate = self._resolve_project_file(context.project_root, configured_path)
            content = await asyncio.to_thread(
                self._read_text_file,
                candidate,
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
    def _hash_file(path: Path, maximum_bytes: int) -> str:
        """Hash a regular file while enforcing a strict input-size limit."""
        if path.stat().st_size > maximum_bytes:
            raise CaptureError(f"Fingerprint file exceeds {maximum_bytes} bytes: {path.name}")
        digest = hashlib.sha256()
        with path.open("rb") as file_handle:
            while chunk := file_handle.read(65_536):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _resolve_project_file(project_root: Path, configured_path: str) -> Path:
        """Resolve a configured path and prevent traversal through symlinks."""
        candidate = (project_root / configured_path).resolve(strict=True)
        try:
            candidate.relative_to(project_root)
        except ValueError as error:
            raise CaptureError(
                f"Allowed file escapes the project root: {configured_path}"
            ) from error
        if not candidate.is_file():
            raise CaptureError(f"Allowed path is not a regular file: {configured_path}")
        return candidate

    @staticmethod
    def _read_text_file(path: Path, maximum_bytes: int) -> str:
        """Read bounded UTF-8 text and reject binary or undecodable content."""
        if path.stat().st_size > maximum_bytes:
            raise CaptureError(f"Allowed file exceeds the output limit: {path.name}")
        raw_content = path.read_bytes()
        if b"\x00" in raw_content:
            raise CaptureError(f"Allowed file appears to be binary: {path.name}")
        try:
            return raw_content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CaptureError(f"Allowed file is not UTF-8 text: {path.name}") from error


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
        del context
        results = await asyncio.gather(*(self._probe(probe) for probe in self._probes))
        return [fact for result in results for fact in result]

    async def _probe(self, probe: RuntimeProbeConfiguration) -> list[CollectedFact]:
        """Run one probe without shell interpretation or inherited standard input."""
        executable = shutil.which(probe.command[0])
        available_key = f"runtime.{probe.name}.available"
        if executable is None:
            return [
                _collected_fact(
                    key=available_key,
                    value=False,
                    collector=self.name,
                    source=f"executable discovery for {probe.command[0]}",
                    sensitivity=Sensitivity.PUBLIC,
                )
            ]
        process = await asyncio.create_subprocess_exec(
            executable,
            *probe.command[1:],
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            standard_output, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=probe.timeout_seconds,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            output = "probe timed out"
        else:
            output = standard_output[:65_536].decode("utf-8", errors="replace").strip()
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
            process = await asyncio.create_subprocess_exec(
                *arguments,
                cwd=working_directory,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as error:
            raise CaptureError(f"Cannot start captured command: {error}") from error

        standard_output_task = asyncio.create_task(
            self._read_bounded(process.stdout, maximum_output_bytes)
        )
        standard_error_task = asyncio.create_task(
            self._read_bounded(process.stderr, maximum_output_bytes)
        )
        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
        except TimeoutError:
            timed_out = True
            process.kill()
            await process.wait()
        standard_output, output_truncated = await standard_output_task
        standard_error, error_truncated = await standard_error_task
        finished_at = datetime.now(UTC)
        duration_milliseconds = max(0, round((time.monotonic() - monotonic_start) * 1_000))
        execution = CommandExecution(
            arguments=arguments,
            working_directory=working_directory.name,
            started_at=started_at,
            finished_at=finished_at,
            duration_milliseconds=duration_milliseconds,
            exit_code=-1 if timed_out else int(process.returncode or 0),
            timed_out=timed_out,
            output_truncated=output_truncated or error_truncated,
        )
        return CommandResult(
            execution=execution,
            standard_output=standard_output,
            standard_error=standard_error,
        )

    @staticmethod
    async def _read_bounded(
        stream: asyncio.StreamReader | None,
        maximum_bytes: int,
    ) -> tuple[str, bool]:
        """Drain a stream completely while retaining at most the configured bytes."""
        if stream is None:
            return "", False
        chunks: list[bytes] = []
        retained_bytes = 0
        truncated = False
        while True:
            chunk = await stream.read(65_536)
            if not chunk:
                break
            remaining = maximum_bytes - retained_bytes
            if remaining > 0:
                retained = chunk[:remaining]
                chunks.append(retained)
                retained_bytes += len(retained)
            if len(chunk) > max(remaining, 0):
                truncated = True
        return b"".join(chunks).decode("utf-8", errors="replace"), truncated
