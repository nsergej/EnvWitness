"""Secure executable discovery and resource-bounded subprocess execution."""

from __future__ import annotations

import asyncio
import ctypes
import os
import signal
import subprocess
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    """Completed subprocess output and resource-limit state."""

    standard_output: bytes
    standard_error: bytes
    return_code: int
    timed_out: bool
    standard_output_truncated: bool
    standard_error_truncated: bool

    @property
    def output_limit_exceeded(self) -> bool:
        """Return whether either output stream exceeded its retention limit."""
        return self.standard_output_truncated or self.standard_error_truncated


@dataclass(slots=True)
class _WindowsJob:
    """Own a Windows Job Object that terminates every assigned process on close."""

    handle: int | None

    def close(self) -> None:  # pragma: no cover - Windows API implementation
        """Close the job exactly once and trigger its kill-on-close policy."""
        if self.handle is None:
            return
        handle = self.handle
        self.handle = None
        with suppress(AttributeError, OSError, ValueError):
            _platform_attribute(ctypes, "windll").kernel32.CloseHandle(ctypes.c_void_p(handle))


def _platform_attribute(module: ModuleType, name: str) -> Any:
    """Return an operating-system-specific module attribute for the active platform."""
    return vars(module)[name]


def resolve_executable(
    command: str,
    *,
    working_directory: Path,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Resolve an executable without implicitly searching the working directory.

    Bare commands are searched only in non-empty absolute directories explicitly
    listed in ``PATH``. Commands containing a path separator are treated as an
    explicit operator choice and resolved relative to ``working_directory``.

    Args:
        command: Executable name or explicit path.
        working_directory: Base directory for explicitly relative executable paths.
        environment: Environment whose ``PATH`` and ``PATHEXT`` control discovery.

    Returns:
        Absolute path to a regular executable file.

    Raises:
        FileNotFoundError: If no permitted executable can be resolved.
        ValueError: If the command is empty or contains a null byte.
    """
    if not command or "\x00" in command:
        raise ValueError("Executable name must be non-empty and cannot contain nulls")
    effective_environment = os.environ if environment is None else environment
    command_path = Path(command)
    has_separator = any(separator in command for separator in ("/", "\\"))
    if command_path.is_absolute() or has_separator:
        base_path = command_path if command_path.is_absolute() else working_directory / command_path
        resolved = _first_executable_candidate(base_path, effective_environment)
        if resolved is not None:
            return str(resolved)
        raise FileNotFoundError(f"Explicit executable does not exist: {command}")

    path_value = effective_environment.get("PATH", "")
    for raw_directory in path_value.split(os.pathsep):
        if not raw_directory.strip():
            continue
        directory = Path(raw_directory).expanduser()
        if not directory.is_absolute():
            continue
        resolved = _first_executable_candidate(directory / command, effective_environment)
        if resolved is not None:
            return str(resolved)
    raise FileNotFoundError(f"Executable is unavailable on the explicit PATH: {command}")


def _first_executable_candidate(
    base_path: Path,
    environment: Mapping[str, str],
) -> Path | None:
    """Return the first platform-compatible executable candidate for a base path."""
    candidates = [base_path]
    if os.name == "nt":
        path_extensions = environment.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
        normalized_extensions = tuple(
            extension.lower() for extension in path_extensions if extension.startswith(".")
        )
        if base_path.suffix.lower() not in normalized_extensions:
            candidates.extend(
                Path(f"{base_path}{extension}")
                for extension in path_extensions
                if extension.startswith(".")
            )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_file():
            continue
        if os.name != "nt" and not os.access(resolved, os.X_OK):
            continue
        return resolved
    return None


async def run_bounded_process(  # noqa: PLR0912
    arguments: tuple[str, ...],
    *,
    working_directory: Path,
    timeout_seconds: float,
    maximum_standard_output_bytes: int,
    maximum_standard_error_bytes: int | None = None,
    input_bytes: bytes | None = None,
    environment: Mapping[str, str] | None = None,
    terminate_on_output_limit: bool = False,
) -> BoundedProcessResult:
    """Run one process with bounded streams and deterministic tree cleanup.

    The timeout covers process execution, standard-input delivery, and complete
    pipe closure. On POSIX the child starts in a new process group. On Windows,
    cleanup uses the system ``taskkill`` binary with tree termination. Cancellation
    always performs the same bounded cleanup before propagating.

    Args:
        arguments: Non-empty argument vector; no shell interpretation is used.
        working_directory: Existing process working directory.
        timeout_seconds: Positive wall-clock limit for the complete operation.
        maximum_standard_output_bytes: Maximum retained standard-output bytes.
        maximum_standard_error_bytes: Maximum retained standard-error bytes.
        input_bytes: Optional bytes written to standard input before it is closed.
        environment: Optional complete child environment.
        terminate_on_output_limit: Stop the process as soon as either limit is exceeded.

    Returns:
        Process result with retained output and limit flags.

    Raises:
        FileNotFoundError: If executable discovery fails.
        OSError: If the process cannot be started.
        ValueError: If arguments or limits are invalid.
        asyncio.CancelledError: After the child process tree has been terminated.
    """
    if not arguments:
        raise ValueError("Process argument vector cannot be empty")
    if timeout_seconds <= 0:
        raise ValueError("Process timeout must be positive")
    if maximum_standard_output_bytes < 0:
        raise ValueError("Standard-output limit cannot be negative")
    standard_error_limit = (
        maximum_standard_output_bytes
        if maximum_standard_error_bytes is None
        else maximum_standard_error_bytes
    )
    if standard_error_limit < 0:
        raise ValueError("Standard-error limit cannot be negative")

    resolved_working_directory = await asyncio.to_thread(
        _validated_working_directory,
        working_directory,
    )
    executable = resolve_executable(
        arguments[0],
        working_directory=resolved_working_directory,
        environment=environment,
    )
    resolved_arguments = (executable, *arguments[1:])
    process_options: dict[str, Any] = {}
    if os.name == "nt":
        process_options["creationflags"] = _platform_attribute(
            subprocess,
            "CREATE_NEW_PROCESS_GROUP",
        )
    else:
        process_options["start_new_session"] = True

    process = await asyncio.create_subprocess_exec(
        *resolved_arguments,
        cwd=resolved_working_directory,
        env=None if environment is None else dict(environment),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **process_options,
    )
    windows_job = _create_windows_kill_on_close_job(process.pid)
    overflow_event = asyncio.Event()
    standard_output_task = asyncio.create_task(
        _read_bounded_stream(
            process.stdout,
            maximum_standard_output_bytes,
            overflow_event,
        )
    )
    standard_error_task = asyncio.create_task(
        _read_bounded_stream(process.stderr, standard_error_limit, overflow_event)
    )
    input_task = asyncio.create_task(_write_input(process, input_bytes))
    wait_task = asyncio.create_task(process.wait())

    async def await_complete() -> None:
        """Wait until process, input, and both output pipes are complete."""
        await asyncio.gather(wait_task, input_task, standard_output_task, standard_error_task)

    completion_task = asyncio.create_task(await_complete())
    overflow_task: asyncio.Task[bool] | None = None
    timed_out = False
    stopped_for_output = False
    try:
        if terminate_on_output_limit:
            overflow_task = asyncio.create_task(_wait_for_event(overflow_event))
            done, _ = await asyncio.wait(
                {completion_task, overflow_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                timed_out = True
            elif overflow_task in done and not completion_task.done():
                stopped_for_output = True
            else:
                await completion_task
        else:
            try:
                await asyncio.wait_for(asyncio.shield(completion_task), timeout=timeout_seconds)
            except TimeoutError:
                timed_out = True

        if timed_out or stopped_for_output:
            await _terminate_process_tree(process, windows_job)
            await _finish_cleanup(
                process,
                (completion_task, wait_task, input_task, standard_output_task, standard_error_task),
            )
    except asyncio.CancelledError:
        await _terminate_process_tree(process, windows_job)
        await _finish_cleanup(
            process,
            (completion_task, wait_task, input_task, standard_output_task, standard_error_task),
        )
        raise
    finally:
        if overflow_task is not None:
            overflow_task.cancel()
            await asyncio.gather(overflow_task, return_exceptions=True)
        if windows_job is not None:
            windows_job.close()

    standard_output, standard_output_truncated = _stream_task_result(standard_output_task)
    standard_error, standard_error_truncated = _stream_task_result(standard_error_task)
    if (
        stopped_for_output
        and overflow_event.is_set()
        and not (standard_output_truncated or standard_error_truncated)
    ):
        standard_output_truncated = True
    return BoundedProcessResult(
        standard_output=standard_output,
        standard_error=standard_error,
        return_code=-1 if timed_out else int(process.returncode or 0),
        timed_out=timed_out,
        standard_output_truncated=standard_output_truncated,
        standard_error_truncated=standard_error_truncated,
    )


async def _wait_for_event(event: asyncio.Event) -> bool:
    """Wait for an event and return a task-compatible sentinel."""
    await event.wait()
    return True


def _validated_working_directory(working_directory: Path) -> Path:
    """Resolve and validate a process working directory outside the event loop."""
    resolved = working_directory.resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(
            f"Process working directory is not a directory: {working_directory}"
        )
    return resolved


async def _read_bounded_stream(
    stream: asyncio.StreamReader | None,
    maximum_bytes: int,
    overflow_event: asyncio.Event,
) -> tuple[bytes, bool]:
    """Drain a stream while retaining no more than its configured byte limit."""
    if stream is None:
        return b"", False
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
            overflow_event.set()
    return b"".join(chunks), truncated


async def _write_input(process: asyncio.subprocess.Process, input_bytes: bytes | None) -> None:
    """Write optional process input and close its pipe without leaking broken-pipe errors."""
    if process.stdin is None:
        return
    try:
        if input_bytes:
            process.stdin.write(input_bytes)
            await process.stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        process.stdin.close()
        with suppress(BrokenPipeError, ConnectionResetError):
            await process.stdin.wait_closed()


async def _terminate_process_tree(
    process: asyncio.subprocess.Process,
    windows_job: _WindowsJob | None,
) -> None:
    """Terminate a process tree using platform-native stdlib-accessible facilities."""
    if os.name == "nt":
        if windows_job is not None:
            windows_job.close()
        taskkill_path = _windows_taskkill_path()
        if taskkill_path is not None:
            try:
                taskkill = await asyncio.create_subprocess_exec(
                    str(taskkill_path),
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    creationflags=_platform_attribute(subprocess, "CREATE_NO_WINDOW"),
                )
                try:
                    await asyncio.wait_for(taskkill.wait(), timeout=2)
                except TimeoutError:
                    taskkill.kill()
                    await taskkill.wait()
            except OSError:
                pass
    else:
        kill_process_group = _platform_attribute(os, "killpg")
        with suppress(ProcessLookupError, PermissionError):
            kill_process_group(process.pid, signal.SIGTERM)
        await asyncio.sleep(0.1)
        with suppress(ProcessLookupError, PermissionError):
            kill_process_group(process.pid, _platform_attribute(signal, "SIGKILL"))
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
    try:
        await asyncio.wait_for(process.wait(), timeout=2)
    except TimeoutError:
        _close_process_transport(process)


def _create_windows_kill_on_close_job(  # noqa: PLR0911
    process_identifier: int,
) -> _WindowsJob | None:  # pragma: no cover - Windows API implementation
    """Assign a new Windows process to a kill-on-close Job Object when possible."""
    if os.name != "nt":
        return None

    class BasicLimitInformation(ctypes.Structure):
        """ctypes layout for JOBOBJECT_BASIC_LIMIT_INFORMATION."""

        _fields_ = [
            ("per_process_user_time_limit", ctypes.c_int64),
            ("per_job_user_time_limit", ctypes.c_int64),
            ("limit_flags", ctypes.c_uint32),
            ("minimum_working_set_size", ctypes.c_size_t),
            ("maximum_working_set_size", ctypes.c_size_t),
            ("active_process_limit", ctypes.c_uint32),
            ("affinity", ctypes.c_size_t),
            ("priority_class", ctypes.c_uint32),
            ("scheduling_class", ctypes.c_uint32),
        ]

    class IoCounters(ctypes.Structure):
        """ctypes layout for IO_COUNTERS."""

        _fields_ = [
            ("read_operation_count", ctypes.c_uint64),
            ("write_operation_count", ctypes.c_uint64),
            ("other_operation_count", ctypes.c_uint64),
            ("read_transfer_count", ctypes.c_uint64),
            ("write_transfer_count", ctypes.c_uint64),
            ("other_transfer_count", ctypes.c_uint64),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        """ctypes layout for JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""

        _fields_ = [
            ("basic_limit_information", BasicLimitInformation),
            ("io_info", IoCounters),
            ("process_memory_limit", ctypes.c_size_t),
            ("job_memory_limit", ctypes.c_size_t),
            ("peak_process_memory_used", ctypes.c_size_t),
            ("peak_job_memory_used", ctypes.c_size_t),
        ]

    try:
        kernel32 = _platform_attribute(ctypes, "windll").kernel32
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        kernel32.AssignProcessToJobObject.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)

        job_handle = kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            return None
        job = _WindowsJob(handle=int(job_handle))
        information = ExtendedLimitInformation()
        information.basic_limit_information.limit_flags = 0x00002000
        configured = kernel32.SetInformationJobObject(
            ctypes.c_void_p(job.handle),
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        if not configured:
            job.close()
            return None

        process_access = 0x0001 | 0x0100
        process_handle = kernel32.OpenProcess(process_access, False, process_identifier)
        if not process_handle:
            job.close()
            return None
        try:
            assigned = kernel32.AssignProcessToJobObject(
                ctypes.c_void_p(job.handle),
                ctypes.c_void_p(process_handle),
            )
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(process_handle))
        if not assigned:
            job.close()
            return None
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    else:
        return job


def _windows_taskkill_path() -> Path | None:  # pragma: no cover - Windows API implementation
    """Return the trusted Windows system taskkill path without PATH discovery."""
    if os.name != "nt":
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32_768)
        length = _platform_attribute(ctypes, "windll").kernel32.GetSystemDirectoryW(
            buffer,
            len(buffer),
        )
        if length <= 0 or length >= len(buffer):
            return None
        candidate = Path(buffer.value) / "taskkill.exe"
        return candidate if candidate.is_file() else None
    except (AttributeError, OSError, ValueError):
        return None


async def _finish_cleanup(
    process: asyncio.subprocess.Process,
    tasks: tuple[asyncio.Task[object], ...],
) -> None:
    """Bound cleanup time, then cancel readers and close the subprocess transport."""
    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=2)
    except TimeoutError:
        for task in tasks:
            task.cancel()
        _close_process_transport(process)
        await asyncio.gather(*tasks, return_exceptions=True)


def _close_process_transport(process: asyncio.subprocess.Process) -> None:
    """Close the asyncio subprocess transport when ordinary cleanup cannot finish."""
    transport = getattr(process, "_transport", None)
    if transport is not None:
        transport.close()


def _stream_task_result(task: asyncio.Task[tuple[bytes, bool]]) -> tuple[bytes, bool]:
    """Return a completed reader result or a conservative truncated fallback."""
    if task.done() and not task.cancelled():
        try:
            return task.result()
        except (OSError, RuntimeError):
            return b"", True
    return b"", True
