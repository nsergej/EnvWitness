from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

from envwitness.infrastructure.processes import resolve_executable, run_bounded_process


def test_resolver_does_not_search_working_directory(project_directory: Path) -> None:
    executable_name = "envwitness-cwd-only.exe" if os.name == "nt" else "envwitness-cwd-only"
    malicious_executable = project_directory / executable_name
    malicious_executable.write_text("malicious", encoding="utf-8")
    malicious_executable.chmod(0o755)

    with pytest.raises(FileNotFoundError, match="explicit PATH"):
        resolve_executable(
            "envwitness-cwd-only",
            working_directory=project_directory,
            environment={"PATH": "", "PATHEXT": ".EXE"},
        )


def test_resolver_accepts_explicit_relative_path(project_directory: Path) -> None:
    executable = project_directory / ("tool.exe" if os.name == "nt" else "tool")
    executable.write_text("tool", encoding="utf-8")
    executable.chmod(0o755)

    resolved = resolve_executable(
        f".{os.sep}{executable.name}",
        working_directory=project_directory,
        environment={"PATH": "", "PATHEXT": ".EXE"},
    )

    assert Path(resolved) == executable.resolve()


def test_process_output_is_retained_with_hard_bounds(project_directory: Path) -> None:
    result = asyncio.run(
        run_bounded_process(
            (
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('o' * 2000000); sys.stderr.write('e' * 2000000)",
            ),
            working_directory=project_directory,
            timeout_seconds=10,
            maximum_standard_output_bytes=1_024,
            maximum_standard_error_bytes=2_048,
        )
    )

    assert result.return_code == 0
    assert len(result.standard_output) == 1_024
    assert len(result.standard_error) == 2_048
    assert result.standard_output_truncated is True
    assert result.standard_error_truncated is True


def test_timeout_terminates_descendant_process(project_directory: Path) -> None:
    marker = project_directory / "descendant-finished"
    child_code = f"import time, pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).touch()"
    parent_code = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "time.sleep(10)"
    )
    started = time.monotonic()

    result = asyncio.run(
        run_bounded_process(
            (sys.executable, "-c", parent_code),
            working_directory=project_directory,
            timeout_seconds=0.5,
            maximum_standard_output_bytes=1_024,
        )
    )
    time.sleep(2.2)

    assert result.timed_out is True
    assert time.monotonic() - started < 5
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object behavior")
def test_timeout_terminates_descendant_after_parent_exits(project_directory: Path) -> None:
    marker = project_directory / "detached-descendant-finished"
    child_code = f"import time, pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).touch()"
    parent_code = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], "
        "stdout=sys.stdout, stderr=sys.stderr)"
    )
    started = time.monotonic()

    result = asyncio.run(
        run_bounded_process(
            (sys.executable, "-c", parent_code),
            working_directory=project_directory,
            timeout_seconds=0.5,
            maximum_standard_output_bytes=1_024,
        )
    )
    elapsed = time.monotonic() - started
    time.sleep(2.2)

    assert result.timed_out is True
    assert elapsed < 2
    assert not marker.exists()


def test_cancellation_terminates_descendant_process(project_directory: Path) -> None:
    marker = project_directory / "cancelled-descendant-finished"
    child_code = f"import time, pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).touch()"
    parent_code = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "time.sleep(10)"
    )

    async def cancel_process() -> None:
        task = asyncio.create_task(
            run_bounded_process(
                (sys.executable, "-c", parent_code),
                working_directory=project_directory,
                timeout_seconds=10,
                maximum_standard_output_bytes=1_024,
            )
        )
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_process())
    time.sleep(2.2)

    assert not marker.exists()
