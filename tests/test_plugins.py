from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from envwitness.application.ports import CaptureContext
from envwitness.domain.errors import PluginError
from envwitness.infrastructure.config import PluginConfiguration
from envwitness.infrastructure.plugins import ProcessPluginCollector, enabled_plugin_collectors


def write_plugin(path: Path, response: dict[str, object], *, exit_code: int = 0) -> Path:
    script = path / "plugin.py"
    script.write_text(
        "import json, sys\n"
        "request = json.load(sys.stdin)\n"
        f"print(json.dumps({response!r}))\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return script


def write_raw_plugin(path: Path, standard_output: bytes, *, standard_error: bytes = b"") -> Path:
    script = path / "raw_plugin.py"
    script.write_text(
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        f"sys.stdout.buffer.write({standard_output!r})\n"
        f"sys.stderr.buffer.write({standard_error!r})\n",
        encoding="utf-8",
    )
    return script


def plugin_context(
    project_directory: Path,
    *,
    maximum_output_bytes: int = 4_096,
) -> CaptureContext:
    return CaptureContext(
        project_root=project_directory,
        maximum_output_bytes=maximum_output_bytes,
    )


def test_plugin_collects_namespaced_fact(project_directory: Path) -> None:
    response = {
        "protocol_version": "1.0",
        "facts": [
            {
                "key": "plugin.demo.version",
                "value": "1.2.3",
                "source": "demo plugin",
                "sensitivity": "public",
            }
        ],
    }
    script = write_plugin(project_directory, response)
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
    )
    facts = asyncio.run(
        ProcessPluginCollector(configuration).collect(plugin_context(project_directory))
    )
    assert facts[0].key == "plugin.demo.version"
    assert facts[0].collector == "plugin.demo"


def test_plugin_rejects_key_outside_namespace(project_directory: Path) -> None:
    response = {
        "protocol_version": "1.0",
        "facts": [{"key": "system.fake", "value": True, "source": "bad", "sensitivity": "public"}],
    }
    script = write_plugin(project_directory, response)
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
    )
    with pytest.raises(PluginError, match="must begin"):
        asyncio.run(
            ProcessPluginCollector(configuration).collect(plugin_context(project_directory))
        )


def test_plugin_nonzero_exit_is_reported(project_directory: Path) -> None:
    script = write_plugin(project_directory, {"protocol_version": "1.0", "facts": []}, exit_code=2)
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
    )
    with pytest.raises(PluginError, match="exited with 2"):
        asyncio.run(
            ProcessPluginCollector(configuration).collect(plugin_context(project_directory))
        )


def test_plugin_error_never_includes_standard_error_secret(project_directory: Path) -> None:
    secret = "ENVWITNESS_PLUGIN_SECRET_42"
    script = project_directory / "failed_plugin.py"
    script.write_text(
        f"import sys\nsys.stdin.buffer.read()\nsys.stderr.write({secret!r})\nraise SystemExit(7)\n",
        encoding="utf-8",
    )
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
    )

    with pytest.raises(PluginError, match="exited with 7") as captured_error:
        asyncio.run(
            ProcessPluginCollector(configuration).collect(plugin_context(project_directory))
        )

    assert secret not in str(captured_error.value)


@pytest.mark.parametrize(
    "response",
    [
        b'{"protocol_version":"1.0","protocol_version":"1.0","facts":[]}',
        b'{"protocol_version":"1.0","facts":[{"key":"plugin.demo.value",'
        b'"value":NaN,"source":"test","sensitivity":"public"}]}',
        b"\xff",
    ],
)
def test_plugin_rejects_ambiguous_or_non_utf8_json(
    project_directory: Path,
    response: bytes,
) -> None:
    script = write_raw_plugin(project_directory, response)
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
    )

    with pytest.raises(PluginError, match="invalid response"):
        asyncio.run(
            ProcessPluginCollector(configuration).collect(plugin_context(project_directory))
        )


def test_plugin_enforces_global_capture_output_limit(project_directory: Path) -> None:
    response = {
        "protocol_version": "1.0",
        "facts": [
            {
                "key": "plugin.demo.large",
                "value": "x" * 8_000,
                "source": "large response",
                "sensitivity": "public",
            }
        ],
    }
    script = write_plugin(project_directory, response)
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
        maximum_output_bytes=64_000,
    )

    with pytest.raises(PluginError, match="exceeds its limit"):
        asyncio.run(
            ProcessPluginCollector(configuration).collect(
                plugin_context(project_directory, maximum_output_bytes=4_096)
            )
        )


def test_plugin_cancellation_terminates_descendants(project_directory: Path) -> None:
    marker = project_directory / "plugin-descendant-finished"
    child_code = f"import time, pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).touch()"
    script = project_directory / "waiting_plugin.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "sys.stdin.buffer.read()\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    configuration = PluginConfiguration(
        name="demo",
        command=(sys.executable, str(script)),
        enabled=True,
    )

    async def cancel_plugin() -> None:
        task = asyncio.create_task(
            ProcessPluginCollector(configuration).collect(plugin_context(project_directory))
        )
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_plugin())
    asyncio.run(asyncio.sleep(2.2))

    assert not marker.exists()


def test_disabled_plugins_are_not_built() -> None:
    configuration = PluginConfiguration(name="demo", command=("demo",), enabled=False)
    assert enabled_plugin_collectors((configuration,)) == ()
    with pytest.raises(PluginError, match="not explicitly enabled"):
        ProcessPluginCollector(configuration)
