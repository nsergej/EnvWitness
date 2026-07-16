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


def plugin_context(project_directory: Path) -> CaptureContext:
    return CaptureContext(project_root=project_directory, maximum_output_bytes=4_096)


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


def test_disabled_plugins_are_not_built() -> None:
    configuration = PluginConfiguration(name="demo", command=("demo",), enabled=False)
    assert enabled_plugin_collectors((configuration,)) == ()
    with pytest.raises(PluginError, match="not explicitly enabled"):
        ProcessPluginCollector(configuration)
