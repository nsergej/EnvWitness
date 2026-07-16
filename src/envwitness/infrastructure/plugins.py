"""Out-of-process collector plugin protocol with strict trust boundaries."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from envwitness.application.ports import CaptureContext, CollectedFact
from envwitness.domain.errors import PluginError
from envwitness.domain.models import Sensitivity, utc_now
from envwitness.infrastructure.config import PluginConfiguration


class PluginFactPayload(BaseModel):
    """One fact returned by an EnvWitness collector plugin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=180, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    value: JsonValue
    source: str = Field(min_length=1, max_length=500)
    sensitivity: Sensitivity = Sensitivity.INTERNAL


class PluginResponse(BaseModel):
    """Versioned response envelope emitted on plugin standard output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: str = Field(pattern=r"^1\.0$")
    facts: tuple[PluginFactPayload, ...] = Field(max_length=500)


class ProcessPluginCollector:
    """Run one explicitly enabled plugin with sanitized environment metadata."""

    def __init__(self, configuration: PluginConfiguration) -> None:
        """Store validated configuration and require explicit enablement."""
        if not configuration.enabled:
            raise PluginError(f"Plugin is not explicitly enabled: {configuration.name}")
        self._configuration = configuration

    @property
    def name(self) -> str:
        """Return a namespaced collector identifier."""
        return f"plugin.{self._configuration.name}"

    async def collect(self, context: CaptureContext) -> list[CollectedFact]:
        """Send minimal JSON context and validate the complete plugin response."""
        request_payload = {
            "protocol_version": "1.0",
            "project_root": str(context.project_root),
            "maximum_output_bytes": context.maximum_output_bytes,
            "metadata": context.metadata,
        }
        environment = self._sanitized_environment()
        try:
            process = await asyncio.create_subprocess_exec(
                *self._configuration.command,
                cwd=context.project_root,
                env=environment,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as error:
            raise PluginError(f"Cannot start plugin {self._configuration.name}: {error}") from error

        encoded_request = json.dumps(request_payload, sort_keys=True).encode("utf-8")
        try:
            standard_output, standard_error = await asyncio.wait_for(
                process.communicate(encoded_request),
                timeout=self._configuration.timeout_seconds,
            )
        except TimeoutError as error:
            process.kill()
            await process.wait()
            raise PluginError(f"Plugin timed out: {self._configuration.name}") from error

        if len(standard_output) > self._configuration.maximum_output_bytes:
            raise PluginError(f"Plugin output exceeds its limit: {self._configuration.name}")
        if process.returncode != 0:
            bounded_error = standard_error[:4_096].decode("utf-8", errors="replace")
            raise PluginError(
                f"Plugin {self._configuration.name} exited with {process.returncode}: "
                f"{bounded_error}"
            )
        try:
            response = PluginResponse.model_validate_json(standard_output)
        except ValidationError as error:
            raise PluginError(
                f"Plugin {self._configuration.name} returned an invalid response: {error}"
            ) from error

        required_prefix = f"plugin.{self._configuration.name}."
        facts: list[CollectedFact] = []
        keys: set[str] = set()
        for payload in response.facts:
            if not payload.key.startswith(required_prefix):
                raise PluginError(
                    f"Plugin fact key must begin with {required_prefix}: {payload.key}"
                )
            if payload.key in keys:
                raise PluginError(f"Plugin returned a duplicate fact key: {payload.key}")
            keys.add(payload.key)
            facts.append(
                CollectedFact(
                    key=payload.key,
                    value=payload.value,
                    collector=self.name,
                    source=payload.source,
                    sensitivity=payload.sensitivity,
                    captured_at=utc_now(),
                )
            )
        return facts

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        """Expose only process-discovery variables required across supported systems."""
        allowed_names = (
            "COMSPEC",
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "WINDIR",
        )
        return {name: os.environ[name] for name in allowed_names if name in os.environ}


def enabled_plugin_collectors(
    configurations: tuple[PluginConfiguration, ...],
) -> tuple[ProcessPluginCollector, ...]:
    """Build collectors only for plugins carrying explicit configuration consent."""
    return tuple(
        ProcessPluginCollector(configuration)
        for configuration in configurations
        if configuration.enabled
    )


def plugin_contract_example(plugin_name: str, project_root: Path) -> dict[str, Any]:
    """Return a complete protocol example for documentation and validation tools."""
    return {
        "request": {
            "protocol_version": "1.0",
            "project_root": str(project_root),
            "maximum_output_bytes": 1_048_576,
            "metadata": {},
        },
        "response": {
            "protocol_version": "1.0",
            "facts": [
                {
                    "key": f"plugin.{plugin_name}.version",
                    "value": "1.0.0",
                    "source": "plugin version endpoint",
                    "sensitivity": "public",
                }
            ],
        },
    }
