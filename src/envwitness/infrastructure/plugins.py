"""Out-of-process collector plugin protocol with strict trust boundaries."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from envwitness.application.ports import CaptureContext, CollectedFact
from envwitness.domain.errors import PluginError
from envwitness.domain.models import Sensitivity, utc_now
from envwitness.infrastructure.config import PluginConfiguration
from envwitness.infrastructure.processes import run_bounded_process


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
        maximum_output_bytes = min(
            self._configuration.maximum_output_bytes,
            context.maximum_output_bytes,
        )
        encoded_request = json.dumps(request_payload, sort_keys=True).encode("utf-8")
        try:
            result = await run_bounded_process(
                self._configuration.command,
                working_directory=context.project_root,
                timeout_seconds=self._configuration.timeout_seconds,
                maximum_standard_output_bytes=maximum_output_bytes,
                maximum_standard_error_bytes=min(maximum_output_bytes, 4_096),
                input_bytes=encoded_request,
                environment=environment,
                terminate_on_output_limit=True,
            )
        except (FileNotFoundError, OSError, ValueError) as error:
            raise PluginError(f"Cannot start plugin {self._configuration.name}: {error}") from error
        if result.timed_out:
            raise PluginError(f"Plugin timed out: {self._configuration.name}")
        if result.output_limit_exceeded:
            raise PluginError(f"Plugin output exceeds its limit: {self._configuration.name}")
        if result.return_code != 0:
            raise PluginError(f"Plugin {self._configuration.name} exited with {result.return_code}")
        try:
            decoded_output = result.standard_output.decode("utf-8", errors="strict")
            raw_response: object = json.loads(
                decoded_output,
                object_pairs_hook=_reject_duplicate_object_keys,
                parse_constant=_reject_non_finite_number,
            )
            response = PluginResponse.model_validate(raw_response)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
            raise PluginError(
                f"Plugin {self._configuration.name} returned an invalid response"
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
        environment = {name: os.environ[name] for name in allowed_names if name in os.environ}
        if "PATH" in environment:
            environment["PATH"] = os.pathsep.join(
                entry
                for entry in environment["PATH"].split(os.pathsep)
                if entry and Path(entry).is_absolute()
            )
        return environment


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting ambiguous duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    """Reject non-standard JSON constants such as NaN and Infinity."""
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


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
