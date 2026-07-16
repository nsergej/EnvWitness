"""Composition root that wires application services to infrastructure adapters."""

from __future__ import annotations

from envwitness import __version__
from envwitness.application.ports import EvidenceCollector
from envwitness.application.services import CaptureService
from envwitness.infrastructure.archive import ZipCapsuleRepository
from envwitness.infrastructure.collectors import (
    AsyncCommandRunner,
    EnvironmentCollector,
    FileFingerprintCollector,
    GitCollector,
    RuntimeCollector,
    SystemCollector,
)
from envwitness.infrastructure.config import EnvWitnessConfiguration
from envwitness.infrastructure.plugins import enabled_plugin_collectors
from envwitness.infrastructure.redaction import DeterministicRedactor
from envwitness.infrastructure.telemetry import (
    AggregateTelemetryClient,
    ConsentStore,
    default_consent_path,
)


class ManagedCaptureService(CaptureService):
    """Capture service with an explicit lifecycle for aggregate telemetry."""

    _managed_telemetry: AggregateTelemetryClient

    def close(self, *, drain_telemetry: bool = True) -> None:
        """Drain and close the owned telemetry worker within its bounded timeout."""
        self._managed_telemetry.close(drain=drain_telemetry)


def build_capture_service(configuration: EnvWitnessConfiguration) -> ManagedCaptureService:
    """Build the production capture service from validated configuration."""
    collector_list: list[EvidenceCollector] = [
        SystemCollector(),
        EnvironmentCollector(
            include_names=configuration.capture.include_environment_names,
        ),
        GitCollector(),
        FileFingerprintCollector(),
        RuntimeCollector(configuration.capture.runtime_probes),
    ]
    collector_list.extend(enabled_plugin_collectors(configuration.plugins))
    telemetry = AggregateTelemetryClient(
        consent_store=ConsentStore(default_consent_path()),
        endpoint=configuration.telemetry.endpoint if configuration.telemetry.enabled else "",
        tool_version=__version__,
    )
    service = ManagedCaptureService(
        collectors=tuple(collector_list),
        redactor=DeterministicRedactor(configuration.redaction.custom_rules),
        command_runner=AsyncCommandRunner(),
        repository=ZipCapsuleRepository(),
        tool_version=__version__,
        telemetry=telemetry,
    )
    service._managed_telemetry = telemetry
    return service
