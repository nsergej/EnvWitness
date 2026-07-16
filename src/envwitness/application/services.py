"""Application services for capture, comparison, rendering, and import."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from envwitness.application.ports import (
    CapsuleRepository,
    CaptureContext,
    CollectedFact,
    CommandResult,
    CommandRunner,
    EvidenceCollector,
    EvidenceRedactor,
    TelemetrySink,
)
from envwitness.domain.errors import CaptureError
from envwitness.domain.models import (
    Capsule,
    ComparisonReport,
    DiagnosticHint,
    DifferenceKind,
    DifferenceSeverity,
    FactDifference,
    RedactionSummary,
    Sensitivity,
    has_unsafe_control_characters,
    utc_now,
)

LOGGER = logging.getLogger(__name__)


def default_project_label(project_root: Path) -> str:
    """Return a useful project label without exposing the home-directory name."""
    resolved_root = project_root.resolve(strict=True)
    try:
        resolved_home = Path.home().resolve(strict=True)
    except OSError:
        resolved_home = None
    if resolved_home is not None and resolved_root == resolved_home:
        return "home-directory"
    label = resolved_root.name.strip() or "filesystem-root"
    return "project" if has_unsafe_control_characters(label) else label


@dataclass(frozen=True, slots=True)
class CaptureRequest:
    """Validated inputs required by the capture use case."""

    project_root: Path
    destination: Path
    project_name: str
    command: tuple[str, ...] = ()
    command_timeout_seconds: int = 300
    maximum_output_bytes: int = 1_048_576
    environment_value_allowlist: tuple[str, ...] = ()
    file_content_allowlist: tuple[str, ...] = ()
    runtime_commands: tuple[tuple[str, ...], ...] = ()

    def validate(self) -> None:
        """Reject invalid paths and resource limits before collection begins."""
        if not self.project_root.exists() or not self.project_root.is_dir():
            raise CaptureError(f"Project root is not a directory: {self.project_root}")
        if not self.project_name.strip() or len(self.project_name) > 120:
            raise CaptureError("Project name must contain between 1 and 120 characters")
        if has_unsafe_control_characters(self.project_name):
            raise CaptureError("Project name cannot contain control characters")
        if not 1 <= self.command_timeout_seconds <= 86_400:
            raise CaptureError("Command timeout must be between 1 second and 24 hours")
        if not 4_096 <= self.maximum_output_bytes <= 16_777_216:
            raise CaptureError("Maximum output must be between 4 KiB and 16 MiB")
        if len(self.command) > 256:
            raise CaptureError("Captured command cannot contain more than 256 arguments")
        if any("\x00" in argument for argument in self.command):
            raise CaptureError("Command arguments cannot contain null bytes")


class NullTelemetrySink:
    """No-operation telemetry implementation used when consent is absent."""

    def record(self, event_name: str, properties: dict[str, int | str | bool]) -> None:
        """Discard an event intentionally."""


class CaptureService:
    """Coordinate concurrent collectors, redaction, sealing, and persistence."""

    def __init__(
        self,
        *,
        collectors: tuple[EvidenceCollector, ...],
        redactor: EvidenceRedactor,
        command_runner: CommandRunner,
        repository: CapsuleRepository,
        tool_version: str,
        telemetry: TelemetrySink | None = None,
    ) -> None:
        """Initialize the service with explicit infrastructure ports."""
        self._collectors = collectors
        self._redactor = redactor
        self._command_runner = command_runner
        self._repository = repository
        self._tool_version = tool_version
        self._telemetry = telemetry or NullTelemetrySink()

    async def capture(self, request: CaptureRequest) -> tuple[Capsule, Path]:
        """Capture, sanitize, seal, and atomically persist one evidence capsule.

        Args:
            request: Complete capture inputs and resource limits.

        Returns:
            The sealed capsule and final archive path.

        Raises:
            CaptureError: If collection fails or collectors produce conflicting facts.
        """
        request.validate()
        project_root = request.project_root.resolve(strict=True)
        context = CaptureContext(
            project_root=project_root,
            maximum_output_bytes=request.maximum_output_bytes,
            environment_value_allowlist=request.environment_value_allowlist,
            file_content_allowlist=request.file_content_allowlist,
            runtime_commands=request.runtime_commands,
        )
        LOGGER.info("capture_started", extra={"collector_count": len(self._collectors)})

        command_task: asyncio.Task[CommandResult] | None = None
        if request.command:
            command_task = asyncio.create_task(
                self._command_runner.run(
                    request.command,
                    project_root,
                    request.command_timeout_seconds,
                    request.maximum_output_bytes,
                )
            )

        try:
            collector_results = await self._collect_all(context)
            command_result = await command_task if command_task is not None else None
            collected_facts = [fact for result in collector_results for fact in result]

            if command_result is not None:
                timestamp = command_result.execution.finished_at
                collected_facts.extend(
                    [
                        CollectedFact(
                            key="command.standard_output",
                            value=command_result.standard_output,
                            collector="command",
                            source="captured process standard output",
                            sensitivity=Sensitivity.SENSITIVE,
                            captured_at=timestamp,
                        ),
                        CollectedFact(
                            key="command.standard_error",
                            value=command_result.standard_error,
                            collector="command",
                            source="captured process standard error",
                            sensitivity=Sensitivity.SENSITIVE,
                            captured_at=timestamp,
                        ),
                        CollectedFact(
                            key="command.exit_code",
                            value=command_result.execution.exit_code,
                            collector="command",
                            source="captured process exit status",
                            sensitivity=Sensitivity.PUBLIC,
                            captured_at=timestamp,
                        ),
                    ]
                )

            self._require_unique_keys(collected_facts)
            stored_facts, redaction_summary = self._redactor.redact(collected_facts)
            stored_command = command_result.execution if command_result is not None else None
            project_root_label = default_project_label(project_root)
            metadata_facts = [
                CollectedFact(
                    key="envwitness.project.name",
                    value=request.project_name.strip(),
                    collector="envwitness",
                    source="configured or derived project name",
                    sensitivity=Sensitivity.INTERNAL,
                    captured_at=utc_now(),
                ),
                CollectedFact(
                    key="envwitness.project.root_label",
                    value=project_root_label,
                    collector="envwitness",
                    source="privacy-safe project root label",
                    sensitivity=Sensitivity.INTERNAL,
                    captured_at=utc_now(),
                ),
            ]
            if stored_command is not None:
                metadata_facts.append(
                    CollectedFact(
                        key="envwitness.command.arguments",
                        value=list(stored_command.arguments),
                        collector="command",
                        source="captured process argument vector",
                        sensitivity=Sensitivity.INTERNAL,
                        captured_at=stored_command.finished_at,
                    )
                )
                metadata_facts.append(
                    CollectedFact(
                        key="envwitness.command.working_directory",
                        value=stored_command.working_directory,
                        collector="command",
                        source="captured process working directory",
                        sensitivity=Sensitivity.INTERNAL,
                        captured_at=stored_command.finished_at,
                    )
                )
            redacted_metadata, metadata_summary = self._redactor.redact(metadata_facts)
            metadata_by_key = {fact.key: fact.value for fact in redacted_metadata}
            stored_project_name = metadata_by_key["envwitness.project.name"]
            stored_project_root_label = metadata_by_key["envwitness.project.root_label"]
            if not isinstance(stored_project_name, str) or not isinstance(
                stored_project_root_label,
                str,
            ):
                raise CaptureError("Redactor returned invalid project metadata")
            if stored_command is not None:
                argument_value = metadata_by_key["envwitness.command.arguments"]
                working_directory_value = metadata_by_key["envwitness.command.working_directory"]
                if not isinstance(argument_value, list) or not all(
                    isinstance(argument, str) for argument in argument_value
                ):
                    raise CaptureError("Redactor returned invalid command arguments")
                if not isinstance(working_directory_value, str):
                    raise CaptureError("Redactor returned an invalid command working directory")
                stored_command = stored_command.model_copy(
                    update={
                        "arguments": tuple(argument_value),
                        "working_directory": working_directory_value,
                    }
                )
            redaction_summary = self._merge_redaction_summaries(
                redaction_summary,
                metadata_summary,
            )

            capsule = Capsule(
                capsule_identifier=f"ew-{secrets.token_hex(12)}",
                created_at=utc_now(),
                tool_version=self._tool_version,
                project_name=stored_project_name,
                project_root_label=stored_project_root_label,
                facts=tuple(sorted(stored_facts, key=lambda fact: fact.key)),
                command=stored_command,
                redaction=redaction_summary,
                plugins=tuple(
                    collector.name
                    for collector in self._collectors
                    if collector.name.startswith("plugin.")
                ),
            ).seal()
            final_path = self._repository.write(capsule, request.destination)
            self._telemetry.record(
                "capture_completed",
                {
                    "fact_count": len(capsule.facts),
                    "plugin_count": len(capsule.plugins),
                    "redacted_fact_count": capsule.redaction.facts_redacted,
                    "command_captured": capsule.command is not None,
                },
            )
            LOGGER.info(
                "capture_completed",
                extra={"fact_count": len(capsule.facts), "destination": str(final_path)},
            )
            return capsule, final_path
        finally:
            if command_task is not None:
                if not command_task.done():
                    command_task.cancel()
                await asyncio.gather(command_task, return_exceptions=True)

    async def _collect_all(self, context: CaptureContext) -> list[list[CollectedFact]]:
        """Run independent collectors concurrently and preserve typed failures."""
        try:
            return await asyncio.gather(
                *(collector.collect(context) for collector in self._collectors)
            )
        except Exception as error:
            raise CaptureError(f"Evidence collection failed: {error}") from error

    @staticmethod
    def _require_unique_keys(facts: list[CollectedFact]) -> None:
        """Reject ambiguous collector output before any data is persisted."""
        seen: set[str] = set()
        duplicates: set[str] = set()
        for fact in facts:
            if fact.key in seen:
                duplicates.add(fact.key)
            seen.add(fact.key)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise CaptureError(f"Collectors produced duplicate fact keys: {duplicate_list}")

    @staticmethod
    def _merge_redaction_summaries(
        first: RedactionSummary,
        second: RedactionSummary,
    ) -> RedactionSummary:
        """Combine redaction accounting for facts and persisted command metadata."""
        rule_counts = Counter(first.rules_triggered)
        rule_counts.update(second.rules_triggered)
        return RedactionSummary(
            facts_scanned=first.facts_scanned + second.facts_scanned,
            facts_redacted=first.facts_redacted + second.facts_redacted,
            replacements=first.replacements + second.replacements,
            rules_triggered=dict(sorted(rule_counts.items())),
        )


class ComparisonService:
    """Compare verified capsules by semantic keys and deterministic rules."""

    _CRITICAL_PREFIXES = ("runtime.", "dependency.", "command.exit_code")
    _WARNING_PREFIXES = ("git.", "system.", "environment.", "file.")

    def compare(self, baseline: Capsule, candidate: Capsule) -> ComparisonReport:
        """Return semantic differences and ranked diagnostic hints.

        Args:
            baseline: Capsule representing the known working environment.
            candidate: Capsule representing the failing or changed environment.

        Returns:
            Immutable comparison report sorted by severity and key.
        """
        baseline_facts = {fact.key: fact for fact in baseline.facts}
        candidate_facts = {fact.key: fact for fact in candidate.facts}
        differences: list[FactDifference] = []

        for key in sorted(baseline_facts.keys() | candidate_facts.keys()):
            baseline_fact = baseline_facts.get(key)
            candidate_fact = candidate_facts.get(key)
            if baseline_fact is None and candidate_fact is not None:
                differences.append(
                    self._difference(key, DifferenceKind.ADDED, None, candidate_fact.value)
                )
            elif candidate_fact is None and baseline_fact is not None:
                differences.append(
                    self._difference(key, DifferenceKind.REMOVED, baseline_fact.value, None)
                )
            elif (
                baseline_fact is not None
                and candidate_fact is not None
                and baseline_fact.digest != candidate_fact.digest
            ):
                differences.append(
                    self._difference(
                        key,
                        DifferenceKind.CHANGED,
                        baseline_fact.value,
                        candidate_fact.value,
                    )
                )

        ordered_differences = tuple(
            sorted(
                differences,
                key=lambda difference: (
                    self._severity_rank(difference.severity),
                    difference.key,
                ),
            )
        )
        hints = tuple(self._build_hints(ordered_differences))
        return ComparisonReport(
            baseline_capsule_identifier=baseline.capsule_identifier,
            candidate_capsule_identifier=candidate.capsule_identifier,
            created_at=utc_now(),
            differences=ordered_differences,
            hints=hints,
            identical=not ordered_differences,
        )

    def _difference(
        self,
        key: str,
        kind: DifferenceKind,
        baseline_value: Any,
        candidate_value: Any,
    ) -> FactDifference:
        """Build a classified difference with concise operator guidance."""
        severity = self._classify_severity(key)
        explanations = {
            DifferenceKind.ADDED: "The candidate reports a fact absent from the baseline.",
            DifferenceKind.REMOVED: "The candidate no longer reports a baseline fact.",
            DifferenceKind.CHANGED: "The stored values differ between environments.",
        }
        return FactDifference(
            key=key,
            kind=kind,
            severity=severity,
            baseline_value=baseline_value,
            candidate_value=candidate_value,
            explanation=explanations[kind],
        )

    def _classify_severity(self, key: str) -> DifferenceSeverity:
        """Classify a semantic key using stable, explainable rules."""
        if key == "command.exit_code" or key.startswith(self._CRITICAL_PREFIXES):
            return DifferenceSeverity.CRITICAL
        if key.startswith(self._WARNING_PREFIXES):
            return DifferenceSeverity.WARNING
        return DifferenceSeverity.INFORMATION

    @staticmethod
    def _severity_rank(severity: DifferenceSeverity) -> int:
        """Return a stable sort rank that places critical differences first."""
        return {
            DifferenceSeverity.CRITICAL: 0,
            DifferenceSeverity.WARNING: 1,
            DifferenceSeverity.INFORMATION: 2,
        }[severity]

    def _build_hints(self, differences: tuple[FactDifference, ...]) -> list[DiagnosticHint]:
        """Derive concise next actions without probabilistic or opaque scoring."""
        keys = {difference.key for difference in differences}
        hints: list[DiagnosticHint] = []
        if any(key.startswith("runtime.") for key in keys):
            hints.append(
                DiagnosticHint(
                    code="RUNTIME_DRIFT",
                    priority=10,
                    title="Align runtime versions first",
                    explanation=(
                        "Runtime output changed. Reproduce with the baseline runtime before "
                        "investigating application behavior."
                    ),
                    related_keys=tuple(sorted(key for key in keys if key.startswith("runtime."))),
                )
            )
        if any(key.startswith("file.hash.") for key in keys):
            hints.append(
                DiagnosticHint(
                    code="DEPENDENCY_INPUT_DRIFT",
                    priority=20,
                    title="Restore matching dependency inputs",
                    explanation=(
                        "A lockfile or build input hash changed. Reinstall from the same locked "
                        "inputs before comparing runtime behavior."
                    ),
                    related_keys=tuple(sorted(key for key in keys if key.startswith("file.hash."))),
                )
            )
        if "git.commit" in keys or "git.dirty" in keys:
            hints.append(
                DiagnosticHint(
                    code="SOURCE_STATE_DRIFT",
                    priority=30,
                    title="Match source state",
                    explanation=(
                        "The commit or dirty-worktree state differs. Compare behavior at the same "
                        "commit with no unreviewed local changes."
                    ),
                    related_keys=tuple(key for key in ("git.commit", "git.dirty") if key in keys),
                )
            )
        if "command.exit_code" in keys:
            hints.append(
                DiagnosticHint(
                    code="COMMAND_OUTCOME_DRIFT",
                    priority=40,
                    title="Inspect the first divergent command output",
                    explanation=(
                        "The command outcome differs. Compare redacted standard error after "
                        "aligning source, runtime, and dependency inputs."
                    ),
                    related_keys=("command.exit_code",),
                )
            )
        return sorted(hints, key=lambda hint: hint.priority)


class ReportRenderer:
    """Render capsules and comparisons into portable text formats."""

    def capsule_to_json(self, capsule: Capsule) -> str:
        """Render a capsule as indented UTF-8 JSON."""
        return capsule.model_dump_json(indent=2)

    def capsule_to_markdown(self, capsule: Capsule) -> str:
        """Render a capsule as a human-readable Markdown report."""
        command_line = "Not captured"
        if capsule.command is not None:
            command_line = " ".join(capsule.command.arguments)
        lines = [
            f"# EnvWitness report: {self._code_span(capsule.project_name)}",
            "",
            f"- Capsule: {self._code_span(capsule.capsule_identifier)}",
            f"- Created: {self._code_span(capsule.created_at.isoformat())}",
            "- Integrity: "
            + self._code_span("verified" if capsule.verify_integrity() else "invalid"),
            f"- Command: {self._code_span(command_line)}",
            f"- Redacted facts: {self._code_span(str(capsule.redaction.facts_redacted))}",
            "",
            "## Evidence",
            "",
            "| Key | Value | Collector | Sensitivity |",
            "| --- | --- | --- | --- |",
        ]
        for fact in capsule.facts:
            rendered_value = json.dumps(fact.value, ensure_ascii=False, sort_keys=True)
            lines.append(
                f"| {self._table_code_span(fact.key)} | "
                f"{self._table_code_span(rendered_value)} | "
                f"{self._table_code_span(fact.collector)} | "
                f"{self._table_code_span(fact.sensitivity.value)} |"
            )
        lines.append("")
        return "\n".join(lines)

    def comparison_to_markdown(self, report: ComparisonReport) -> str:
        """Render a comparison report as actionable Markdown."""
        lines = [
            "# EnvWitness comparison",
            "",
            f"- Baseline: {self._code_span(report.baseline_capsule_identifier)}",
            f"- Candidate: {self._code_span(report.candidate_capsule_identifier)}",
            f"- Identical: {self._code_span('yes' if report.identical else 'no')}",
            "",
            "## Diagnostic hints",
            "",
        ]
        if report.hints:
            for hint in report.hints:
                lines.extend(
                    [
                        f"### {self._code_span(hint.title)}",
                        "",
                        self._code_span(hint.explanation),
                        "",
                    ]
                )
        else:
            lines.extend(["No semantic drift was detected.", ""])
        lines.extend(
            [
                "## Differences",
                "",
                "| Severity | Key | Change | Baseline | Candidate |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for difference in report.differences:
            baseline_value = self._table_value(difference.baseline_value)
            candidate_value = self._table_value(difference.candidate_value)
            lines.append(
                f"| {self._table_code_span(difference.severity.value)} | "
                f"{self._table_code_span(difference.key)} | "
                f"{self._table_code_span(difference.kind.value)} | "
                f"{self._table_code_span(baseline_value)} | "
                f"{self._table_code_span(candidate_value)} |"
            )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _table_value(value: Any) -> str:
        """Render a JSON value safely inside a Markdown table cell."""
        if value is None:
            return "-"
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _code_span(value: str) -> str:
        """Wrap arbitrary text in a CommonMark code span without delimiter breakout."""
        normalized = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
        normalized = "".join(
            f"\\u{ord(character):04x}" if has_unsafe_control_characters(character) else character
            for character in normalized
        )
        longest_run = max(
            (len(match.group(0)) for match in re.finditer(r"`+", normalized)),
            default=0,
        )
        delimiter = "`" * (longest_run + 1)
        return f"{delimiter} {normalized} {delimiter}"

    @classmethod
    def _table_code_span(cls, value: str) -> str:
        """Render arbitrary text in a code span that cannot split a Markdown table."""
        table_safe = value.replace("|", "\\u007c").replace("\r", "\\r").replace("\n", "\\n")
        return cls._code_span(table_safe)
