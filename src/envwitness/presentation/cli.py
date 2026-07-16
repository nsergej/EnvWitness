"""Production command-line interface for EnvWitness."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from envwitness import __version__
from envwitness.application.services import (
    CaptureRequest,
    ComparisonService,
    ReportRenderer,
    default_project_label,
)
from envwitness.domain.errors import EnvWitnessError
from envwitness.infrastructure.archive import JsonCapsuleImporter, ZipCapsuleRepository
from envwitness.infrastructure.bootstrap import build_capture_service
from envwitness.infrastructure.config import (
    EnvWitnessConfiguration,
    load_configuration,
    write_default_configuration,
)
from envwitness.infrastructure.logging import configure_logging
from envwitness.infrastructure.plugins import plugin_contract_example
from envwitness.infrastructure.telemetry import ConsentStore, default_consent_path
from envwitness.infrastructure.updater import (
    AutomaticUpdateCoordinator,
    PyPiUpdater,
    default_update_state_path,
)
from envwitness.presentation.api import create_api_application

app = typer.Typer(
    name="envwitness",
    help="Create privacy-first, proof-carrying bug reports and compare environments.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
telemetry_app = typer.Typer(help="Manage explicit aggregate telemetry consent.")
plugin_app = typer.Typer(help="Inspect and validate the out-of-process plugin contract.")
update_app = typer.Typer(help="Check or install stable releases from PyPI.")
app.add_typer(telemetry_app, name="telemetry")
app.add_typer(plugin_app, name="plugins")
app.add_typer(update_app, name="update")

CONSOLE = Console()
ERROR_CONSOLE = Console(stderr=True)
LOGGER = logging.getLogger(__name__)


@app.callback()
def main(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable detailed operational logging."),
    ] = False,
    json_logs: Annotated[
        bool,
        typer.Option("--json-logs", help="Write structured JSON logs to standard error."),
    ] = False,
) -> None:
    """Configure process-wide diagnostics before a command runs."""
    configure_logging(verbose=verbose, json_output=json_logs)


@app.command("version")
def show_version() -> None:
    """Print the installed EnvWitness version."""
    CONSOLE.print(f"EnvWitness {__version__}")


@app.command("init")
def initialize_configuration(
    destination: Annotated[
        Path,
        typer.Option("--output", "-o", help="Configuration file to create."),
    ] = Path("envwitness.yml"),
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace an existing configuration file."),
    ] = False,
) -> None:
    """Create a complete security-first YAML configuration."""
    try:
        path = write_default_configuration(destination, overwrite=force)
    except EnvWitnessError as error:
        _abort(error)
    CONSOLE.print(f"Created [bold]{path}[/bold]")


@app.command("capture")
def capture(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Destination .evw archive."),
    ] = None,
    configuration_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Strict YAML configuration path."),
    ] = None,
    project_root: Annotated[
        Path,
        typer.Option("--project-root", help="Project directory to inspect."),
    ] = Path("."),
    command: Annotated[
        list[str] | None,
        typer.Argument(
            help="Command and arguments to run after --.",
            metavar="COMMAND...",
        ),
    ] = None,
) -> None:
    """Capture evidence and optionally run the command following ``--``."""
    try:
        configuration = load_configuration(configuration_path)
        _apply_automatic_update_policy(configuration)
        captured_command = tuple(command or ())
        resolved_root = project_root.resolve(strict=True)
        project_name = configuration.project_name.strip() or default_project_label(resolved_root)
        destination = output or _default_capsule_path(project_name)
        request = CaptureRequest(
            project_root=resolved_root,
            destination=destination,
            project_name=project_name,
            command=captured_command,
            command_timeout_seconds=configuration.capture.command_timeout_seconds,
            maximum_output_bytes=configuration.capture.maximum_output_bytes,
            environment_value_allowlist=configuration.capture.environment_value_allowlist,
            file_content_allowlist=configuration.capture.file_content_allowlist,
            runtime_commands=tuple(probe.command for probe in configuration.capture.runtime_probes),
        )
        capture_service = build_capture_service(configuration)
        try:
            capsule, final_path = asyncio.run(capture_service.capture(request))
        finally:
            capture_service.close()
    except (EnvWitnessError, OSError, ValueError) as error:
        _abort(error)
    CONSOLE.print(
        f"[bold green]Captured[/bold green] {len(capsule.facts)} facts to [bold]{final_path}[/bold]"
    )
    CONSOLE.print(
        f"Integrity {capsule.integrity.manifest_digest if capsule.integrity else 'missing'}; "
        f"redacted {capsule.redaction.facts_redacted} facts."
    )


@app.command("verify")
def verify_capsule(source: Annotated[Path, typer.Argument(help="Capsule to verify.")]) -> None:
    """Validate archive safety, schema, fact digests, and manifest integrity."""
    try:
        capsule = ZipCapsuleRepository().read(source, verify=True)
    except EnvWitnessError as error:
        _abort(error)
    CONSOLE.print(
        f"[bold green]Verified[/bold green] {capsule.capsule_identifier} "
        f"with {len(capsule.facts)} facts."
    )


@app.command("inspect")
def inspect_capsule(
    source: Annotated[Path, typer.Argument(help="Capsule to inspect.")],
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: summary, json, or markdown."),
    ] = "summary",
) -> None:
    """Inspect one verified capsule without extracting it to disk."""
    try:
        capsule = ZipCapsuleRepository().read(source, verify=True)
        renderer = ReportRenderer()
        if output_format == "json":
            CONSOLE.print_json(renderer.capsule_to_json(capsule))
            return
        if output_format == "markdown":
            CONSOLE.print(renderer.capsule_to_markdown(capsule), markup=False)
            return
        if output_format != "summary":
            raise EnvWitnessError("Format must be summary, json, or markdown")
    except EnvWitnessError as error:
        _abort(error)
    table = Table(title=f"EnvWitness {capsule.project_name}", show_header=True)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_column("Source", style="dim", overflow="fold")
    for fact in capsule.facts:
        rendered_value = json.dumps(fact.value, ensure_ascii=False, sort_keys=True)
        table.add_row(fact.key, rendered_value, fact.collector)
    CONSOLE.print(table)


@app.command("compare")
def compare_capsules(
    baseline: Annotated[Path, typer.Argument(help="Known working capsule.")],
    candidate: Annotated[Path, typer.Argument(help="Failing or changed capsule.")],
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: markdown or json."),
    ] = "markdown",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional report destination."),
    ] = None,
) -> None:
    """Compare two verified capsules and rank deterministic diagnostic hints."""
    try:
        repository = ZipCapsuleRepository()
        report = ComparisonService().compare(
            repository.read(baseline, verify=True),
            repository.read(candidate, verify=True),
        )
        if output_format == "json":
            rendered_report = report.model_dump_json(indent=2)
        elif output_format == "markdown":
            rendered_report = ReportRenderer().comparison_to_markdown(report)
        else:
            raise EnvWitnessError("Format must be markdown or json")
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered_report, encoding="utf-8", newline="\n")
        else:
            CONSOLE.print(rendered_report, markup=False)
    except (EnvWitnessError, OSError) as error:
        _abort(error)


@app.command("export")
def export_capsule(
    source: Annotated[Path, typer.Argument(help="Capsule to export.")],
    destination: Annotated[Path, typer.Argument(help="JSON or Markdown destination.")],
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: json or markdown."),
    ] = "json",
) -> None:
    """Export a verified capsule to a reviewable portable document."""
    try:
        capsule = ZipCapsuleRepository().read(source, verify=True)
        renderer = ReportRenderer()
        if output_format == "json":
            content = renderer.capsule_to_json(capsule)
        elif output_format == "markdown":
            content = renderer.capsule_to_markdown(capsule)
        else:
            raise EnvWitnessError("Format must be json or markdown")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
    except (EnvWitnessError, OSError) as error:
        _abort(error)
    CONSOLE.print(f"Exported [bold]{destination}[/bold]")


@app.command("import")
def import_capsule(
    source: Annotated[Path, typer.Argument(help="Exported capsule JSON manifest.")],
    destination: Annotated[Path, typer.Argument(help="Destination .evw archive.")],
) -> None:
    """Import verified JSON without weakening integrity or schema checks."""
    try:
        final_path = JsonCapsuleImporter(ZipCapsuleRepository()).import_file(source, destination)
    except EnvWitnessError as error:
        _abort(error)
    CONSOLE.print(f"Imported [bold]{final_path}[/bold]")


@app.command("serve")
def serve(
    configuration_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Strict YAML configuration path."),
    ] = None,
    project_root: Annotated[
        Path,
        typer.Option("--project-root", help="Project directory exposed to collectors."),
    ] = Path("."),
) -> None:
    """Run the loopback-only REST API and local diagnostic dashboard."""
    try:
        configuration = load_configuration(configuration_path)
        _apply_automatic_update_policy(configuration)
        resolved_root = project_root.resolve(strict=True)
        api_application = create_api_application(configuration, resolved_root)
    except (EnvWitnessError, OSError, ValueError) as error:
        _abort(error)
    CONSOLE.print(
        f"Dashboard: http://{_format_url_host(configuration.api.host)}:"
        f"{configuration.api.port} "
        "(mutations require a bearer token)"
    )
    uvicorn.run(
        api_application,
        host=configuration.api.host,
        port=configuration.api.port,
        log_level="info",
        access_log=True,
    )


@telemetry_app.command("enable")
def enable_telemetry() -> None:
    """Persist explicit consent for allowlisted aggregate telemetry."""
    try:
        ConsentStore(default_consent_path()).set_enabled(True)
    except EnvWitnessError as error:
        _abort(error)
    CONSOLE.print("Aggregate telemetry consent is [bold green]enabled[/bold green].")


@telemetry_app.command("disable")
def disable_telemetry() -> None:
    """Withdraw consent and stop all telemetry delivery immediately."""
    try:
        ConsentStore(default_consent_path()).set_enabled(False)
    except EnvWitnessError as error:
        _abort(error)
    CONSOLE.print("Aggregate telemetry consent is [bold]disabled[/bold].")


@telemetry_app.command("status")
def telemetry_status() -> None:
    """Display the locally stored telemetry consent state."""
    enabled = ConsentStore(default_consent_path()).is_enabled()
    CONSOLE.print(f"Telemetry consent: {'enabled' if enabled else 'disabled'}")


@plugin_app.command("example")
def show_plugin_example(
    name: Annotated[str, typer.Option("--name", help="Example plugin namespace.")] = "demo",
) -> None:
    """Print a complete versioned plugin request and response example."""
    CONSOLE.print_json(json.dumps(plugin_contract_example(name, Path.cwd()), indent=2))


@update_app.command("check")
def check_for_updates(
    configuration_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Strict YAML configuration path."),
    ] = None,
) -> None:
    """Check the canonical PyPI endpoint for a stable update."""
    try:
        configuration = load_configuration(configuration_path)
        updater = _build_updater(configuration)
        status = updater.check()
    except EnvWitnessError as error:
        _abort(error)
    if status.update_available:
        CONSOLE.print(
            f"Update available: [bold]{status.current_version}[/bold] -> "
            f"[bold green]{status.latest_version}[/bold green]"
        )
    else:
        CONSOLE.print(f"EnvWitness {status.current_version} is current.")


@update_app.command("install")
def install_update(
    version: Annotated[
        str | None,
        typer.Option("--version", help="Exact stable version; latest when omitted."),
    ] = None,
    configuration_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Strict YAML configuration path."),
    ] = None,
) -> None:
    """Install an exact stable release with the active Python interpreter."""
    try:
        configuration = load_configuration(configuration_path)
        updater = _build_updater(configuration)
        target_version = version or updater.check().latest_version
        updater.install(target_version)
    except EnvWitnessError as error:
        _abort(error)
    CONSOLE.print(f"Installed EnvWitness [bold green]{target_version}[/bold green].")


def _build_updater(configuration: EnvWitnessConfiguration) -> PyPiUpdater:
    """Create an updater restricted by validated configuration."""
    return PyPiUpdater(
        current_version=__version__,
        metadata_url=configuration.updates.metadata_url,
    )


def _apply_automatic_update_policy(configuration: EnvWitnessConfiguration) -> None:
    """Apply an opted-in update policy without breaking the requested command."""
    try:
        result = AutomaticUpdateCoordinator(
            updater=_build_updater(configuration),
            state_path=default_update_state_path(),
        ).run(
            automatic_check=configuration.updates.automatic_check,
            automatic_install=configuration.updates.automatic_install,
            interval_hours=configuration.updates.check_interval_hours,
        )
    except EnvWitnessError:
        LOGGER.warning("automatic_update_failed", exc_info=True)
        return
    if result.installed_version is not None:
        LOGGER.info(
            "automatic_update_installed",
            extra={"installed_version": result.installed_version},
        )
    elif result.checked:
        LOGGER.info("automatic_update_check_completed")


def _format_url_host(host: str) -> str:
    """Bracket an IPv6 host for display in an absolute URL."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _default_capsule_path(project_name: str) -> Path:
    """Build a portable default archive name without interpreting path separators."""
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", project_name).strip(".-_")
    return Path(f"{safe_stem or 'capture'}.evw")


def _abort(error: Exception) -> None:
    """Present a safe command error and terminate with a stable exit code."""
    ERROR_CONSOLE.print(f"[bold red]Error:[/bold red] {error}")
    raise typer.Exit(code=1)


def run() -> None:
    """Invoke the Typer application from an installed console script."""
    app()
