"""Loopback-only REST API and local dashboard application."""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from envwitness.application.services import CaptureRequest, ComparisonService
from envwitness.domain.errors import EnvWitnessError
from envwitness.infrastructure.archive import ZipCapsuleRepository
from envwitness.infrastructure.bootstrap import build_capture_service
from envwitness.infrastructure.config import EnvWitnessConfiguration


class ApiCaptureRequest(BaseModel):
    """Validated JSON body for a local capture request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    command: tuple[str, ...] = Field(default=(), max_length=256)
    output_name: str = Field(
        default="capture.evw",
        min_length=1,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*\.evw$",
    )


class ApiComparisonRequest(BaseModel):
    """Validated JSON body naming two stored capsule archives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*\.evw$")
    candidate: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*\.evw$")


def create_api_application(
    configuration: EnvWitnessConfiguration,
    project_root: Path,
) -> FastAPI:
    """Create a configured FastAPI application bound to one project root.

    Args:
        configuration: Validated service configuration.
        project_root: Fixed project root available to collectors.

    Returns:
        Fully configured local API and static dashboard application.
    """
    resolved_project_root = project_root.resolve(strict=True)
    storage_directory = _resolve_storage_directory(
        resolved_project_root,
        configuration.api.storage_directory,
    )
    storage_directory.mkdir(parents=True, exist_ok=True)
    repository = ZipCapsuleRepository()
    api_token = os.environ.get(configuration.api.token_environment_variable, "")
    static_directory = Path(__file__).with_name("static")

    application = FastAPI(
        title="EnvWitness Local API",
        version="1.0.0",
        description="Loopback API for proof-carrying diagnostic evidence.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    application.mount("/static", StaticFiles(directory=static_directory), name="static")

    def require_mutation_token(authorization: str | None = Header(default=None)) -> None:
        """Require a constant-time bearer token match for state-changing endpoints."""
        if not api_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"Set {configuration.api.token_environment_variable} before using "
                    "mutation endpoints"
                ),
            )
        scheme, separator, provided_token = (authorization or "").partition(" ")
        if (
            separator != " "
            or scheme.lower() != "bearer"
            or not secrets.compare_digest(
                provided_token,
                api_token,
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid bearer token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @application.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        """Return the packaged local dashboard shell."""
        return FileResponse(static_directory / "index.html")

    @application.get("/healthz", tags=["operations"])
    async def health() -> dict[str, str]:
        """Return a dependency-free liveness response."""
        return {"status": "ok"}

    @application.get("/api/v1/capsules", tags=["capsules"])
    async def list_capsules() -> dict[str, list[dict[str, object]]]:
        """List verified capsules from the configured project-local store."""
        capsules: list[dict[str, object]] = []
        for capsule_path in sorted(storage_directory.glob("*.evw")):
            try:
                capsule = repository.read(capsule_path, verify=True)
            except EnvWitnessError:
                continue
            capsules.append(
                {
                    "name": capsule_path.name,
                    "capsule_identifier": capsule.capsule_identifier,
                    "project_name": capsule.project_name,
                    "created_at": capsule.created_at,
                    "fact_count": len(capsule.facts),
                    "redacted_fact_count": capsule.redaction.facts_redacted,
                    "command_exit_code": (
                        capsule.command.exit_code if capsule.command is not None else None
                    ),
                }
            )
        return {"capsules": capsules}

    @application.get("/api/v1/capsules/{capsule_name}", tags=["capsules"])
    async def get_capsule(capsule_name: str) -> dict[str, object]:
        """Return one verified capsule manifest by safe basename."""
        capsule_path = _safe_capsule_path(storage_directory, capsule_name)
        try:
            capsule = repository.read(capsule_path, verify=True)
        except EnvWitnessError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return capsule.model_dump(mode="json")

    @application.post(
        "/api/v1/capture",
        tags=["capsules"],
        dependencies=[Depends(require_mutation_token)],
        status_code=status.HTTP_201_CREATED,
    )
    async def capture(request_body: ApiCaptureRequest) -> dict[str, object]:
        """Capture project evidence into the fixed project-local store."""
        destination = _safe_capsule_path(storage_directory, request_body.output_name)
        project_name = configuration.project_name.strip() or resolved_project_root.name
        capture_request = CaptureRequest(
            project_root=resolved_project_root,
            destination=destination,
            project_name=project_name,
            command=request_body.command,
            command_timeout_seconds=configuration.capture.command_timeout_seconds,
            maximum_output_bytes=configuration.capture.maximum_output_bytes,
            environment_value_allowlist=configuration.capture.environment_value_allowlist,
            file_content_allowlist=configuration.capture.file_content_allowlist,
            runtime_commands=tuple(probe.command for probe in configuration.capture.runtime_probes),
        )
        try:
            capsule, final_path = await build_capture_service(configuration).capture(
                capture_request
            )
        except EnvWitnessError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return {
            "name": final_path.name,
            "capsule_identifier": capsule.capsule_identifier,
            "fact_count": len(capsule.facts),
            "redacted_fact_count": capsule.redaction.facts_redacted,
        }

    @application.post("/api/v1/compare", tags=["comparison"])
    async def compare(request_body: ApiComparisonRequest) -> dict[str, object]:
        """Compare two verified stored capsules without mutating state."""
        try:
            baseline = repository.read(
                _safe_capsule_path(storage_directory, request_body.baseline),
                verify=True,
            )
            candidate = repository.read(
                _safe_capsule_path(storage_directory, request_body.candidate),
                verify=True,
            )
        except EnvWitnessError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        report = ComparisonService().compare(baseline, candidate)
        return report.model_dump(mode="json")

    return application


def _resolve_storage_directory(project_root: Path, configured_path: str) -> Path:
    """Resolve storage and ensure it cannot escape the fixed project root."""
    if not configured_path or "\x00" in configured_path:
        raise ValueError("API storage directory cannot be empty or contain nulls")
    candidate_path = Path(configured_path)
    if candidate_path.is_absolute():
        raise ValueError("API storage directory must be project-relative")
    resolved_path = (project_root / candidate_path).resolve()
    try:
        resolved_path.relative_to(project_root)
    except ValueError as error:
        raise ValueError("API storage directory escapes the project root") from error
    return resolved_path


def _safe_capsule_path(storage_directory: Path, capsule_name: str) -> Path:
    """Return a safe capsule path for a strictly validated basename."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.evw", capsule_name):
        raise HTTPException(status_code=400, detail="Invalid capsule name")
    capsule_path = (storage_directory / capsule_name).resolve()
    try:
        capsule_path.relative_to(storage_directory.resolve())
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Capsule path escapes storage") from error
    return capsule_path
