"""Loopback-only REST API and local dashboard application."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import secrets
import stat as stat_module
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from envwitness.application.services import CaptureRequest, ComparisonService, default_project_label
from envwitness.domain.errors import EnvWitnessError
from envwitness.domain.models import Capsule
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


class LoopbackTrustedHostMiddleware:
    """Reject DNS-rebinding Host headers while preserving loopback IPv4 and IPv6."""

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str]) -> None:
        """Initialize middleware with normalized exact host names."""
        self._application = app
        self._allowed_hosts = frozenset(
            normalized_host
            for host in allowed_hosts
            if (normalized_host := _normalize_host_header(host)) is not None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Allow HTTP and WebSocket traffic only for exact configured loopback hosts."""
        if scope["type"] not in {"http", "websocket"}:
            await self._application(scope, receive, send)
            return
        supplied_host = _normalize_host_header(Headers(scope=scope).get("host", ""))
        if supplied_host not in self._allowed_hosts:
            response = PlainTextResponse("Invalid host header", status_code=400)
            await response(scope, receive, send)
            return
        await self._application(scope, receive, send)


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
    capture_service = build_capture_service(configuration)
    api_token = os.environ.get(configuration.api.token_environment_variable, "")
    static_directory = Path(__file__).with_name("static")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        """Close the shared telemetry worker when the local API shuts down."""
        try:
            yield
        finally:
            await asyncio.to_thread(capture_service.close)

    application = FastAPI(
        title="EnvWitness Local API",
        version="1.0.0",
        description="Loopback API for proof-carrying diagnostic evidence.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    application.add_middleware(
        LoopbackTrustedHostMiddleware,
        allowed_hosts={configuration.api.host, "localhost", "127.0.0.1", "::1"},
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
                provided_token.encode("utf-8"),
                api_token.encode("utf-8"),
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
        capsules = await asyncio.to_thread(
            _list_verified_capsules,
            repository,
            storage_directory,
        )
        return {"capsules": capsules}

    @application.get("/api/v1/capsules/{capsule_name}", tags=["capsules"])
    async def get_capsule(capsule_name: str) -> dict[str, object]:
        """Return one verified capsule manifest by safe basename."""
        try:
            capsule = await asyncio.to_thread(
                _read_stored_capsule,
                repository,
                storage_directory,
                capsule_name,
            )
        except HTTPException:
            raise
        except (EnvWitnessError, OSError) as error:
            raise HTTPException(
                status_code=404,
                detail="Capsule not found or invalid",
            ) from error
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
        project_name = configuration.project_name.strip() or default_project_label(
            resolved_project_root
        )
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
            capsule, final_path = await capture_service.capture(capture_request)
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
            baseline, candidate = await asyncio.gather(
                asyncio.to_thread(
                    _read_stored_capsule,
                    repository,
                    storage_directory,
                    request_body.baseline,
                ),
                asyncio.to_thread(
                    _read_stored_capsule,
                    repository,
                    storage_directory,
                    request_body.candidate,
                ),
            )
        except HTTPException:
            raise
        except (EnvWitnessError, OSError) as error:
            raise HTTPException(
                status_code=404,
                detail="Capsule not found or invalid",
            ) from error
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


def _safe_capsule_path(
    storage_directory: Path,
    capsule_name: str,
    *,
    require_existing: bool = False,
) -> Path:
    """Return a safe capsule path for a strictly validated basename."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.evw", capsule_name):
        raise HTTPException(status_code=400, detail="Invalid capsule name")
    _ensure_canonical_storage(storage_directory)
    capsule_path = storage_directory / capsule_name
    if _is_reparse_point(capsule_path):
        raise HTTPException(status_code=404, detail="Capsule not found or invalid")
    try:
        resolved_capsule_path = capsule_path.resolve(strict=require_existing)
        resolved_capsule_path.relative_to(storage_directory)
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=404, detail="Capsule not found or invalid") from error
    if require_existing and not resolved_capsule_path.is_file():
        raise HTTPException(status_code=404, detail="Capsule not found or invalid")
    return resolved_capsule_path


def _read_stored_capsule(
    repository: ZipCapsuleRepository,
    storage_directory: Path,
    capsule_name: str,
) -> Capsule:
    """Read one verified regular capsule without following a storage reparse point."""
    capsule_path = _safe_capsule_path(
        storage_directory,
        capsule_name,
        require_existing=True,
    )
    return repository.read(capsule_path, verify=True)


def _list_verified_capsules(
    repository: ZipCapsuleRepository,
    storage_directory: Path,
) -> list[dict[str, object]]:
    """List verified regular capsules synchronously for execution in a worker thread."""
    capsules: list[dict[str, object]] = []
    try:
        _ensure_canonical_storage(storage_directory)
        capsule_paths = sorted(storage_directory.iterdir(), key=lambda path: path.name)
    except (HTTPException, OSError):
        return capsules
    for candidate_path in capsule_paths:
        if candidate_path.suffix != ".evw":
            continue
        try:
            capsule_path = _safe_capsule_path(
                storage_directory,
                candidate_path.name,
                require_existing=True,
            )
            capsule = repository.read(capsule_path, verify=True)
        except (EnvWitnessError, HTTPException, OSError):
            continue
        capsules.append(
            {
                "name": candidate_path.name,
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
    return capsules


def _ensure_canonical_storage(storage_directory: Path) -> None:
    """Reject storage directories replaced by symlinks or Windows junctions."""
    if _is_reparse_point(storage_directory):
        raise HTTPException(status_code=404, detail="Capsule not found or invalid")
    try:
        if storage_directory.resolve(strict=True) != storage_directory:
            raise HTTPException(status_code=404, detail="Capsule not found or invalid")
    except OSError as error:
        raise HTTPException(status_code=404, detail="Capsule not found or invalid") from error


def _is_reparse_point(path: Path) -> bool:
    """Return whether a path is a symlink or a Windows filesystem reparse point."""
    try:
        path_status = path.lstat()
    except OSError:
        return False
    reparse_attribute = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    file_attributes = getattr(path_status, "st_file_attributes", 0)
    return path.is_symlink() or bool(file_attributes & reparse_attribute)


def _normalize_host_header(host_header: str) -> str | None:
    """Normalize one Host header while rejecting ambiguous ports and bracket syntax."""
    normalized_host: str | None = None
    hostname = ""
    valid_header = bool(host_header) and host_header == host_header.strip()
    if valid_header and host_header.startswith("["):
        closing_bracket = host_header.find("]")
        remainder = host_header[closing_bracket + 1 :] if closing_bracket >= 0 else ""
        valid_header = closing_bracket >= 0 and (
            not remainder or (remainder.startswith(":") and remainder[1:].isdigit())
        )
        if valid_header:
            hostname = host_header[1:closing_bracket]
    elif valid_header and host_header.count(":") == 1:
        hostname, port = host_header.rsplit(":", 1)
        valid_header = port.isdigit()
    elif valid_header:
        hostname = host_header

    if valid_header and hostname:
        try:
            normalized_host = ipaddress.ip_address(hostname).compressed
        except ValueError:
            normalized_host = hostname.lower()
    return normalized_host
