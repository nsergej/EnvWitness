from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from envwitness.domain.models import Capsule
from envwitness.infrastructure.archive import ZipCapsuleRepository
from envwitness.infrastructure.config import EnvWitnessConfiguration
from envwitness.presentation.api import create_api_application


@pytest.mark.anyio
async def test_api_health_and_empty_listing(project_directory: Path) -> None:
    application = create_api_application(EnvWitnessConfiguration(), project_directory)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/healthz")).json() == {"status": "ok"}
        assert (await client.get("/api/v1/capsules")).json() == {"capsules": []}
        assert (await client.get("/")).status_code == 200
        assert "EnvWitness" in (await client.get("/")).text


@pytest.mark.anyio
async def test_api_capture_requires_configured_token(
    project_directory: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("ENVWITNESS_API_TOKEN", raising=False)
    application = create_api_application(EnvWitnessConfiguration(), project_directory)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/capture", json={"output_name": "api.evw"})
        assert response.status_code == 503


@pytest.mark.anyio
async def test_api_capture_list_get_and_compare(
    project_directory: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ENVWITNESS_API_TOKEN", "test-token-with-enough-entropy")
    configuration = EnvWitnessConfiguration.model_validate(
        {
            "capture": {
                "runtime_probes": [],
                "maximum_output_bytes": 4096,
            }
        }
    )
    transport = httpx.ASGITransport(app=create_api_application(configuration, project_directory))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unauthorized = await client.post("/api/v1/capture", json={"output_name": "first.evw"})
        assert unauthorized.status_code == 401
        headers = {"Authorization": "Bearer test-token-with-enough-entropy"}
        first = await client.post(
            "/api/v1/capture",
            json={"output_name": "first.evw"},
            headers=headers,
        )
        second = await client.post(
            "/api/v1/capture",
            json={"output_name": "second.evw"},
            headers=headers,
        )
        assert first.status_code == 201
        assert second.status_code == 201
        listing = (await client.get("/api/v1/capsules")).json()["capsules"]
        assert [item["name"] for item in listing] == ["first.evw", "second.evw"]
        manifest = await client.get("/api/v1/capsules/first.evw")
        assert manifest.status_code == 200
        comparison = await client.post(
            "/api/v1/compare",
            json={"baseline": "first.evw", "candidate": "second.evw"},
        )
        assert comparison.status_code == 200
        assert comparison.json()["identical"] is True


@pytest.mark.anyio
async def test_api_lists_only_valid_capsules(
    project_directory: Path,
    sample_capsule: Capsule,
) -> None:
    storage = project_directory / ".envwitness" / "capsules"
    storage.mkdir(parents=True)
    ZipCapsuleRepository().write(sample_capsule, storage / "valid.evw")
    (storage / "invalid.evw").write_text("not an archive", encoding="utf-8")
    application = create_api_application(EnvWitnessConfiguration(), project_directory)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        listing = (await client.get("/api/v1/capsules")).json()["capsules"]
        assert [item["name"] for item in listing] == ["valid.evw"]
        response = await client.get("/api/v1/capsules/../invalid.evw")
        assert response.status_code in {400, 404}


def test_api_rejects_storage_escape(project_directory: Path) -> None:
    configuration = EnvWitnessConfiguration.model_validate(
        {"api": {"storage_directory": "../outside"}}
    )
    try:
        create_api_application(configuration, project_directory)
    except ValueError as error:
        assert "escapes" in str(error)
    else:
        raise AssertionError("Storage traversal should be rejected")
