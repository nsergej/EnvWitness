from __future__ import annotations

from pathlib import Path

import pytest

from envwitness.domain.models import (
    Capsule,
    EvidenceFact,
    RedactionSummary,
    Sensitivity,
    utc_now,
)


@pytest.fixture
def anyio_backend() -> str:
    """Run asynchronous API tests on the production asyncio backend."""
    return "asyncio"


@pytest.fixture
def sample_fact() -> EvidenceFact:
    return EvidenceFact.create(
        key="runtime.python.version",
        value="Python 3.13.1",
        collector="runtime",
        source="python --version",
        sensitivity=Sensitivity.PUBLIC,
    )


@pytest.fixture
def sample_capsule(sample_fact: EvidenceFact) -> Capsule:
    return Capsule(
        capsule_identifier="ew-0123456789abcdef",
        created_at=utc_now(),
        tool_version="1.0.0",
        project_name="sample",
        project_root_label="sample",
        facts=(sample_fact,),
        redaction=RedactionSummary(
            facts_scanned=1,
            facts_redacted=0,
            replacements=0,
        ),
    ).seal()


@pytest.fixture
def project_directory(tmp_path: Path) -> Path:
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    return project_root
