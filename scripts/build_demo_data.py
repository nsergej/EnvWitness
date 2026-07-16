"""Build deterministic demonstration capsules for screenshots and documentation."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from envwitness.domain.models import (
    Capsule,
    CommandExecution,
    EvidenceFact,
    RedactionSummary,
    Sensitivity,
)
from envwitness.infrastructure.archive import ZipCapsuleRepository

CAPTURE_TIME = datetime(2026, 7, 16, 10, 30, tzinfo=UTC)


def evidence(key: str, value: str | int | bool, source: str) -> EvidenceFact:
    """Create one stable public demonstration fact."""
    return EvidenceFact.create(
        key=key,
        value=value,
        collector=key.split(".", maxsplit=1)[0],
        source=source,
        sensitivity=Sensitivity.PUBLIC,
        captured_at=CAPTURE_TIME,
    )


def redacted_evidence(key: str, value: str, source: str) -> EvidenceFact:
    """Create one stable demonstration fact that records its redaction rule."""
    return EvidenceFact.create(
        key=key,
        value=value,
        collector=key.split(".", maxsplit=1)[0],
        source=source,
        sensitivity=Sensitivity.SENSITIVE,
        captured_at=CAPTURE_TIME,
        redacted=True,
        redaction_rules=("authorization-header",),
    )


def build_capsule(
    *,
    identifier: str,
    python_version: str,
    lock_digest: str,
    commit: str,
    exit_code: int,
    standard_error: str,
) -> Capsule:
    """Build a sealed demonstration capsule with realistic semantic facts."""
    standard_error_fact = (
        redacted_evidence(
            "command.standard_error",
            standard_error,
            "captured standard error",
        )
        if exit_code
        else evidence("command.standard_error", "", "captured standard error")
    )
    facts = (
        evidence("system.operating_system", "Linux", "platform.system"),
        evidence("system.architecture", "x86_64", "platform.machine"),
        evidence("runtime.python.available", True, "executable discovery"),
        evidence("runtime.python.version", python_version, "python --version"),
        evidence("runtime.git.version", "git version 2.50.1", "git --version"),
        evidence("git.commit", commit, "git rev-parse HEAD"),
        evidence("git.dirty", False, "git status --porcelain=v1"),
        evidence("file.hash.uv.lock", lock_digest, "SHA-256 of uv.lock"),
        evidence("command.exit_code", exit_code, "captured process exit status"),
        standard_error_fact,
    )
    command = CommandExecution(
        arguments=("python", "-m", "pytest", "tests/test_checkout.py"),
        working_directory="payments-api",
        started_at=CAPTURE_TIME,
        finished_at=CAPTURE_TIME,
        duration_milliseconds=842 if exit_code == 0 else 1194,
        exit_code=exit_code,
    )
    return Capsule(
        capsule_identifier=identifier,
        created_at=CAPTURE_TIME,
        tool_version="1.0.0",
        project_name="payments-api",
        project_root_label="payments-api",
        facts=facts,
        command=command,
        redaction=RedactionSummary(
            facts_scanned=len(facts),
            facts_redacted=1 if exit_code else 0,
            replacements=1 if exit_code else 0,
            rules_triggered={"authorization-header": 1} if exit_code else {},
        ),
    ).seal()


def build_demo_data(output_directory: Path) -> tuple[Path, Path]:
    """Write working and failing demonstration capsules."""
    output_directory.mkdir(parents=True, exist_ok=True)
    repository = ZipCapsuleRepository()
    working = build_capsule(
        identifier="ew-demo-working-20260716",
        python_version="Python 3.12.11",
        lock_digest="a" * 64,
        commit="57a0c1d8e1f24aaf093a6100d66f37a19d7b90de",
        exit_code=0,
        standard_error="",
    )
    failing = build_capsule(
        identifier="ew-demo-failing-20260716",
        python_version="Python 3.13.5",
        lock_digest="b" * 64,
        commit="a4fdc9c47d2a7d16fd38e4405df9d9c5300ec54e",
        exit_code=1,
        standard_error="AuthenticationError: Authorization: [REDACTED:authorization-header]",
    )
    return (
        repository.write(working, output_directory / "working.evw"),
        repository.write(failing, output_directory / "failing.evw"),
    )


def main() -> None:
    """Parse arguments and build the documentation data set."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".envwitness/capsules"),
        help="Directory that receives working.evw and failing.evw.",
    )
    arguments = parser.parse_args()
    working, failing = build_demo_data(arguments.output)
    print(f"Created {working}")
    print(f"Created {failing}")


if __name__ == "__main__":
    main()
