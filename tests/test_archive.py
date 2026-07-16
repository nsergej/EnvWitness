from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from envwitness.domain.errors import CapsuleFormatError, IntegrityError
from envwitness.domain.models import Capsule
from envwitness.infrastructure.archive import JsonCapsuleImporter, ZipCapsuleRepository


def test_archive_round_trip(tmp_path: Path, sample_capsule: Capsule) -> None:
    repository = ZipCapsuleRepository()
    archive_path = repository.write(sample_capsule, tmp_path / "sample")
    loaded = repository.read(archive_path)
    assert archive_path.suffix == ".evw"
    assert loaded == sample_capsule
    with zipfile.ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == {"manifest.json", "CAPSULE.md"}


def test_archive_rejects_traversal_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../manifest.json", "{}")
    with pytest.raises(CapsuleFormatError, match="Unsafe archive member"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_rejects_unknown_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "unknown.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("payload.bin", b"content")
    with pytest.raises(CapsuleFormatError, match="Unsupported archive member"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_detects_manifest_tampering(tmp_path: Path, sample_capsule: Capsule) -> None:
    archive_path = tmp_path / "tampered.evw"
    payload = sample_capsule.model_dump(mode="json")
    payload["project_name"] = "tampered"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(payload))
    with pytest.raises(IntegrityError, match="integrity"):
        ZipCapsuleRepository().read(archive_path)


def test_json_import_requires_integrity(tmp_path: Path, sample_capsule: Capsule) -> None:
    source = tmp_path / "capsule.json"
    source.write_text(sample_capsule.model_dump_json(indent=2), encoding="utf-8")
    destination = JsonCapsuleImporter(ZipCapsuleRepository()).import_file(
        source, tmp_path / "imported.evw"
    )
    assert ZipCapsuleRepository().read(destination) == sample_capsule


def test_repository_refuses_unsealed_capsule(tmp_path: Path, sample_capsule: Capsule) -> None:
    unsealed = sample_capsule.model_copy(update={"integrity": None})
    with pytest.raises(IntegrityError, match="unsealed"):
        ZipCapsuleRepository().write(unsealed, tmp_path / "unsealed.evw")


def test_repository_rejects_missing_and_plain_files(tmp_path: Path) -> None:
    repository = ZipCapsuleRepository()
    with pytest.raises(CapsuleFormatError, match="does not exist"):
        repository.read(tmp_path / "missing.evw")
    plain_file = tmp_path / "plain.evw"
    plain_file.write_text("plain text", encoding="utf-8")
    with pytest.raises(CapsuleFormatError, match="valid ZIP"):
        repository.read(plain_file)


def test_archive_requires_manifest(tmp_path: Path) -> None:
    archive_path = tmp_path / "missing-manifest.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("CAPSULE.md", "report")
    with pytest.raises(CapsuleFormatError, match="missing manifest"):
        ZipCapsuleRepository().read(archive_path)


def test_import_rejects_invalid_json(tmp_path: Path) -> None:
    source = tmp_path / "invalid.json"
    source.write_text("{", encoding="utf-8")
    with pytest.raises(CapsuleFormatError, match="Invalid capsule JSON"):
        JsonCapsuleImporter(ZipCapsuleRepository()).import_file(source, tmp_path / "invalid.evw")
