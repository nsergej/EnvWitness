from __future__ import annotations

import json
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from envwitness.domain.errors import CapsuleFormatError, IntegrityError
from envwitness.domain.models import Capsule
from envwitness.infrastructure import archive as archive_module
from envwitness.infrastructure.archive import JsonCapsuleImporter, ZipCapsuleRepository


def mark_first_member_encrypted(archive_path: Path) -> None:
    content = bytearray(archive_path.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        header_offset = content.find(signature)
        assert header_offset >= 0
        value_offset = header_offset + flag_offset
        flags = int.from_bytes(content[value_offset : value_offset + 2], "little") | 0x1
        content[value_offset : value_offset + 2] = flags.to_bytes(2, "little")
    archive_path.write_bytes(content)


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


def test_archive_rejects_duplicate_members(tmp_path: Path) -> None:
    archive_path = tmp_path / "duplicate.evw"
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(archive_path, "w") as archive,
    ):
        archive.writestr("manifest.json", "{}")
        archive.writestr("manifest.json", "{}")

    with pytest.raises(CapsuleFormatError, match="duplicate archive members"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_rejects_encrypted_member_flag(tmp_path: Path) -> None:
    archive_path = tmp_path / "encrypted.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", "{}")
    mark_first_member_encrypted(archive_path)

    with pytest.raises(CapsuleFormatError, match="Encrypted archive members"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_rejects_excessive_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "expanded.evw"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", "x" * 128)
    monkeypatch.setattr(archive_module, "MAXIMUM_UNCOMPRESSED_BYTES", 64)

    with pytest.raises(CapsuleFormatError, match="expands beyond"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_detects_report_tampering(tmp_path: Path, sample_capsule: Capsule) -> None:
    repository = ZipCapsuleRepository()
    archive_path = repository.write(sample_capsule, tmp_path / "report.evw")
    with zipfile.ZipFile(archive_path, "r") as archive:
        manifest = archive.read("manifest.json")
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", manifest)
        archive.writestr("CAPSULE.md", "# substituted report\n")

    with pytest.raises(IntegrityError, match=r"CAPSULE\.md"):
        repository.read(archive_path)


def test_archive_accepts_safe_legacy_report(tmp_path: Path, sample_capsule: Capsule) -> None:
    archive_path = tmp_path / "legacy.evw"
    legacy_report = archive_module._legacy_capsule_to_markdown(sample_capsule)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", sample_capsule.model_dump_json())
        archive.writestr("CAPSULE.md", legacy_report)

    assert ZipCapsuleRepository().read(archive_path) == sample_capsule


def test_archive_rejects_unsafe_legacy_report(
    tmp_path: Path,
    sample_capsule: Capsule,
) -> None:
    hostile_capsule = sample_capsule.model_copy(
        update={
            "project_name": "![report](javascript:alert(1))",
            "integrity": None,
        }
    ).seal()
    archive_path = tmp_path / "unsafe-legacy.evw"
    legacy_report = archive_module._legacy_capsule_to_markdown(hostile_capsule)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", hostile_capsule.model_dump_json())
        archive.writestr("CAPSULE.md", legacy_report)

    with pytest.raises(IntegrityError, match=r"CAPSULE\.md"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_accepts_legacy_manifest_without_report(
    tmp_path: Path,
    sample_capsule: Capsule,
) -> None:
    archive_path = tmp_path / "legacy-no-report.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", sample_capsule.model_dump_json())

    assert ZipCapsuleRepository().read(archive_path) == sample_capsule


def test_repository_removes_temporary_file_after_write_failure(
    tmp_path: Path,
    sample_capsule: Capsule,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_write(*args: object, **kwargs: object) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(zipfile.ZipFile, "writestr", fail_write)

    with pytest.raises(OSError, match="simulated write failure"):
        ZipCapsuleRepository().write(sample_capsule, tmp_path / "atomic.evw")

    assert list(tmp_path.glob(".atomic.evw.*.temporary")) == []
    assert not (tmp_path / "atomic.evw").exists()


def test_repository_refuses_symbolic_link_target(
    tmp_path: Path,
    sample_capsule: Capsule,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / "linked.evw"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"Symbolic links are unavailable: {error}")

    with pytest.raises(CapsuleFormatError, match="symbolic link"):
        ZipCapsuleRepository().write(sample_capsule, link)

    assert target.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda manifest: manifest.replace(
            '"tool_version":"1.0.0"',
            '"tool_version":"1.0.0","tool_version":"1.0.0"',
            1,
        ),
        lambda manifest: manifest.replace('"Python 3.13.1"', "NaN", 1),
    ],
)
def test_json_import_rejects_duplicate_keys_and_nonfinite_numbers(
    tmp_path: Path,
    sample_capsule: Capsule,
    mutate: Callable[[str], str],
) -> None:
    source = tmp_path / "hostile.json"
    original = sample_capsule.model_dump_json()
    hostile = mutate(original)
    assert hostile != original
    source.write_text(hostile, encoding="utf-8")

    with pytest.raises(CapsuleFormatError, match="Invalid capsule JSON"):
        JsonCapsuleImporter(ZipCapsuleRepository()).import_file(source, tmp_path / "hostile.evw")


def test_archive_rejects_malformed_manifest_json(tmp_path: Path) -> None:
    archive_path = tmp_path / "malformed.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", "{")

    with pytest.raises(CapsuleFormatError, match="manifest validation failed"):
        ZipCapsuleRepository().read(archive_path)


def test_repository_rejects_generated_archive_over_limit(
    tmp_path: Path,
    sample_capsule: Capsule,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(archive_module, "MAXIMUM_ARCHIVE_BYTES", 1)

    with pytest.raises(CapsuleFormatError, match="Generated capsule exceeds"):
        ZipCapsuleRepository().write(sample_capsule, tmp_path / "large.evw")

    assert list(tmp_path.glob(".large.evw.*.temporary")) == []


def test_repository_rejects_existing_archive_over_limit(
    tmp_path: Path,
    sample_capsule: Capsule,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = ZipCapsuleRepository()
    archive_path = repository.write(sample_capsule, tmp_path / "large-read.evw")
    monkeypatch.setattr(
        archive_module,
        "MAXIMUM_ARCHIVE_BYTES",
        archive_path.stat().st_size - 1,
    )

    with pytest.raises(CapsuleFormatError, match="archive size limit"):
        repository.read(archive_path)


def test_archive_requires_report_for_nonlegacy_capsule(
    tmp_path: Path,
    sample_capsule: Capsule,
) -> None:
    current_capsule = sample_capsule.model_copy(
        update={"tool_version": "1.1.0", "integrity": None}
    ).seal()
    archive_path = tmp_path / "missing-current-report.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", current_capsule.model_dump_json())

    with pytest.raises(CapsuleFormatError, match=r"missing CAPSULE\.md"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_rejects_non_utf8_report(tmp_path: Path, sample_capsule: Capsule) -> None:
    archive_path = tmp_path / "invalid-report.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", sample_capsule.model_dump_json())
        archive.writestr("CAPSULE.md", b"\xff")

    with pytest.raises(CapsuleFormatError, match="valid UTF-8"):
        ZipCapsuleRepository().read(archive_path)


def test_archive_member_reader_enforces_actual_byte_limit(tmp_path: Path) -> None:
    archive_path = tmp_path / "bounded.evw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", b"0123456789")

    with (
        zipfile.ZipFile(archive_path, "r") as archive,
        pytest.raises(CapsuleFormatError, match="Archive member exceeds"),
    ):
        ZipCapsuleRepository._read_member_bounded(archive, "manifest.json", 4)


def test_json_import_rejects_oversized_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "oversized.json"
    source.write_bytes(b"x" * 17)
    monkeypatch.setattr(archive_module, "MAXIMUM_UNCOMPRESSED_BYTES", 16)

    with pytest.raises(CapsuleFormatError, match="Import source exceeds"):
        JsonCapsuleImporter(ZipCapsuleRepository()).import_file(source, tmp_path / "output.evw")


def test_json_import_rejects_tampered_integrity(
    tmp_path: Path,
    sample_capsule: Capsule,
) -> None:
    source = tmp_path / "tampered.json"
    tampered = sample_capsule.model_copy(update={"project_name": "tampered"})
    source.write_text(tampered.model_dump_json(), encoding="utf-8")

    with pytest.raises(IntegrityError, match="Imported manifest integrity"):
        JsonCapsuleImporter(ZipCapsuleRepository()).import_file(source, tmp_path / "output.evw")


def test_repository_detects_symbolic_link_swap_before_replace(
    tmp_path: Path,
    sample_capsule: Capsule,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "swapped.evw"
    original_is_symlink = Path.is_symlink
    destination_checks = 0

    def simulated_is_symlink(path: Path) -> bool:
        nonlocal destination_checks
        if path == destination:
            destination_checks += 1
            return destination_checks > 1
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", simulated_is_symlink)

    with pytest.raises(CapsuleFormatError, match="symbolic link"):
        ZipCapsuleRepository().write(sample_capsule, destination)

    assert list(tmp_path.glob(".swapped.evw.*.temporary")) == []
