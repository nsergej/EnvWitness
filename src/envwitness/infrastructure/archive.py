"""Atomic, bounded, and self-verifying ``.evw`` capsule archives."""

from __future__ import annotations

import io
import json
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from envwitness.application.services import ReportRenderer
from envwitness.domain.errors import CapsuleFormatError, IntegrityError
from envwitness.domain.models import Capsule, has_unsafe_control_characters

MANIFEST_NAME = "manifest.json"
REPORT_NAME = "CAPSULE.md"
ALLOWED_ARCHIVE_MEMBERS = frozenset({MANIFEST_NAME, REPORT_NAME})
MAXIMUM_ARCHIVE_BYTES = 26_214_400
MAXIMUM_UNCOMPRESSED_BYTES = 52_428_800


class ZipCapsuleRepository:
    """Store capsules as small portable ZIP archives with an ``.evw`` suffix."""

    def write(self, capsule: Capsule, destination: Path) -> Path:
        """Write a sealed capsule atomically without following an existing symlink."""
        if not capsule.verify_integrity():
            raise IntegrityError("Refusing to persist an unsealed or invalid capsule")
        final_path = destination
        if final_path.suffix.lower() != ".evw":
            final_path = final_path.with_suffix(".evw")
        final_path.parent.mkdir(parents=True, exist_ok=True)
        if final_path.is_symlink():
            raise CapsuleFormatError(f"Refusing to overwrite a symbolic link: {final_path}")

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{final_path.name}.",
            suffix=".temporary",
            dir=final_path.parent,
        )
        temporary_path = Path(temporary_name)
        os.close(file_descriptor)
        try:
            with zipfile.ZipFile(
                temporary_path,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                archive.writestr(
                    MANIFEST_NAME,
                    capsule.model_dump_json(indent=2).encode("utf-8"),
                )
                archive.writestr(
                    REPORT_NAME,
                    ReportRenderer().capsule_to_markdown(capsule).encode("utf-8"),
                )
            if temporary_path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
                raise CapsuleFormatError("Generated capsule exceeds the archive size limit")
            if final_path.is_symlink():
                raise CapsuleFormatError(f"Refusing to overwrite a symbolic link: {final_path}")
            temporary_path.replace(final_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        return final_path.resolve()

    def read(self, source: Path, *, verify: bool = True) -> Capsule:
        """Read a bounded archive, reject unsafe members, and validate its manifest."""
        if source.is_symlink():
            raise CapsuleFormatError(f"Refusing to read a symbolic link: {source}")
        if not source.exists() or not source.is_file():
            raise CapsuleFormatError(f"Capsule does not exist: {source}")
        archive_bytes = _read_file_snapshot(
            source,
            maximum_bytes=MAXIMUM_ARCHIVE_BYTES,
            size_error="Capsule exceeds the archive size limit",
            changed_error="Capsule changed while it was being opened",
        )
        archive_stream = io.BytesIO(archive_bytes)
        if not zipfile.is_zipfile(archive_stream):
            raise CapsuleFormatError("Capsule is not a valid ZIP archive")
        archive_stream.seek(0)
        try:
            with zipfile.ZipFile(archive_stream, mode="r") as archive:
                self._validate_members(archive)
                manifest = self._read_member_bounded(
                    archive,
                    MANIFEST_NAME,
                    MAXIMUM_UNCOMPRESSED_BYTES,
                )
                report = (
                    self._read_member_bounded(
                        archive,
                        REPORT_NAME,
                        MAXIMUM_UNCOMPRESSED_BYTES,
                    )
                    if REPORT_NAME in archive.namelist()
                    else None
                )
        except (OSError, RuntimeError, zipfile.BadZipFile, KeyError) as error:
            raise CapsuleFormatError(f"Cannot read capsule: {error}") from error
        try:
            capsule = Capsule.model_validate(_strict_json_loads(manifest))
        except (UnicodeError, ValueError, ValidationError) as error:
            raise CapsuleFormatError(f"Capsule manifest validation failed: {error}") from error
        if verify and not capsule.verify_integrity():
            raise IntegrityError("Capsule manifest integrity verification failed")
        self._validate_report(capsule, report)
        return capsule

    @staticmethod
    def _validate_members(archive: zipfile.ZipFile) -> None:
        """Reject traversal, encryption, duplicates, and decompression bombs."""
        names: list[str] = []
        total_uncompressed = 0
        for member in archive.infolist():
            member_path = PurePosixPath(member.filename)
            if member.flag_bits & 0x1:
                raise CapsuleFormatError("Encrypted archive members are not supported")
            if member_path.is_absolute() or ".." in member_path.parts:
                raise CapsuleFormatError(f"Unsafe archive member path: {member.filename}")
            if member.filename not in ALLOWED_ARCHIVE_MEMBERS:
                raise CapsuleFormatError(f"Unsupported archive member: {member.filename}")
            names.append(member.filename)
            total_uncompressed += member.file_size
            if total_uncompressed > MAXIMUM_UNCOMPRESSED_BYTES:
                raise CapsuleFormatError("Capsule expands beyond the safety limit")
        if len(names) != len(set(names)):
            raise CapsuleFormatError("Capsule contains duplicate archive members")
        if MANIFEST_NAME not in names:
            raise CapsuleFormatError("Capsule is missing manifest.json")

    @staticmethod
    def _read_member_bounded(
        archive: zipfile.ZipFile,
        member_name: str,
        maximum_bytes: int,
    ) -> bytes:
        """Read one member through a strict decompressed-byte ceiling."""
        with archive.open(member_name, mode="r") as member:
            content = member.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise CapsuleFormatError(f"Archive member exceeds the safety limit: {member_name}")
        return content

    @staticmethod
    def _validate_report(capsule: Capsule, report: bytes | None) -> None:
        """Require an embedded report to be a deterministic projection of its manifest."""
        if report is None:
            if _is_legacy_capsule(capsule):
                return
            raise CapsuleFormatError("Capsule is missing CAPSULE.md")
        try:
            decoded_report = report.decode("utf-8")
        except UnicodeError as error:
            raise CapsuleFormatError("CAPSULE.md is not valid UTF-8") from error

        current_report = ReportRenderer().capsule_to_markdown(capsule)
        if decoded_report == current_report:
            return
        if (
            _is_legacy_capsule(capsule)
            and _legacy_report_is_safe(capsule)
            and decoded_report == _legacy_capsule_to_markdown(capsule)
        ):
            return
        raise IntegrityError("CAPSULE.md does not match the capsule manifest")


class JsonCapsuleImporter:
    """Import a previously exported manifest into a verified capsule archive."""

    def __init__(self, repository: ZipCapsuleRepository) -> None:
        """Initialize the importer with the archive repository."""
        self._repository = repository

    def import_file(self, source: Path, destination: Path) -> Path:
        """Validate one bounded JSON manifest and persist it as ``.evw``."""
        if source.is_symlink():
            raise CapsuleFormatError(f"Refusing to import a symbolic link: {source}")
        if not source.exists() or not source.is_file():
            raise CapsuleFormatError(f"Import source does not exist: {source}")
        try:
            encoded_data = _read_file_snapshot(
                source,
                maximum_bytes=MAXIMUM_UNCOMPRESSED_BYTES,
                size_error="Import source exceeds the safety limit",
                changed_error="Import source changed while it was being opened",
            )
            capsule = Capsule.model_validate(_strict_json_loads(encoded_data))
        except CapsuleFormatError:
            raise
        except (OSError, UnicodeError, ValueError, ValidationError) as error:
            raise CapsuleFormatError(f"Invalid capsule JSON: {error}") from error
        if not capsule.verify_integrity():
            raise IntegrityError("Imported manifest integrity verification failed")
        return self._repository.write(capsule, destination)


def _strict_json_loads(content: bytes | str) -> object:
    """Decode JSON while rejecting duplicate keys and non-finite numbers."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="strict")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for key, value in pairs:
            if key in decoded:
                raise ValueError("JSON object contains a duplicate key")
            decoded[key] = value
        return decoded

    def reject_non_finite_number(value: str) -> object:
        raise ValueError(f"JSON contains a non-finite number: {value}")

    return json.loads(
        content,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_non_finite_number,
    )


def _read_file_snapshot(
    source: Path,
    *,
    maximum_bytes: int,
    size_error: str,
    changed_error: str,
) -> bytes:
    """Read one regular file once while binding path checks to its open handle."""
    try:
        with source.open("rb") as source_handle:
            handle_status = os.fstat(source_handle.fileno())
            content = source_handle.read(maximum_bytes + 1)
            path_is_symlink = source.is_symlink()
            path_status = source.stat()
    except OSError as error:
        raise CapsuleFormatError(changed_error) from error
    if not stat.S_ISREG(handle_status.st_mode) or path_is_symlink:
        raise CapsuleFormatError(changed_error)
    if (handle_status.st_dev, handle_status.st_ino) != (
        path_status.st_dev,
        path_status.st_ino,
    ):
        raise CapsuleFormatError(changed_error)
    if len(content) > maximum_bytes:
        raise CapsuleFormatError(size_error)
    return content


def _is_legacy_capsule(capsule: Capsule) -> bool:
    """Return whether the capsule predates deterministic report validation."""
    return capsule.schema_version == "1.0" and capsule.tool_version == "1.0.0"


def _legacy_report_is_safe(capsule: Capsule) -> bool:
    """Allow legacy Markdown only when old delimiters cannot be escaped."""
    if re.search(r"[`<>\[\]\r\n]", capsule.project_name) or has_unsafe_control_characters(
        capsule.project_name
    ):
        return False
    if capsule.command is not None and any(
        re.search(r"[`\r\n]", argument) or has_unsafe_control_characters(argument)
        for argument in capsule.command.arguments
    ):
        return False
    for fact in capsule.facts:
        rendered_value = json.dumps(fact.value, ensure_ascii=False, sort_keys=True)
        if (
            "`" in rendered_value
            or "\r" in fact.collector
            or "\n" in fact.collector
            or has_unsafe_control_characters(rendered_value)
            or has_unsafe_control_characters(fact.collector)
        ):
            return False
    return True


def _legacy_capsule_to_markdown(capsule: Capsule) -> str:
    """Reproduce the original 1.0 report for narrowly bounded compatibility."""
    command_line = "Not captured"
    if capsule.command is not None:
        command_line = " ".join(capsule.command.arguments)
    lines = [
        f"# EnvWitness report: {capsule.project_name}",
        "",
        f"- Capsule: `{capsule.capsule_identifier}`",
        f"- Created: `{capsule.created_at.isoformat()}`",
        f"- Integrity: `{'verified' if capsule.verify_integrity() else 'invalid'}`",
        f"- Command: `{command_line}`",
        f"- Redacted facts: `{capsule.redaction.facts_redacted}`",
        "",
        "## Evidence",
        "",
        "| Key | Value | Collector | Sensitivity |",
        "| --- | --- | --- | --- |",
    ]
    for fact in capsule.facts:
        rendered_value = json.dumps(fact.value, ensure_ascii=False, sort_keys=True)
        safe_value = rendered_value.replace("|", "\\|").replace("\n", "<br>")
        lines.append(
            f"| `{fact.key}` | `{safe_value}` | `{fact.collector}` | `{fact.sensitivity.value}` |"
        )
    lines.append("")
    return "\n".join(lines)
