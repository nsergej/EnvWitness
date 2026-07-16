"""Atomic, bounded, and self-verifying ``.evw`` capsule archives."""

from __future__ import annotations

import json
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from envwitness.application.services import ReportRenderer
from envwitness.domain.errors import CapsuleFormatError, IntegrityError
from envwitness.domain.models import Capsule

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
            temporary_path.replace(final_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        return final_path.resolve()

    def read(self, source: Path, *, verify: bool = True) -> Capsule:
        """Read a bounded archive, reject unsafe members, and validate its manifest."""
        if not source.exists() or not source.is_file():
            raise CapsuleFormatError(f"Capsule does not exist: {source}")
        if source.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
            raise CapsuleFormatError("Capsule exceeds the archive size limit")
        if not zipfile.is_zipfile(source):
            raise CapsuleFormatError("Capsule is not a valid ZIP archive")
        try:
            with zipfile.ZipFile(source, mode="r") as archive:
                self._validate_members(archive)
                manifest = archive.read(MANIFEST_NAME)
        except (OSError, zipfile.BadZipFile, KeyError) as error:
            raise CapsuleFormatError(f"Cannot read capsule: {error}") from error
        if len(manifest) > MAXIMUM_UNCOMPRESSED_BYTES:
            raise CapsuleFormatError("Capsule manifest exceeds the safety limit")
        try:
            capsule = Capsule.model_validate_json(manifest)
        except ValidationError as error:
            raise CapsuleFormatError(f"Capsule manifest validation failed: {error}") from error
        if verify and not capsule.verify_integrity():
            raise IntegrityError("Capsule manifest integrity verification failed")
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


class JsonCapsuleImporter:
    """Import a previously exported manifest into a verified capsule archive."""

    def __init__(self, repository: ZipCapsuleRepository) -> None:
        """Initialize the importer with the archive repository."""
        self._repository = repository

    def import_file(self, source: Path, destination: Path) -> Path:
        """Validate one bounded JSON manifest and persist it as ``.evw``."""
        if not source.exists() or not source.is_file():
            raise CapsuleFormatError(f"Import source does not exist: {source}")
        if source.stat().st_size > MAXIMUM_UNCOMPRESSED_BYTES:
            raise CapsuleFormatError("Import source exceeds the safety limit")
        try:
            raw_data = json.loads(source.read_text(encoding="utf-8"))
            capsule = Capsule.model_validate(raw_data)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
            raise CapsuleFormatError(f"Invalid capsule JSON: {error}") from error
        if not capsule.verify_integrity():
            raise IntegrityError("Imported manifest integrity verification failed")
        return self._repository.write(capsule, destination)
