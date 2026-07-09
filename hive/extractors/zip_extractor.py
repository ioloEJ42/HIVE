"""ZIP archive extraction and recursive content analysis for HIVE.

Extracts ZIP attachments, hashes contents, runs URL extraction on
supported file types, and recurses into nested ZIPs. Uses only
Python stdlib zipfile — no new dependencies.
"""

from __future__ import annotations

import hashlib
import logging
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from hive.extractors.headers import defang
from hive.parser.common import Attachment, sanitise_filename

logger = logging.getLogger(__name__)

MAX_FILES_PER_ZIP = 100
MAX_TOTAL_UNCOMPRESSED_SIZE = 50 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 20 * 1024 * 1024


@dataclass
class ZipEntry:
    """A single file extracted from a ZIP archive."""

    filename: str  # sanitised filename
    original_filename: str  # as found in ZIP
    data: bytes  # raw file bytes
    size: int  # bytes
    hashes: dict  # md5, sha1, sha256
    content_type: str  # guessed from extension
    urls: list[str]  # defanged URLs found in this file
    has_macros: bool | None  # None = not checked or not applicable
    macro_details: str | None
    is_image: bool  # True if image type detected
    is_encrypted: bool  # True if nested encrypted ZIP
    nested_zip_entries: list[ZipEntry] = field(default_factory=list)


@dataclass
class ZipExtractionResult:
    """Result of extracting a ZIP attachment."""

    source_filename: str  # the ZIP filename
    entries: list[ZipEntry]  # all extracted entries
    total_files: int  # count of files found
    skipped_encrypted: bool  # True if ZIP was password-protected
    skipped_too_deep: bool  # True if depth limit reached
    errors: list[str]  # non-fatal errors encountered


def flatten_zip_entries(entries: list[ZipEntry]) -> list[ZipEntry]:
    """Return a flat list of ZIP entries including nested archive contents."""
    flat: list[ZipEntry] = []
    for entry in entries:
        flat.append(entry)
        if entry.nested_zip_entries:
            flat.extend(flatten_zip_entries(entry.nested_zip_entries))
    return flat


def _compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, and SHA256 hex digests for the given bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _is_zip_encrypted(data: bytes) -> bool:
    """Return True if a ZIP file has the encryption flag set in its header."""
    try:
        return (
            len(data) >= 7
            and data[:4] == b"PK\x03\x04"
            and (data[6] & 0x1) == 1
        )
    except Exception:
        return False


def _guess_content_type(filename: str) -> str:
    """Guess MIME type from a filename extension."""
    lower = filename.lower()
    if lower.endswith(".pdf"):
        return "application/pdf"
    if lower.endswith(".docx"):
        return (
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document"
        )
    if lower.endswith(".xlsx"):
        return (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    if lower.endswith(".pptx"):
        return (
            "application/vnd.openxmlformats-officedocument"
            ".presentationml.presentation"
        )
    if lower.endswith(".doc"):
        return "application/msword"
    if lower.endswith(".xls"):
        return "application/vnd.ms-excel"
    if lower.endswith(".rtf"):
        return "application/rtf"
    if lower.endswith(".txt"):
        return "text/plain"
    if lower.endswith(".html") or lower.endswith(".htm"):
        return "text/html"
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    if lower.endswith(".gif"):
        return "image/gif"
    if lower.endswith(".bmp"):
        return "image/bmp"
    if lower.endswith(".zip"):
        return "application/zip"
    return "application/octet-stream"


def extract_entry_raw_urls(
    filename: str,
    content_type: str,
    data: bytes,
) -> list[str]:
    """Extract raw (non-defanged) URLs from a ZIP entry's bytes."""
    try:
        from hive.extractors.urls import (
            _extract_from_docx,
            _extract_from_html_content,
            _extract_from_pdf,
            _extract_from_pptx,
            _extract_from_plain_bytes,
            _extract_from_rtf,
            _extract_from_xlsx,
        )

        lower_name = filename.lower()
        ct = content_type.lower()

        if ct == "application/pdf" or lower_name.endswith(".pdf"):
            return _extract_from_pdf(data)
        if (
            ct
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            or lower_name.endswith(".docx")
        ):
            return _extract_from_docx(data)
        if (
            ct
            == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            or lower_name.endswith(".xlsx")
        ):
            return _extract_from_xlsx(data)
        if (
            ct
            == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            or lower_name.endswith(".pptx")
        ):
            return _extract_from_pptx(data)
        if ct == "application/rtf" or lower_name.endswith(".rtf"):
            return _extract_from_rtf(data)
        if ct == "text/plain" or lower_name.endswith(".txt"):
            return _extract_from_plain_bytes(data)
        if (
            ct == "text/html"
            or lower_name.endswith(".html")
            or lower_name.endswith(".htm")
        ):
            html = data.decode("utf-8", errors="replace")
            return _extract_from_html_content(html)
        return []
    except Exception:
        logger.warning(
            "Failed to extract URLs from ZIP entry: %s",
            filename,
            exc_info=True,
        )
        return []


def _sanitise_zip_entry_name(raw_name: str) -> tuple[str, str]:
    """Return (sanitised basename, original name) for a ZIP entry path."""
    original = raw_name.replace("\\", "/")
    basename = Path(original).name or original
    sanitised = sanitise_filename(basename)
    if sanitised != basename:
        logger.info(
            "Sanitised ZIP entry filename: %r -> %r",
            basename,
            sanitised,
        )
    return sanitised, original


def _analyse_entry(
    filename: str,
    original_filename: str,
    data: bytes,
    content_type: str,
    depth: int,
    max_depth: int,
    errors: list[str],
) -> ZipEntry:
    """Analyse a single extracted ZIP entry."""
    from hive.extractors.attachments import scan_macros

    hashes = _compute_hashes(data)
    raw_urls = extract_entry_raw_urls(filename, content_type, data)
    urls = [defang(url) for url in raw_urls]

    entry_attachment = Attachment(
        filename=filename,
        original_filename=original_filename,
        content_type=content_type,
        data=data,
        size=len(data),
        hashes=hashes,
    )
    scanned = scan_macros(entry_attachment)
    is_image = "Image attachment" in (scanned.macro_details or "")

    entry = ZipEntry(
        filename=filename,
        original_filename=original_filename,
        data=data,
        size=len(data),
        hashes=hashes,
        content_type=content_type,
        urls=urls,
        has_macros=scanned.has_macros,
        macro_details=scanned.macro_details,
        is_image=is_image,
        is_encrypted=False,
    )

    is_nested_zip = content_type == "application/zip" or filename.lower().endswith(
        ".zip"
    )
    if is_nested_zip:
        if _is_zip_encrypted(data):
            entry.is_encrypted = True
        elif depth + 1 >= max_depth:
            errors.append(
                f"Max depth reached — nested ZIP not extracted: {filename}"
            )
        else:
            nested_attachment = Attachment(
                filename=filename,
                original_filename=original_filename,
                content_type="application/zip",
                data=data,
                size=len(data),
                hashes=hashes,
            )
            nested_result = extract_zip(
                nested_attachment,
                depth=depth + 1,
                max_depth=max_depth,
            )
            entry.nested_zip_entries = nested_result.entries
            errors.extend(nested_result.errors)
            if nested_result.skipped_encrypted:
                entry.is_encrypted = True

    return entry


def extract_zip(
    attachment: Attachment,
    depth: int = 0,
    max_depth: int = 10,
) -> ZipExtractionResult:
    """
    Extract and analyse a ZIP attachment recursively.

    Args:
        attachment: The ZIP Attachment to extract
        depth: Current recursion depth (shared with email depth)
        max_depth: Maximum allowed depth

    Returns:
        ZipExtractionResult with all findings

    Never raises — all errors caught and added to result.errors
    """
    result = ZipExtractionResult(
        source_filename=attachment.filename,
        entries=[],
        total_files=0,
        skipped_encrypted=False,
        skipped_too_deep=False,
        errors=[],
    )

    try:
        if _is_zip_encrypted(attachment.data):
            result.skipped_encrypted = True
            return result

        with zipfile.ZipFile(BytesIO(attachment.data)) as archive:
            file_infos = [info for info in archive.infolist() if not info.is_dir()]
            result.total_files = len(file_infos)

            if len(file_infos) > MAX_FILES_PER_ZIP:
                result.errors.append(
                    f"ZIP bomb protection: more than {MAX_FILES_PER_ZIP} files "
                    f"({len(file_infos)} found)"
                )
                file_infos = file_infos[:MAX_FILES_PER_ZIP]

            total_uncompressed = 0

            for info in file_infos:
                try:
                    if info.flag_bits & 0x1:
                        filename, original_filename = _sanitise_zip_entry_name(
                            info.filename
                        )
                        result.entries.append(
                            ZipEntry(
                                filename=filename,
                                original_filename=original_filename,
                                data=b"",
                                size=0,
                                hashes=_compute_hashes(b""),
                                content_type=_guess_content_type(filename),
                                urls=[],
                                has_macros=None,
                                macro_details="Encrypted ZIP entry — not extracted",
                                is_image=False,
                                is_encrypted=True,
                            )
                        )
                        continue

                    if info.file_size > MAX_SINGLE_FILE_SIZE:
                        result.errors.append(
                            f"Skipped file exceeding size limit: {info.filename}"
                        )
                        continue

                    projected_total = total_uncompressed + info.file_size
                    if projected_total > MAX_TOTAL_UNCOMPRESSED_SIZE:
                        result.errors.append(
                            "ZIP bomb protection: total uncompressed size exceeds "
                            f"{MAX_TOTAL_UNCOMPRESSED_SIZE} bytes"
                        )
                        break

                    data = archive.read(info.filename)
                    if len(data) > MAX_SINGLE_FILE_SIZE:
                        result.errors.append(
                            f"Skipped file exceeding size limit: {info.filename}"
                        )
                        continue

                    total_uncompressed += len(data)
                    filename, original_filename = _sanitise_zip_entry_name(info.filename)
                    content_type = _guess_content_type(filename)

                    entry = _analyse_entry(
                        filename,
                        original_filename,
                        data,
                        content_type,
                        depth,
                        max_depth,
                        result.errors,
                    )
                    if entry.nested_zip_entries and depth + 1 >= max_depth:
                        result.skipped_too_deep = True
                    result.entries.append(entry)
                except Exception:
                    result.errors.append(
                        f"Failed to extract ZIP entry: {info.filename}"
                    )
                    logger.exception(
                        "Failed to extract ZIP entry %s from %s",
                        info.filename,
                        attachment.filename,
                    )

    except zipfile.BadZipFile:
        result.errors.append(f"Invalid or corrupt ZIP archive: {attachment.filename}")
        logger.exception("Bad ZIP file: %s", attachment.filename)
    except Exception:
        result.errors.append(f"Failed to extract ZIP: {attachment.filename}")
        logger.exception("Failed to extract ZIP: %s", attachment.filename)

    return result
