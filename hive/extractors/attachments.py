"""Attachment macro scanning and hash CSV formatting for HIVE.

Verifies parser-computed attachment hashes for forensic output and scans
eligible Office documents for VBA macros using oletools. Produces the
hashes.csv content and provides recursive attachment collection.
"""

from __future__ import annotations

import csv
import io
import logging
import zipfile
from dataclasses import replace

from oletools.olevba import VBA_Parser

from hive.parser.common import Attachment, ParsedEmail
from hive.extractors.zip_extractor import ZipExtractionResult, extract_zip

logger = logging.getLogger(__name__)

# Office file extensions eligible for macro scanning
_MACRO_EXTENSIONS = (
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".dot",
    ".dotm",
    ".xlt",
    ".xltm",
    ".pot",
    ".potm",
    ".xlam",
    ".ppam",
)

# MIME content-type keywords that indicate Office/OpenDocument files
_MACRO_CONTENT_TYPE_KEYWORDS = (
    "msword",
    "ms-excel",
    "ms-powerpoint",
    "officedocument",
    "opendocument",
)

_OLE2_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_OOXML_EXTENSIONS = (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")

_LEGACY_OFFICE_EXTENSIONS = (".doc", ".xls", ".ppt")

_PROTECTED_ZIP_DETAILS = "Password-protected ZIP — contents not extracted"

_PROTECTED_PDF_DETAILS = "Password-protected PDF — content not extracted"

_PROTECTED_OOXML_DETAILS = (
    "Password-protected Office document — content not extracted"
)

_PROTECTED_LEGACY_OFFICE_DETAILS = (
    "Password-protected legacy Office document — content not extracted"
)

_IMAGE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".webp", ".tiff", ".tif", ".svg",
})

_IMAGE_CONTENT_TYPES = frozenset({
    "image/png", "image/jpeg", "image/jpg", "image/gif",
    "image/bmp", "image/webp", "image/tiff", "image/svg+xml",
})

_IMAGE_ATTACHMENT_DETAILS = (
    "Image attachment — manual review recommended "
    "(may contain QR code or embedded content)"
)

_CSV_HEADER = [
    "filename",
    "original_filename",
    "size_bytes",
    "md5",
    "sha1",
    "sha256",
    "content_type",
    "has_macros",
]


def _is_macro_scannable(attachment: Attachment) -> bool:
    """Return True if the attachment type is eligible for macro scanning."""
    filename = attachment.filename.lower()
    if any(filename.endswith(extension) for extension in _MACRO_EXTENSIONS):
        return True

    content_type = (attachment.content_type or "").lower()
    return any(keyword in content_type for keyword in _MACRO_CONTENT_TYPE_KEYWORDS)


def _format_has_macros(attachment: Attachment) -> str:
    """Format has_macros for CSV output."""
    if is_encrypted(attachment):
        return "encrypted"
    if "Image attachment" in (attachment.macro_details or ""):
        return "image"
    value = attachment.has_macros
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def is_encrypted(attachment: Attachment) -> bool:
    """Return True if attachment.macro_details indicates encryption."""
    if not attachment.macro_details:
        return False
    return "password-protected" in attachment.macro_details.lower()


def _protected_attachment_copy(attachment: Attachment, details: str) -> Attachment:
    """Return a copy flagged as password-protected."""
    return replace(attachment, has_macros=None, macro_details=details)


def _is_zip_attachment(attachment: Attachment) -> bool:
    filename = attachment.filename.lower()
    content_type = (attachment.content_type or "").lower()
    return filename.endswith(".zip") or content_type == "application/zip"


def _is_pdf_attachment(attachment: Attachment) -> bool:
    filename = attachment.filename.lower()
    content_type = (attachment.content_type or "").lower()
    return filename.endswith(".pdf") or content_type == "application/pdf"


def _is_ooxml_attachment(attachment: Attachment) -> bool:
    filename = attachment.filename.lower()
    content_type = (attachment.content_type or "").lower()
    if any(filename.endswith(extension) for extension in _OOXML_EXTENSIONS):
        return True
    return "officedocument" in content_type


def _is_legacy_office_attachment(attachment: Attachment) -> bool:
    filename = attachment.filename.lower()
    content_type = (attachment.content_type or "").lower()
    if any(filename.endswith(extension) for extension in _LEGACY_OFFICE_EXTENSIONS):
        return True
    return any(keyword in content_type for keyword in ("msword", "ms-excel", "ms-powerpoint"))


def _detect_encrypted_zip(attachment: Attachment) -> Attachment | None:
    try:
        data = attachment.data
        if len(data) >= 7 and data[:4] == b"PK\x03\x04" and (data[6] & 0x1) == 1:
            return _protected_attachment_copy(attachment, _PROTECTED_ZIP_DETAILS)
    except Exception:
        logger.warning(
            "Failed encrypted ZIP detection for attachment: %s",
            attachment.filename,
            exc_info=True,
        )
    return None


def _detect_encrypted_pdf(attachment: Attachment) -> Attachment | None:
    try:
        if b"/Encrypt" in attachment.data:
            return _protected_attachment_copy(attachment, _PROTECTED_PDF_DETAILS)
    except Exception:
        logger.warning(
            "Failed encrypted PDF detection for attachment: %s",
            attachment.filename,
            exc_info=True,
        )
    return None


def _detect_encrypted_ooxml(attachment: Attachment) -> Attachment | None:
    try:
        with zipfile.ZipFile(io.BytesIO(attachment.data)) as archive:
            if "EncryptedPackage" in archive.namelist():
                return _protected_attachment_copy(attachment, _PROTECTED_OOXML_DETAILS)
    except zipfile.BadZipFile:
        return _protected_attachment_copy(attachment, _PROTECTED_OOXML_DETAILS)
    except Exception:
        logger.warning(
            "Failed encrypted Office Open XML detection for attachment: %s",
            attachment.filename,
            exc_info=True,
        )
    return None


def _detect_encrypted_legacy_office(attachment: Attachment) -> Attachment | None:
    try:
        data = attachment.data
        if len(data) < 8 or data[:8] != _OLE2_SIGNATURE:
            return None

        if b"\x13\x00" in data:
            return _protected_attachment_copy(
                attachment, _PROTECTED_LEGACY_OFFICE_DETAILS
            )

        vba_parser = None
        try:
            vba_parser = VBA_Parser(attachment.filename, data=attachment.data)
        except Exception as exc:
            if "encrypt" in str(exc).lower():
                return _protected_attachment_copy(
                    attachment, _PROTECTED_LEGACY_OFFICE_DETAILS
                )
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    logger.exception(
                        "Failed to close VBA_Parser during encryption check: %s",
                        attachment.filename,
                    )
    except Exception:
        logger.warning(
            "Failed encrypted legacy Office detection for attachment: %s",
            attachment.filename,
            exc_info=True,
        )
    return None


def detect_password_protected(attachment: Attachment) -> Attachment:
    """Detect whether an attachment is password-protected or encrypted.

    Returns a new Attachment copy with has_macros and macro_details updated
    if encryption is detected. Never raises. Never mutates the input.
    """
    try:
        if _is_zip_attachment(attachment):
            protected = _detect_encrypted_zip(attachment)
            if protected is not None:
                return protected

        if _is_pdf_attachment(attachment):
            protected = _detect_encrypted_pdf(attachment)
            if protected is not None:
                return protected

        if _is_ooxml_attachment(attachment):
            protected = _detect_encrypted_ooxml(attachment)
            if protected is not None:
                return protected

        if _is_legacy_office_attachment(attachment):
            protected = _detect_encrypted_legacy_office(attachment)
            if protected is not None:
                return protected

        return replace(attachment)
    except Exception:
        logger.exception(
            "Unexpected error during password-protection detection: %s",
            attachment.filename,
        )
        return replace(attachment)


def _has_image_content_type(attachment: Attachment) -> bool:
    try:
        return (attachment.content_type or "").lower() in _IMAGE_CONTENT_TYPES
    except Exception:
        return False


def _has_image_extension(attachment: Attachment) -> bool:
    try:
        filename = attachment.filename.lower()
        return any(filename.endswith(extension) for extension in _IMAGE_EXTENSIONS)
    except Exception:
        return False


def _has_image_magic_bytes(data: bytes) -> bool:
    try:
        if len(data) >= 4 and data[:4] == b"\x89PNG":
            return True
        if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
            return True
        if len(data) >= 6 and data[:6] in (b"GIF87a", b"GIF89a"):
            return True
        if len(data) >= 2 and data[:2] == b"BM":
            return True
        if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return True
        if len(data) >= 4 and data[:4] in (b"II*\x00", b"MM\x00*"):
            return True
    except Exception:
        logger.warning("Failed image magic-byte detection", exc_info=True)
    return False


def detect_image_attachment(attachment: Attachment) -> Attachment:
    """Detect image attachments that may contain QR codes or embedded content.

    Returns a new Attachment copy with macro_details populated if an image is
    detected. Never raises. Never mutates the input.
    """
    try:
        is_image = False

        try:
            is_image = _has_image_content_type(attachment)
        except Exception:
            logger.warning(
                "Failed image content-type detection for attachment: %s",
                attachment.filename,
                exc_info=True,
            )

        if not is_image:
            try:
                is_image = _has_image_extension(attachment)
            except Exception:
                logger.warning(
                    "Failed image extension detection for attachment: %s",
                    attachment.filename,
                    exc_info=True,
                )

        if not is_image:
            try:
                is_image = _has_image_magic_bytes(attachment.data)
            except Exception:
                logger.warning(
                    "Failed image signature detection for attachment: %s",
                    attachment.filename,
                    exc_info=True,
                )

        if is_image:
            return replace(attachment, macro_details=_IMAGE_ATTACHMENT_DETAILS)

        return replace(attachment)
    except Exception:
        logger.exception(
            "Unexpected error during image attachment detection: %s",
            attachment.filename,
        )
        return replace(attachment)


def scan_macros(attachment: Attachment) -> Attachment:
    """Scan a single attachment for VBA macros using oletools.

    Returns a new Attachment copy with has_macros and macro_details
    populated. The input attachment is never mutated.

    Args:
        attachment: Attachment to scan.

    Returns:
        A copy of the attachment with macro scan results applied.
    """
    try:
        protected_attachment = detect_password_protected(attachment)
        macro_details = protected_attachment.macro_details or ""
        if (
            "Password-protected" in macro_details
            or "not extracted" in macro_details.lower()
        ):
            return protected_attachment

        image_attachment = detect_image_attachment(protected_attachment)
        image_details = image_attachment.macro_details or ""
        if "Image attachment" in image_details:
            return image_attachment

        attachment = image_attachment

        if not _is_macro_scannable(attachment):
            return replace(attachment)

        vba_parser = None
        try:
            vba_parser = VBA_Parser(attachment.filename, data=attachment.data)
            if vba_parser.detect_vba_macros():
                macro_lines: list[str] = []
                for _, _, vba_filename, vba_code in vba_parser.extract_macros():
                    macro_lines.append(
                        f"[{vba_filename}] {len(vba_code)} bytes of VBA code"
                    )
                return replace(
                    attachment,
                    has_macros=True,
                    macro_details="\n".join(macro_lines),
                )

            return replace(attachment, has_macros=False, macro_details=None)
        except Exception as exc:
            logger.exception(
                "Macro scan failed for attachment: %s", attachment.filename
            )
            return replace(
                attachment,
                has_macros=None,
                macro_details=f"Macro scan failed: {exc}",
            )
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    logger.exception(
                        "Failed to close VBA_Parser for attachment: %s",
                        attachment.filename,
                    )
    except Exception:
        logger.exception(
            "Unexpected error during macro scan for attachment: %s",
            attachment.filename,
        )
        return replace(attachment)


def build_hashes_csv(attachments: list) -> str:
    """Build the hashes.csv content for a flat list of attachments.

    Args:
        attachments: Flat list of Attachment objects from all email levels.

    Returns:
        CSV string with quoted fields and a header row.
    """
    try:
        output = io.StringIO(newline="")
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(_CSV_HEADER)

        for attachment in attachments:
            writer.writerow(
                [
                    attachment.filename,
                    attachment.original_filename,
                    attachment.size,
                    attachment.hashes.get("md5", ""),
                    attachment.hashes.get("sha1", ""),
                    attachment.hashes.get("sha256", ""),
                    attachment.content_type,
                    _format_has_macros(attachment),
                ]
            )

        return output.getvalue()
    except Exception:
        logger.exception("Failed to build hashes.csv content")
        output = io.StringIO(newline="")
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(_CSV_HEADER)
        return output.getvalue()


def process_zip_attachment(
    attachment: Attachment,
    depth: int = 0,
    max_depth: int = 10,
) -> ZipExtractionResult | None:
    """
    Process a ZIP attachment if it is not encrypted.
    Returns ZipExtractionResult or None if not a ZIP or encrypted.
    Never raises.
    """
    try:
        lower = attachment.filename.lower()
        ct = (attachment.content_type or "").lower()
        is_zip = lower.endswith(".zip") or "zip" in ct
        if not is_zip:
            return None
        if is_encrypted(attachment):
            return None
        return extract_zip(attachment, depth=depth, max_depth=max_depth)
    except Exception:
        logger.exception("Failed to process ZIP: %s", attachment.filename)
        return None


def collect_zip_entries_as_attachments(
    zip_result: ZipExtractionResult,
) -> list[Attachment]:
    """
    Convert ZipEntry objects to Attachment objects for hashes.csv.
    Allows ZIP contents to appear in the hash output.
    Never raises.
    """
    try:
        from hive.extractors.zip_extractor import flatten_zip_entries

        attachments: list[Attachment] = []
        for entry in flatten_zip_entries(zip_result.entries):
            if not entry.data:
                continue
            attachments.append(
                Attachment(
                    filename=f"[zip]{entry.filename}",
                    original_filename=entry.original_filename,
                    content_type=entry.content_type,
                    data=entry.data,
                    size=entry.size,
                    hashes=entry.hashes,
                    has_macros=entry.has_macros,
                    macro_details=entry.macro_details,
                )
            )
        return attachments
    except Exception:
        logger.exception(
            "Failed to convert ZIP entries to attachments for %s",
            zip_result.source_filename,
        )
        return []


def collect_attachments(email: ParsedEmail) -> list[Attachment]:
    """Recursively collect all attachments from an email and its nested emails.

    Args:
        email: Parsed email that may contain nested messages.

    Returns:
        Flat list of attachments from every nesting level.
    """
    try:
        attachments = list(email.attachments)
        for nested in email.nested_emails:
            attachments.extend(collect_attachments(nested))
        zip_attachments: list[Attachment] = []
        for attachment in attachments:
            zip_result = process_zip_attachment(attachment)
            if zip_result is not None:
                zip_attachments.extend(
                    collect_zip_entries_as_attachments(zip_result)
                )
        attachments.extend(zip_attachments)
        return attachments
    except Exception:
        logger.exception("Failed to collect attachments from parsed email")
        return []
