"""Attachment macro scanning and hash CSV formatting for HIVE.

Verifies parser-computed attachment hashes for forensic output and scans
eligible Office documents for VBA macros using oletools. Produces the
hashes.csv content and provides recursive attachment collection.
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import replace

from oletools.olevba import VBA_Parser

from hive.parser.common import Attachment, ParsedEmail

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


def _format_has_macros(value: bool | None) -> str:
    """Format has_macros for CSV output."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


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
                    _format_has_macros(attachment.has_macros),
                ]
            )

        return output.getvalue()
    except Exception:
        logger.exception("Failed to build hashes.csv content")
        output = io.StringIO(newline="")
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(_CSV_HEADER)
        return output.getvalue()


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
        return attachments
    except Exception:
        logger.exception("Failed to collect attachments from parsed email")
        return []
