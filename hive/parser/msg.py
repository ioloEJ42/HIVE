"""Parser for Microsoft Outlook .msg files.

Uses the extract-msg library to parse OLE2 .msg files into ParsedEmail
instances. Handles transit headers, attachment extraction, and recursive
nested .eml / .msg parsing. Nested .msg files are written to a temporary
file for recursive parsing only — attachment content is never persisted.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import HeaderParser
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

import extract_msg

from hive.parser.common import Attachment, ParsedEmail, sanitise_filename
from hive.parser.eml import parse_eml_from_bytes

logger = logging.getLogger(__name__)

_HEADER_PARSER = HeaderParser(policy=policy.compat32)


def _compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, and SHA256 hex digests for the given bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _decode_header_value(value: str) -> str:
    """Decode RFC2047 encoded words in a header value string.

    Returns a clean Unicode string. Never raises.
    """
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        try:
            fragments: list[str] = []
            for fragment, charset in decode_header(value):
                if isinstance(fragment, bytes):
                    fragments.append(fragment.decode(charset or "utf-8", errors="replace"))
                else:
                    fragments.append(fragment)
            return "".join(fragments)
        except Exception:
            return value


def _format_datetime(dt: datetime) -> str:
    """Format a datetime object as a UTC timestamp string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_date_from_header(date_header: str) -> str:
    """Parse a Date header string to UTC or return the raw string on failure."""
    if not date_header:
        return ""
    try:
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return date_header


def _parse_headers_raw(headers_raw: str) -> dict[str, list[str]]:
    """Parse a raw header block into a lowercase key → list of values dict."""
    headers: dict[str, list[str]] = {}
    if not headers_raw:
        return headers
    try:
        parsed = _HEADER_PARSER.parsestr(headers_raw)
        raw_headers = getattr(parsed, "_headers", None)
        if raw_headers:
            for key, value in raw_headers:
                headers.setdefault(key.lower(), []).append(_decode_header_value(value))
        else:
            for key in parsed.keys():
                for value in parsed.get_all(key, []):
                    headers.setdefault(key.lower(), []).append(_decode_header_value(value))
    except Exception:
        logger.exception("Failed to parse headers from .msg header block")
    return headers


def _build_synthetic_headers(
    sender: str,
    to: str,
    subject: str,
    date: str,
) -> str:
    """Construct a minimal synthetic header block when transit headers are absent."""
    return (
        f"From: {sender}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
    )


def _split_address_field(value: str | None) -> list[str]:
    """Split a semicolon-separated To or CC field into a flat recipient list."""
    if not value:
        return []
    return [part.strip() for part in value.split(";") if part.strip()]


def _basename(filename: str) -> str:
    """Return the final path component of a filename string."""
    parts = re.split(r"[/\\]+", filename)
    return parts[-1] if parts and parts[-1] else filename


def _decode_html_body(html_body: bytes | None) -> str | None:
    """Decode HTML body bytes to a Unicode string."""
    if html_body is None:
        return None
    try:
        return html_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return html_body.decode("latin-1", errors="replace")


def _check_reply_to_domain(sender: str, reply_to: str | None, warnings: list[str]) -> None:
    """Append a warning when Reply-To domain differs from From domain."""
    if not reply_to:
        return
    _, from_addr = parseaddr(sender)
    _, reply_addr = parseaddr(reply_to)
    from_domain = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    reply_domain = reply_addr.rsplit("@", 1)[-1].lower() if "@" in reply_addr else ""
    if from_domain and reply_domain and from_domain != reply_domain:
        warnings.append("Reply-To does not match From domain")


def _get_attachment_filename(att) -> str:
    """Return the best available filename for an extract-msg attachment."""
    for attr in ("longFilename", "shortFilename"):
        value = getattr(att, attr, None)
        if value:
            return str(value)
    return "unnamed_attachment"


def _is_nested_attachment(filename: str, mimetype: str | None) -> bool:
    """Return True if an attachment appears to be a nested email."""
    lower = filename.lower()
    if lower.endswith(".eml") or lower.endswith(".msg"):
        return True
    if mimetype in ("message/rfc822", "application/vnd.ms-outlook"):
        return True
    return False


def _nested_parser_kind(filename: str, mimetype: str | None) -> str:
    """Return 'msg' or 'eml' to select the parser for a nested attachment.

    Filename extension takes precedence over MIME type when both are present.
    """
    lower = filename.lower()
    if lower.endswith(".msg"):
        return "msg"
    if lower.endswith(".eml"):
        return "eml"
    if mimetype == "application/vnd.ms-outlook":
        return "msg"
    return "eml"


def _make_attachment(
    original_filename: str,
    content_type: str,
    data: bytes,
    warnings: list[str],
) -> Attachment:
    """Build an Attachment with hashes and filename sanitisation warnings."""
    safe_name = sanitise_filename(original_filename)
    basename = _basename(original_filename)
    if original_filename and safe_name != basename:
        warnings.append(
            f"Attachment filename contained path traversal attempt: {original_filename}"
        )

    return Attachment(
        filename=safe_name,
        original_filename=original_filename,
        content_type=content_type,
        data=data,
        size=len(data),
        hashes=_compute_hashes(data),
        has_macros=None,
        macro_details=None,
    )


def _parse_nested_msg(
    data: bytes,
    depth: int,
    max_depth: int,
    warnings: list[str],
) -> ParsedEmail:
    """Parse nested .msg bytes via a temporary file (required by extract-msg)."""
    warnings.append("Nested .msg extracted to temp file for recursive parsing")
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        return parse_msg(tmp_path, depth=depth + 1, max_depth=max_depth)
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.exception("Failed to delete temporary nested .msg file: %s", tmp_path)


def _process_attachments(
    msg_obj,
    depth: int,
    max_depth: int,
    warnings: list[str],
) -> tuple[list[Attachment], list[ParsedEmail]]:
    """Extract attachments and nested emails from an open extract-msg object."""
    attachments: list[Attachment] = []
    nested_emails: list[ParsedEmail] = []

    for att in msg_obj.attachments or []:
        original_filename = _get_attachment_filename(att)
        data = att.data
        mimetype = getattr(att, "mimetype", None)

        if not data:
            warnings.append(
                f"Attachment data is None or empty — skipped: {original_filename}"
            )
            continue

        is_nested = _is_nested_attachment(original_filename, mimetype)

        if is_nested and depth < max_depth:
            try:
                if _nested_parser_kind(original_filename, mimetype) == "msg":
                    nested = _parse_nested_msg(data, depth, max_depth, warnings)
                else:
                    nested = parse_eml_from_bytes(
                        data,
                        depth=depth + 1,
                        max_depth=max_depth,
                    )
                nested_emails.append(nested)
            except Exception as exc:
                logger.exception(
                    "Failed to parse nested email attachment: %s", original_filename
                )
                warnings.append(f"Parse error: {exc}")
                content_type = mimetype or "application/octet-stream"
                attachments.append(
                    _make_attachment(original_filename, content_type, data, warnings)
                )
            continue

        if is_nested and depth >= max_depth:
            warnings.append("Max recursion depth reached — nested email not parsed")

        content_type = mimetype or "application/octet-stream"
        attachments.append(
            _make_attachment(original_filename, content_type, data, warnings)
        )

    return attachments, nested_emails


def _parse_msg_internal(
    source_file: Path,
    raw: bytes,
    depth: int,
    max_depth: int,
) -> ParsedEmail:
    """Core .msg parsing logic for an on-disk file."""
    warnings: list[str] = []
    source_hash = _compute_hashes(raw)
    msg_obj = None

    try:
        msg_obj = extract_msg.openMsg(str(source_file))

        subject = (msg_obj.subject or "").strip()
        sender = (msg_obj.sender or "").strip()
        to_field = (msg_obj.to or "").strip()
        cc_field = (msg_obj.cc or "").strip()

        date = ""
        if msg_obj.date and isinstance(msg_obj.date, datetime):
            date = _format_datetime(msg_obj.date)

        if msg_obj.header:
            headers_raw = msg_obj.header
        else:
            headers_raw = _build_synthetic_headers(sender, to_field, subject, date)
            warnings.append("No transit headers available — synthetic header generated")

        headers = _parse_headers_raw(headers_raw)

        reply_to_values = headers.get("reply-to", [])
        reply_to = reply_to_values[0] if reply_to_values else None

        recipients = _split_address_field(msg_obj.to) + _split_address_field(msg_obj.cc)

        if not date:
            date_values = headers.get("date", [])
            if date_values:
                date = _format_date_from_header(date_values[0])

        body_plain = (msg_obj.body or "").strip() or None
        body_html = _decode_html_body(msg_obj.htmlBody)

        _check_reply_to_domain(sender, reply_to, warnings)

        attachments, nested_emails = _process_attachments(
            msg_obj, depth, max_depth, warnings
        )

        return ParsedEmail(
            source_file=source_file,
            source_hash=source_hash,
            headers_raw=headers_raw,
            headers=headers,
            subject=subject,
            sender=sender,
            reply_to=reply_to,
            recipients=recipients,
            date=date,
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            nested_emails=nested_emails,
            depth=depth,
            warnings=warnings,
        )
    finally:
        if msg_obj is not None:
            try:
                msg_obj.close()
            except Exception:
                logger.exception("Failed to close .msg file: %s", source_file)


def parse_msg(
    source_file: Path,
    depth: int = 0,
    max_depth: int = 10,
) -> ParsedEmail:
    """Parse a .msg file and return a ParsedEmail instance.

    Uses extract-msg for OLE2 parsing. Never raises — errors are logged and
    returned as warnings on the result.

    Args:
        source_file: Path to the .msg file on disk.
        depth: Current recursion depth for nested email handling.
        max_depth: Maximum allowed recursion depth.

    Returns:
        A fully populated ParsedEmail dataclass.
    """
    resolved = source_file.resolve()
    try:
        raw = resolved.read_bytes()
        return _parse_msg_internal(resolved, raw, depth, max_depth)
    except Exception as exc:
        logger.exception("Failed to parse .msg file: %s", resolved)
        raw: bytes | None = None
        try:
            raw = resolved.read_bytes()
        except Exception:
            pass
        return ParsedEmail(
            source_file=resolved,
            source_hash=_compute_hashes(raw) if raw is not None else {
                "md5": "",
                "sha1": "",
                "sha256": "",
            },
            headers_raw="",
            headers={},
            subject="",
            sender="",
            reply_to=None,
            recipients=[],
            date="",
            body_plain=None,
            body_html=None,
            depth=depth,
            warnings=[f"Parse error: {exc}"],
        )
