"""Parser for RFC 822 / MIME .eml files.

Uses Python's stdlib email package to parse .eml files into ParsedEmail
instances. Handles RFC2047 header decoding, MIME body walking, attachment
extraction, and recursive nested message/rfc822 parsing — all in-memory,
with no disk writes or network calls.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from io import BytesIO
from pathlib import Path

from hive.parser.common import Attachment, ParsedEmail, sanitise_filename

logger = logging.getLogger(__name__)

_PARSER = BytesParser(policy=policy.compat32)
_BODY_SEPARATOR = re.compile(rb"\r?\n\r?\n")


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


def _extract_headers_raw(raw: bytes) -> str:
    """Return the verbatim header block (bytes before the first blank line).

    Decoded with latin-1 so every source byte maps to a single code point
    without normalisation or reformatting.
    """
    match = _BODY_SEPARATOR.search(raw)
    header_bytes = raw[: match.start()] if match else raw
    return header_bytes.decode("latin-1")


def _format_date(date_header: str) -> str:
    """Parse a Date header to UTC or return the raw string on failure."""
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


def _build_headers_dict(msg) -> dict[str, list[str]]:
    """Build a lowercase key → list of decoded values header dict."""
    headers: dict[str, list[str]] = {}
    raw_headers = getattr(msg, "_headers", None)
    if raw_headers:
        for key, value in raw_headers:
            headers.setdefault(key.lower(), []).append(_decode_header_value(value))
    else:
        for key in msg.keys():
            for value in msg.get_all(key, []):
                headers.setdefault(key.lower(), []).append(_decode_header_value(value))
    return headers


def _extract_recipients(msg) -> list[str]:
    """Return a flat list of decoded To and CC recipients (BCC excluded)."""
    recipients: list[str] = []
    for name, addr in getaddresses([msg.get("To", ""), msg.get("Cc", "")]):
        if not addr:
            continue
        recipients.append(f"{name} <{addr}>" if name else addr)
    return recipients


def _basename(filename: str) -> str:
    """Return the final path component of a filename string."""
    parts = re.split(r"[/\\]+", filename)
    return parts[-1] if parts and parts[-1] else filename


def _decode_part(part) -> tuple[str | None, list[str]]:
    """Decode a MIME part payload to a Unicode string.

    Returns the decoded text and any warnings generated during decoding.
    """
    warnings: list[str] = []
    payload = part.get_payload(decode=True)
    if payload is None:
        return None, warnings
    if isinstance(payload, str):
        return payload, warnings

    charset = part.get_content_charset() or "utf-8"
    try:
        text = payload.decode(charset, errors="replace")
    except LookupError:
        warnings.append(f"Failed to decode part charset {charset} — replaced bad bytes")
        text = payload.decode("utf-8", errors="replace")
    return text, warnings


def _is_attachment_part(part) -> bool:
    """Return True if a MIME part should be treated as an attachment."""
    if part.get_content_type() == "message/rfc822":
        return True
    if part.get_content_disposition() == "attachment":
        return True
    if part.get_filename():
        return True
    return False


def _is_body_part(part) -> bool:
    """Return True if a MIME part contributes to the visible message body."""
    if part.get_content_maintype() == "multipart":
        return False
    content_type = part.get_content_type()
    if content_type not in ("text/plain", "text/html"):
        return False
    return not _is_attachment_part(part)


def _is_nested_email(part, filename: str | None) -> bool:
    """Return True if a MIME part contains a nested email message."""
    if part.get_content_type() == "message/rfc822":
        return True
    if filename and filename.lower().endswith(".eml"):
        return True
    return False


def _extract_nested_bytes(part) -> bytes:
    """Extract raw bytes from a message/rfc822 or nested .eml MIME part."""
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes) and payload:
        return payload

    sub = part.get_payload()
    if isinstance(sub, list):
        sub = sub[0] if sub else None
    if sub is None:
        return b""

    if hasattr(sub, "as_bytes"):
        return sub.as_bytes(policy=policy.compat32)

    from email.generator import BytesGenerator

    buf = BytesIO()
    BytesGenerator(policy=policy.compat32).flatten(sub, buf)
    return buf.getvalue()


def _get_part_bytes(part) -> bytes:
    """Return the decoded raw bytes of a MIME part payload."""
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8", errors="replace")
    if payload is None:
        return b""
    # Nested message object without decodable bytes
    return _extract_nested_bytes(part)


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


def _make_attachment(
    part,
    original_filename: str,
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

    content_type = part.get_content_type() or "application/octet-stream"
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


def _parse_eml_internal(
    raw: bytes,
    source_file: Path,
    depth: int,
    max_depth: int,
) -> ParsedEmail:
    """Core .eml parsing logic shared by file and bytes entry points."""
    warnings: list[str] = []
    source_hash = _compute_hashes(raw)
    headers_raw = _extract_headers_raw(raw)

    msg = _PARSER.parsebytes(raw)
    headers = _build_headers_dict(msg)

    subject = _decode_header_value(msg.get("Subject", "") or "")
    sender = _decode_header_value(msg.get("From", "") or "")
    reply_to_raw = msg.get("Reply-To")
    reply_to = _decode_header_value(reply_to_raw) if reply_to_raw else None
    recipients = _extract_recipients(msg)
    date = _format_date(msg.get("Date", "") or "")

    _check_reply_to_domain(sender, reply_to, warnings)

    body_plain_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[Attachment] = []
    nested_emails: list[ParsedEmail] = []

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        if _is_body_part(part):
            text, part_warnings = _decode_part(part)
            warnings.extend(part_warnings)
            if text is not None:
                if part.get_content_type() == "text/plain":
                    body_plain_parts.append(text)
                elif part.get_content_type() == "text/html":
                    body_html_parts.append(text)
            continue

        filename = part.get_filename()
        if filename:
            filename = _decode_header_value(filename)

        is_nested = _is_nested_email(part, filename)

        if is_nested:
            nested_bytes = _extract_nested_bytes(part)
            if depth < max_depth and nested_bytes:
                try:
                    nested = parse_eml_from_bytes(
                        nested_bytes,
                        depth=depth + 1,
                        max_depth=max_depth,
                    )
                    nested_emails.append(nested)
                except Exception as exc:
                    logger.exception("Failed to parse nested email at depth %d", depth + 1)
                    warnings.append(f"Parse error: {exc}")
                    if nested_bytes:
                        nested_name = filename or "nested_message.eml"
                        attachments.append(
                            _make_attachment(part, nested_name, nested_bytes, warnings)
                        )
            else:
                if depth >= max_depth:
                    warnings.append("Max recursion depth reached — nested email not parsed")
                if nested_bytes := _extract_nested_bytes(part):
                    nested_name = filename or "nested_message.eml"
                    attachments.append(
                        _make_attachment(part, nested_name, nested_bytes, warnings)
                    )
            continue

        # Regular attachment: explicit filename or attachment disposition
        if filename or part.get_content_disposition() == "attachment":
            data = _get_part_bytes(part)
            original_name = filename or "unnamed_attachment"
            attachments.append(_make_attachment(part, original_name, data, warnings))

    body_plain = "\n---\n".join(body_plain_parts) if body_plain_parts else None
    body_html = "\n---\n".join(body_html_parts) if body_html_parts else None

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


def parse_eml_from_bytes(
    raw: bytes,
    depth: int = 0,
    max_depth: int = 10,
) -> ParsedEmail:
    """Parse raw .eml bytes and return a ParsedEmail instance.

    Used for nested email parsing. source_file is set to Path("") and
    source_hash is computed from the supplied bytes.

    Args:
        raw: Raw .eml file content as bytes.
        depth: Current recursion depth for nested email handling.
        max_depth: Maximum allowed recursion depth.

    Returns:
        A fully populated ParsedEmail dataclass.
    """
    try:
        return _parse_eml_internal(raw, Path(""), depth, max_depth)
    except Exception as exc:
        logger.exception("Failed to parse .eml from bytes at depth %d", depth)
        return ParsedEmail(
            source_file=Path(""),
            source_hash=_compute_hashes(raw),
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


def parse_eml(
    source_file: Path,
    depth: int = 0,
    max_depth: int = 10,
) -> ParsedEmail:
    """Parse a .eml file and return a ParsedEmail instance.

    Reads the raw header block verbatim into headers_raw without modification.
    Never raises — errors are logged and returned as warnings on the result.

    Args:
        source_file: Path to the .eml file on disk.
        depth: Current recursion depth for nested email handling.
        max_depth: Maximum allowed recursion depth.

    Returns:
        A fully populated ParsedEmail dataclass.
    """
    resolved = source_file.resolve()
    try:
        raw = resolved.read_bytes()
        return _parse_eml_internal(raw, resolved, depth, max_depth)
    except Exception as exc:
        logger.exception("Failed to parse .eml file: %s", resolved)
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
