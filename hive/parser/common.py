"""Core data structures for HIVE email parsing.

Defines the Attachment and ParsedEmail dataclasses that form the canonical
internal representation of a parsed .eml or .msg file. All parsers
(eml.py, msg.py) produce ParsedEmail instances; extractors and the output
writer consume them. Filename sanitisation for path-traversal protection
lives here so it is available before any attachment is written to disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_MAX_FILENAME_LENGTH = 200
_FALLBACK_FILENAME = "unnamed_attachment"


def sanitise_filename(filename: str) -> str:
    """Return a bare filename safe for writing to the attachments directory.

    Strips directory components and path-traversal sequences, removes
    characters unsafe on Windows and Linux, and truncates long names.
    Never raises an exception; always returns a non-empty safe string.

    Args:
        filename: Raw filename as found in the email (may contain paths
            or unsafe characters).

    Returns:
        A sanitised filename with no directory components, suitable for
        use as a single path segment on disk.
    """
    if not filename:
        return _FALLBACK_FILENAME

    try:
        name = str(filename)
    except Exception:
        return _FALLBACK_FILENAME

    parts = re.split(r"[/\\]+", name)
    name = parts[-1] if parts and parts[-1] else name
    name = name.replace("/", "_").replace("\\", "_")
    name = name.lstrip(".")
    name = _UNSAFE_FILENAME_CHARS.sub("_", name)

    if len(name) > _MAX_FILENAME_LENGTH:
        name = name[:_MAX_FILENAME_LENGTH]

    if not name:
        return _FALLBACK_FILENAME

    return name


@dataclass
class Attachment:
    """A single email attachment with forensic metadata."""

    filename: str  # sanitised filename, path-traversal protected, safe for disk writes
    original_filename: str  # exactly as found in the email, never modified
    content_type: str  # MIME content type, e.g. "application/pdf"
    data: bytes  # raw attachment bytes
    size: int  # length of data in bytes
    hashes: dict  # hex digests keyed by "md5", "sha1", "sha256"; populated by extractors
    has_macros: bool | None = None  # None = not checked/applicable; True/False = scan result
    macro_details: str | None = None  # oletools summary when macros found; else None


@dataclass
class ParsedEmail:
    """Structured representation of a parsed .eml or .msg file."""

    source_file: Path  # absolute path to the original input file on disk
    source_hash: dict  # md5/sha1/sha256 hex digests of the input file for evidence integrity
    headers_raw: str  # verbatim untouched header block; written directly to headers.txt
    headers: dict  # parsed headers as lowercase key → list of values (multi-value aware)
    subject: str  # decoded Subject header; empty string if absent
    sender: str  # decoded From header value; empty string if absent
    reply_to: str | None  # decoded Reply-To header value; None if absent
    recipients: list[str]  # combined decoded To + CC addresses; empty list if none
    date: str  # Date header as UTC-normalised string where possible; empty if absent
    body_plain: str | None  # plain-text body content; None if not present
    body_html: str | None  # raw HTML body; never executed; saved as body.html.txt
    attachments: list[Attachment] = field(default_factory=list)  # all file attachments found
    nested_emails: list[ParsedEmail] = field(default_factory=list)  # nested ParsedEmail objects
    depth: int = 0  # recursion depth; 0 = top-level email, incremented per nesting level
    warnings: list[str] = field(default_factory=list)  # human-readable parsing warnings
