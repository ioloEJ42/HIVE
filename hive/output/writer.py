"""Forensic output writer for HIVE.

Wires together parsers and extractors to write the complete per-email
output folder structure to disk, including recursive nested email output.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from hive import __version__
from hive.extractors.attachments import build_hashes_csv, collect_attachments
from hive.extractors.auth import auth_results_to_text, parse_auth_results
from hive.extractors.body import get_body_html_txt, get_body_txt
from hive.extractors.headers import defang, get_headers_txt, parse_hop_chain
from hive.extractors.urls import UrlFinding, check_punycode, extract_urls, get_url_warnings
from hive.parser.common import Attachment, ParsedEmail

logger = logging.getLogger(__name__)

# Replace spaces and unsafe characters in directory names
_DIR_NAME_UNSAFE_RE = re.compile(r"[^\w.\-]+")


def _utc_timestamp() -> str:
    """Return the current UTC timestamp as a formatted string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sanitise_dir_name(name: str) -> str:
    """Sanitise a directory name for safe use on disk."""
    try:
        cleaned = _DIR_NAME_UNSAFE_RE.sub("_", name).strip("._")
        return cleaned or "email"
    except Exception:
        logger.exception("Failed to sanitise directory name")
        return "email"


def _unique_dir(base: Path) -> Path:
    """Return a unique directory path, appending _N if needed."""
    try:
        if not base.exists():
            return base
        for index in range(1, 10000):
            candidate = base.parent / f"{base.name}_{index}"
            if not candidate.exists():
                return candidate
        return base.parent / f"{base.name}_{int(time.time())}"
    except Exception:
        logger.exception("Failed to resolve unique directory for %s", base)
        return base


def _setup_log_handler(log_path: Path) -> logging.FileHandler:
    """Create and attach a UTF-8 FileHandler on the hive package logger."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s UTC | %(levelname)s | %(name)s | %(message)s"
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    hive_logger = logging.getLogger("hive")
    if hive_logger.getEffectiveLevel() > logging.INFO:
        hive_logger.setLevel(logging.INFO)
    hive_logger.addHandler(handler)
    return handler


def _teardown_log_handler(handler: logging.FileHandler) -> None:
    """Flush, close, and remove a FileHandler from the hive package logger."""
    try:
        handler.flush()
        handler.close()
        logging.getLogger("hive").removeHandler(handler)
    except Exception:
        logger.exception("Failed to tear down log handler")


def _write_file(
    path: Path,
    content: str,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> None:
    """Write a text file, creating parent directories as needed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding, errors=errors)
    except Exception:
        logger.exception("Failed to write file: %s", path)


def _email_display_name(email: ParsedEmail) -> str:
    """Return a human-readable source label for output headers."""
    if email.depth == 0 and str(email.source_file):
        return email.source_file.name
    return "nested email"


def _level_url_findings(email: ParsedEmail) -> list[UrlFinding]:
    """Return URL findings for the current email level only."""
    return [finding for finding in extract_urls(email) if finding.depth == email.depth]


def _format_url_finding_annotations(finding: UrlFinding) -> list[str]:
    """Return indented annotation lines for flagged URL findings."""
    annotations: list[str] = []
    try:
        if finding.is_shortener:
            annotations.append("    ⚠ URL shortener — destination unknown")
        if finding.is_punycode:
            _, decoded = check_punycode(finding.raw_url)
            decoded_defanged = defang(decoded) if decoded else finding.defanged_url
            annotations.append(
                f"    ⚠ Punycode domain — renders as: {decoded_defanged}"
            )
        if finding.homoglyph_detail:
            parts = finding.homoglyph_detail.split("\n", 1)
            annotations.append(f"    ⚠ Suspicious Unicode — {parts[0]}")
            if len(parts) > 1 and parts[1].strip():
                annotations.append(f"    ⚠ Suspicious chars: {parts[1].strip()}")
    except Exception:
        logger.exception("Failed to format URL finding annotations")
    return annotations


def _write_urls_txt(findings: list[UrlFinding], email_name: str) -> str:
    """Format the urls.txt content for a single email level."""
    try:
        lines = [
            f"# HIVE URL Extract — {email_name}",
            f"# Generated : {_utc_timestamp()}",
            "# All URLs defanged. Sources noted.",
            "# ─────────────────────────────────────────────",
            "",
        ]

        if not findings:
            lines.append("# No URLs found.")
            return "\n".join(lines)

        grouped: dict[str, list[UrlFinding]] = {}
        source_order: list[str] = []
        for finding in findings:
            if finding.source not in grouped:
                grouped[finding.source] = []
                source_order.append(finding.source)
            grouped[finding.source].append(finding)

        for index, source in enumerate(source_order):
            lines.append(f"[{source}]")
            for finding in grouped[source]:
                lines.append(finding.defanged_url)
                lines.extend(_format_url_finding_annotations(finding))
            if index < len(source_order) - 1:
                lines.append("")

        return "\n".join(lines)
    except Exception:
        logger.exception("Failed to format urls.txt content")
        return "# No URLs found.\n"


def _format_hop_line(index: int, hop: dict[str, str]) -> str:
    """Format one Received-header hop line for summary.txt."""
    origin = hop.get("from_host", "")
    from_ip = hop.get("from_ip", "")
    if from_ip:
        ip_text = defang(from_ip)
        origin = f"{origin} ({ip_text})" if origin else f"({ip_text})"
    if not origin:
        origin = "[unknown]"

    by_host = hop.get("by_host", "") or "[unknown]"
    timestamp = hop.get("timestamp", "")
    return f"  [{index}] {origin} → {by_host}  {timestamp}".rstrip()


def _format_attachment_line(attachment: Attachment) -> str:
    """Format one attachment summary line."""
    sha256 = attachment.hashes.get("sha256", "")
    line = (
        f"  {attachment.filename} | {attachment.size} bytes | SHA256: {sha256}"
    )
    if attachment.has_macros is True:
        line += " | ⚠ MACROS DETECTED"
    elif (
        attachment.has_macros is None
        and attachment.macro_details
        and "failed" in attachment.macro_details.lower()
    ):
        line += " | ⚠ MACRO SCAN FAILED"
    return line


def _write_summary_txt(
    email: ParsedEmail,
    url_findings: list[UrlFinding],
    attachments: list[Attachment],
    timestamp: str,
) -> str:
    """Return formatted summary.txt content for one email level."""
    try:
        auth = parse_auth_results(email)
        hops = parse_hop_chain(email)

        source_path = str(email.source_file) if str(email.source_file) else "nested email"
        recipients = ", ".join(email.recipients) if email.recipients else "[Not present]"

        lines = [
            "═══════════════════════════════════════════════════════════",
            "HIVE - Email Forensic Summary",
            f"Version  : {__version__}",
            f"Analysed : {timestamp}",
            "═══════════════════════════════════════════════════════════",
            "",
            "SOURCE FILE",
            f"  Path   : {source_path}",
            f"  MD5    : {email.source_hash.get('md5', '')}",
            f"  SHA256 : {email.source_hash.get('sha256', '')}",
            "",
            "EMAIL METADATA",
            f"  Subject  : {email.subject or '[Not present]'}",
            f"  From     : {email.sender or '[Not present]'}",
            f"  Reply-To : {email.reply_to or '[Not present]'}",
            f"  To       : {recipients}",
            f"  Date     : {email.date or '[Not present]'}",
            "",
            "ROUTING (Received headers, oldest → newest)",
        ]

        if hops:
            for index, hop in enumerate(hops, start=1):
                lines.append(_format_hop_line(index, hop))
        else:
            lines.append("  [No Received headers found]")

        lines.extend(
            [
                "",
                "AUTHENTICATION",
                f"  SPF   : {auth.spf.result.upper()}",
                f"  DKIM  : {auth.dkim.result.upper()}",
                f"  DMARC : {auth.dmarc.result.upper()}",
                f"  ARC   : {auth.arc.result.upper()}",
                "",
                f"ATTACHMENTS ({len(attachments)})",
            ]
        )

        if attachments:
            lines.extend(_format_attachment_line(attachment) for attachment in attachments)
        else:
            lines.append("  [None]")

        lines.extend(["", f"NESTED EMAILS ({len(email.nested_emails)})"])
        if email.nested_emails:
            for index, nested in enumerate(email.nested_emails, start=1):
                if (
                    nested.source_file in (Path(""), Path("."))
                    or not nested.source_file.stem
                ):
                    nested_name = "embedded message"
                else:
                    nested_name = nested.source_file.name
                lines.append(f"  nested_{index:03d}/ ← {nested_name}")
        else:
            lines.append("  [None]")

        lines.extend(["", f"URLS ({len(url_findings)} total)"])
        if url_findings:
            for finding in url_findings:
                lines.append(f"  {finding.defanged_url}  ← {finding.source}")
        else:
            lines.append("  [None found]")

        url_warnings = get_url_warnings(url_findings)
        all_warnings = list(email.warnings) + url_warnings

        lines.extend(["", f"WARNINGS ({len(all_warnings)})"])
        if all_warnings:
            lines.extend(f"  ⚠ {warning}" for warning in all_warnings)
        else:
            lines.append("  [None]")

        return "\n".join(lines) + "\n"
    except Exception:
        logger.exception("Failed to format summary.txt content")
        return (
            "═══════════════════════════════════════════════════════════\n"
            "HIVE - Email Forensic Summary\n"
            f"Version  : {__version__}\n"
            f"Analysed : {timestamp}\n"
            "═══════════════════════════════════════════════════════════\n"
        )


def _write_attachments(email: ParsedEmail, email_dir: Path, no_extract: bool) -> None:
    """Write attachment files to the attachments/ subdirectory."""
    if no_extract or not email.attachments:
        return

    attachments_dir = email_dir / "attachments"
    try:
        attachments_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        logger.exception("Failed to create attachments directory: %s", attachments_dir)
        return

    for attachment in email.attachments:
        try:
            target = attachments_dir / attachment.filename
            target.write_bytes(attachment.data)
        except Exception:
            logger.exception(
                "Failed to write attachment file: %s", attachment.filename
            )


def _write_email_files(
    email: ParsedEmail,
    email_dir: Path,
    no_extract: bool,
) -> None:
    """Write all standard output files for one email level."""
    timestamp = _utc_timestamp()
    email_name = _email_display_name(email)
    url_findings = _level_url_findings(email)
    attachments = list(email.attachments)

    if email.depth == 0:
        hash_attachments = collect_attachments(email)
    else:
        hash_attachments = attachments

    try:
        _write_file(email_dir / "headers.txt", get_headers_txt(email))
        _write_file(
            email_dir / "auth_analysis.txt",
            auth_results_to_text(parse_auth_results(email)),
        )
        _write_file(email_dir / "body.txt", get_body_txt(email))
        _write_file(email_dir / "body.html.txt", get_body_html_txt(email))
        _write_file(
            email_dir / "urls.txt",
            _write_urls_txt(url_findings, email_name),
        )
        _write_file(email_dir / "hashes.csv", build_hashes_csv(hash_attachments))
        _write_file(
            email_dir / "summary.txt",
            _write_summary_txt(email, url_findings, attachments, timestamp),
        )
        _write_attachments(email, email_dir, no_extract)
    except Exception:
        logger.exception(
            "Failed while writing output files for email at depth %s", email.depth
        )


def write_output(
    email: ParsedEmail,
    output_dir: Path,
    no_extract: bool = False,
) -> Path:
    """Write the complete forensic output folder for a parsed email.

    Creates the per-email directory structure, writes all analysis files,
    and recurses into nested emails. Never raises — errors are logged to
    hive.log when configured.

    Args:
        email: Fully parsed email with attachment macro scans completed.
        output_dir: Root output directory for top-level emails, or the
            target directory for nested emails.
        no_extract: If True, skip writing attachment files to disk.

    Returns:
        Path to the created email output directory.
    """
    handler: logging.FileHandler | None = None
    email_dir: Path | None = None

    try:
        if email.depth == 0:
            stem = email.source_file.stem if str(email.source_file) else "email"
            base_name = _sanitise_dir_name(stem)
            candidate = output_dir / base_name
            email_dir = _unique_dir(candidate)
            if email_dir != candidate:
                logger.warning(
                    "Output directory already exists; writing to %s instead",
                    email_dir,
                )
            email_dir.mkdir(parents=True, exist_ok=True)
            handler = _setup_log_handler(email_dir / "hive.log")
            logger.info(
                "HIVE v%s writing forensic output for %s",
                __version__,
                email.source_file.name if str(email.source_file) else "email",
            )
        else:
            email_dir = output_dir
            email_dir.mkdir(parents=True, exist_ok=True)

        _write_email_files(email, email_dir, no_extract)

        for index, nested in enumerate(email.nested_emails, start=1):
            nested_dir = email_dir / f"nested_{index:03d}"
            write_output(nested, nested_dir, no_extract)

        return email_dir
    except Exception:
        logger.exception("Failed to write output for email at depth %s", email.depth)
        return email_dir if email_dir is not None else output_dir
    finally:
        if handler is not None:
            _teardown_log_handler(handler)
