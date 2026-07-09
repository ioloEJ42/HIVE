"""Batch and single-file orchestration for HIVE.

Ties together parsers, macro scanning, and the output writer to process
.eml and .msg files end-to-end from the CLI.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace as dataclass_replace
from pathlib import Path

from hive.extractors.attachments import collect_attachments, scan_macros
from hive.extractors.urls import extract_urls
from hive.output.writer import write_output
from hive.parser.common import ParsedEmail
from hive.parser.eml import parse_eml
from hive.parser.msg import parse_msg

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".eml", ".msg"}


@dataclass
class ProcessResult:
    """Result of processing a single email file."""

    source: Path  # input file path
    output_path: Path | None  # output directory created; None on failure
    success: bool
    error: str  # empty string on success
    warnings: list[str]  # parser warnings on success; empty on failure
    attachment_count: int  # total attachments found across all nesting levels
    url_count: int  # total URLs found across all nesting levels
    macro_hits: int  # attachments where has_macros is True


def _failure_result(source: Path, error: str) -> ProcessResult:
    """Build a failed ProcessResult with zeroed counters."""
    return ProcessResult(
        source=source,
        output_path=None,
        success=False,
        error=error,
        warnings=[],
        attachment_count=0,
        url_count=0,
        macro_hits=0,
    )


def _is_supported_extension(path: Path) -> bool:
    """Return True if the file extension is .eml or .msg."""
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def _rescan_attachments(email: ParsedEmail) -> ParsedEmail:
    """Return a copy of the email tree with macro-scanned attachments."""
    try:
        scanned_attachments = [scan_macros(attachment) for attachment in email.attachments]
        scanned_nested = [_rescan_attachments(nested) for nested in email.nested_emails]
        return dataclass_replace(
            email,
            attachments=scanned_attachments,
            nested_emails=scanned_nested,
        )
    except Exception:
        logger.exception("Failed to rescan attachments for email at depth %s", email.depth)
        return email


def _count_urls(email: ParsedEmail) -> int:
    """Return the total URL count across all nesting levels."""
    try:
        return len(extract_urls(email))
    except Exception:
        logger.exception("Failed to count URLs for parsed email")
        return 0


def _count_macro_hits(email: ParsedEmail) -> int:
    """Return the number of attachments with detected macros."""
    try:
        return sum(
            1
            for attachment in collect_attachments(email)
            if attachment.has_macros is True
        )
    except Exception:
        logger.exception("Failed to count macro hits for parsed email")
        return 0


def _validate_source_file(source: Path, max_size_mb: int) -> str | None:
    """Validate a source file before parsing. Returns an error message or None."""
    try:
        if not source.exists():
            return f"File does not exist: {source}"
        if not source.is_file():
            return f"Path is not a file: {source}"
        if not _is_supported_extension(source):
            return (
                f"Unsupported file extension '{source.suffix}'. "
                "Only .eml and .msg files are supported."
            )

        max_bytes = max_size_mb * 1024 * 1024
        if source.stat().st_size > max_bytes:
            return (
                f"File exceeds maximum size of {max_size_mb} MB: {source}"
            )
        return None
    except Exception as exc:
        logger.exception("Failed to validate source file: %s", source)
        return f"Validation failed: {exc}"


def _parse_email(source: Path, max_depth: int) -> ParsedEmail:
    """Parse a validated .eml or .msg file."""
    extension = source.suffix.lower()
    if extension == ".eml":
        return parse_eml(source, max_depth=max_depth)
    return parse_msg(source, max_depth=max_depth)


def process_file(
    source: Path,
    output_dir: Path,
    no_extract: bool = False,
    max_depth: int = 10,
    max_size_mb: int = 50,
    verbose: bool = False,
) -> ProcessResult:
    """Process a single .eml or .msg file end-to-end.

    Validates the input, parses the email, scans attachments for macros,
    and writes forensic output to disk.

    Args:
        source: Path to the input email file.
        output_dir: Root directory for forensic output.
        no_extract: If True, skip writing attachment files to disk.
        max_depth: Maximum nested-email recursion depth for parsing.
        max_size_mb: Maximum allowed input file size in megabytes.
        verbose: If True, emit additional informational log messages.

    Returns:
        ProcessResult describing success or failure.
    """
    resolved_source = source.resolve()

    try:
        validation_error = _validate_source_file(resolved_source, max_size_mb)
        if validation_error:
            if verbose:
                logger.info("Validation failed for %s: %s", resolved_source, validation_error)
            return _failure_result(resolved_source, validation_error)

        if verbose:
            logger.info("Parsing %s", resolved_source)

        try:
            parsed_email = _parse_email(resolved_source, max_depth)
        except Exception as exc:
            logger.exception("Failed to parse email file: %s", resolved_source)
            return _failure_result(resolved_source, f"Parse failed: {exc}")

        try:
            parsed_email = _rescan_attachments(parsed_email)
        except Exception as exc:
            logger.exception("Failed to scan macros for: %s", resolved_source)
            return _failure_result(resolved_source, f"Macro scan failed: {exc}")

        attachment_count = len(collect_attachments(parsed_email))
        url_count = _count_urls(parsed_email)
        macro_hits = _count_macro_hits(parsed_email)

        if verbose:
            logger.info(
                "Writing output for %s (%d attachments, %d URLs, %d macro hits)",
                resolved_source,
                attachment_count,
                url_count,
                macro_hits,
            )

        try:
            output_path = write_output(parsed_email, output_dir, no_extract)
        except Exception as exc:
            logger.exception("Failed to write output for: %s", resolved_source)
            return _failure_result(resolved_source, f"Output write failed: {exc}")

        return ProcessResult(
            source=resolved_source,
            output_path=output_path,
            success=True,
            error="",
            warnings=list(parsed_email.warnings),
            attachment_count=attachment_count,
            url_count=url_count,
            macro_hits=macro_hits,
        )
    except Exception as exc:
        logger.exception("Unexpected error processing file: %s", resolved_source)
        return _failure_result(resolved_source, f"Unexpected error: {exc}")


def process_directory(
    source_dir: Path,
    output_dir: Path,
    no_extract: bool = False,
    max_depth: int = 10,
    max_size_mb: int = 50,
    verbose: bool = False,
) -> list[ProcessResult]:
    """Process all .eml and .msg files in a directory (non-recursive).

    Args:
        source_dir: Directory containing email files to process.
        output_dir: Root directory for forensic output.
        no_extract: If True, skip writing attachment files to disk.
        max_depth: Maximum nested-email recursion depth for parsing.
        max_size_mb: Maximum allowed input file size in megabytes.
        verbose: If True, emit additional informational log messages.

    Returns:
        List of ProcessResult objects, one per processed file.
    """
    resolved_dir = source_dir.resolve()

    try:
        if not resolved_dir.exists() or not resolved_dir.is_dir():
            error = f"Source directory does not exist or is not a directory: {resolved_dir}"
            logger.error(error)
            return [_failure_result(resolved_dir, error)]

        email_files = sorted(
            path
            for path in resolved_dir.iterdir()
            if path.is_file() and _is_supported_extension(path)
        )

        if not email_files:
            logger.warning("No .eml or .msg files found in %s", resolved_dir)
            return []

        results: list[ProcessResult] = []
        for email_file in email_files:
            results.append(
                process_file(
                    email_file,
                    output_dir,
                    no_extract=no_extract,
                    max_depth=max_depth,
                    max_size_mb=max_size_mb,
                    verbose=verbose,
                )
            )
        return results
    except Exception as exc:
        logger.exception("Unexpected error processing directory: %s", resolved_dir)
        return [_failure_result(resolved_dir, f"Unexpected error: {exc}")]
