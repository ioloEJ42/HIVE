"""Command-line interface for HIVE.

Entry point for the HIVE forensic email analysis tool. Parses arguments,
dispatches to batch processing, and prints human-readable results for
security analysts.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from hive import __version__
from hive.batch import ProcessResult, process_directory, process_file

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = Path("./hive_output")
DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_SIZE_MB = 50


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the HIVE argument parser."""
    parser = argparse.ArgumentParser(
        prog="hive",
        description="HIVE — Header, Indicator & Vector Examiner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"HIVE {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse a single .eml/.msg file or a directory of email files.",
    )
    parse_parser.add_argument(
        "input",
        type=Path,
        help="Path to a .eml/.msg file or a directory containing email files.",
    )
    parse_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory (default: ./hive_output).",
    )
    parse_parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Skip writing attachment files to disk.",
    )
    parse_parser.add_argument(
        "--flat",
        action="store_true",
        help="Do not recurse into nested emails.",
    )
    parse_parser.add_argument(
        "--max-depth",
        type=int,
        default=DEFAULT_MAX_DEPTH,
        help=f"Maximum recursion depth for nested emails (default: {DEFAULT_MAX_DEPTH}).",
    )
    parse_parser.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_SIZE_MB,
        help=f"Maximum input file size in MB (default: {DEFAULT_MAX_SIZE_MB}).",
    )
    parse_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose status to the terminal.",
    )
    parse_parser.add_argument(
        "--version",
        action="version",
        version=f"HIVE {__version__}",
    )

    return parser


def _print_result(result: ProcessResult, verbose: bool) -> None:
    """Print one ProcessResult to stdout."""
    try:
        filename = result.source.name
        if result.success:
            print(f"✔  {filename}")
            print(f"     Output  : {result.output_path}")
            print(
                "     Attachments : "
                f"{result.attachment_count}  |  "
                f"URLs : {result.url_count}  |  "
                f"Macros : {result.macro_hits}"
            )
            print(f"     Warnings    : {len(result.warnings)}")
            if result.warnings and verbose:
                for warning in result.warnings:
                    print(f"     ⚠ {warning}")
        else:
            print(f"✘  {filename}")
            print(f"     Error: {result.error}")
    except Exception:
        logger.exception("Failed to print process result for %s", result.source)


def _print_summary(results: list[ProcessResult], verbose: bool) -> None:
    """Print the final summary block for all process results."""
    try:
        succeeded = sum(1 for result in results if result.success)
        failed = len(results) - succeeded
        total_macro_hits = sum(result.macro_hits for result in results if result.success)
        has_warnings = any(result.warnings for result in results if result.success)

        print("  ─────────────────────────────────────────")
        print(f"  HIVE complete — {succeeded} processed, {failed} failed")
        print("  ─────────────────────────────────────────")

        if total_macro_hits > 0:
            print(
                f"  ⚠  Macros detected in {total_macro_hits} attachment(s) "
                "— review hashes.csv"
            )

        if has_warnings and not verbose:
            print("  ℹ  Run with --verbose to see warnings")
    except Exception:
        logger.exception("Failed to print CLI summary")


def main() -> None:
    """Entry point for the hive CLI."""
    try:
        parser = _build_parser()
        args = parser.parse_args()

        verbose = bool(getattr(args, "verbose", False))
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.WARNING,
            format="%(asctime)s UTC | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        if args.command != "parse":
            parser.print_help()
            sys.exit(1)

        input_path = args.input.resolve()
        if not input_path.exists():
            print(f"Error: Input path does not exist: {input_path}")
            sys.exit(1)

        max_depth = 0 if args.flat else args.max_depth
        process_kwargs = {
            "no_extract": args.no_extract,
            "max_depth": max_depth,
            "max_size_mb": args.max_size,
            "verbose": verbose,
        }

        results: list[ProcessResult]
        if input_path.is_file():
            results = [process_file(input_path, args.output, **process_kwargs)]
        elif input_path.is_dir():
            results = process_directory(input_path, args.output, **process_kwargs)
        else:
            print(f"Error: Input path is neither a file nor a directory: {input_path}")
            sys.exit(1)

        for result in results:
            _print_result(result, verbose)

        _print_summary(results, verbose)

        if not results or all(not result.success for result in results):
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        logger.exception("Unexpected CLI error")
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
