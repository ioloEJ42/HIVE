"""Integrity verification for HIVE.

Computes SHA256 hashes of all Python source files in the hive/
package and compares them against a committed manifest. Allows
analysts and administrators to confirm the tool has not been
modified since the manifest was last generated.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path(__file__).parent / "MANIFEST.sha256"
PACKAGE_ROOT = Path(__file__).parent

_CHUNK_SIZE = 65536


@dataclass
class VerifyResult:
    """Result of comparing current source hashes against the manifest."""

    passed: bool
    manifest_found: bool
    files_checked: int
    files_ok: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    files_missing: list[str] = field(default_factory=list)
    files_new: list[str] = field(default_factory=list)
    error: str = ""


def compute_file_hash(path: Path) -> str:
    """Compute SHA256 hex digest of a file. Never raises — returns empty string on error."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        logger.exception("Failed to compute hash for file: %s", path)
        return ""


def collect_python_files(root: Path) -> list[Path]:
    """Return sorted list of all .py files under root (recursive).

    Excludes __pycache__ directories. Never raises.
    """
    try:
        files = [
            path
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
        ]
        return sorted(files)
    except Exception:
        logger.exception("Failed to collect Python files under %s", root)
        return []


def _relative_manifest_path(root: Path, file_path: Path) -> str:
    """Return a manifest-relative path using forward slashes."""
    return file_path.relative_to(root).as_posix()


def generate_manifest(root: Path = PACKAGE_ROOT) -> dict[str, str]:
    """Compute SHA256 for every .py file under root.

    Returns dict of {relative_path_str: sha256hex}.
    Relative paths use forward slashes regardless of OS.
    Never raises.
    """
    manifest: dict[str, str] = {}
    try:
        for file_path in collect_python_files(root):
            file_hash = compute_file_hash(file_path)
            if not file_hash:
                continue
            manifest[_relative_manifest_path(root, file_path)] = file_hash
    except Exception:
        logger.exception("Failed to generate integrity manifest under %s", root)
    return manifest


def write_manifest(
    manifest: dict[str, str],
    manifest_path: Path = MANIFEST_PATH,
) -> None:
    """Write manifest to disk in sha256sum format.

    Format: <sha256hex>  <relative/path>
    Sorted by path. Never raises — logs errors instead.
    """
    try:
        lines = [
            f"{file_hash}  {relative_path}\n"
            for relative_path, file_hash in sorted(manifest.items())
        ]
        manifest_path.write_text("".join(lines), encoding="utf-8")
        logger.info("Wrote integrity manifest with %d files to %s", len(lines), manifest_path)
    except Exception:
        logger.exception("Failed to write integrity manifest: %s", manifest_path)


def read_manifest(
    manifest_path: Path = MANIFEST_PATH,
) -> dict[str, str]:
    """Read manifest from disk.

    Returns dict of {relative_path_str: sha256hex}.
    Returns empty dict if file not found. Never raises.
    """
    try:
        if not manifest_path.is_file():
            return {}

        manifest: dict[str, str] = {}
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "  " not in stripped:
                logger.warning("Skipping malformed manifest line: %r", line)
                continue
            file_hash, relative_path = stripped.split("  ", 1)
            if not file_hash or not relative_path:
                logger.warning("Skipping malformed manifest line: %r", line)
                continue
            manifest[relative_path.strip()] = file_hash.strip()
        return manifest
    except Exception:
        logger.exception("Failed to read integrity manifest: %s", manifest_path)
        return {}


def verify_integrity(
    root: Path = PACKAGE_ROOT,
    manifest_path: Path = MANIFEST_PATH,
) -> VerifyResult:
    """Compare current file hashes against the manifest.

    Returns a VerifyResult. Never raises.
    """
    try:
        manifest = read_manifest(manifest_path)
        if not manifest:
            return VerifyResult(
                passed=False,
                manifest_found=False,
                files_checked=0,
            )

        current = generate_manifest(root)
        manifest_paths = set(manifest)
        current_paths = set(current)

        files_ok = sorted(
            path
            for path in manifest_paths
            if path in current and manifest[path] == current[path]
        )
        files_modified = sorted(
            path
            for path in manifest_paths
            if path in current and manifest[path] != current[path]
        )
        files_missing = sorted(path for path in manifest_paths if path not in current)
        files_new = sorted(path for path in current_paths if path not in manifest_paths)

        passed = not files_modified and not files_missing
        return VerifyResult(
            passed=passed,
            manifest_found=True,
            files_checked=len(manifest),
            files_ok=files_ok,
            files_modified=files_modified,
            files_missing=files_missing,
            files_new=files_new,
        )
    except Exception as exc:
        logger.exception("Integrity verification failed")
        return VerifyResult(
            passed=False,
            manifest_found=manifest_path.is_file(),
            files_checked=0,
            error=str(exc),
        )
