"""
tools/acquisition.py
──────────────────────────────────────────────────────────────
Memory dump acquisition helpers: integrity verification,
metadata extraction, and dump enumeration.
"""

from __future__ import annotations

import hashlib
import logging
import os
import pathlib
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

DUMP_EXTENSIONS = {".mem", ".raw", ".dmp", ".vmem", ".lime"}


def verify_dump_integrity(dump_path: str, expected_hash: str | None = None) -> dict[str, Any]:
    """
    Compute SHA-256 hash of the memory dump and optionally compare
    against an expected hash for chain-of-custody validation.
    """
    p = pathlib.Path(dump_path)
    if not p.exists():
        return {"status": "error", "message": f"File not found: {dump_path}"}

    logger.info("Computing SHA-256 hash for: %s", dump_path)
    sha256 = hashlib.sha256()
    file_size = p.stat().st_size

    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    computed_hash = sha256.hexdigest()

    result: dict[str, Any] = {
        "file": str(p.resolve()),
        "size_bytes": file_size,
        "size_human": _human_size(file_size),
        "sha256": computed_hash,
        "integrity_verified": None,
    }

    if expected_hash:
        match = computed_hash.lower() == expected_hash.lower().strip()
        result["integrity_verified"] = match
        result["expected_hash"] = expected_hash
        if match:
            logger.info("✅ Hash match — dump integrity confirmed.")
        else:
            logger.warning("❌ Hash MISMATCH — dump may be tampered!")
    else:
        result["integrity_verified"] = "not_checked"
        logger.info("SHA-256: %s (no reference hash provided)", computed_hash)

    return result


def get_dump_info(dump_path: str) -> dict[str, Any]:
    """Return metadata about the memory dump file."""
    p = pathlib.Path(dump_path)
    if not p.exists():
        return {"status": "error", "message": f"File not found: {dump_path}"}

    stat = p.stat()
    size = stat.st_size

    created = datetime.fromtimestamp(stat.st_ctime).isoformat()
    modified = datetime.fromtimestamp(stat.st_mtime).isoformat()

    # Naive OS hint based on file magic / extension
    profile_hint = _guess_os_profile(p)

    return {
        "file": str(p.resolve()),
        "filename": p.name,
        "extension": p.suffix,
        "size_bytes": size,
        "size_human": _human_size(size),
        "created": created,
        "modified": modified,
        "profile_hint": profile_hint,
    }


def list_available_dumps(directory: str) -> dict[str, Any]:
    """List all memory dump files in the given directory."""
    d = pathlib.Path(directory)
    if not d.is_dir():
        return {"status": "error", "message": f"Directory not found: {directory}"}

    dumps = []
    for f in sorted(d.rglob("*")):
        if f.suffix.lower() in DUMP_EXTENSIONS and f.is_file():
            stat = f.stat()
            dumps.append({
                "path": str(f.resolve()),
                "name": f.name,
                "size_human": _human_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

    return {
        "directory": str(d.resolve()),
        "count": len(dumps),
        "dumps": dumps,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} TB"


def _guess_os_profile(path: pathlib.Path) -> str:
    """Naive profile hint from filename patterns."""
    name_lower = path.name.lower()
    if "win10" in name_lower or "windows10" in name_lower:
        return "Windows 10 (likely)"
    if "win11" in name_lower or "windows11" in name_lower:
        return "Windows 11 (likely)"
    if "win7" in name_lower:
        return "Windows 7 (likely)"
    if "xp" in name_lower:
        return "Windows XP (likely)"
    # Check magic bytes (MZ / PAGEDUMP / HIBR)
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
        if magic[:4] == b"PAGE":
            return "Windows Full Memory Dump"
        if magic[:4] == b"HIBR":
            return "Windows Hibernation File"
    except OSError:
        pass
    return "Unknown — check profile manually"
