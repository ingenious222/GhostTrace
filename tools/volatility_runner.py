"""
tools/volatility_runner.py
──────────────────────────────────────────────────────────────
Wrappers for Volatility 3 (and Vol2 fallback) plugins.
Each function runs a plugin as a subprocess, parses the output
into a list of dicts, and returns JSON-serialisable data.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _get_vol_cmd() -> list[str]:
    """Build the base Volatility command from environment."""
    vol_path = os.getenv("VOLATILITY_PATH", "vol")
    version = os.getenv("VOLATILITY_VERSION", "vol3").lower()
    if version == "vol2":
        return ["python", vol_path]
    # Vol3: prefer python invocation for cross-platform
    if vol_path.endswith(".py"):
        return ["python", vol_path]
    return [vol_path]


def _run_plugin(
    dump_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
    timeout_override: int | None = None,
) -> str:
    """Execute a Volatility plugin and return raw stdout."""
    version = os.getenv("VOLATILITY_VERSION", "vol3").lower()
    cmd = _get_vol_cmd()

    if version == "vol2":
        cmd += ["-f", dump_path, "--profile=auto", plugin] + (extra_args or [])
    else:
        # Vol3 syntax — optionally inject local symbol directory
        symbol_dir = os.getenv("VOLATILITY_SYMBOL_DIRS", "")
        sym_args = ["-s", symbol_dir] if symbol_dir else []

        # Each plugin gets its own cache subdirectory so parallel processes
        # write to separate SQLite files — no "database is locked" conflicts.
        base_cache = os.getenv("VOLATILITY_CACHE_PATH", "")
        if base_cache:
            plugin_safe = plugin.replace(".", "_").replace(" ", "_")
            plugin_cache = os.path.join(base_cache, plugin_safe)
            os.makedirs(plugin_cache, exist_ok=True)
            cache_args = ["--cache-path", plugin_cache]
        else:
            cache_args = []

        # --output json is a GLOBAL flag → must come BEFORE the plugin name
        cmd += sym_args + cache_args + ["--output", "json", "-f", dump_path, plugin] + (extra_args or [])

    # Generous timeout — first run builds symbol caches (can take 10-30 min)
    timeout = timeout_override if timeout_override is not None else int(os.getenv("VOL_TIMEOUT", "3600"))
    logger.debug("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            # Volatility crashed — log filtered stderr and return empty
            if result.stderr and not _is_mock():
                _filtered_stderr = "\n".join(
                    line for line in result.stderr.splitlines()
                    if not line.strip().startswith("Progress:")
                    and "Updating caches" not in line
                    and "Stopping..." not in line
                    and line.strip()
                )
                if _filtered_stderr.strip():
                    logger.warning("Volatility [%s] error: %s", plugin, _filtered_stderr[:300])
            return ""   # empty → parser returns [] → analysis continues safely
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning("Volatility plugin '%s' timed out after %ss", plugin, timeout)
        return ""
    except FileNotFoundError:
        raise RuntimeError(
            f"Volatility not found at '{' '.join(_get_vol_cmd())}'. "
            "Check VOLATILITY_PATH in your .env file."
        )



# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_table(raw: str, min_cols: int = 3) -> list[dict[str, Any]]:
    """
    Parse Volatility tabular output into a list of dicts.
    First non-empty line is treated as the header.
    """
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return []

    # Find header line (must contain typical PID/PPID/Name etc.)
    header_line = None
    data_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.search(r"\bPID\b|\bOffset\b|\bProto\b|\bProcess\b", stripped, re.IGNORECASE):
            header_line = stripped
            data_start = i + 1
            break

    if header_line is None:
        return [{"raw": line.strip()} for line in lines if line.strip()]

    # Parse headers using tab or multi-space as delimiter
    headers = re.split(r"\t{1,}|\s{2,}", header_line)
    headers = [h.strip() for h in headers if h.strip()]

    records: list[dict[str, Any]] = []
    for line in lines[data_start:]:
        if not line.strip():
            continue
        cols = re.split(r"\t{1,}|\s{2,}", line.strip())
        if len(cols) < min_cols:
            continue
        record: dict[str, Any] = {}
        for j, header in enumerate(headers):
            record[header] = cols[j].strip() if j < len(cols) else ""
        records.append(record)

    return records


def _mock_data(plugin: str) -> list[dict[str, Any]]:
    """Return realistic mock data when --mock mode is active."""
    import json, pathlib
    fixture_map = {
        "windows.pslist":   "sample_pslist.json",
        "windows.pstree":   "sample_pstree.json",
        "windows.malfind":  "sample_malfind.json",
        "windows.netscan":  "sample_netscan.json",
        "windows.dlllist":  "sample_dlllist.json",
        "windows.cmdline":  "sample_cmdline.json",
        "windows.handles":  "sample_handles.json",
        "windows.getsids":  "sample_getsids.json",
    }
    fixture_name = fixture_map.get(plugin)
    if fixture_name:
        fixture_path = pathlib.Path(__file__).parent.parent / "tests" / "fixtures" / fixture_name
        if fixture_path.exists():
            try:
                content = fixture_path.read_text(encoding="utf-8")
                if not content.strip():
                    logger.warning("Mock fixture file is empty: %s", fixture_path)
                    return [{"info": f"Empty fixture file for plugin: {plugin}"}]
                return json.loads(content)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load mock fixture %s: %s", fixture_path, exc)
                return [{"info": f"Failed to load mock fixture for plugin: {plugin}", "error": str(exc)}]
        else:
            logger.warning("Mock fixture not found: %s", fixture_path)
    return [{"info": f"No mock data available for plugin: {plugin}"}]


def _is_mock() -> bool:
    # Re-read .env so changes take effect without restarting Streamlit
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except ImportError:
        pass
    return os.getenv("MEMFORENSIC_MOCK", "0") == "1"


def _parse_vol_json(raw: str) -> list[dict[str, Any]]:
    """
    Parse Volatility 3 JSON output (--output json) into a list of dicts.
    Volatility JSON format: {"columns": [...], "rows": [[...], ...]}
    Falls back to _parse_table if JSON parsing fails.
    """
    import json as _json
    if not raw or not raw.strip():
        return []
    # Volatility may prefix JSON with progress/warning lines — find first '{'
    brace = raw.find("{")
    if brace == -1:
        return _parse_table(raw)
    try:
        data = _json.loads(raw[brace:])
        columns = data.get("columns", [])
        rows    = data.get("rows", [])
        if not columns or not rows:
            return []
        records: list[dict[str, Any]] = []
        for row in rows:
            record: dict[str, Any] = {}
            for i, col in enumerate(columns):
                record[col] = row[i] if i < len(row) else ""
            records.append(record)
        return records
    except Exception:
        return _parse_table(raw)


# ---------------------------------------------------------------------------
# Plugin wrappers
# ---------------------------------------------------------------------------

def run_pslist(dump_path: str, pid: int | None = None) -> list[dict[str, Any]]:
    """List all running processes from the memory dump."""
    if _is_mock():
        return _mock_data("windows.pslist")
    plugin = "windows.pslist"
    extra: list[str] = []
    if pid:
        extra = ["--pid", str(pid)]
    raw = _run_plugin(dump_path, plugin, extra)
    results = _parse_vol_json(raw)
    logger.info("pslist: found %d processes", len(results))
    return results


def run_pstree(dump_path: str) -> list[dict[str, Any]]:
    """Show hierarchical parent-child process relationships."""
    if _is_mock():
        return _mock_data("windows.pstree")
    raw = _run_plugin(dump_path, "windows.pstree")
    results = _parse_vol_json(raw)
    logger.info("pstree: found %d entries", len(results))
    return results


def run_malfind(dump_path: str, pid: int | None = None) -> list[dict[str, Any]]:
    """Detect code injection and suspicious memory regions."""
    if _is_mock():
        return _mock_data("windows.malfind")
    # Updated plugin path (windows.malfind renamed to windows.malware.malfind)
    plugin = "windows.malware.malfind"
    extra: list[str] = []
    if pid:
        extra = ["--pid", str(pid)]
    try:
        raw = _run_plugin(dump_path, plugin, extra)
        results = _parse_vol_json(raw)
        if not results:
            # Fallback: try old name in case of older Volatility version
            raw = _run_plugin(dump_path, "windows.malfind", extra)
            results = _parse_vol_json(raw)
        logger.info("malfind: found %d injection regions", len(results))
        return results
    except Exception as exc:
        logger.warning("malfind failed (non-fatal): %s", exc)
        return []


def _parse_malfind_output(raw: str) -> list[dict[str, Any]]:
    """Parse multi-block malfind output into structured records."""
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    hex_bytes: list[str] = []

    for line in raw.splitlines():
        # New block starts with PID
        pid_match = re.match(r"^(\d+)\s+(\S+)\s+0x([0-9a-fA-F]+)\s+(\S+)\s+(.+)", line)
        if pid_match:
            if current:
                current["hex_preview"] = " ".join(hex_bytes[:16])
                records.append(current)
            current = {
                "pid": pid_match.group(1),
                "process": pid_match.group(2),
                "address": "0x" + pid_match.group(3),
                "vad_tag": pid_match.group(4),
                "protection": pid_match.group(5).strip(),
            }
            hex_bytes = []
        elif re.match(r"^[0-9a-fA-F]{4}\s+[0-9a-fA-F ]+", line):
            hex_part = line.split("  ")[0] if "  " in line else line
            hex_bytes.append(hex_part.strip())

    if current:
        current["hex_preview"] = " ".join(hex_bytes[:8])
        records.append(current)

    # Fallback to table parser if block parsing yields nothing
    if not records:
        records = _parse_table(raw, min_cols=2)

    return records


def run_netscan(dump_path: str) -> list[dict[str, Any]]:
    """Extract network connections from memory.

    netscan is the most fragile Volatility plugin — it can crash on
    corrupted/unusual network structures in a dump.  Always returns a
    list (empty on failure) so the rest of the analysis is unaffected.
    """
    if _is_mock():
        return _mock_data("windows.netscan")
    try:
        netscan_timeout = int(os.getenv("NETSCAN_TIMEOUT", "1800"))
        raw = _run_plugin(dump_path, "windows.netscan", timeout_override=netscan_timeout)
        results = _parse_vol_json(raw)
        logger.info("netscan: found %d connection entries", len(results))
        return results
    except Exception as exc:
        logger.warning("netscan failed (non-fatal): %s", exc)
        return []


def run_dlllist(dump_path: str, pid: int | None = None) -> list[dict[str, Any]]:
    """List DLLs loaded in processes."""
    if _is_mock():
        return _mock_data("windows.dlllist")
    plugin = "windows.dlllist"
    extra: list[str] = []
    if pid:
        extra = ["--pid", str(pid)]
    try:
        raw = _run_plugin(dump_path, plugin, extra)
        results = _parse_vol_json(raw)
        logger.info("dlllist: found %d DLL entries", len(results))
        return results
    except Exception as exc:
        logger.warning("dlllist failed (non-fatal): %s", exc)
        return []


def run_cmdline(dump_path: str, pid: int | None = None) -> list[dict[str, Any]]:
    """Extract command-line arguments for all processes."""
    if _is_mock():
        return _mock_data("windows.cmdline")
    plugin = "windows.cmdline"
    extra: list[str] = []
    if pid:
        extra = ["--pid", str(pid)]
    try:
        raw = _run_plugin(dump_path, plugin, extra)
        results = _parse_vol_json(raw)
        if not results:
            results = _parse_cmdline_output(raw)
        logger.info("cmdline: found %d process command lines", len(results))
        return results
    except Exception as exc:
        logger.warning("cmdline failed (non-fatal): %s", exc)
        return []


def _parse_cmdline_output(raw: str) -> list[dict[str, Any]]:
    """Parse cmdline plugin output (PID + process + command line)."""
    records: list[dict[str, Any]] = []
    pattern = re.compile(
        r"(\w[\w\s.]+?)\s+PID:\s+(\d+)\s*\n\s*Command line\s*:\s*(.*)", re.IGNORECASE
    )
    for match in pattern.finditer(raw):
        records.append({
            "process": match.group(1).strip(),
            "pid": match.group(2).strip(),
            "cmdline": match.group(3).strip(),
        })
    if not records:
        # Fallback to table parsing
        records = _parse_table(raw, min_cols=2)
    return records


def run_handles(dump_path: str, pid: int | None = None) -> list[dict[str, Any]]:
    """List open handles for processes."""
    if _is_mock():
        return _mock_data("windows.handles")
    plugin = "windows.handles"
    extra: list[str] = []
    if pid:
        extra = ["--pid", str(pid)]
    try:
        raw = _run_plugin(dump_path, plugin, extra)
        results = _parse_vol_json(raw)
        logger.info("handles: found %d handle entries", len(results))
        return results
    except Exception as exc:
        logger.warning("handles failed (non-fatal): %s", exc)
        return []


def run_getsids(dump_path: str, pid: int | None = None) -> list[dict[str, Any]]:
    """
    Run windows.getsids to identify the user account and group memberships
    for each process.  Returns records with pid, process, username, sid, groups.
    Answers the "which user is the malicious process running as?" question.
    """
    if _is_mock():
        return _mock_data("windows.getsids")
    plugin = "windows.getsids"
    extra: list[str] = []
    if pid:
        extra = ["--pid", str(pid)]
    raw = _run_plugin(dump_path, plugin, extra)
    results = _parse_getsids_output(raw)
    logger.info("getsids: found %d SID entries", len(results))
    return results


def _parse_getsids_output(raw: str) -> list[dict[str, Any]]:
    """
    Parse windows.getsids output.

    Vol3 format (tabular):
        PID  Process         SID                                     Name
        3692 powershell.exe  S-1-5-21-...-1001                       Elon
        3692 powershell.exe  S-1-5-32-544                            Administrators

    Grouped output is collapsed so the first SID entry per PID becomes the
    'username' and subsequent entries become group memberships.
    """
    records: list[dict[str, Any]] = []

    # Try table parser first
    rows = _parse_table(raw, min_cols=2)
    if rows and any("SID" in r or "Name" in r or "Sid" in r for r in rows):
        # Collapse rows per PID — first Name is the user, rest are groups
        pid_seen: dict[str, dict[str, Any]] = {}
        for row in rows:
            pid   = str(row.get("PID",  row.get("Pid",  row.get("pid",  ""))))
            proc  = str(row.get("Process", row.get("ImageFileName", "")))
            sid   = str(row.get("SID",  row.get("Sid",  "")))
            name  = str(row.get("Name", row.get("FriendlyName", "")))
            if not pid:
                continue
            if pid not in pid_seen:
                pid_seen[pid] = {
                    "pid": pid,
                    "process": proc,
                    "username": name,
                    "sid": sid,
                    "groups": [],
                }
            else:
                if name:
                    pid_seen[pid]["groups"].append(name)
        records = list(pid_seen.values())
        return records

    # Fallback: line-by-line regex
    pattern = re.compile(
        r"(\d+)\s+(\S+)\s+(S-\d[-\d]+)\s*(.*)", re.IGNORECASE
    )
    pid_seen_fb: dict[str, dict[str, Any]] = {}
    for line in raw.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        pid_, proc_, sid_, name_ = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        if pid_ not in pid_seen_fb:
            pid_seen_fb[pid_] = {
                "pid": pid_,
                "process": proc_,
                "username": name_,
                "sid": sid_,
                "groups": [],
            }
        else:
            if name_:
                pid_seen_fb[pid_]["groups"].append(name_)
    records = list(pid_seen_fb.values())
    if not records:
        records = [{"raw": line.strip()} for line in raw.splitlines() if line.strip()]
    return records

