"""
tools/process_inspector.py
──────────────────────────────────────────────────────────────
Detects suspicious process patterns: orphaned processes,
duplicate names (spoofing), abnormal parent-child chains,
and LOLBAS / system process name abuse.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-good parent-child relationships
# ---------------------------------------------------------------------------

# process_name → acceptable parent names (lowercase)
EXPECTED_PARENTS: dict[str, list[str]] = {
    "explorer.exe": ["userinit.exe", "winlogon.exe"],
    "services.exe": ["wininit.exe"],
    "lsass.exe": ["wininit.exe"],
    "svchost.exe": ["services.exe"],
    "taskhost.exe": ["services.exe"],
    "taskhostw.exe": ["services.exe"],
    "spoolsv.exe": ["services.exe"],
    "winlogon.exe": ["smss.exe"],
    "csrss.exe": ["smss.exe"],
    "wininit.exe": ["smss.exe"],
    "smss.exe": ["system", ""],
}

# Processes that should almost never spawn shells or PowerShell
SUSPICIOUS_PARENT_OF_SHELL = {
    "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
    "acrord32.exe", "acrobat.exe", "iexplore.exe", "chrome.exe",
    "firefox.exe", "msedge.exe", "mspaint.exe", "notepad.exe",
}

# Known system process names that malware commonly spoofs
SYSTEM_PROCESS_NAMES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe",
    "explorer.exe", "taskmgr.exe", "conhost.exe",
}


def detect_process_anomalies(
    pslist_data: list[dict[str, Any]],
    pstree_data: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Analyse process data for anomalies indicative of fileless malware.
    Returns a list of anomaly dicts with category, description, severity.
    """
    anomalies: list[dict[str, Any]] = []

    pid_to_proc = _build_pid_map(pslist_data)

    # 1. Orphaned processes (PPID points to non-existent process)
    anomalies.extend(_detect_orphans(pslist_data, pid_to_proc))

    # 2. Duplicate / spoofed process names
    anomalies.extend(_detect_duplicates(pslist_data))

    # 3. Abnormal parent-child chains
    anomalies.extend(_detect_abnormal_parents(pslist_data, pid_to_proc))

    # 4. Suspicious child spawning (office apps → shell)
    anomalies.extend(_detect_shell_spawning(pslist_data, pid_to_proc))

    # 5. System process name typosquatting
    anomalies.extend(_detect_name_spoofing(pslist_data))

    logger.info("Process inspector: found %d anomalies.", len(anomalies))
    return anomalies


# ---------------------------------------------------------------------------
# Individual detection functions
# ---------------------------------------------------------------------------

def _build_pid_map(pslist: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a PID → process dict for quick lookups."""
    pid_map: dict[str, dict[str, Any]] = {}
    for proc in pslist:
        pid = str(proc.get("PID", proc.get("pid", "")))
        if pid:
            pid_map[pid] = proc
    return pid_map


def _detect_orphans(
    pslist: list[dict[str, Any]], pid_map: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    anomalies = []
    for proc in pslist:
        name = proc.get("Name", proc.get("name", proc.get("ImageFileName", "unknown")))
        pid = str(proc.get("PID", proc.get("pid", "")))
        ppid = str(proc.get("PPID", proc.get("ppid", "")))

        if ppid and ppid != "0" and ppid not in pid_map and name.lower() not in {"system", "smss.exe"}:
            anomalies.append({
                "category": "orphan_process",
                "severity": "HIGH",
                "process": name,
                "pid": pid,
                "ppid": ppid,
                "description": (
                    f"Process '{name}' (PID {pid}) has PPID {ppid} which does not "
                    "exist in the process list — possible process hollowing or injection artefact."
                ),
            })
    return anomalies


def _detect_duplicates(pslist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    anomalies = []
    name_counts: dict[str, list[str]] = {}
    for proc in pslist:
        name = proc.get("Name", proc.get("name", proc.get("ImageFileName", ""))).lower()
        pid = str(proc.get("PID", proc.get("pid", "")))
        if name:
            name_counts.setdefault(name, []).append(pid)

    # Only flag system processes that should only appear once
    single_instance = {"lsass.exe", "winlogon.exe", "wininit.exe", "smss.exe", "services.exe"}
    for name, pids in name_counts.items():
        if name in single_instance and len(pids) > 1:
            anomalies.append({
                "category": "duplicate_system_process",
                "severity": "CRITICAL",
                "process": name,
                "pids": pids,
                "description": (
                    f"Multiple instances of '{name}' found (PIDs: {', '.join(pids)}). "
                    "This is a strong indicator of process spoofing or DLL injection."
                ),
            })
    return anomalies


def _detect_abnormal_parents(
    pslist: list[dict[str, Any]], pid_map: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    anomalies = []
    for proc in pslist:
        name = proc.get("Name", proc.get("name", proc.get("ImageFileName", ""))).lower()
        pid  = str(proc.get("PID", proc.get("pid", "")))
        ppid = str(proc.get("PPID", proc.get("ppid", "")))

        expected = EXPECTED_PARENTS.get(name)
        if expected is None:
            continue  # Not a monitored process

        parent = pid_map.get(ppid)
        parent_name = ""
        if parent:
            parent_name = parent.get(
                "Name", parent.get("name", parent.get("ImageFileName", ""))
            ).lower()

        if parent_name and parent_name not in expected:
            anomalies.append({
                "category": "abnormal_parent",
                "severity": "HIGH",
                "process": name,
                "pid": pid,
                "parent": parent_name,
                "ppid": ppid,
                "expected_parents": expected,
                "description": (
                    f"'{name}' (PID {pid}) has an unexpected parent '{parent_name}' (PPID {ppid}). "
                    f"Expected parent(s): {', '.join(expected) or 'none'}."
                ),
            })
    return anomalies


def _detect_shell_spawning(
    pslist: list[dict[str, Any]], pid_map: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    anomalies = []
    shell_processes = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}

    for proc in pslist:
        name = proc.get("Name", proc.get("name", proc.get("ImageFileName", ""))).lower()
        pid  = str(proc.get("PID", proc.get("pid", "")))
        ppid = str(proc.get("PPID", proc.get("ppid", "")))

        if name not in shell_processes:
            continue

        parent = pid_map.get(ppid)
        if not parent:
            continue

        parent_name = parent.get(
            "Name", parent.get("name", parent.get("ImageFileName", ""))
        ).lower()

        if parent_name in SUSPICIOUS_PARENT_OF_SHELL:
            anomalies.append({
                "category": "suspicious_shell_spawn",
                "severity": "CRITICAL",
                "process": name,
                "pid": pid,
                "parent": parent_name,
                "ppid": ppid,
                "description": (
                    f"⚠️ '{parent_name}' (PPID {ppid}) spawned '{name}' (PID {pid}). "
                    "This is a classic fileless malware indicator — document/browser macros "
                    "or exploitation launching a shell."
                ),
            })
    return anomalies


def _detect_name_spoofing(pslist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect typosquatted system process names (e.g., svch0st.exe, Iexplore.exe)."""
    anomalies = []
    for proc in pslist:
        raw_name = proc.get("Name", proc.get("name", proc.get("ImageFileName", "")))
        name_lower = raw_name.lower()
        pid = str(proc.get("PID", proc.get("pid", "")))

        for sys_name in SYSTEM_PROCESS_NAMES:
            if name_lower == sys_name:
                break  # exact match — ok
            # Check edit distance (simple substitution check)
            if _is_typosquat(name_lower, sys_name):
                anomalies.append({
                    "category": "name_spoofing",
                    "severity": "HIGH",
                    "process": raw_name,
                    "pid": pid,
                    "spoofed_target": sys_name,
                    "description": (
                        f"Process '{raw_name}' (PID {pid}) closely resembles the system process "
                        f"'{sys_name}' — possible masquerading attempt."
                    ),
                })
                break
    return anomalies


def _is_typosquat(candidate: str, target: str) -> bool:
    """Return True if candidate looks like a typosquat of target."""
    if abs(len(candidate) - len(target)) > 2:
        return False
    if candidate == target:
        return False
    # Strip extensions and compare
    c_base = re.sub(r"\.\w+$", "", candidate)
    t_base = re.sub(r"\.\w+$", "", target)
    # Must share at least half their characters to avoid cross-name false positives
    if len(t_base) > 0 and len(c_base) > 0:
        shorter = min(len(c_base), len(t_base))
        if shorter < 4:
            return False  # too short to reliably detect typosquats
        # Simple character difference count on aligned prefix
        diffs = sum(1 for a, b in zip(c_base, t_base) if a != b) + abs(len(c_base) - len(t_base))
        return diffs == 1  # Only flag single-character substitutions (e.g., svchost→svch0st)
    return False
