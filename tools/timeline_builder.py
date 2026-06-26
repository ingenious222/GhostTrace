"""
tools/timeline_builder.py
──────────────────────────────────────────────────────────────
Reconstructs a chronological attack timeline from all collected
memory artefacts. Where timestamps exist they are used directly;
where undated, events are ordered by forensic phase logic.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event type ordering (used when no timestamps available)
# ---------------------------------------------------------------------------

PHASE_ORDER = {
    "memory_acquisition": 0,
    "process_created": 10,
    "dll_loaded": 20,
    "network_connection": 30,
    "code_injection": 40,
    "handle_opened": 45,
    "powershell_launched": 50,
    "encoded_command": 55,
    "download_cradle": 60,
    "amsi_bypass": 65,
    "payload_execution": 70,
    "network_c2": 80,
    "persistence": 90,
    "unknown": 100,
}


def build_attack_timeline(
    pslist_data: list[dict[str, Any]] | None = None,
    malfind_data: list[dict[str, Any]] | None = None,
    cmdline_data: list[dict[str, Any]] | None = None,
    netscan_data: list[dict[str, Any]] | None = None,
    powershell_findings: list[dict[str, Any]] | None = None,
    process_anomalies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Build a chronological attack timeline from all artefact sources.
    Returns a list of timeline events sorted by timestamp / phase order.
    """
    events: list[dict[str, Any]] = []

    events.extend(_events_from_pslist(pslist_data or []))
    events.extend(_events_from_malfind(malfind_data or []))
    events.extend(_events_from_cmdline(cmdline_data or []))
    events.extend(_events_from_netscan(netscan_data or []))
    events.extend(_events_from_powershell(powershell_findings or []))

    # Sort: timestamped events first (earliest → latest),
    # then un-timestamped events by phase order
    events_with_ts = [e for e in events if e.get("timestamp")]
    events_no_ts   = [e for e in events if not e.get("timestamp")]

    events_with_ts.sort(key=lambda e: _parse_ts(e["timestamp"]))
    events_no_ts.sort(key=lambda e: PHASE_ORDER.get(e.get("event_type", "unknown"), 100))

    # Merge: timestamped events come first, undated events appended
    timeline = events_with_ts + events_no_ts

    # Add sequence numbers
    for i, event in enumerate(timeline, start=1):
        event["step"] = i

    logger.info("Timeline builder: %d events reconstructed.", len(timeline))
    return {"timeline": timeline, "total": len(timeline)}


# ---------------------------------------------------------------------------
# Per-source event builders
# ---------------------------------------------------------------------------

def _events_from_pslist(pslist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for proc in pslist:
        name  = _get(proc, ["Name", "name", "ImageFileName"], "unknown")
        pid   = _get(proc, ["PID", "pid"], "?")
        ppid  = _get(proc, ["PPID", "ppid"], "?")
        start = _get(proc, ["CreateTime", "create_time", "Start", "StartTime"], None)

        events.append({
            "event_type": "process_created",
            "timestamp": start,
            "pid": pid,
            "ppid": ppid,
            "process": name,
            "description": f"Process '{name}' (PID {pid}) started. Parent PID: {ppid}.",
            "source": "pslist",
            "severity": "INFO",
        })
    return events


def _events_from_malfind(malfind: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for region in malfind:
        proc    = _get(region, ["process", "Process", "ImageFileName"], "unknown")
        pid     = _get(region, ["pid", "PID"], "?")
        address = _get(region, ["address", "Address", "Base"], "?")
        prot    = _get(region, ["protection", "Protection", "Permissions", "VadTag"], "?")

        events.append({
            "event_type": "code_injection",
            "timestamp": None,
            "pid": pid,
            "process": proc,
            "description": (
                f"⚠️ Injected/suspicious memory region in '{proc}' (PID {pid}) "
                f"at {address} with protection: {prot}. "
                "Possible shellcode or PE injection."
            ),
            "source": "malfind",
            "severity": "CRITICAL",
            "address": address,
        })
    return events


def _events_from_cmdline(cmdline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for entry in cmdline:
        proc = _get(entry, ["process", "Process", "Name", "ImageFileName"], "unknown")
        pid  = _get(entry, ["pid", "PID"], "?")
        cmd  = _get(entry, ["cmdline", "CommandLine", "Args", "CmdLine"], "")

        if not cmd:
            continue

        event_type = "process_created"
        severity   = "INFO"

        if "powershell" in str(proc).lower() or "powershell" in cmd.lower():
            event_type = "powershell_launched"
            severity = "MEDIUM"

        if re.search(r"-[Ee]nc(?:oded[Cc]ommand)?", cmd):
            event_type = "encoded_command"
            severity = "CRITICAL"
        elif re.search(r"(?i)DownloadString|IEX|Invoke-Expression", cmd):
            event_type = "download_cradle"
            severity = "CRITICAL"

        events.append({
            "event_type": event_type,
            "timestamp": None,
            "pid": pid,
            "process": proc,
            "description": f"'{proc}' (PID {pid}) executed with args: {cmd[:200]}",
            "source": "cmdline",
            "severity": severity,
            "cmdline": cmd[:300],
        })
    return events


def _events_from_netscan(netscan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for conn in netscan:
        foreign = _get(conn, ["ForeignAddr", "foreign_addr", "ForeignAddress", "RemoteAddress"], "")
        local   = _get(conn, ["LocalAddr", "local_addr", "LocalAddress"], "")
        state   = _get(conn, ["State", "state"], "?")
        pid     = _get(conn, ["PID", "pid", "Owner"], "?")
        proto   = _get(conn, ["Proto", "proto", "Protocol"], "TCP")
        ts      = _get(conn, ["Created", "created", "Timestamp", "timestamp"], None)

        if not foreign or foreign in {"-", "*", "0.0.0.0:0"}:
            continue

        events.append({
            "event_type": "network_connection",
            "timestamp": ts,
            "pid": pid,
            "process": _get(conn, ["Owner", "Process", "ImageFileName"], "unknown"),
            "description": (
                f"Network connection: {local} → {foreign} | "
                f"State: {state} | Protocol: {proto} | PID: {pid}"
            ),
            "source": "netscan",
            "severity": "MEDIUM" if state == "ESTABLISHED" else "INFO",
            "local": local,
            "foreign": foreign,
            "state": state,
        })
    return events


def _events_from_powershell(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for finding in findings:
        pid     = finding.get("pid", "?")
        process = finding.get("process", "powershell.exe")
        patterns = finding.get("patterns_found", [])
        decoded  = finding.get("decoded_content")

        for pattern in patterns:
            name = pattern.get("name", "unknown")
            sev  = pattern.get("severity", "MEDIUM")
            desc = pattern.get("description", "")

            event_type_map = {
                "EncodedCommand":    "encoded_command",
                "IEX_DownloadCradle":"download_cradle",
                "DownloadString":    "download_cradle",
                "AMSIBypass":        "amsi_bypass",
                "ETWBypass":         "amsi_bypass",
                "ProcessInjection":  "payload_execution",
                "ReflectionAssembly":"payload_execution",
            }

            events.append({
                "event_type": event_type_map.get(name, "powershell_launched"),
                "timestamp": None,
                "pid": pid,
                "process": process,
                "description": (
                    f"⚠️ PowerShell pattern '{name}' detected in PID {pid}: {desc}. "
                    + (f"Decoded: {decoded[:150]}..." if decoded else "")
                ),
                "source": "powershell_decoder",
                "severity": sev,
                "pattern": name,
            })
    return events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(d: dict[str, Any], keys: list[str], default: Any) -> Any:
    for k in keys:
        if k in d and d[k]:
            return d[k]
    return default


def _parse_ts(ts_str: str | None) -> datetime:
    if not ts_str:
        return datetime.min
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S UTC"):
        try:
            return datetime.strptime(ts_str.strip().replace(" UTC", ""), fmt.replace(" UTC", ""))
        except ValueError:
            continue
    return datetime.min
