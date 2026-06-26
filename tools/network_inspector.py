"""
tools/network_inspector.py
──────────────────────────────────────────────────────────────
Analyses netscan output to detect suspicious network activity:
unusual ports, C2 connections, processes communicating on
unexpected interfaces, and geographic flagging.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Processes that should NOT have network connections
NON_NETWORK_PROCESSES = {
    "notepad.exe", "mspaint.exe", "calc.exe", "wordpad.exe",
    "regedit.exe", "taskmgr.exe", "winver.exe", "charmap.exe",
}

# Processes that are expected to have network connections
EXPECTED_NETWORK_PROCESSES = {
    "svchost.exe", "lsass.exe", "chrome.exe", "firefox.exe",
    "iexplore.exe", "msedge.exe", "outlook.exe", "Teams.exe",
    "Skype.exe", "OneDrive.exe", "MsMpEng.exe", "searchindexer.exe",
}

# Suspicious listening ports used by RATs / shells
SUSPICIOUS_PORTS = {
    4444, 4445, 1234, 5555, 6666, 7777, 8888, 9999,  # Metasploit defaults
    31337, 12345, 54321,                               # Classic backdoor ports
    1337, 6969, 2222, 3333,
}


def detect_suspicious_connections(
    netscan_data: list[dict[str, Any]],
    pslist_data: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Flag suspicious network connections from netscan output.
    """
    pid_map = _build_pid_map(pslist_data or [])
    anomalies: list[dict[str, Any]] = []

    for conn in netscan_data:
        local_addr = _get_field(conn, ["LocalAddr", "local_addr", "Local Address", "LocalAddress"], "")
        foreign_addr = _get_field(conn, ["ForeignAddr", "foreign_addr", "Foreign Address", "ForeignAddress", "RemoteAddress"], "")
        state = _get_field(conn, ["State", "state"], "").upper()
        proto = _get_field(conn, ["Proto", "proto", "Protocol"], "").upper()
        pid = _get_field(conn, ["PID", "pid", "Pid", "Owner"], "")
        proc_name = pid_map.get(str(pid), {}).get("name", "") or _get_field(conn, ["Owner", "Process", "ImageFileName"], "")

        # Parse foreign IP and port
        foreign_ip, foreign_port = _parse_addr(foreign_addr)
        _, local_port = _parse_addr(local_addr)

        if not foreign_ip and not local_addr:
            continue

        # Check 1: Non-network process with an active connection
        if proc_name.lower() in NON_NETWORK_PROCESSES and state in {"ESTABLISHED", "LISTEN", "LISTENING"}:
            anomalies.append({
                "category": "unexpected_process_connection",
                "severity": "CRITICAL",
                "pid": pid,
                "process": proc_name,
                "local": local_addr,
                "foreign": foreign_addr,
                "state": state,
                "description": (
                    f"⚠️ '{proc_name}' (PID {pid}) has a {state} connection to {foreign_addr}. "
                    "Non-network processes should not have active connections — possible injection."
                ),
            })

        # Check 2: Connection to suspicious port number
        if foreign_port and foreign_port in SUSPICIOUS_PORTS:
            anomalies.append({
                "category": "suspicious_port",
                "severity": "HIGH",
                "pid": pid,
                "process": proc_name,
                "local": local_addr,
                "foreign": foreign_addr,
                "port": foreign_port,
                "description": (
                    f"Connection from '{proc_name}' (PID {pid}) to port {foreign_port} on {foreign_ip}. "
                    "This port is commonly used by C2 frameworks (Metasploit, Cobalt Strike, etc.)."
                ),
            })

        # Check 3: Local suspicious LISTENING port
        if local_port and local_port in SUSPICIOUS_PORTS and state in {"LISTEN", "LISTENING"}:
            anomalies.append({
                "category": "suspicious_port",
                "severity": "HIGH",
                "pid": pid,
                "process": proc_name,
                "local": local_addr,
                "port": local_port,
                "description": (
                    f"'{proc_name}' (PID {pid}) is LISTENING on suspicious port {local_port}. "
                    "Possible backdoor or reverse shell handler."
                ),
            })

        # Check 4: Public (non-RFC1918) foreign IP in ESTABLISHED state
        if foreign_ip and state == "ESTABLISHED":
            try:
                ip_obj = ipaddress.ip_address(foreign_ip)
                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                    anomalies.append({
                        "category": "external_connection",
                        "severity": "MEDIUM",
                        "pid": pid,
                        "process": proc_name,
                        "local": local_addr,
                        "foreign": foreign_addr,
                        "ip": foreign_ip,
                        "description": (
                            f"'{proc_name}' (PID {pid}) has an ESTABLISHED connection to "
                            f"public IP {foreign_ip}:{foreign_port}. Verify if expected."
                        ),
                    })
            except ValueError:
                pass

    logger.info("Network inspector: found %d suspicious connections.", len(anomalies))
    return anomalies


def cross_reference_connections(
    netscan_data: list[dict[str, Any]],
    pslist_data: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map network connections to their owning processes by PID."""
    pid_map = _build_pid_map(pslist_data)
    results: list[dict[str, Any]] = []

    for conn in netscan_data:
        pid = _get_field(conn, ["PID", "pid", "Pid", "Owner"], "")
        proc = pid_map.get(str(pid), {})
        proc_name = proc.get("name", "unknown") or _get_field(conn, ["Owner", "Process"], "unknown")

        results.append({
            **conn,
            "process_name": proc_name,
            "pid_resolved": bool(proc),
        })

    return results


def geo_flag_connections(netscan_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag non-private IPs for geo-lookup (returns IPs for external investigation)."""
    flagged = []
    for conn in netscan_data:
        foreign_addr = _get_field(conn, ["ForeignAddr", "foreign_addr", "ForeignAddress"], "")
        ip, port = _parse_addr(foreign_addr)
        if not ip:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                flagged.append({
                    "ip": ip,
                    "port": port,
                    "full_address": foreign_addr,
                    "recommendation": f"Run threat intel lookup on {ip} (VirusTotal, AbuseIPDB, Shodan)",
                })
        except ValueError:
            pass
    return flagged


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_pid_map(pslist: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    pid_map: dict[str, dict[str, Any]] = {}
    for proc in pslist:
        pid = str(_get_field(proc, ["PID", "pid"], ""))
        name = _get_field(proc, ["Name", "name", "ImageFileName"], "")
        if pid:
            pid_map[pid] = {"name": name}
    return pid_map


def _get_field(d: dict[str, Any], keys: list[str], default: Any = "") -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return default


def _parse_addr(addr: str) -> tuple[str, int | None]:
    """Parse 'ip:port' or 'ip' into (ip, port_or_None)."""
    if not addr or addr in {"-", "*", ""}:
        return "", None
    # IPv6 format [::1]:port
    ipv6_match = re.match(r"\[([^\]]+)\]:(\d+)", addr)
    if ipv6_match:
        return ipv6_match.group(1), int(ipv6_match.group(2))
    # IPv4 ip:port
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except (ValueError, IndexError):
            return parts[0], None
    return addr, None
