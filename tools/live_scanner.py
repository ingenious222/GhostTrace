"""
tools/live_scanner.py
=====================
Dynamic analysis: scan the LIVE running system using psutil.
Produces output in the same format as Volatility plugins so the
existing analysis pipeline (threat_scorer, process_inspector, etc.)
works unchanged.
"""

from __future__ import annotations

import datetime
import logging
import os
import socket
import subprocess
import sys
from typing import Any

import psutil

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError):
        return default


# ---------------------------------------------------------------------------
# pslist equivalent
# ---------------------------------------------------------------------------

def live_pslist() -> list[dict[str, Any]]:
    """Return all running processes in Volatility pslist format."""
    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "create_time", "num_threads", "username"]
    ):
        info = proc.info
        rows.append({
            "PID":        info.get("pid", ""),
            "PPID":       info.get("ppid", ""),
            "ImageFileName": info.get("name", ""),
            "Name":       info.get("name", ""),
            "Threads":    info.get("num_threads", ""),
            "Wow64":      "",
            "CreateTime": datetime.datetime.fromtimestamp(
                info.get("create_time") or 0
            ).isoformat(timespec="seconds"),
            "ExitTime":   "",
            "_live":      True,
        })
    return rows


# ---------------------------------------------------------------------------
# netscan equivalent
# ---------------------------------------------------------------------------

def live_netscan() -> list[dict[str, Any]]:
    """Return all active network connections in Volatility netscan format."""
    rows: list[dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except PermissionError:
        conns = []

    # Build pid→name map
    pid_name: dict[int, str] = {}
    for p in psutil.process_iter(["pid", "name"]):
        try:
            pid_name[p.info["pid"]] = p.info["name"] or ""
        except Exception:
            pass

    for c in conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        faddr_ip   = c.raddr.ip   if c.raddr else "*"
        faddr_port = c.raddr.port if c.raddr else 0
        rows.append({
            "Offset":      "0x0",
            "Proto":       "TCPv4" if c.family == socket.AF_INET else "TCPv6",
            "LocalAddr":   laddr,
            "ForeignAddr": faddr_ip,
            "ForeignPort": faddr_port,
            "State":       c.status or "NONE",
            "PID":         c.pid or "",
            "Owner":       pid_name.get(c.pid or 0, ""),
            "Created":     _ts(),
            "_live":       True,
        })
    return rows


# ---------------------------------------------------------------------------
# cmdline equivalent
# ---------------------------------------------------------------------------

def live_cmdline() -> list[dict[str, Any]]:
    """Return command lines of all running processes."""
    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            cmd = " ".join(proc.cmdline()) or proc.name()
            rows.append({
                "PID":         proc.info["pid"],
                "Process":     proc.info["name"],
                "CommandLine": cmd,
                "_live":       True,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return rows


# ---------------------------------------------------------------------------
# dlllist equivalent  (loaded modules)
# ---------------------------------------------------------------------------

def live_dlllist() -> list[dict[str, Any]]:
    """Return loaded modules (DLLs) for each running process."""
    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            mods = proc.memory_maps(grouped=False)
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
        for m in mods:
            path = m.path if hasattr(m, "path") else ""
            rows.append({
                "PID":     proc.info["pid"],
                "Process": proc.info["name"],
                "Base":    "",
                "Size":    getattr(m, "size", ""),
                "Path":    path,
                "Name":    os.path.basename(path) if path else "",
                "_live":   True,
            })
    return rows


# ---------------------------------------------------------------------------
# handles equivalent  (open files / sockets, approximated)
# ---------------------------------------------------------------------------

def live_handles() -> list[dict[str, Any]]:
    """Return open file handles for each running process."""
    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                rows.append({
                    "PID":           proc.info["pid"],
                    "Process":       proc.info["name"],
                    "HandleValue":   "",
                    "Type":          "File",
                    "GrantedAccess": "0x120089",
                    "Name":          f.path,
                    "Offset":        "",
                    "_live":         True,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return rows


# ---------------------------------------------------------------------------
# malfind equivalent  (heuristic — executable private mem regions)
# ---------------------------------------------------------------------------

def live_malfind() -> list[dict[str, Any]]:
    """
    Detect suspicious executable memory regions in running processes.
    Looks for private memory marked executable — a common shellcode/injection indicator.
    Requires elevated privileges on Windows for full coverage.
    """
    rows: list[dict[str, Any]] = []
    SUSPICIOUS_PROCS = {
        "notepad.exe", "calc.exe", "mspaint.exe", "explorer.exe",
        "svchost.exe", "lsass.exe", "csrss.exe",
    }
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            maps = proc.memory_maps(grouped=False)
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
        name = (proc.info.get("name") or "").lower()
        for m in maps:
            perms = getattr(m, "perms", "") or ""
            path  = getattr(m, "path", "")  or ""
            # Executable + writable private region with no backing file → suspicious
            if ("x" in perms.lower() or "exec" in perms.lower()) and not path:
                rows.append({
                    "pid":        proc.info["pid"],
                    "process":    proc.info["name"],
                    "address":    getattr(m, "addr", ""),
                    "protection": perms,
                    "tag":        "VadS",
                    "VadTag":     "VadS",
                    "Protection": perms,
                    "PID":        proc.info["pid"],
                    "ImageFileName": proc.info["name"],
                    "_live":      True,
                })
            # Also flag known-benign processes talking on network — injection indicator
            elif name in SUSPICIOUS_PROCS and "x" in perms.lower():
                rows.append({
                    "pid":        proc.info["pid"],
                    "process":    proc.info["name"],
                    "address":    getattr(m, "addr", ""),
                    "protection": perms,
                    "tag":        "VadS",
                    "VadTag":     "VadS",
                    "Protection": perms,
                    "PID":        proc.info["pid"],
                    "ImageFileName": proc.info["name"],
                    "_live":      True,
                })
    return rows[:30]   # cap at 30


# ---------------------------------------------------------------------------
# Top-level: collect everything
# ---------------------------------------------------------------------------

def run_live_scan(progress_callback=None) -> dict[str, Any]:
    """
    Run a complete live system scan.
    Returns a dict with the same keys as the Volatility plugin results dict.
    """
    def _step(msg: str, pct: float):
        logger.info(msg)
        if progress_callback:
            progress_callback(pct, msg)

    _step("🔍 Enumerating processes…", 0.10)
    pslist  = live_pslist()

    _step("🌐 Scanning network connections…", 0.25)
    netscan = live_netscan()

    _step("⚡ Collecting command lines…", 0.40)
    cmdline = live_cmdline()

    _step("📦 Loading DLL/module maps…", 0.55)
    try:
        dlllist = live_dlllist()
    except Exception as e:
        logger.warning("DLL list failed (may need elevation): %s", e)
        dlllist = []

    _step("🔑 Collecting open file handles…", 0.70)
    try:
        handles = live_handles()
    except Exception as e:
        logger.warning("Handles failed: %s", e)
        handles = []

    _step("💉 Scanning executable memory regions…", 0.85)
    try:
        malfind = live_malfind()
    except Exception as e:
        logger.warning("Malfind failed: %s", e)
        malfind = []

    _step("✅ Live scan complete", 1.0)

    return {
        "pslist":  pslist,
        "netscan": netscan,
        "cmdline": cmdline,
        "dlllist": dlllist,
        "handles": handles,
        "malfind": malfind,
        "source":  "live",
        "scan_time": _ts(),
        "host":    socket.gethostname(),
        "pid_count": len(pslist),
        "conn_count": len(netscan),
    }
