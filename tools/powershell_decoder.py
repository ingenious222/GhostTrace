"""
tools/powershell_decoder.py
──────────────────────────────────────────────────────────────
Decodes and analyses PowerShell commands found in memory:
base64 -EncodedCommand payloads, download cradles,
AMSI/ETW bypass attempts, and IOC (URL/IP) extraction.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suspicious pattern signatures
# ---------------------------------------------------------------------------

OBFUSCATION_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "EncodedCommand",
        "pattern": r"-[Ee]nc(?:oded[Cc]ommand)?\s+([A-Za-z0-9+/=]{20,})",
        "severity": "CRITICAL",
        "description": "Base64-encoded PowerShell command (-EncodedCommand)",
    },
    {
        "name": "IEX_DownloadCradle",
        "pattern": r"(?i)(IEX|Invoke-Expression)\s*\(",
        "severity": "CRITICAL",
        "description": "Invoke-Expression download/exec cradle",
    },
    {
        "name": "DownloadString",
        "pattern": r"(?i)\.DownloadString\s*\(['\"]?(https?://[^'\")\s]+)",
        "severity": "HIGH",
        "description": "WebClient.DownloadString — downloads and executes remote payload",
    },
    {
        "name": "DownloadFile",
        "pattern": r"(?i)\.DownloadFile\s*\(",
        "severity": "HIGH",
        "description": "WebClient.DownloadFile — file download to disk",
    },
    {
        "name": "AMSIBypass",
        "pattern": r"(?i)(amsiutils|amsicontext|amsiInitFailed|Reflection\.Assembly.*amsi)",
        "severity": "CRITICAL",
        "description": "AMSI bypass attempt — evades antimalware scanning",
    },
    {
        "name": "ETWBypass",
        "pattern": r"(?i)(EtwEventWrite|ntdll.*etw|Patch.*ETW)",
        "severity": "CRITICAL",
        "description": "ETW (Event Tracing for Windows) bypass — evades logging",
    },
    {
        "name": "ExecutionBypass",
        "pattern": r"(?i)-[Ee]xecution[Pp]olicy\s*(bypass|unrestricted|remotesigned)",
        "severity": "HIGH",
        "description": "Execution policy bypass flag",
    },
    {
        "name": "WindowHidden",
        "pattern": r"(?i)-[Ww]indow[Ss]tyle\s*(hidden|1)",
        "severity": "MEDIUM",
        "description": "Hidden window — script runs without visible console",
    },
    {
        "name": "NonInteractive",
        "pattern": r"(?i)-[Nn]on[Ii]nteractive|-[Nn]o[Pp]rofile",
        "severity": "LOW",
        "description": "Non-interactive / no-profile flags (evasion indicator)",
    },
    {
        "name": "ReflectionAssembly",
        "pattern": r"(?i)\[Reflection\.Assembly\]|System\.Reflection\.Assembly.*Load",
        "severity": "HIGH",
        "description": "Reflection.Assembly.Load — loads .NET assembly in memory (fileless)",
    },
    {
        "name": "ProcessInjection",
        "pattern": r"(?i)(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtQueueApcThread)",
        "severity": "CRITICAL",
        "description": "Win32 API calls for process injection in PowerShell script",
    },
]

# Regex for IOC extraction
_URL_RE = re.compile(r"https?://[a-zA-Z0-9\-._/?=&%#+@:]+")
_IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


def decode_powershell_commands(
    cmdline_data: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Analyse cmdline data for PowerShell obfuscation and encoded payloads.
    Decodes base64 -EncodedCommand arguments and identifies attack patterns.
    """
    findings: list[dict[str, Any]] = []

    for entry in cmdline_data:
        cmdline = entry.get("cmdline", entry.get("CommandLine", entry.get("Args", "")))
        pid     = entry.get("pid", entry.get("PID", ""))
        process = entry.get("process", entry.get("Name", entry.get("Process", "")))

        if not cmdline:
            continue

        # Skip non-PowerShell processes
        if "powershell" not in str(process).lower() and "powershell" not in cmdline.lower() and "pwsh" not in cmdline.lower():
            continue

        finding: dict[str, Any] = {
            "pid": pid,
            "process": process,
            "raw_cmdline": cmdline,
            "patterns_found": [],
            "decoded_content": None,
            "iocs": [],
        }

        decoded_text = cmdline

        # Step 1: Decode base64 payload if present
        enc_match = re.search(r"-[Ee]nc(?:oded[Cc]ommand)?\s+([A-Za-z0-9+/=]{20,})", cmdline)
        if enc_match:
            b64_blob = enc_match.group(1)
            decoded = _safe_b64_decode(b64_blob)
            if decoded:
                finding["decoded_content"] = decoded
                decoded_text = decoded
                finding["patterns_found"].append({
                    "name": "EncodedCommand",
                    "severity": "CRITICAL",
                    "matched": b64_blob[:50] + "...",
                    "decoded": decoded[:300],
                })

        # Step 2: Scan both raw and decoded text for patterns
        scan_text = cmdline + "\n" + (decoded_text or "")
        for sig in OBFUSCATION_PATTERNS:
            if sig["name"] == "EncodedCommand":
                continue  # Already handled above
            m = re.search(sig["pattern"], scan_text)
            if m:
                finding["patterns_found"].append({
                    "name": sig["name"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "matched": m.group(0)[:100],
                })

        # Step 3: Extract IOCs from decoded content
        if decoded_text:
            finding["iocs"] = _extract_iocs_from_text(decoded_text)

        if finding["patterns_found"] or finding["decoded_content"]:
            findings.append(finding)
            logger.info(
                "PowerShell finding in PID %s: %d patterns found.",
                pid, len(finding["patterns_found"]),
            )

    return findings


def extract_iocs(
    decoded_commands: "list[dict[str, Any]] | str",
    netscan_data: list[dict[str, Any]] | None = None,
) -> "list[dict[str, Any]] | dict[str, list[str]]":
    """
    Compile all IOCs (URLs, IPs, domains) from decoded commands and
    network scan data into a deduplicated IOC list.

    When called with a plain string, returns a dict with keys
    'urls', 'ips', 'domains' (each a list of string values).
    """
    # Accept a raw text string for convenience
    if isinstance(decoded_commands, str):
        ioc_list = _extract_iocs_from_text(decoded_commands)
        result: dict[str, list[str]] = {"urls": [], "ips": [], "domains": []}
        for ioc in ioc_list:
            ioc_type = ioc.get("type", "")
            ioc_value = ioc.get("value", "")
            if ioc_type == "url":
                result["urls"].append(ioc_value)
            elif ioc_type == "ip":
                result["ips"].append(ioc_value)
            elif ioc_type == "domain":
                result["domains"].append(ioc_value)
        return result

    iocs: dict[str, dict[str, Any]] = {}

    # From decoded PS commands
    for finding in decoded_commands:
        source = f"PowerShell PID {finding.get('pid', '?')}"
        for ioc in finding.get("iocs", []):
            key = ioc["value"]
            if key not in iocs:
                iocs[key] = {**ioc, "sources": [source]}
            else:
                if source not in iocs[key]["sources"]:
                    iocs[key]["sources"].append(source)

    # From netscan external IPs
    if netscan_data:
        for conn in netscan_data:
            foreign = conn.get("ForeignAddr", conn.get("foreign_addr", ""))
            ip, port = _parse_addr(foreign)
            if ip and ip not in ("0.0.0.0", "127.0.0.1", "::1", "*"):
                key = ip
                if key not in iocs:
                    iocs[key] = {
                        "type": "ip",
                        "value": ip,
                        "port": port,
                        "sources": ["netscan"],
                        "recommendation": f"Lookup on VirusTotal / AbuseIPDB: {ip}",
                    }

    return list(iocs.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_b64_decode(blob: str) -> str | None:
    """Decode a base64 blob, handling UTF-16LE (PowerShell default)."""
    # Pad to multiple of 4
    padded = blob + "=" * (-len(blob) % 4)
    for encoding in ("utf-16-le", "utf-8", "latin-1"):
        try:
            raw = base64.b64decode(padded)
            # UTF-16-LE requires an even number of bytes; strip trailing null if needed
            if encoding == "utf-16-le" and len(raw) % 2 != 0:
                raw = raw[:-1]
            return raw.decode(encoding).strip()
        except Exception:  # noqa: BLE001
            continue
    return None


def _extract_iocs_from_text(text: str) -> list[dict[str, Any]]:
    iocs = []
    for url in set(_URL_RE.findall(text)):
        iocs.append({"type": "url", "value": url, "recommendation": f"Block/investigate URL: {url}"})
    for ip in set(_IP_RE.findall(text)):
        if not ip.startswith(("192.168.", "10.", "172.")):
            iocs.append({"type": "ip", "value": ip, "recommendation": f"Lookup IP on threat intel: {ip}"})
    return iocs


def _parse_addr(addr: str) -> tuple[str, int | None]:
    if not addr or addr in {"-", "*", ""}:
        return "", None
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except (ValueError, IndexError):
            return parts[0], None
    return addr, None
