"""
tools/static_analyzer.py
──────────────────────────────────────────────────────────────
Static analysis of extracted memory regions and PE files.

Detects:
  - PE header magic bytes (MZ / DOS header)
  - Section entropy (packed / encrypted code → high entropy)
  - Suspicious section names (UPX, .reloc anomalies)
  - YARA-style string pattern matching (no YARA dependency)
  - Shellcode heuristics (GetProcAddress / LoadLibrary stubs)
  - Import table red flags (VirtualAlloc, CreateRemoteThread)
"""

from __future__ import annotations

import logging
import math
import re
import struct
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suspicious API imports — fileless malware hallmarks
# ---------------------------------------------------------------------------
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc":          ("CRITICAL", "Dynamic memory allocation — shellcode staging"),
    "VirtualAllocEx":        ("CRITICAL", "Remote process memory allocation — injection"),
    "WriteProcessMemory":    ("CRITICAL", "Writing to another process — injection"),
    "CreateRemoteThread":    ("CRITICAL", "Remote thread creation — classic DLL injection"),
    "NtCreateThreadEx":      ("CRITICAL", "NT-level remote thread — advanced injection"),
    "QueueUserAPC":          ("HIGH",     "APC injection technique"),
    "SetWindowsHookEx":      ("HIGH",     "Hook injection"),
    "LoadLibraryA":          ("HIGH",     "Dynamic library loading"),
    "LoadLibraryW":          ("HIGH",     "Dynamic library loading (wide)"),
    "GetProcAddress":        ("HIGH",     "Dynamic API resolution — shellcode pattern"),
    "NtUnmapViewOfSection":  ("HIGH",     "Process hollowing — unmapping target"),
    "ZwUnmapViewOfSection":  ("HIGH",     "Process hollowing — Zw variant"),
    "RtlMoveMemory":         ("MEDIUM",   "Memory copy — possible payload staging"),
    "OpenProcess":           ("MEDIUM",   "Opening another process handle"),
    "CreateToolhelp32Snapshot": ("LOW",   "Process enumeration"),
}

# Suspicious section names
SUSPICIOUS_SECTIONS = {
    "UPX0", "UPX1", "UPX2",          # UPX packer
    ".MPRESS1", ".MPRESS2",            # MPRESS packer
    "themida", "winlicen",             # Themida
    ".ndata",                          # NSIS installer
    ".rmnet",                          # Bredolab
    ".perpet",                         # Perpetual packer
}

# YARA-style byte pattern signatures (hex string → description)
BYTE_PATTERNS = {
    "4d5a":         ("LOW",     "MZ header — PE file in memory region"),
    "5a4d":         ("LOW",     "Reversed MZ — possibly obfuscated PE"),
    "e8000000005b": ("HIGH",    "Call+pop shellcode prologue (position-independent)"),
    "fc4889":       ("HIGH",    "64-bit Meterpreter shellcode prologue"),
    "6a6068":       ("HIGH",    "Classic shellcode push sequence"),
    "60e800":       ("MEDIUM",  "PEB walking / GetProcAddress stub"),
    "0f34":         ("MEDIUM",  "SYSENTER instruction"),
    "4d534346":     ("LOW",     "CAB archive magic"),
    "504b0304":     ("LOW",     "ZIP archive magic"),
}

# String patterns to search for in hex/string data
STRING_PATTERNS = [
    (r"(?i)cmd\.exe",             "MEDIUM",  "cmd.exe string reference"),
    (r"(?i)powershell",           "MEDIUM",  "PowerShell string reference"),
    (r"(?i)WScript\.Shell",       "HIGH",    "WScript.Shell COM object reference"),
    (r"(?i)CreateObject",         "HIGH",    "VBA/VBScript CreateObject call"),
    (r"(?i)http[s]?://",          "LOW",     "URL string found in binary"),
    (r"(?i)\\\\.*\\admin\$",      "HIGH",    "Admin share path — lateral movement"),
    (r"(?i)mimikatz",             "CRITICAL","Mimikatz string reference"),
    (r"(?i)sekurlsa",             "CRITICAL","Mimikatz sekurlsa module reference"),
    (r"(?i)lsadump",              "CRITICAL","Mimikatz lsadump reference"),
    (r"(?i)invoke-expression",    "HIGH",    "PowerShell IEX — code execution"),
    (r"(?i)downloadstring",       "HIGH",    "PowerShell download cradle"),
    (r"(?i)bypass",               "MEDIUM",  "Policy bypass string"),
    (r"(?i)amsi",                 "HIGH",    "AMSI reference — possible bypass attempt"),
    (r"[A-Za-z0-9+/]{60,}={0,2}", "LOW",    "Long base64-like string"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_malfind_regions(
    malfind_data: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Run static analysis on malfind-extracted memory regions.

    Args:
        malfind_data: list of dicts from run_malfind(), each may contain:
            - hex_preview: raw hex bytes (space-separated)
            - disasm: disassembly lines
            - protection: VAD protection string

    Returns:
        {
            "regions_analysed": int,
            "findings": list[dict],
            "high_risk_count": int,
            "summary": str,
        }
    """
    findings: list[dict[str, Any]] = []

    for region in malfind_data:
        pid      = str(region.get("pid",     region.get("PID",     "?")))
        process  = region.get("process",  region.get("Process",  "unknown"))
        address  = region.get("address",  region.get("Address",  "0x0"))
        hex_data = region.get("hex_preview", region.get("hex", ""))
        disasm   = region.get("disasm",   "")
        prot     = region.get("protection", region.get("Protection", ""))

        region_findings: list[dict[str, Any]] = []

        # 1. PE header detection
        pe = _detect_pe_header(hex_data, pid, process, address)
        if pe:
            region_findings.extend(pe)

        # 2. Entropy
        ent = _calculate_hex_entropy(hex_data)
        if ent is not None and ent > 7.0:
            region_findings.append({
                "type": "high_entropy",
                "severity": "HIGH",
                "pid": pid,
                "process": process,
                "address": address,
                "entropy": round(ent, 3),
                "description": (
                    f"Memory region at {address} in '{process}' (PID {pid}) has entropy "
                    f"{ent:.3f}/8.0 — strongly suggests packed or encrypted payload."
                ),
            })

        # 3. Shellcode pattern matching on hex
        shell = _match_byte_patterns(hex_data, pid, process, address)
        region_findings.extend(shell)

        # 4. String patterns on disasm / any text data
        text_data = f"{hex_data} {disasm}"
        str_hits = _match_string_patterns(text_data, pid, process, address)
        region_findings.extend(str_hits)

        # 5. Dangerous VAD protection flags
        if any(flag in prot.upper() for flag in ("EXECUTE_READWRITE", "EXECUTE_WRITECOPY")):
            region_findings.append({
                "type": "rwx_memory",
                "severity": "HIGH",
                "pid": pid,
                "process": process,
                "address": address,
                "protection": prot,
                "description": (
                    f"Region {address} in '{process}' (PID {pid}) is mapped RWX "
                    f"({prot}) — classic shellcode staging area."
                ),
            })

        findings.extend(region_findings)

    high_risk = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))

    return {
        "regions_analysed": len(malfind_data),
        "findings": findings,
        "high_risk_count": high_risk,
        "summary": _build_summary(findings, len(malfind_data)),
    }


def analyze_pe_bytes(
    raw_bytes: bytes,
    source_label: str = "unknown",
) -> dict[str, Any]:
    """
    Analyse raw PE bytes (e.g., extracted from memory with procdump).

    Returns a structured report with:
      - PE validity
      - Section analysis (names, sizes, entropy)
      - Suspicious import names found in byte stream
      - Overall risk rating
    """
    findings: list[dict[str, Any]] = []

    # 1. Validate MZ header
    if len(raw_bytes) < 2 or raw_bytes[:2] != b"MZ":
        return {
            "valid_pe": False,
            "source": source_label,
            "findings": [],
            "summary": "Not a valid PE file (missing MZ header).",
        }

    findings.append({
        "type": "pe_header",
        "severity": "LOW",
        "description": f"Valid MZ/PE header detected in {source_label}.",
    })

    # 2. Section analysis if large enough
    try:
        sections = _parse_pe_sections(raw_bytes)
        for sec in sections:
            ent = _entropy_bytes(sec["data"])
            sev = "HIGH" if ent > 7.2 else "MEDIUM" if ent > 6.5 else "LOW"
            findings.append({
                "type": "pe_section",
                "severity": sev,
                "name": sec["name"],
                "entropy": round(ent, 3),
                "size": sec["raw_size"],
                "description": (
                    f"Section '{sec['name']}': size={sec['raw_size']}B, "
                    f"entropy={ent:.3f}/8.0"
                    + (" — HIGH ENTROPY (packed/encrypted)" if ent > 7.0 else "")
                ),
            })
            if sec["name"].strip("\x00").upper() in SUSPICIOUS_SECTIONS:
                findings.append({
                    "type": "suspicious_section",
                    "severity": "HIGH",
                    "name": sec["name"],
                    "description": f"Known packer/obfuscator section name: '{sec['name']}'",
                })
    except Exception as e:
        logger.debug("PE section parse failed: %s", e)

    # 3. String scan for suspicious APIs and patterns
    try:
        text = raw_bytes.decode("latin-1", errors="replace")
        for api, (sev, desc) in SUSPICIOUS_IMPORTS.items():
            if api in text:
                findings.append({
                    "type": "suspicious_import",
                    "severity": sev,
                    "api": api,
                    "description": f"Import '{api}' found — {desc}",
                })
        for pattern, sev, desc in STRING_PATTERNS:
            if re.search(pattern, text):
                findings.append({
                    "type": "string_pattern",
                    "severity": sev,
                    "description": desc,
                })
    except Exception as e:
        logger.debug("String scan failed: %s", e)

    high_risk = sum(1 for f in findings if f["severity"] in ("CRITICAL", "HIGH"))
    overall   = "CRITICAL" if high_risk >= 3 else "HIGH" if high_risk >= 1 else "MEDIUM"

    return {
        "valid_pe": True,
        "source": source_label,
        "findings": findings,
        "high_risk_count": high_risk,
        "overall_risk": overall,
        "summary": _build_summary(findings, 1),
    }


def quick_scan_hex(hex_str: str, label: str = "") -> list[dict[str, Any]]:
    """
    Fast pattern scan of a hex string (e.g., from malfind hex_preview).
    Returns list of hits with severity and description.
    """
    findings = _match_byte_patterns(hex_str, "?", label, "?")
    findings += _detect_pe_header(hex_str, "?", label, "?")
    ent = _calculate_hex_entropy(hex_str)
    if ent and ent > 7.0:
        findings.append({
            "type": "high_entropy",
            "severity": "HIGH",
            "entropy": round(ent, 3),
            "description": f"High entropy ({ent:.3f}/8.0) in hex region '{label}'",
        })
    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_pe_header(
    hex_data: str, pid: str, process: str, address: str
) -> list[dict[str, Any]]:
    findings = []
    clean = hex_data.replace(" ", "").lower()
    if clean.startswith("4d5a"):
        findings.append({
            "type": "pe_in_memory",
            "severity": "HIGH",
            "pid": pid,
            "process": process,
            "address": address,
            "description": (
                f"PE file (MZ header) found at {address} in '{process}' (PID {pid}). "
                "Indicates reflective DLL injection or process hollowing."
            ),
        })
    return findings


def _calculate_hex_entropy(hex_str: str) -> float | None:
    """Calculate Shannon entropy of the bytes represented by a hex string."""
    try:
        clean = hex_str.replace(" ", "").replace("\n", "")
        if len(clean) < 32:
            return None
        raw = bytes.fromhex(clean)
        return _entropy_bytes(raw)
    except (ValueError, TypeError):
        return None


def _entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def _match_byte_patterns(
    hex_data: str, pid: str, process: str, address: str
) -> list[dict[str, Any]]:
    findings = []
    clean = hex_data.replace(" ", "").lower()
    for pattern, (sev, desc) in BYTE_PATTERNS.items():
        if pattern in clean:
            findings.append({
                "type": "byte_pattern",
                "severity": sev,
                "pattern": pattern,
                "pid": pid,
                "process": process,
                "address": address,
                "description": f"{desc} — pattern `{pattern}` at {address} in '{process}' (PID {pid})",
            })
    return findings


def _match_string_patterns(
    text: str, pid: str, process: str, address: str
) -> list[dict[str, Any]]:
    findings = []
    for pattern, sev, desc in STRING_PATTERNS:
        if re.search(pattern, text):
            findings.append({
                "type": "string_pattern",
                "severity": sev,
                "pid": pid,
                "process": process,
                "address": address,
                "description": f"{desc} — found in '{process}' (PID {pid}) at {address}",
            })
    return findings


def _parse_pe_sections(data: bytes) -> list[dict[str, Any]]:
    """Very lightweight PE section table parser."""
    sections = []
    if len(data) < 64:
        return sections
    # e_lfanew at offset 0x3C
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data):
        return sections
    pe_sig = data[e_lfanew:e_lfanew + 4]
    if pe_sig != b"PE\x00\x00":
        return sections
    # Optional header size
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    section_offset = e_lfanew + 24 + opt_size
    for i in range(min(num_sections, 30)):
        off = section_offset + i * 40
        if off + 40 > len(data):
            break
        name      = data[off:off + 8].decode("latin-1", errors="replace")
        raw_size  = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr   = struct.unpack_from("<I", data, off + 20)[0]
        sec_data  = data[raw_ptr:raw_ptr + min(raw_size, 65536)]
        sections.append({"name": name, "raw_size": raw_size, "data": sec_data})
    return sections


def _build_summary(findings: list[dict[str, Any]], regions: int) -> str:
    if not findings:
        return f"No suspicious indicators found across {regions} memory region(s)."
    counts = {}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    parts = [f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[0]))]
    return f"{len(findings)} finding(s) across {regions} region(s): {', '.join(parts)}."
