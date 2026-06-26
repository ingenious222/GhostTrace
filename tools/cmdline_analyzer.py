"""
tools/cmdline_analyzer.py
──────────────────────────────────────────────────────────────
Analyzes process command lines from windows.cmdline output to
detect malicious behaviors, extract artifacts, and map to
MITRE ATT&CK techniques.

Detects (with ATT&CK tagging):
  - Rundll32 executing remote/local DLLs          T1218.011
  - Net.exe mapping WebDAV/SMB shares             T1021.002 / T1021.001
  - VBScript / VBS execution                      T1059.005
  - JScript execution (cscript/wscript/mshta)     T1059.007
  - Suspicious PowerShell execution               T1059.001
  - LOLBAS proxy execution (mshta, regsvr32 etc.) T1218.*
  - InstallUtil / Odbcconf proxy execution        T1218.004 / T1218.008
  - BITSAdmin file download                       T1197
  - Forfiles / Scriptrunner proxy launch          T1216 / T1218
  - Process injection via cmdline patterns         T1055
  - Scheduled task creation                       T1053.005
  - Service manipulation                          T1543.003
  - Registry persistence                          T1547.001

Returns structured findings with:
  - pid, process, cmdline
  - behavior name
  - mitre_technique + mitre_name
  - severity (CRITICAL / HIGH / MEDIUM / LOW)
  - artifacts dict (dll_filename, share_name, remote_server, etc.)
  - description
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Artifact extraction helpers  (referenced by lambdas in _BEHAVIORS)
# ---------------------------------------------------------------------------

def _first_url(s: str) -> str:
    """Extract first http/https URL from a string."""
    m = re.search(r'https?://[^\s\'")\]]+', s)
    return m.group(0) if m else ""

def _first_dll_after(s: str) -> str:
    """Extract first .dll or suspicious .exe argument from a string."""
    m = re.search(r'(\S+\.dll)\b', s, re.IGNORECASE)
    return m.group(1) if m else ""

def _forfiles_cmd(s: str) -> str:
    """Extract the /c argument from a forfiles command line."""
    m = re.search(r'/c\s+"([^"]+)"', s, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r'/c\s+(\S+)', s, re.IGNORECASE)
    return m.group(1) if m else ""

# ---------------------------------------------------------------------------
# MITRE ATT&CK behavior signatures
# ---------------------------------------------------------------------------

# Each entry: (behavior_key, pattern_regex, severity, technique_id, technique_name, description_template)
# description_template may reference captured groups via {artifacts}

_BEHAVIORS: list[dict[str, Any]] = [
    # ── Rundll32 remote DLL execution (T1218.011) ──────────────────────────
    {
        "behavior": "rundll32_remote_dll",
        "technique": "T1218.011",
        "technique_name": "System Binary Proxy Execution: Rundll32",
        "severity": "CRITICAL",
        # matches: rundll32.exe \\server\share\file.dll[,entry]
        # or:      rundll32.exe http://...  or C:\path\suspicious.dll
        "pattern": re.compile(
            r"rundll32(?:\.exe)?\s+"
            r"((?:\\\\[^\s,]+|https?://[^\s,]+|[a-zA-Z]:\\[^\s,]+\.dll)[^,\s]*)"
            r"(?:,\s*([^\s]+))?",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {
            "dll_path": m.group(1).strip(),
            "dll_filename": m.group(1).strip().split("\\")[-1].split("/")[-1],
            "entry_point": (m.group(2) or "").strip(),
            "remote": m.group(1).startswith("\\\\") or m.group(1).startswith("http"),
        },
    },
    # ── Net use / WebDAV share mapping (T1021.002) ─────────────────────────
    {
        "behavior": "net_use_share_mount",
        "technique": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bnet(?:\.exe)?\s+use\b.*?(\\\\([^\s\\:,\"\']+(?::\d+)?)[\\\/]([^\s\\,\"\']+))",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {
            "unc_path": m.group(1).strip(),
            "remote_server": m.group(2).strip() if m.group(2) else "",
            "share_name": m.group(3).strip() if m.group(3) else "",
        },
    },
    # ── WebDAV specifically (davwwwroot pattern) ────────────────────────────
    {
        "behavior": "webdav_share_access",
        "technique": "T1021.002",
        "technique_name": "Remote Services: WebDAV Share Access",
        "severity": "HIGH",
        "pattern": re.compile(r"dav(?:www(?:root)?)?|webdav", re.IGNORECASE),
        "artifact_fn": lambda m: {"share_pattern": m.group(0)},
    },
    # ── Mshta remote execution (T1218.005) ─────────────────────────────────
    {
        "behavior": "mshta_remote_exec",
        "technique": "T1218.005",
        "technique_name": "System Binary Proxy Execution: Mshta",
        "severity": "CRITICAL",
        "pattern": re.compile(r"mshta(?:\.exe)?\s+(https?://[^\s]+|\\\\[^\s]+)", re.IGNORECASE),
        "artifact_fn": lambda m: {"url": m.group(1)},
    },
    # ── Regsvr32 remote execution (T1218.010) ──────────────────────────────
    {
        "behavior": "regsvr32_remote_exec",
        "technique": "T1218.010",
        "technique_name": "System Binary Proxy Execution: Regsvr32",
        "severity": "CRITICAL",
        "pattern": re.compile(r"regsvr32(?:\.exe)?\s+/[si]\s+.*?(https?://[^\s]+|\\\\[^\s]+)", re.IGNORECASE),
        "artifact_fn": lambda m: {"url": m.group(1)},
    },
    # ── PowerShell encoded command (T1059.001) ─────────────────────────────
    {
        "behavior": "powershell_encoded_command",
        "technique": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "severity": "HIGH",
        "pattern": re.compile(r"-[Ee]nc(?:oded[Cc]ommand)?\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE),
        "artifact_fn": lambda m: {"encoded_payload": m.group(1)[:80] + ("…" if len(m.group(1)) > 80 else "")},
    },
    # ── Scheduled task creation (T1053.005) ────────────────────────────────
    {
        "behavior": "scheduled_task_creation",
        "technique": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "severity": "HIGH",
        "pattern": re.compile(r"schtasks(?:\.exe)?\s+/create", re.IGNORECASE),
        "artifact_fn": lambda m: {},
    },
    # ── Service creation (T1543.003) ───────────────────────────────────────
    {
        "behavior": "service_creation",
        "technique": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "severity": "HIGH",
        "pattern": re.compile(r"\bsc(?:\.exe)?\s+create\b|\bsc\s+config\b", re.IGNORECASE),
        "artifact_fn": lambda m: {},
    },
    # ── Registry run key persistence (T1547.001) ───────────────────────────
    {
        "behavior": "registry_run_key",
        "technique": "T1547.001",
        "technique_name": "Boot or Logon Autostart: Registry Run Keys",
        "severity": "HIGH",
        "pattern": re.compile(
            r"reg(?:\.exe)?\s+add.*?(?:CurrentVersion\\Run|CurrentVersion\\RunOnce)",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {},
    },
    # ── Net user account manipulation (T1136.001) ──────────────────────────
    {
        "behavior": "net_user_manipulation",
        "technique": "T1136.001",
        "technique_name": "Create Account: Local Account",
        "severity": "HIGH",
        "pattern": re.compile(r"\bnet(?:\.exe)?\s+(?:user|localgroup)\b", re.IGNORECASE),
        "artifact_fn": lambda m: {},
    },
    # ── Certutil download cradle (T1105) ───────────────────────────────────
    {
        "behavior": "certutil_download",
        "technique": "T1105",
        "technique_name": "Ingress Tool Transfer: certutil",
        "severity": "CRITICAL",
        "pattern": re.compile(r"certutil(?:\.exe)?\s+.*?-(?:url|decode|encode|split)\b", re.IGNORECASE),
        "artifact_fn": lambda m: {},
    },
    # ── WMIC process creation (T1047) ──────────────────────────────────────
    {
        "behavior": "wmic_process_create",
        "technique": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "severity": "HIGH",
        "pattern": re.compile(r"wmic(?:\.exe)?\s+.*?process\s+call\s+create", re.IGNORECASE),
        "artifact_fn": lambda m: {},
    },
    # ── VBScript execution via cscript/wscript (T1059.005) ─────────────────
    {
        "behavior": "vbscript_execution",
        "technique": "T1059.005",
        "technique_name": "Command and Scripting Interpreter: Visual Basic",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:c|w)script(?:\.exe)?\s+.*?\.vb[se]\b"
            r"|mshta(?:\.exe)?\s+vbscript:"
            r"|wscript(?:\.exe)?\s+//e:vbscript",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {"script": m.group(0).split()[-1] if m.group(0) else ""},
    },
    # ── JScript execution via cscript/wscript (T1059.007) ──────────────────
    {
        "behavior": "jscript_execution",
        "technique": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:c|w)script(?:\.exe)?\s+.*?\.js\b"
            r"|mshta(?:\.exe)?\s+javascript:"
            r"|(?:c|w)script(?:\.exe)?\s+//e:(?:jscript|javascript)",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {"script": m.group(0).split()[-1] if m.group(0) else ""},
    },
    # ── CScript/WScript running remote/temp script (generic) (T1059.005) ───
    {
        "behavior": "script_from_temp_or_remote",
        "technique": "T1059.005",
        "technique_name": "Command and Scripting Interpreter: Script from suspicious path",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:c|w)script(?:\.exe)?\s+.*?(?:\\\\[^\s]+|%TEMP%|%APPDATA%|C:\\Users\\[^\\]+\\AppData\\(?:Local|Roaming)\\Temp)[^\s]*\.(?:vb[se]|js|hta|wsf|ps1)\b",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {"script_path": re.search(r'(?:\\\\\S+|%\w+%\S+|C:\\Users\\\S+)', m.group(0), re.IGNORECASE).group(0) if re.search(r'(?:\\\\\S+|%\w+%\S+|C:\\Users\\\S+)', m.group(0), re.IGNORECASE) else ""},
    },
    # ── Mshta HTA execution (T1218.005) ────────────────────────────────────
    {
        "behavior": "mshta_hta_exec",
        "technique": "T1218.005",
        "technique_name": "System Binary Proxy Execution: Mshta (HTA)",
        "severity": "HIGH",
        "pattern": re.compile(
            r"mshta(?:\.exe)?\s+.*?\.hta\b",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {"hta_path": re.search(r'\S+\.hta', m.group(0), re.IGNORECASE).group(0) if re.search(r'\S+\.hta', m.group(0), re.IGNORECASE) else ""},
    },
    # ── BITSAdmin download (T1197) ──────────────────────────────────────────
    {
        "behavior": "bitsadmin_download",
        "technique": "T1197",
        "technique_name": "BITS Jobs: BITSAdmin download",
        "severity": "HIGH",
        "pattern": re.compile(
            r"bitsadmin(?:\.exe)?\s+.*?/(?:transfer|addfile|create)\b",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {"url": _first_url(m.string)},
    },
    # ── InstallUtil proxy execution (T1218.004) ────────────────────────────
    {
        "behavior": "installutil_proxy_exec",
        "technique": "T1218.004",
        "technique_name": "System Binary Proxy Execution: InstallUtil",
        "severity": "CRITICAL",
        "pattern": re.compile(r"installutil(?:\.exe)?\s+.*?\.(?:dll|exe)\b", re.IGNORECASE),
        "artifact_fn": lambda m: {"binary": _first_dll_after(m.group(0))},
    },
    # ── Odbcconf proxy execution (T1218.008) ───────────────────────────────
    {
        "behavior": "odbcconf_proxy_exec",
        "technique": "T1218.008",
        "technique_name": "System Binary Proxy Execution: Odbcconf",
        "severity": "CRITICAL",
        "pattern": re.compile(r"odbcconf(?:\.exe)?\s+.*?regsvr\b", re.IGNORECASE),
        "artifact_fn": lambda m: {},
    },
    # ── Forfiles proxy execution (T1216) ───────────────────────────────────
    {
        "behavior": "forfiles_proxy_exec",
        "technique": "T1216",
        "technique_name": "System Script Proxy Execution: Forfiles",
        "severity": "HIGH",
        "pattern": re.compile(r"forfiles(?:\.exe)?\s+.*?/c\b", re.IGNORECASE),
        "artifact_fn": lambda m: {"command": _forfiles_cmd(m.string)},
    },
    # ── Scriptrunner / SyncAppvPublishingServer proxy (T1216) ──────────────
    {
        "behavior": "scriptrunner_proxy_exec",
        "technique": "T1216",
        "technique_name": "System Script Proxy Execution: Scriptrunner/SyncAppv",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:scriptrunner|syncappvpublishingserver)(?:\.exe)?\s+",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {},
    },
    # ── PowerShell download cradle IEX / DownloadString (T1059.001) ────────
    {
        "behavior": "powershell_download_cradle",
        "technique": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell download cradle",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?:IEX|Invoke-Expression)\s*\(.*?(?:DownloadString|DownloadFile|WebClient)"
            r"|(?:\.)?(?:DownloadString|DownloadFile)\s*\(\s*['\"]https?://",
            re.IGNORECASE,
        ),
        "artifact_fn": lambda m: {"url": _first_url(m.string)},
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_cmdline_behaviors(
    cmdline_data: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Analyze cmdline records from windows.cmdline for malicious behaviors.

    Args:
        cmdline_data: List of dicts with 'pid', 'process', 'cmdline' keys
                      (output of run_cmdline / decode_powershell_commands).

    Returns:
        List of finding dicts, each with:
          pid, process, cmdline, behavior, technique, technique_name,
          severity, artifacts, description
    """
    findings: list[dict[str, Any]] = []

    for entry in cmdline_data:
        pid     = str(entry.get("pid", entry.get("PID", "")))
        process = str(entry.get("process", entry.get("Process", entry.get("ImageFileName", ""))))
        cmdline = str(entry.get("cmdline", entry.get("CommandLine", entry.get("Args", ""))))

        if not cmdline or cmdline in ("-", "N/A", "Required memory at"):
            continue

        for sig in _BEHAVIORS:
            m = sig["pattern"].search(cmdline)
            if not m:
                continue

            try:
                artifacts = sig["artifact_fn"](m)
            except Exception:
                artifacts = {}

            finding = {
                "pid": pid,
                "process": process,
                "cmdline": cmdline[:300],
                "behavior": sig["behavior"],
                "mitre_technique": sig["technique"],
                "mitre_name": sig["technique_name"],
                "severity": sig["severity"],
                "artifacts": artifacts,
                "description": _build_description(process, pid, sig, artifacts),
            }
            findings.append(finding)
            logger.debug(
                "cmdline hit: %s [%s] pid=%s cmdline=%s",
                sig["behavior"], sig["technique"], pid, cmdline[:80],
            )

    logger.info("cmdline_analyzer: %d behavioral findings", len(findings))
    return findings


def extract_process_account_from_getsids(
    getsids_data: list[dict[str, Any]],
    pid: int | str | None = None,
) -> list[dict[str, Any]]:
    """
    Extract username and privilege context from getsids output.
    If pid is given, filters to that specific process.

    Returns records like:
        {pid, process, username, sid, groups, is_admin, is_system}
    """
    results: list[dict[str, Any]] = []
    for entry in getsids_data:
        if pid is not None and str(entry.get("pid", "")) != str(pid):
            continue
        groups = entry.get("groups", [])
        is_admin  = any("admin" in g.lower() for g in groups)
        is_system = any("system" in g.lower() or "S-1-5-18" in g for g in groups) or (
            "S-1-5-18" in entry.get("sid", "")
        )
        results.append({
            "pid":      entry.get("pid", ""),
            "process":  entry.get("process", ""),
            "username": entry.get("username", ""),
            "sid":      entry.get("sid", ""),
            "groups":   groups,
            "is_admin":  is_admin,
            "is_system": is_system,
        })
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_description(
    process: str, pid: str, sig: dict[str, Any], artifacts: dict[str, Any]
) -> str:
    tech = sig["technique"]
    name = sig["technique_name"]
    base = f"[{tech}] {name} — '{process}' (PID {pid})"

    behavior = sig["behavior"]
    if behavior == "rundll32_remote_dll":
        dll = artifacts.get("dll_filename", "unknown.dll")
        remote = artifacts.get("remote", False)
        ep    = artifacts.get("entry_point", "")
        src   = "remote path" if remote else "local path"
        return f"{base}: rundll32 executing '{dll}' via {src}" + (f", entry={ep}" if ep else "")
    if behavior == "net_use_share_mount":
        share = artifacts.get("share_name", "")
        server = artifacts.get("remote_server", "")
        return f"{base}: net use mapping '\\\\{server}\\{share}' — WebDAV/SMB share access"
    if behavior == "webdav_share_access":
        return f"{base}: WebDAV share pattern detected in command line"
    if behavior == "powershell_encoded_command":
        return f"{base}: Base64 -EncodedCommand detected — possible fileless payload"
    if behavior == "scheduled_task_creation":
        return f"{base}: schtasks /create — persistence via scheduled task"
    if behavior == "service_creation":
        return f"{base}: sc create — persistence via Windows service"
    if behavior == "registry_run_key":
        return f"{base}: reg add to Run key — autostart persistence"
    if behavior == "vbscript_execution":
        script = artifacts.get("script", "")
        return f"{base}: VBScript execution" + (f" — '{script}'" if script else "")
    if behavior == "jscript_execution":
        script = artifacts.get("script", "")
        return f"{base}: JScript/JavaScript execution" + (f" — '{script}'" if script else "")
    if behavior == "script_from_temp_or_remote":
        path = artifacts.get("script_path", "")
        return f"{base}: Script launched from suspicious path" + (f" ({path})" if path else "")
    if behavior == "mshta_hta_exec":
        hta = artifacts.get("hta_path", "")
        return f"{base}: mshta executing HTA file" + (f" — '{hta}'" if hta else "")
    if behavior == "bitsadmin_download":
        url = artifacts.get("url", "")
        return f"{base}: BITSAdmin file transfer" + (f" from {url}" if url else "")
    if behavior == "installutil_proxy_exec":
        binary = artifacts.get("binary", "")
        return f"{base}: InstallUtil proxy execution" + (f" — '{binary}'" if binary else "")
    if behavior == "odbcconf_proxy_exec":
        return f"{base}: Odbcconf REGSVR LOLBin proxy execution"
    if behavior == "forfiles_proxy_exec":
        cmd = artifacts.get("command", "")
        return f"{base}: Forfiles LOLBin proxy execution" + (f" /c '{cmd}'" if cmd else "")
    if behavior == "scriptrunner_proxy_exec":
        return f"{base}: Scriptrunner/SyncAppvPublishingServer used as proxy launcher"
    if behavior == "powershell_download_cradle":
        url = artifacts.get("url", "")
        return f"{base}: PowerShell download cradle (IEX/DownloadString)" + (f" — {url}" if url else "")
    return f"{base}: {behavior}"
