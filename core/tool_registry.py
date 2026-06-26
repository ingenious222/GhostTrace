"""
core/tool_registry.py
──────────────────────────────────────────────────────────────
Central registry of all tools exposed to the LLM agent.
Each tool is defined with full OpenAI-style JSON Schema so the
LLM can invoke them with correct arguments.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Tool Definitions  (OpenAI function-calling format)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    # ── Memory Acquisition Tools ────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "verify_dump_integrity",
            "description": "Verify memory dump integrity via SHA-256; returns file metadata and hash.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {
                        "type": "string",
                        "description": "Absolute path to the memory dump file (.mem, .raw, .dmp)",
                    },
                    "expected_hash": {
                        "type": "string",
                        "description": "Optional expected SHA-256 hash for integrity comparison",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dump_info",
            "description": "Return metadata about the memory dump: file size, creation time, OS profile hint.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Absolute path to the memory dump"},
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_available_dumps",
            "description": "List memory dump files in a directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory path to search for memory dump files",
                    },
                },
                "required": ["directory"],
            },
        },
    },
    # ── Volatility Plugin Tools ─────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_pslist",
            "description": "Run Volatility pslist: list all running processes (PID, PPID, name, threads, handles, timestamps).",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                    "pid": {
                        "type": "integer",
                        "description": "Optional: filter results for a specific process ID",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_pstree",
            "description": "Run Volatility pstree: hierarchical parent-child process view to detect orphaned or injected processes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_malfind",
            "description": "Run Volatility malfind: detects code injection, shellcode, and RWX memory regions. Primary tool for process injection/hollowing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                    "pid": {
                        "type": "integer",
                        "description": "Optional: limit scan to a specific process ID",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_netscan",
            "description": "Run Volatility netscan: extract active/historical network connections (IP:port, state, protocol, owning PID).",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_dlllist",
            "description": "Run Volatility dlllist: list all DLLs per process; detects reflective injection and suspicious DLL paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                    "pid": {
                        "type": "integer",
                        "description": "Optional: filter to a specific process ID",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cmdline",
            "description": "Run Volatility cmdline: extract full command-line arguments for all processes; flags encoded PowerShell and LOLBAS abuse.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                    "pid": {
                        "type": "integer",
                        "description": "Optional: filter to a specific process ID",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_handles",
            "description": "Run Volatility handles: list open handles (files, registry, mutants) per process; detects privilege escalation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                    "pid": {
                        "type": "integer",
                        "description": "Optional: filter to a specific process ID",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_getsids",
            "description": "Run windows.getsids: get username and group memberships per process; identifies which user account runs each process.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the memory dump file"},
                    "pid": {
                        "type": "integer",
                        "description": "Optional: filter to a specific process ID",
                    },
                },
                "required": ["dump_path"],
            },
        },
    },
    # ── Process Inspection Tools ────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "detect_process_anomalies",
            "description": "Detect orphaned processes, duplicate names, suspicious parent-child relationships, and system process abuse.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pslist_data": {
                        "type": "array",
                        "description": "Process list data returned by run_pslist",
                        "items": {"type": "object"},
                    },
                    "pstree_data": {
                        "type": "array",
                        "description": "Process tree data returned by run_pstree",
                        "items": {"type": "object"},
                    },
                },
                "required": ["pslist_data"],
            },
        },
    },
    # ── Network Inspection Tools ────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "detect_suspicious_connections",
            "description": "Flag suspicious network connections: external IPs, high ports, LISTENING on unusual processes, non-network processes connecting out.",
            "parameters": {
                "type": "object",
                "properties": {
                    "netscan_data": {
                        "type": "array",
                        "description": "Network scan data returned by run_netscan",
                        "items": {"type": "object"},
                    },
                    "pslist_data": {
                        "type": "array",
                        "description": "Process list for cross-referencing PIDs to process names",
                        "items": {"type": "object"},
                    },
                },
                "required": ["netscan_data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cross_reference_connections",
            "description": "Cross-reference network connections with processes to map which process owns each connection.",
            "parameters": {
                "type": "object",
                "properties": {
                    "netscan_data": {"type": "array", "items": {"type": "object"}},
                    "pslist_data": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["netscan_data", "pslist_data"],
            },
        },
    },
    # ── PowerShell Decoder Tools ────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "decode_powershell_commands",
            "description": "Decode and analyse PowerShell cmdline output: -EncodedCommand, IEX cradles, AMSI/ETW bypass, Invoke-Expression.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cmdline_data": {
                        "type": "array",
                        "description": "Command-line data returned by run_cmdline",
                        "items": {"type": "object"},
                    },
                },
                "required": ["cmdline_data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_iocs",
            "description": "Extract IOCs from decoded PowerShell and memory artefacts: URLs, IPs, domains, file paths, registry keys.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decoded_commands": {"type": "array", "items": {"type": "object"}},
                    "netscan_data": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["decoded_commands"],
            },
        },
    },
    # ── Cmdline Behavioral Analysis ─────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "analyze_cmdline_behaviors",
            "description": "Analyze process command lines for malicious behaviors: rundll32 remote DLL (T1218.011), net use WebDAV (T1021.002), encoded PowerShell (T1059.001), LOLBAS proxy execution, and persistence. Returns MITRE ATT&CK tagged findings with extracted artifacts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cmdline_data": {
                        "type": "array",
                        "description": "Command-line data returned by run_cmdline",
                        "items": {"type": "object"},
                    },
                },
                "required": ["cmdline_data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_process_account_from_getsids",
            "description": "Extract username, SID, and group memberships from getsids output; flags admin/SYSTEM processes. Use after run_getsids to identify which user account is running a suspicious process.",
            "parameters": {
                "type": "object",
                "properties": {
                    "getsids_data": {
                        "type": "array",
                        "description": "Output from run_getsids",
                        "items": {"type": "object"},
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Optional: filter to a specific process ID",
                    },
                },
                "required": ["getsids_data"],
            },
        },
    },
    # ── Scoring & Timeline Tools ────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "score_threats",
            "description": "Apply multi-factor threat scoring to all artefacts. Returns score (0-100), level (LOW/MEDIUM/HIGH/CRITICAL), per-category breakdown, and recommendations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "malfind_data": {"type": "array", "items": {"type": "object"}},
                    "process_anomalies": {"type": "array", "items": {"type": "object"}},
                    "network_anomalies": {"type": "array", "items": {"type": "object"}},
                    "powershell_findings": {"type": "array", "items": {"type": "object"}},
                    "dll_anomalies": {"type": "array", "items": {"type": "object"}},
                    "handle_anomalies": {"type": "array", "items": {"type": "object"}},
                    "cmdline_behaviors": {"type": "array", "items": {"type": "object"}},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_attack_timeline",
            "description": "Reconstruct a chronological attack timeline from all memory artefacts, ordered by timestamp with inferred sequence for undated events.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pslist_data": {"type": "array", "items": {"type": "object"}},
                    "malfind_data": {"type": "array", "items": {"type": "object"}},
                    "cmdline_data": {"type": "array", "items": {"type": "object"}},
                    "netscan_data": {"type": "array", "items": {"type": "object"}},
                    "powershell_findings": {"type": "array", "items": {"type": "object"}},
                },
                "required": [],
            },
        },
    },
    # ── Static Analysis Tools ───────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "analyze_malfind_regions",
            "description": (
                "Run deep static analysis on malfind memory regions: "
                "PE header detection, Shannon entropy (packed/encrypted payload), "
                "shellcode byte-pattern matching, YARA-style string scanning, and "
                "RWX protection flagging. Always call this after run_malfind."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "malfind_data": {
                        "type": "array",
                        "description": "Memory region list returned by run_malfind",
                        "items": {"type": "object"},
                    },
                },
                "required": ["malfind_data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "quick_scan_hex",
            "description": (
                "Quickly scan a hex string for known shellcode patterns, PE headers, "
                "and byte-level IOCs. Use to triage a single memory region."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hex_str": {"type": "string", "description": "Hex bytes (space-separated or continuous)"},
                    "label":   {"type": "string", "description": "Label for the region (e.g., 'PID 3200 @ 0x400000')"},
                },
                "required": ["hex_str"],
            },
        },
    },
    # ── Report Generation ───────────────────────────────────────────────────

    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": "Generate forensic report (PDF + HTML + JSON) with full case details, threat score, process/network/injection analysis, timeline, and recommendations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {"type": "string", "description": "Path to the analysed memory dump"},
                    "threat_score": {
                        "type": "object",
                        "description": "Score result from score_threats()",
                    },
                    "timeline": {
                        "type": "array",
                        "description": "Timeline events from build_attack_timeline()",
                        "items": {"type": "object"},
                    },
                    "pslist_data": {"type": "array", "items": {"type": "object"}},
                    "malfind_data": {"type": "array", "items": {"type": "object"}},
                    "netscan_data": {"type": "array", "items": {"type": "object"}},
                    "cmdline_data": {"type": "array", "items": {"type": "object"}},
                    "process_anomalies": {"type": "array", "items": {"type": "object"}},
                    "network_anomalies": {"type": "array", "items": {"type": "object"}},
                    "powershell_findings": {"type": "array", "items": {"type": "object"}},
                    "cmdline_behaviors": {"type": "array", "items": {"type": "object"}},
                    "iocs": {"type": "array", "items": {"type": "object"}},
                    "investigator_notes": {
                        "type": "string",
                        "description": "Optional investigator commentary to include in the report",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory where report files will be saved",
                    },
                },
                "required": ["dump_path", "threat_score"],
            },
        },
    },
]


def get_tools() -> list[dict[str, Any]]:
    """Return all tool definitions for the LLM agent."""
    return TOOL_DEFINITIONS


def get_tool_names() -> list[str]:
    """Return a list of all registered tool names."""
    return [t["function"]["name"] for t in TOOL_DEFINITIONS]
