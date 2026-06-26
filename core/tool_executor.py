"""
core/tool_executor.py
──────────────────────────────────────────────────────────────
Dispatches tool calls from the LLM to the correct tool module.
All results are returned as JSON-serialisable dicts.
"""

from __future__ import annotations

import json
import logging
import traceback
from typing import Any

from tools.acquisition import get_dump_info, list_available_dumps, verify_dump_integrity
from tools.cmdline_analyzer import analyze_cmdline_behaviors, extract_process_account_from_getsids
from tools.network_inspector import cross_reference_connections, detect_suspicious_connections
from tools.powershell_decoder import decode_powershell_commands, extract_iocs
from tools.process_inspector import detect_process_anomalies
from tools.threat_scorer import score_threats
from tools.timeline_builder import build_attack_timeline
from tools.static_analyzer import analyze_malfind_regions, quick_scan_hex
from tools.volatility_runner import (
    run_cmdline,
    run_dlllist,
    run_getsids,
    run_handles,
    run_malfind,
    run_netscan,
    run_pslist,
    run_pstree,
)
from reporting.report_generator import generate_report

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

# Map tool name → callable
_DISPATCH: dict[str, Any] = {
    # Acquisition
    "verify_dump_integrity": verify_dump_integrity,
    "get_dump_info": get_dump_info,
    "list_available_dumps": list_available_dumps,
    # Volatility plugins
    "run_pslist": run_pslist,
    "run_pstree": run_pstree,
    "run_malfind": run_malfind,
    "run_netscan": run_netscan,
    "run_dlllist": run_dlllist,
    "run_cmdline": run_cmdline,
    "run_handles": run_handles,
    "run_getsids": run_getsids,
    # Process inspection
    "detect_process_anomalies": detect_process_anomalies,
    # Network inspection
    "detect_suspicious_connections": detect_suspicious_connections,
    "cross_reference_connections": cross_reference_connections,
    # PowerShell
    "decode_powershell_commands": decode_powershell_commands,
    "extract_iocs": extract_iocs,
    # Cmdline behavioral analysis
    "analyze_cmdline_behaviors": analyze_cmdline_behaviors,
    "extract_process_account_from_getsids": extract_process_account_from_getsids,
    # Scoring & timeline
    "score_threats": score_threats,
    "build_attack_timeline": build_attack_timeline,
    # Static analysis
    "analyze_malfind_regions": analyze_malfind_regions,
    "quick_scan_hex": quick_scan_hex,
    # Reporting
    "generate_report": generate_report,
}


def execute_tool(tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a named tool with the provided arguments.

    Returns a JSON-serialisable dict with:
        {"status": "ok", "result": <data>}        on success
        {"status": "error", "error": <message>}   on failure
    """
    if tool_name not in _DISPATCH:
        logger.error("Unknown tool requested: %s", tool_name)
        return {
            "status": "error",
            "error": f"Unknown tool '{tool_name}'. Available tools: {list(_DISPATCH.keys())}",
        }

    logger.info("⚙️  Executing tool: %s | args: %s", tool_name, json.dumps(tool_args, default=str))

    try:
        fn = _DISPATCH[tool_name]
        result = fn(**tool_args)
        logger.info("✅ Tool '%s' completed successfully.", tool_name)
        return {"status": "ok", "result": result}
    except TypeError as exc:
        msg = f"Invalid arguments for tool '{tool_name}': {exc}"
        logger.error(msg)
        return {"status": "error", "error": msg}
    except Exception as exc:  # noqa: BLE001
        msg = f"Tool '{tool_name}' raised an exception: {exc}"
        logger.error("%s\n%s", msg, traceback.format_exc())
        return {"status": "error", "error": msg, "traceback": traceback.format_exc()}


def execute_tool_call(tool_call: Any) -> str:
    """
    Accept an OpenAI ToolCall object (or dict), execute the tool,
    and return the result as a JSON string (to add back to messages).
    """
    if hasattr(tool_call, "function"):
        # OpenAI SDK object
        tool_name = tool_call.function.name
        try:
            tool_args = json.loads(tool_call.function.arguments)
        except json.JSONDecodeError as exc:
            return json.dumps({"status": "error", "error": f"Could not parse tool arguments: {exc}"})
    else:
        # Dict-style (from mock/Ollama)
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("arguments", {})
        if isinstance(tool_args, str):
            try:
                tool_args = json.loads(tool_args)
            except json.JSONDecodeError:
                tool_args = {}

    result = execute_tool(tool_name, tool_args)
    return json.dumps(result, default=str, indent=2)
