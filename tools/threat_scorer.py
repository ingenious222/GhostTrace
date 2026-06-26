"""
tools/threat_scorer.py
──────────────────────────────────────────────────────────────
Custom multi-factor threat scoring model.

Scoring factors (weights sum to 100):
  Malfind injections      →  30 pts
  Encoded PowerShell      →  20 pts
  Orphan/anomalous procs  →  20 pts
  Suspicious network      →  15 pts
  DLL anomalies           →  10 pts
  Handle anomalies        →   5 pts

Score ranges:
  0–30   →  LOW
  31–65  →  MEDIUM
  66–89  →  HIGH
  90–100 →  CRITICAL
"""

from __future__ import annotations

import logging
import os
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default weights (overridden by config.yaml)
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS = {
    "malfind_injections": 25,
    "encoded_powershell":  18,
    "orphan_processes":    18,
    "suspicious_network":  15,
    "lolbas_execution":    14,
    "dll_anomalies":        7,
    "handle_anomalies":     3,
}

THRESHOLDS = {
    "low":      (0,  30),
    "medium":   (31, 65),
    "high":     (66, 89),
    "critical": (90, 100),
}

RECOMMENDATIONS: dict[str, list[str]] = {
    "LOW": [
        "Continue monitoring — no immediate threat detected.",
        "Ensure endpoint protection is up to date.",
        "Review flagged processes for false positives.",
    ],
    "MEDIUM": [
        "Isolate the affected system from the network for further investigation.",
        "Collect and preserve all log files and memory artefacts.",
        "Run a full antivirus and EDR scan on the host.",
        "Investigate flagged processes and network connections manually.",
    ],
    "HIGH": [
        "⚠️  IMMEDIATE CONTAINMENT recommended — isolate the host.",
        "Preserve memory dump with chain-of-custody documentation.",
        "Engage incident response team.",
        "Perform deep-dive forensics on all flagged PIDs.",
        "Review all network connections and block suspicious IPs.",
        "Check for persistence mechanisms (registry, scheduled tasks, services).",
        "Notify stakeholders and begin incident report.",
    ],
    "CRITICAL": [
        "🚨 CRITICAL THREAT — Immediate incident response required.",
        "Isolate the host IMMEDIATELY. Disconnect from network and domain.",
        "Preserve full memory dump and disk image with hashing.",
        "Escalate to security operations centre (SOC) and management.",
        "Evidence of active compromise — treat as full breach.",
        "File forensic incident report with full chain of custody.",
        "Conduct user account audit — check for credential theft.",
        "Review all lateral movement paths from this system.",
    ],
}


def score_threats(
    malfind_data: list[dict[str, Any]] | None = None,
    process_anomalies: list[dict[str, Any]] | None = None,
    network_anomalies: list[dict[str, Any]] | None = None,
    powershell_findings: list[dict[str, Any]] | None = None,
    dll_anomalies: list[dict[str, Any]] | None = None,
    handle_anomalies: list[dict[str, Any]] | None = None,
    cmdline_behaviors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Apply the multi-factor threat scoring model to collected artefacts.

    Returns:
        {
            "score": int,          # 0-100
            "level": str,          # LOW / MEDIUM / HIGH / CRITICAL
            "breakdown": dict,     # per-category scores
            "total_findings": int,
            "recommendations": list[str],
        }
    """
    weights = _load_weights()

    malfind_data       = malfind_data       or []
    process_anomalies  = process_anomalies  or []
    network_anomalies  = network_anomalies  or []
    powershell_findings= powershell_findings or []
    dll_anomalies      = dll_anomalies      or []
    handle_anomalies   = handle_anomalies   or []
    cmdline_behaviors  = cmdline_behaviors  or []

    # ── Category scoring ────────────────────────────────────────────────────

    # Malfind: each injection region contributes, capped at weight
    # 3+ injections = full weight (lower threshold reflects fileless malware severity)
    malfindscore = _scale(len(malfind_data), max_items=3, weight=weights["malfind_injections"])

    # PowerShell: scored by severity of patterns found
    ps_score = _score_ps_findings(powershell_findings, weights["encoded_powershell"])

    # Process anomalies: weighted by severity
    proc_score = _score_by_severity(process_anomalies, weights["orphan_processes"])

    # Network anomalies
    net_score = _score_by_severity(network_anomalies, weights["suspicious_network"])

    # DLL anomalies
    dll_score = _scale(len(dll_anomalies), max_items=10, weight=weights["dll_anomalies"])

    # Handle anomalies
    hdl_score = _scale(len(handle_anomalies), max_items=20, weight=weights["handle_anomalies"])

    # LOLBAS / cmdline behaviors (weighted by severity)
    lolbas_weight = weights.get("lolbas_execution", 14)
    lolbas_score = _score_by_severity(cmdline_behaviors, lolbas_weight)

    total_score = min(100, int(malfindscore + ps_score + proc_score + net_score + dll_score + hdl_score + lolbas_score))
    level = _classify(total_score)

    total_findings = (
        len(malfind_data) + len(process_anomalies) + len(network_anomalies)
        + len(powershell_findings) + len(dll_anomalies) + len(handle_anomalies)
        + len(cmdline_behaviors)
    )

    breakdown = {
        "malfind_injections": {
            "count": len(malfind_data),
            "score": round(malfindscore, 1),
            "max_score": weights["malfind_injections"],
        },
        "encoded_powershell": {
            "count": len(powershell_findings),
            "score": round(ps_score, 1),
            "max_score": weights["encoded_powershell"],
        },
        "process_anomalies": {
            "count": len(process_anomalies),
            "score": round(proc_score, 1),
            "max_score": weights["orphan_processes"],
        },
        "network_anomalies": {
            "count": len(network_anomalies),
            "score": round(net_score, 1),
            "max_score": weights["suspicious_network"],
        },
        "dll_anomalies": {
            "count": len(dll_anomalies),
            "score": round(dll_score, 1),
            "max_score": weights["dll_anomalies"],
        },
        "handle_anomalies": {
            "count": len(handle_anomalies),
            "score": round(hdl_score, 1),
            "max_score": weights["handle_anomalies"],
        },
        "lolbas_execution": {
            "count": len(cmdline_behaviors),
            "score": round(lolbas_score, 1),
            "max_score": lolbas_weight,
        },
    }

    result = {
        "score": total_score,
        "level": level,
        "breakdown": breakdown,
        "total_findings": total_findings,
        "recommendations": RECOMMENDATIONS[level],
    }

    logger.info("Threat score: %d / 100 — %s", total_score, level)
    return result


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _load_weights() -> dict[str, int]:
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("scoring", {}).get("weights", DEFAULT_WEIGHTS)
    except Exception:  # noqa: BLE001
        return DEFAULT_WEIGHTS


def _scale(count: int, max_items: int, weight: int) -> float:
    """Scale a count to a [0, weight] range."""
    if max_items == 0:
        return 0.0
    ratio = min(count / max_items, 1.0)
    return ratio * weight


def _score_by_severity(items: list[dict[str, Any]], weight: int) -> float:
    """Score anomaly list by severity (CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.1)."""
    if not items:
        return 0.0
    severity_map = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1}
    total = sum(severity_map.get(i.get("severity", "LOW"), 0.1) for i in items)
    max_possible = len(items)
    ratio = min(total / max_possible, 1.0) if max_possible > 0 else 0.0
    return ratio * weight


def _score_ps_findings(findings: list[dict[str, Any]], weight: int) -> float:
    """Score PowerShell findings by number and severity of patterns."""
    if not findings:
        return 0.0
    severity_map = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1}
    total_severity = 0.0
    for finding in findings:
        for pattern in finding.get("patterns_found", []):
            total_severity += severity_map.get(pattern.get("severity", "LOW"), 0.1)
    ratio = min(total_severity / (len(findings) * 3), 1.0)  # normalise
    return ratio * weight


def _classify(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 66:
        return "HIGH"
    if score >= 31:
        return "MEDIUM"
    return "LOW"
