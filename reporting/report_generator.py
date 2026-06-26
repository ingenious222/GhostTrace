"""
reporting/report_generator.py
──────────────────────────────────────────────────────────────
Generates structured forensic reports in HTML, JSON, and PDF.
PDF is mandatory and generated via WeasyPrint.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
from datetime import datetime
from typing import Any

from jinja2 import Environment, FileSystemLoader

from reporting.ai_analyzer import generate_ai_analysis  # noqa: F401  (re-exported)
from reporting.pdf_exporter import export_pdf

logger = logging.getLogger(__name__)

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"


def generate_report(
    dump_path: str,
    threat_score: dict[str, Any],
    timeline: list[dict[str, Any]] | None = None,
    pslist_data: list[dict[str, Any]] | None = None,
    malfind_data: list[dict[str, Any]] | None = None,
    netscan_data: list[dict[str, Any]] | None = None,
    cmdline_data: list[dict[str, Any]] | None = None,
    process_anomalies: list[dict[str, Any]] | None = None,
    network_anomalies: list[dict[str, Any]] | None = None,
    powershell_findings: list[dict[str, Any]] | None = None,
    cmdline_behaviors: list[dict[str, Any]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    investigator_notes: str | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """
    Generate PDF, HTML, and JSON forensic reports.
    Returns paths to all generated files.
    """
    out_dir = pathlib.Path(output_dir or os.getenv("REPORT_OUTPUT_DIR", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build report context
    timestamp = datetime.now()
    dump_name = pathlib.Path(dump_path).name if dump_path else "unknown.mem"
    case_id = f"MFA-{timestamp.strftime('%Y%m%d-%H%M%S')}"

    context: dict[str, Any] = {
        "case_id": case_id,
        "dump_path": dump_path,
        "dump_name": dump_name,
        "generated_at": timestamp.strftime("%d %B %Y  %H:%M:%S") + " PKT (UTC+5)",
        "generated_iso": timestamp.isoformat(),
        "threat_score": threat_score,
        "score_value": threat_score.get("score", 0),
        "score_level": threat_score.get("level", "UNKNOWN"),
        "breakdown": threat_score.get("breakdown", {}),
        "recommendations": threat_score.get("recommendations", []),
        "timeline": (timeline.get("timeline", []) if isinstance(timeline, dict) else timeline) or [],
        "pslist": pslist_data or [],
        "malfind": malfind_data or [],
        "netscan": netscan_data or [],
        "cmdline": cmdline_data or [],
        "process_anomalies": process_anomalies or [],
        "network_anomalies": network_anomalies or [],
        "powershell_findings": powershell_findings or [],
        "cmdline_behaviors": cmdline_behaviors or [],
        "iocs": iocs or [],
        "investigator_notes": investigator_notes or "",
        "total_findings": threat_score.get("total_findings", 0),
        "ai_analysis": "",           # populated below
        # Court-report fields — safe defaults (overwritten below)
        "evidence_sha256": "",
        "evidence_md5": "",
        "legal_sections": [],
        "severity_word": "UNKNOWN",
        # Severity CSS classes
        "level_class": {
            "LOW": "level-low",
            "MEDIUM": "level-medium",
            "HIGH": "level-high",
            "CRITICAL": "level-critical",
        }.get(threat_score.get("level", ""), "level-low"),
        "level_emoji": {
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🔴",
            "CRITICAL": "💀",
        }.get(threat_score.get("level", ""), "⚪"),
    }

    # ── Evidence integrity hashes ─────────────────────────────────────────────
    _raw_bytes = json.dumps({
        "process_anomalies": process_anomalies or [],
        "malfind": malfind_data or [],
        "network_anomalies": network_anomalies or [],
        "powershell_findings": powershell_findings or [],
        "threat_score": threat_score,
    }, sort_keys=True, default=str).encode()
    context["evidence_sha256"] = hashlib.sha256(_raw_bytes).hexdigest()
    context["evidence_md5"]    = hashlib.md5(_raw_bytes).hexdigest()

    # ── PECA / PPC legal section mapping ─────────────────────────────────────
    _legal: list[dict] = []
    if malfind_data:
        _legal += [
            {"section": "PECA 2016 – Section 5",
             "title": "Interference with Information System or Data",
             "nexus": "Memory injection into running processes constitutes unauthorised interference with an information system"},
            {"section": "PECA 2016 – Section 3",
             "title": "Unauthorised Access to Information System",
             "nexus": "Injected code accessed protected process memory spaces without authorisation"},
        ]
    if network_anomalies:
        _legal += [
            {"section": "PECA 2016 – Section 23",
             "title": "Unauthorised Interception",
             "nexus": "Suspicious outbound connections indicate unauthorised data interception or exfiltration"},
            {"section": "PECA 2016 – Section 20",
             "title": "Electronic Fraud",
             "nexus": "C2-style connections may indicate fraudulent remote control of victim system"},
        ]
    if powershell_findings:
        _legal += [
            {"section": "PECA 2016 – Section 18",
             "title": "Malicious Code",
             "nexus": "Obfuscated or encoded PowerShell constitutes malicious code under the Prevention of Electronic Crimes Act 2016"},
            {"section": "PECA 2016 – Section 4",
             "title": "Unauthorised Copying or Transmission of Data",
             "nexus": "Download cradles and encoded commands facilitate unauthorised transmission of data"},
        ]
    if process_anomalies:
        _legal += [
            {"section": "PECA 2016 – Section 6",
             "title": "Unauthorised Access to Critical Infrastructure Information System",
             "nexus": "Anomalous processes may have accessed critical system components without authorisation"},
            {"section": "PPC – Section 419",
             "title": "Cheating by Personation (Pakistan Penal Code)",
             "nexus": "Process masquerading (MITRE T1036) constitutes personation under the Pakistan Penal Code"},
        ]
    _score = threat_score.get("score", 0)
    if _score >= 60:
        _legal += [
            {"section": "PECA 2016 – Section 19",
             "title": "Cyber Terrorism",
             "nexus": f"Threat score {_score}/100 indicates coordinated attack consistent with cyber terrorism as defined under PECA 2016"},
            {"section": "Investigation for Fair Trial Act 2013 – Section 27",
             "title": "Interception of Communications",
             "nexus": "Warrant-based interception evidence collected under this Act is admissible in court"},
        ]
    _legal += [
        {"section": "Electronic Transactions Ordinance 2002 – Section 36",
         "title": "Offences – ETO 2002",
         "nexus": "Digital evidence collected per ETO 2002 standards is admissible in any court or tribunal in Pakistan"},
        {"section": "PECA 2016 – Section 29",
         "title": "Production of Data",
         "nexus": "Law enforcement may compel production of this forensic report and underlying data under Section 29"},
        {"section": "Qanoon-e-Shahadat Order 1984 – Article 164",
         "title": "Admissibility of Electronic Records",
         "nexus": "This forensic report and its digital evidence are admissible as electronic records under Article 164"},
    ]
    # deduplicate by section
    _seen: set = set()
    _unique_legal: list[dict] = []
    for l in _legal:
        if l["section"] not in _seen:
            _seen.add(l["section"])
            _unique_legal.append(l)
    context["legal_sections"] = _unique_legal

    # ── Severity word ─────────────────────────────────────────────────────────
    context["severity_word"] = (
        "CRITICAL — IMMEDIATE ACTION REQUIRED" if _score >= 80 else
        "HIGH — URGENT INVESTIGATION REQUIRED" if _score >= 60 else
        "MEDIUM — INVESTIGATION REQUIRED"       if _score >= 40 else
        "LOW — MONITOR AND REVIEW"
    )

    # ── AI Narrative Analysis ─────────────────────────────────────────────────
    logger.info("Generating AI analysis narrative…")
    context["ai_analysis"] = generate_ai_analysis(context)

    # ── Generate HTML ────────────────────────────────────────────────────────
    html_content = _render_html(context)
    html_path = out_dir / f"{case_id}_report.html"
    html_path.write_text(html_content, encoding="utf-8")
    logger.info("HTML report saved: %s", html_path)

    # ── Generate JSON ────────────────────────────────────────────────────────
    json_path = out_dir / f"{case_id}_report.json"
    json_path.write_text(
        json.dumps(context, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("JSON report saved: %s", json_path)

    # ── Generate PDF (mandatory) ─────────────────────────────────────────────
    pdf_path = out_dir / f"{case_id}_report.pdf"
    pdf_result = export_pdf(str(html_path), str(pdf_path), context=context)
    if pdf_result["status"] == "ok":
        logger.info("PDF report saved: %s", pdf_path)
    else:
        logger.error("PDF generation failed: %s", pdf_result.get("error"))

    return {
        "status": "ok",
        "case_id": case_id,
        "output_dir": str(out_dir.resolve()),
        "html": str(html_path.resolve()),
        "json": str(json_path.resolve()),
        "pdf": str(pdf_path.resolve()) if pdf_result["status"] == "ok" else None,
        "pdf_error": pdf_result.get("error"),
        "generated_at": context["generated_at"],
        "threat_level": context["score_level"],
        "score": context["score_value"],
    }


def _render_html(context: dict[str, Any]) -> str:
    """Render the Jinja2 HTML report template."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    # Custom filters
    env.filters["score_bar"] = lambda v: min(int(v), 100)
    env.filters["truncate_cmd"] = lambda s, n=120: (s[:n] + "…") if len(s) > n else s

    template = env.get_template("report.html")
    return template.render(**context)
