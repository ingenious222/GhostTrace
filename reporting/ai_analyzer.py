"""
reporting/ai_analyzer.py
──────────────────────────────────────────────────────────────
AI-powered forensic narrative generator.
Builds a compact prompt from report context and calls the
configured LLM once (via OpenRouter, OpenAI, or Ollama) to
produce a full incident narrative.
"""

from __future__ import annotations

import logging
import os
import pathlib
from typing import Any

logger = logging.getLogger(__name__)

# Max tokens for the narrative — 1 200 is enough for a rich ~600-word report
_MAX_TOKENS = int(os.getenv("AI_REPORT_MAX_TOKENS", "1200"))

_SYSTEM = (
    "You are a senior memory forensics analyst. "
    "Write a concise, evidence-cited incident narrative in professional forensic language. "
    "Use ## headings. Cite real PIDs, addresses, IPs, and timestamps from the data. No filler."
)


def _load_env() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
        env = pathlib.Path(__file__).parent.parent / ".env"
        if env.exists():
            load_dotenv(str(env), override=False)
    except ImportError:
        pass


def _fmt_list(items: list[str]) -> str:
    return "\n".join(items) if items else "  (none)"


def generate_ai_analysis(context: dict[str, Any]) -> str:
    """
    Generate a unified forensic narrative for the given report context.

    Sections produced:
    - Overview & Malware Identification
    - Infection Vector & Execution Chain
    - Memory Injection Evidence
    - C2 / Network Activity
    - Timeline Narrative
    - Risk Assessment

    Returns the narrative string, or an error placeholder on failure.
    """
    _load_env()

    # ── Pull context keys ────────────────────────────────────────────────
    score_val   = context.get("score_value", 0)
    score_level = context.get("score_level", "UNKNOWN")
    dump_name   = context.get("dump_name", "unknown.mem")
    case_id     = context.get("case_id", "?")
    proc_anom   = context.get("process_anomalies", [])
    malfind     = context.get("malfind", [])
    netscan     = context.get("netscan", [])
    timeline    = context.get("timeline", [])
    iocs        = context.get("iocs", [])
    ps_finds    = context.get("powershell_findings", [])
    net_anom    = context.get("network_anomalies", [])

    # ── Compact data summaries ───────────────────────────────────────────
    procs = _fmt_list([
        f"  {a.get('process','?')} PID {a.get('pid','?')} [{a.get('severity','?')}]: {str(a.get('description',''))[:100]}"
        for a in proc_anom[:6]
    ])
    injections = _fmt_list([
        f"  PID {m.get('pid','?')} {m.get('process','?')} @ {m.get('address','?')}"
        f" prot={m.get('protection','?')} hex={str(m.get('hex_preview',''))[:16]}"
        for m in malfind[:5]
    ])
    conns = _fmt_list([
        f"  {n.get('Proto','?')} {n.get('ForeignAddr','?')}:{n.get('ForeignPort','?')}"
        f" [{n.get('State','?')}] owner={n.get('Owner','?')}"
        for n in netscan
        if n.get("State", "") not in ("LISTENING", "")
    ][:6])
    ioc_list = _fmt_list([
        f"  [{i.get('type','?')}] {i.get('value','?')}"
        for i in iocs[:6]
    ])
    ps_list = _fmt_list([
        f"  PID {f.get('pid','?')} {f.get('process','?')}: {[p.get('name') for p in f.get('patterns_found',[])[:3]]}"
        for f in ps_finds[:3]
    ])
    tl_list = _fmt_list([
        f"  Step {e.get('step','')} [{e.get('severity','?')}] {e.get('event_type','?')}"
        f" @ {e.get('timestamp','')} — {str(e.get('description',''))[:90]}"
        for e in timeline[:12]
    ])
    net_anom_list = _fmt_list([
        f"  [{a.get('severity','?')}] {a.get('category','?')}: {str(a.get('description',''))[:80]}"
        for a in net_anom[:4]
    ])

    prompt = f"""FORENSIC CASE: {case_id} | Dump: {dump_name} | Score: {score_val}/100 ({score_level})

PROCESS ANOMALIES ({len(proc_anom)}):
{procs}

MALFIND INJECTIONS ({len(malfind)}):
{injections}

NETWORK CONNECTIONS (non-listening, {len(netscan)} total):
{conns}

NETWORK ANOMALIES ({len(net_anom)}):
{net_anom_list}

POWERSHELL ({len(ps_finds)}):
{ps_list}

IOCs ({len(iocs)}):
{ioc_list}

ATTACK TIMELINE ({len(timeline)} events):
{tl_list}

Write the forensic narrative with these sections:
## Overview & Malware Identification
## Infection Vector & Execution Chain
## Memory Injection Technique
## C2 Communication & Network Activity
## Timeline Narrative (walk through each timeline step in plain English)
## Risk Assessment & Impact

Max 700 words. Cite specific PIDs, addresses, IPs, and timestamps. Be concise."""

    try:
        from core.agent import _get_client, _get_model  # type: ignore
        client = _get_client()
        model  = _get_model()
        resp = client.chat.completions.create(
            model=model,
            temperature=0.15,
            max_tokens=_MAX_TOKENS,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": prompt},
            ],
        )
        text = (resp.choices[0].message.content or "").strip()
        logger.info("AI analysis generated: %d chars", len(text))
        return text
    except ImportError:
        logger.warning("AI analysis: cannot import agent — skipping")
        return ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI analysis failed: %s", exc)
        return f"[AI analysis unavailable: {exc}]"
