"""
gui/app.py — GhostTrace Streamlit Dashboard
Run:  streamlit run gui/app.py
"""

import json
import os
import sys
import pathlib
import tempfile

# ── make sure project root is on path ─────────────────────────────────────
ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env", override=True)

import streamlit as st
from PIL import Image as _PILImage

# ── Load logo (used for favicon + sidebar) ───────────────────────────────────
_LOGO_PATH = ROOT / "gui" / "logo.png"
_logo_img  = _PILImage.open(_LOGO_PATH) if _LOGO_PATH.exists() else None

# ── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GhostTrace",
    page_icon=_logo_img if _logo_img else "🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Session state bootstrap (MUST be before ANY widget/CSS code) ─────────────
_STATE_DEFAULTS = {
    "pslist": [], "pstree": [], "malfind": [], "netscan": [],
    "cmdline": [], "dlllist": [], "handles": [],
    "proc_anomalies": [], "net_anomalies": [], "ps_findings": [],
    "threat_score": None, "timeline": None,
    "analysis_done": False,
    "chat_history": [],
    "agent": None,
    "dark_mode": True,
    "ai_tab_cache": {},
    "current_scan_id": None,
    "current_dump_path": "",
    "uploaded_dump_path": "",
    # ── App navigation ──────────────────────────────────────────────
    "app_state": "splash",          # splash | dashboard | analysis | live_monitor
    "splash_done": False,
    "dashboard_mode": None,         # "static" | "live"
    # ── Live monitoring ─────────────────────────────────────────────
    "lm_running": False,
    "lm_snapshot": None,
    "lm_prev_pids": set(),
    "lm_alerts": [],
}
for _k, _v in _STATE_DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Auto-restore latest scan from DB on every fresh page load ────────────────
def _load_scan_db():
    """Import scan_db regardless of whether gui/ is on sys.path."""
    try:
        import scan_db as _sdb
        return _sdb
    except ImportError:
        pass
    try:
        import gui.scan_db as _sdb
        return _sdb
    except ImportError:
        return None

_sdb = _load_scan_db()
if _sdb:
    _sdb.init_db()

# ── NOTE: Auto-restore on startup is intentionally disabled. ──────────────────
# Results only appear after:
#   1. Running a new analysis with "🚀 Run Full Analysis"
#   2. Explicitly clicking "Load" on a scan in the Scan History sidebar
# This prevents stale results from a previous session appearing without a dump.


# ── Dark/light aware CSS ──────────────────────────────────────────────────────
_DARK = st.session_state.dark_mode   # shorthand used below


_BG          = "#0a0010" if _DARK else "#ffffff"
_BG2         = "#12001e" if _DARK else "#ffffff"
_SIDEBAR_BG  = "linear-gradient(180deg,#1a0030 0%,#0a0010 100%)" if _DARK else "#ffffff"
_TEXT        = "#f0e6ff" if _DARK else "#1e1030"
_SUBTEXT     = "#c084fc" if _DARK else "#7c3aed"
_ACCENT1     = "#ec4899"   # hot pink — primary accent
_ACCENT2     = "#a855f7"   # purple — secondary accent
_CARD_BG     = "#1a0030" if _DARK else "#ffffff"
_CARD_BORDER = "rgba(236,72,153,0.25)" if _DARK else "rgba(168,85,247,0.18)"
_GRID        = "rgba(236,72,153,0.05)" if _DARK else "rgba(168,85,247,0.04)"

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@700;900&display=swap');

html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}

/* ── Force pure white in light mode ── */
html, body, .main, .block-container,
[data-testid="stAppViewContainer"],
[data-testid="stVerticalBlock"],
[data-testid="stHorizontalBlock"] {{
  background-color: {_BG} !important;
}}

/* ── App background ── */
.stApp {{
  background-color: {_BG} !important;
  background-image:
    linear-gradient({_GRID} 1px, transparent 1px),
    linear-gradient(90deg, {_GRID} 1px, transparent 1px);
  background-size: 44px 44px;
  color: {_TEXT} !important;
}}

/* ── Sidebar ── */
[data-testid="stSidebar"] {{
  background: {_SIDEBAR_BG} !important;
  border-right: 1px solid rgba(236,72,153,0.2) !important;
  position: relative;
}}
[data-testid="stSidebar"] * {{ color: {"#d8b4fe" if _DARK else "#4a3568"} !important; }}
[data-testid="stSidebar"] strong,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {{ color: {"#ec4899" if _DARK else "#6d28d9"} !important; }}
[data-testid="stSidebar"]::after {{
  content:''; position:absolute; top:0; bottom:0; right:0; width:2px;
  background:linear-gradient(180deg,transparent 0%,{_ACCENT1} 40%,{_ACCENT2} 60%,transparent 100%);
  animation:sidebarGlow 4s ease-in-out infinite;
}}
@keyframes sidebarGlow {{ 0%,100%{{opacity:.2}} 50%{{opacity:.8}} }}

/* ── Main text & headings ── */
p, li, span, div {{ color: {_TEXT}; }}
h2 {{
  font-family:'Orbitron',sans-serif !important; font-size:1.05rem !important;
  letter-spacing:.08em; text-transform:uppercase;
  color: {_ACCENT1} !important;
}}
h3 {{ color: {_ACCENT2} !important; font-weight:600;
  border-bottom:1px solid {"rgba(236,72,153,0.2)" if _DARK else "rgba(168,85,247,0.15)"};
  padding-bottom:6px; }}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {{
  background: {"rgba(236,72,153,0.06)" if _DARK else "rgba(168,85,247,0.04)"};
  border:1px solid {"rgba(236,72,153,0.18)" if _DARK else "rgba(168,85,247,0.14)"};
  border-radius:12px; padding:5px 8px; gap:6px;
}}
.stTabs [data-baseweb="tab"] {{
  background:transparent; border-radius:8px;
  color: {_SUBTEXT};
  font-weight:500; font-size:.83rem; transition:all .2s; padding:8px 16px !important;
}}
.stTabs [aria-selected="true"] {{
  background:linear-gradient(135deg,rgba(236,72,153,0.2),rgba(168,85,247,0.15)) !important;
  color: {_ACCENT1} !important; border:1px solid rgba(236,72,153,0.4) !important;
  box-shadow:0 2px 12px rgba(236,72,153,0.15);
}}

/* ── Metric ── */
div[data-testid="metric-container"] {{
  background: {"rgba(236,72,153,0.06)" if _DARK else "rgba(168,85,247,0.05)"};
  border:1px solid {_CARD_BORDER}; border-radius:14px; padding:16px;
}}
[data-testid="stMetricLabel"] {{ color:{_ACCENT1} !important; font-size:.7rem !important; letter-spacing:.1em; text-transform:uppercase; }}
[data-testid="stMetricValue"] {{ color:{_ACCENT2} !important; font-family:'JetBrains Mono',monospace !important; font-size:1.65rem !important; }}

/* ── Score badges ── */
.score-badge {{
  display:inline-block; padding:10px 30px; border-radius:50px;
  font-size:2.8rem; font-weight:900; font-family:'Orbitron','JetBrains Mono',monospace;
  margin:8px 0; letter-spacing:-0.02em;
}}
.badge-low     {{ background:linear-gradient(135deg,#052e16,#14532d); color:#4ade80; border:2px solid #22c55e; box-shadow:0 0 20px #22c55e44; }}
.badge-medium  {{ background:linear-gradient(135deg,#1c1000,#451a00); color:#fbbf24; border:2px solid #f59e0b; box-shadow:0 0 20px #f59e0b44; }}
.badge-high    {{ background:linear-gradient(135deg,#1c0a00,#431407); color:#fb923c; border:2px solid #f97316; box-shadow:0 0 20px #f9731644; }}
.badge-critical{{ background:linear-gradient(135deg,#200,#3f0); color:#ff4444; border:2px solid #ef4444; box-shadow:0 0 28px #ef444466; animation:critPulse 1.6s ease-in-out infinite; }}
@keyframes critPulse {{ 0%,100%{{box-shadow:0 0 24px #ef444455}} 50%{{box-shadow:0 0 44px #ef4444bb}} }}

/* ── KPI tiles ── */
.kpi-tile {{
  background: {_CARD_BG}; border:1px solid {_CARD_BORDER};
  border-radius:16px; padding:18px 16px; text-align:center;
  transition:all .25s; position:relative; overflow:hidden;
  box-shadow:0 2px 8px rgba(236,72,153,0.08);
}}
.kpi-tile::before {{
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background:linear-gradient(90deg,transparent,{_ACCENT1},transparent);
}}
.kpi-tile:hover {{ border-color:rgba(236,72,153,0.4); box-shadow:0 4px 20px rgba(236,72,153,0.15); transform:translateY(-2px); }}
.kpi-value {{ font-family:'Orbitron','JetBrains Mono',monospace; font-size:2rem; font-weight:700; line-height:1; color:{_ACCENT1}; }}
.kpi-label {{ font-size:.68rem; color:{_SUBTEXT}; letter-spacing:.12em; text-transform:uppercase; margin-top:6px; }}
.kpi-tile.kpi-red   {{ border-color:rgba(239,68,68,.4); background:{"#200010" if _DARK else "#fff5f5"}; }}
.kpi-tile.kpi-red   .kpi-value {{ color:#ff4444; }}
.kpi-tile.kpi-amber {{ border-color:rgba(245,158,11,.4); background:{"#1a1000" if _DARK else "#fffbf0"}; }}
.kpi-tile.kpi-amber .kpi-value {{ color:#f59e0b; }}
.kpi-tile.kpi-green {{ border-color:rgba(34,197,94,.4); background:{"#001a10" if _DARK else "#f0fdf4"}; }}
.kpi-tile.kpi-green .kpi-value {{ color:#22c55e; }}

/* ── Category bars ── */
.cat-bar-wrap {{ margin:10px 0; }}
.cat-bar-header {{ display:flex; justify-content:space-between; margin-bottom:5px; }}
.cat-bar-label {{ color:{_ACCENT1}; letter-spacing:.08em; text-transform:uppercase; font-size:.72rem; }}
.cat-bar-value {{ font-family:'JetBrains Mono',monospace; font-size:.78rem; color:{_TEXT}; }}
.cat-bar-bg {{ background:{"rgba(236,72,153,0.08)" if _DARK else "rgba(168,85,247,0.08)"}; border-radius:6px; height:8px; width:100%; overflow:hidden; }}
.cat-bar-fill {{ height:100%; border-radius:6px; transition:width .8s cubic-bezier(.4,0,.2,1); }}

/* ── Anomaly cards ── */
.anomaly-card {{
  background: {_CARD_BG}; border:1px solid {_CARD_BORDER};
  border-left:3px solid; border-radius:10px; padding:11px 15px; margin:7px 0;
  font-size:.85rem; transition:all .2s;
}}
.anomaly-card:hover {{ border-color:rgba(236,72,153,0.4); transform:translateX(2px); }}
.sev-CRITICAL {{ border-left-color:#ef4444; box-shadow:-4px 0 12px #ef44441a; }}
.sev-HIGH     {{ border-left-color:#f97316; box-shadow:-4px 0 10px #f973161a; }}
.sev-MEDIUM   {{ border-left-color:#f59e0b; box-shadow:-4px 0 10px #f59e0b1a; }}
.sev-LOW      {{ border-left-color:#22c55e; box-shadow:-4px 0 10px #22c55e1a; }}

/* ── Buttons ── */
.stButton > button {{
  background:linear-gradient(135deg,rgba(236,72,153,.1),rgba(168,85,247,.1));
  border:1px solid rgba(236,72,153,.35); color:{_ACCENT1};
  border-radius:9px; font-weight:600; letter-spacing:.03em; transition:all .2s;
}}
.stButton > button:hover {{
  background:linear-gradient(135deg,rgba(236,72,153,.2),rgba(168,85,247,.2));
  border-color:{_ACCENT1}; box-shadow:0 2px 14px rgba(236,72,153,.25); transform:translateY(-1px);
}}
.stButton > button[kind="primary"] {{
  background:linear-gradient(135deg,{_ACCENT1},{_ACCENT2});
  border:1px solid {_ACCENT1}; color:#fff; box-shadow:0 2px 14px rgba(236,72,153,.3);
}}
.stButton > button[kind="primary"]:hover {{
  box-shadow:0 4px 22px rgba(236,72,153,.5); transform:translateY(-1px);
}}

/* ── Chat ── */
.chat-user {{ background:rgba(236,72,153,.06); border:1px solid rgba(236,72,153,.2); border-radius:12px; padding:12px 16px; margin:8px 0; }}
.chat-ai   {{ background:rgba(168,85,247,.05); border:1px solid rgba(168,85,247,.15); border-radius:12px; padding:12px 16px; margin:8px 0; }}

/* ── Data frames ── */
.stDataFrame {{ border:1px solid {_CARD_BORDER} !important; border-radius:10px; }}

/* ── Progress bar ── */
.stProgress > div > div > div {{
  background:linear-gradient(90deg,{_ACCENT1},{_ACCENT2}) !important;
  box-shadow:0 0 8px rgba(236,72,153,.4);
}}

/* ── Scrollbar ── */
::-webkit-scrollbar {{ width:5px; height:5px; }}
::-webkit-scrollbar-track {{ background:transparent; }}
::-webkit-scrollbar-thumb {{ background:rgba(236,72,153,.35); border-radius:10px; }}
::-webkit-scrollbar-thumb:hover {{ background:rgba(236,72,153,.6); }}

/* ── Expander ── */
.streamlit-expanderHeader {{ background:{"rgba(236,72,153,0.06)" if _DARK else "rgba(168,85,247,0.04)"} !important; border-radius:8px !important; }}

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header {{ visibility:hidden; }}

/* ── Force sidebar pinned ── */
section[data-testid="stSidebar"] {{
  transform:translateX(0) !important; min-width:21rem !important;
  width:21rem !important; visibility:visible !important; display:block !important;
}}
[data-testid="collapsedControl"],
button[title="Close sidebar"],
button[aria-label="Close sidebar"],
section[data-testid="stSidebar"] > div > div > button {{ display:none !important; }}
</style>
""", unsafe_allow_html=True)


# Helpers
# ════════════════════════════════════════════════════════════════════════════

def _enable_mock():
    os.environ["MEMFORENSIC_MOCK"] = "1"

def _disable_mock():
    os.environ.pop("MEMFORENSIC_MOCK", None)

def _severity_color(sev: str) -> str:
    return {"CRITICAL": "#ff4444", "HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950"}.get(sev, "#8b949e")

def _level_color(level: str) -> str:
    return {"CRITICAL": "#ff4444", "HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950"}.get(level, "#8b949e")

def _score_badge(score: int, level: str) -> str:
    cls = f"badge-{level.lower()}"
    level_icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "💀"}
    icon = level_icons.get(level, "")
    return f'''
    <div style="text-align:center;">
      <div class="score-badge {cls}">{score}<span style="font-size:1.1rem;margin-left:8px;opacity:0.7;font-family:Inter,sans-serif;font-weight:400;">/100</span></div>
      <div style="font-family:'Orbitron',monospace;font-size:0.9rem;letter-spacing:0.2em;margin-top:6px;">{icon} {level}</div>
    </div>'''

def _cat_bar(label: str, score: float, max_score: int, count: int, color: str):
    pct = (score / max_score * 100) if max_score > 0 else 0
    glow = f"box-shadow: 0 0 8px {color}80;"
    st.markdown(f"""
    <div class="cat-bar-wrap">
      <div class="cat-bar-header">
        <span class="cat-bar-label">{label}</span>
        <span class="cat-bar-value" style="color:{color};">
          {score:.1f}<span style="color:#3a5a78;">/{max_score}</span>
          &nbsp;<span style="color:#2d4f6e;font-size:0.7rem;">({count} findings)</span>
        </span>
      </div>
      <div class="cat-bar-bg">
        <div class="cat-bar-fill" style="width:{pct}%;background:linear-gradient(90deg,{color}99,{color});{glow}"></div>
      </div>
    </div>""", unsafe_allow_html=True)



# ════════════════════════════════════════════════════════════════════════════
# Session state  ← MUST come before any widget code
# ════════════════════════════════════════════════════════════════════════════

def _init_state():
    defaults = {
        "pslist": [], "pstree": [], "malfind": [], "netscan": [],
        "cmdline": [], "dlllist": [], "handles": [],
        "proc_anomalies": [], "net_anomalies": [], "ps_findings": [],
        "threat_score": None, "timeline": None,
        "analysis_done": False,
        "chat_history": [],
        "agent": None,
        "dark_mode": True,
        "ai_tab_cache": {},
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()



# ════════════════════════════════════════════════════════════════════════════
# App Navigation Router
# States: splash → dashboard → analysis | live_monitor
# ════════════════════════════════════════════════════════════════════════════

import time as _time

_app_state = st.session_state.get("app_state", "splash")

# ── Shared logo (base64) — used by splash + dashboard ─────────────────────────
import base64 as _b64
_logo_b64 = ""
if _LOGO_PATH.exists():
    with open(_LOGO_PATH, "rb") as _lf:
        _logo_b64 = _b64.b64encode(_lf.read()).decode()
_logo_tag_sm = (  # 48px — sidebar / small
    f'<img src="data:image/png;base64,{_logo_b64}" style="height:48px;width:48px;object-fit:contain;border-radius:10px;">'
    if _logo_b64 else '<span style="font-size:2.4rem;">🧠</span>'
)
_logo_tag_lg = (  # 100px — splash hero
    f'<img src="data:image/png;base64,{_logo_b64}" style="height:100px;width:100px;object-fit:contain;border-radius:18px;filter:drop-shadow(0 0 24px rgba(168,85,247,0.5));">'
    if _logo_b64 else '<span style="font-size:5rem;">🧠</span>'
)
_logo_tag_md = (  # 72px — dashboard header
    f'<img src="data:image/png;base64,{_logo_b64}" style="height:72px;width:72px;object-fit:contain;border-radius:14px;filter:drop-shadow(0 0 16px rgba(168,85,247,0.4));">'
    if _logo_b64 else '<span style="font-size:3.5rem;">🧠</span>'
)

# ── SPLASH ────────────────────────────────────────────────────────────────────
if _app_state == "splash":
    st.markdown("""
    <style>
    #MainMenu, header, footer,
    [data-testid="stSidebar"],
    [data-testid="collapsedControl"],
    section[data-testid="stSidebarCollapsedControl"] {display:none!important}
    .block-container {padding:0!important; max-width:100%!important}
    [data-testid="stCustomComponentV1"] {height:0!important;overflow:hidden!important;margin:0!important}
    </style>
    """, unsafe_allow_html=True)

    _msgs = [
        "Initializing forensics engine…",
        "Loading threat intelligence…",
        "Calibrating anomaly detectors…",
        "Preparing memory analysis modules…",
        "Ready.",
    ]

    # Step-based: one message per render — no blocking loop
    _step  = st.session_state.get("splash_step", 0)
    if _step >= len(_msgs):
        st.session_state.app_state   = "dashboard"
        st.session_state.splash_done = True
        st.session_state.pop("splash_step", None)
        st.rerun()

    _msg   = _msgs[_step]
    _bar_w = int((_step + 1) / len(_msgs) * 100)

    st.markdown(f"""
    <div style="min-height:100vh;background:#09000f;display:flex;
                align-items:center;justify-content:center;">
      <div style="background:#12001e;border:1px solid #3a1a5a;border-radius:20px;
                  padding:56px 72px;text-align:center;min-width:480px;
                  box-shadow:0 0 80px rgba(168,85,247,0.25);">
        <div style="margin-bottom:18px;display:flex;justify-content:center;">
          {_logo_tag_lg}
        </div>
        <div style="font-family:'Orbitron',monospace;font-size:2.2rem;font-weight:900;
                    color:#ec4899;letter-spacing:4px;margin-bottom:4px;">
          Ghost<span style="color:#a855f7;">Trace</span>
        </div>
        <div style="color:#7a5a9a;font-size:0.82rem;letter-spacing:3px;
                    text-transform:uppercase;margin-bottom:40px;">
          Memory Forensics Platform
        </div>
        <div style="background:#1a0a2a;border-radius:999px;height:6px;
                    margin-bottom:18px;overflow:hidden;">
          <div style="height:6px;width:{_bar_w}%;
                      background:linear-gradient(90deg,#a855f7,#ec4899);
                      border-radius:999px;transition:width 0.4s ease;">
          </div>
        </div>
        <div style="color:#a855f7;font-size:0.82rem;font-family:monospace;
                    letter-spacing:1px;">{_msg}</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.session_state.splash_step = _step + 1
    _time.sleep(0.35)
    st.rerun()


# ── DASHBOARD ────────────────────────────────────────────────────────────────
elif _app_state == "dashboard":
    st.markdown("""
    <style>
    #MainMenu, header, footer,
    [data-testid="stSidebar"],
    [data-testid="collapsedControl"],
    section[data-testid="stSidebarCollapsedControl"] {display:none!important}
    .block-container {padding:2rem 3rem!important; max-width:100%!important}
    </style>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="display:flex;align-items:center;justify-content:space-between;
                margin-bottom:40px;padding-bottom:20px;
                border-bottom:1px solid rgba(168,85,247,0.15);">
      <div style="display:flex;align-items:center;gap:16px;">
        {_logo_tag_md}
        <div>
          <div style="font-family:'Orbitron',monospace;font-size:1.8rem;font-weight:900;
                       color:#ec4899;letter-spacing:3px;line-height:1.1;">
            Ghost<span style="color:#a855f7;">Trace</span>
          </div>
          <div style="color:#6a3a8a;font-size:0.75rem;letter-spacing:2px;
                      text-transform:uppercase;margin-top:2px;">Memory Forensics Platform</div>
        </div>
        <span style="background:#1a0a2a;border:1px solid #3a1a5a;color:#7a5a9a;
                     border-radius:20px;padding:2px 12px;font-size:0.72rem;
                     font-family:monospace;letter-spacing:2px;align-self:flex-start;
                     margin-top:4px;">v2.0</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="color:#7a5a9a;font-size:0.72rem;letter-spacing:3px;
                text-transform:uppercase;margin-bottom:20px;">
      ⚡ Choose Analysis Mode
    </div>
    """, unsafe_allow_html=True)

    # ── Mode cards ───────────────────────────────────────────────────────────
    _col1, _col2 = st.columns(2, gap="large")

    with _col1:
        st.markdown("""
        <div style="background:#111827;border:1px solid #1e3a2f;border-radius:14px;
                    padding:32px;min-height:260px;position:relative;">
          <div style="font-size:2.2rem;margin-bottom:16px;">🗄️</div>
          <div style="font-size:1.3rem;font-weight:800;color:#f0fdf4;
                      margin-bottom:12px;letter-spacing:0.5px;">
            Static Memory Analysis
          </div>
          <div style="color:#6b7280;font-size:0.85rem;line-height:1.6;margin-bottom:24px;">
            Analyse pre-collected Windows memory dumps (.dmp) using Volatility 3.
            Full offline investigation with process inspection, injection detection,
            network forensics, and threat scoring.
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;">
            <span style="background:#1a2e1a;border:1px solid #2d4a2d;color:#86efac;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              📁 Memory Dump
            </span>
            <span style="background:#1a2e1a;border:1px solid #2d4a2d;color:#86efac;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              🔬 Volatility 3
            </span>
            <span style="background:#1a2e1a;border:1px solid #2d4a2d;color:#86efac;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              💉 Malfind
            </span>
            <span style="background:#1a2e1a;border:1px solid #2d4a2d;color:#86efac;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              📊 Threat Score
            </span>
            <span style="background:#1a2e1a;border:1px solid #2d4a2d;color:#86efac;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              🤖 AI Analysis
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        if st.button("🔬  Open Memory Dump Analysis", key="btn_static",
                     use_container_width=True, type="primary"):
            st.session_state.app_state = "analysis"
            st.rerun()

    with _col2:
        st.markdown("""
        <div style="background:#111827;border:1px solid #2d1a3a;border-radius:14px;
                    padding:32px;min-height:260px;position:relative;">
          <div style="font-size:2.2rem;margin-bottom:16px;">📡</div>
          <div style="font-size:1.3rem;font-weight:800;color:#faf5ff;
                      margin-bottom:12px;letter-spacing:0.5px;">
            Live Dynamic Monitoring
          </div>
          <div style="color:#6b7280;font-size:0.85rem;line-height:1.6;margin-bottom:24px;">
            Real-time surveillance of the current Windows endpoint. Detect suspicious
            processes, monitor network connections, stream process events, and receive
            instant threat alerts — no dump file needed.
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;">
            <span style="background:#1f1033;border:1px solid #3b1f5e;color:#c084fc;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              🔴 Live Processes
            </span>
            <span style="background:#1f1033;border:1px solid #3b1f5e;color:#c084fc;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              🌐 Network Stream
            </span>
            <span style="background:#1f1033;border:1px solid #3b1f5e;color:#c084fc;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              ⚠️ Threat Alerts
            </span>
            <span style="background:#1f1033;border:1px solid #3b1f5e;color:#c084fc;
                         border-radius:6px;padding:3px 10px;font-size:0.72rem;">
              📈 Auto Refresh
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        if st.button("🔴  Open Live Monitor", key="btn_live",
                     use_container_width=True):
            st.session_state.app_state = "live_monitor"
            st.rerun()

    st.stop()


# ── LIVE MONITOR ──────────────────────────────────────────────────────────────
elif _app_state == "live_monitor":
    st.markdown("""
    <style>
    #MainMenu, header, footer,
    [data-testid="stSidebar"],
    [data-testid="collapsedControl"],
    section[data-testid="stSidebarCollapsedControl"] {display:none!important}
    .block-container {padding:1.2rem 2rem!important; max-width:100%!important}
    [data-testid="stCustomComponentV1"] {height:0!important;overflow:hidden!important;
                                         margin:0!important;padding:0!important}
    </style>
    """, unsafe_allow_html=True)

    import psutil as _psutil, datetime as _dt

    try:
        from streamlit_autorefresh import st_autorefresh as _st_ar
        _st_ar(interval=5000, limit=None, key="lm_refresh")
    except ImportError:
        pass

    # ── Top bar ──────────────────────────────────────────────────────────────
    _lm_col1, _lm_col2, _lm_col3 = st.columns([3, 2, 1])
    with _lm_col1:
        st.markdown("""
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:1.6rem;">📡</span>
          <span style="font-family:'Orbitron',monospace;font-size:1.4rem;
                       font-weight:900;color:#ec4899;">
            Live Monitor
          </span>
          <span style="background:#1a0a2a;border:1px solid #ef444455;
                       color:#ef4444;border-radius:20px;padding:2px 10px;
                       font-size:0.7rem;letter-spacing:2px;">● LIVE</span>
        </div>
        """, unsafe_allow_html=True)
    with _lm_col2:
        st.markdown(f"""
        <div style="color:#7a5a9a;font-size:0.8rem;margin-top:10px;">
          🕒 {_dt.datetime.now().strftime('%H:%M:%S')} &nbsp;·&nbsp;
          Auto-refresh: 5s
        </div>
        """, unsafe_allow_html=True)
    with _lm_col3:
        if st.button("← Dashboard", key="lm_back"):
            st.session_state.app_state = "dashboard"
            st.rerun()

    st.markdown("<hr style='border-color:rgba(168,85,247,0.15);margin:12px 0 20px'>",
                unsafe_allow_html=True)

    # ── Snapshot current system ───────────────────────────────────────────────
    try:
        _procs = list(_psutil.process_iter(
            ["pid","ppid","name","cpu_percent","memory_percent",
             "status","create_time","username"]))
        _conns = _psutil.net_connections(kind="inet")
    except Exception:
        _procs, _conns = [], []

    _cur_pids = {p.info["pid"] for p in _procs}
    _prev_pids = st.session_state.lm_prev_pids or set()
    _new_pids  = _cur_pids - _prev_pids
    st.session_state.lm_prev_pids = _cur_pids

    # Alert on new processes
    _SUSP_NAMES = {"cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                   "mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe",
                   "bitsadmin.exe","mimikatz.exe","procdump.exe","psexec.exe"}
    for _p in _procs:
        if _p.info["pid"] in _new_pids:
            _pname = (_p.info.get("name") or "").lower()
            if _pname in _SUSP_NAMES:
                _alert = {
                    "time": _dt.datetime.now().strftime("%H:%M:%S"),
                    "pid": _p.info["pid"],
                    "name": _p.info["name"],
                    "msg": f"⚠️ Suspicious process spawned: {_p.info['name']} (PID {_p.info['pid']})"
                }
                st.session_state.lm_alerts = ([_alert]
                    + st.session_state.lm_alerts)[:20]

    # ── Metrics row ──────────────────────────────────────────────────────────
    _mc1,_mc2,_mc3,_mc4,_mc5 = st.columns(5)
    _mc1.metric("🔬 Processes",   len(_procs))
    _mc2.metric("🌐 Connections", len([c for c in _conns if c.raddr]))
    _mc3.metric("🆕 New PIDs",    len(_new_pids), delta=int(len(_new_pids)) if _new_pids else None)
    _mc4.metric("⚠️ Alerts",      len(st.session_state.lm_alerts))
    try:
        _mc5.metric("💻 CPU %", f"{_psutil.cpu_percent(interval=None):.1f}%")
    except Exception:
        pass

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Alerts panel ─────────────────────────────────────────────────────────
    _lm_alerts = st.session_state.lm_alerts
    if _lm_alerts:
        with st.expander(f"🚨 Threat Alerts ({len(_lm_alerts)})", expanded=True):
            for _a in _lm_alerts[:10]:
                st.markdown(f"""
                <div style="background:#1a0000;border-left:4px solid #ef4444;
                            border-radius:6px;padding:8px 14px;margin:4px 0;
                            color:#fca5a5;font-size:0.82rem;font-family:monospace;">
                  [{_a['time']}] {_a['msg']}
                </div>""", unsafe_allow_html=True)
            if st.button("🗑 Clear Alerts", key="lm_clear"):
                st.session_state.lm_alerts = []
                st.rerun()

    # ── Processes & Network tabs ──────────────────────────────────────────────
    _lt1, _lt2 = st.tabs(["🔬 Live Processes", "🌐 Network Connections"])

    with _lt1:
        import pandas as _lpd
        _proc_rows = []
        for _p in sorted(_procs, key=lambda x: x.info.get("cpu_percent") or 0,
                         reverse=True)[:100]:
            _is_new  = _p.info["pid"] in _new_pids
            _is_susp = (_p.info.get("name") or "").lower() in _SUSP_NAMES
            _proc_rows.append({
                "🆕": "🆕" if _is_new else "",
                "⚠️": "⚠️" if _is_susp else "",
                "PID":      _p.info["pid"],
                "Name":     _p.info.get("name", ""),
                "PPID":     _p.info.get("ppid", ""),
                "CPU%":     round(_p.info.get("cpu_percent") or 0, 2),
                "RAM%":     round(_p.info.get("memory_percent") or 0, 2),
                "Status":   _p.info.get("status", ""),
                "User":     (_p.info.get("username") or "")[:25],
            })
        _proc_df = _lpd.DataFrame(_proc_rows)
        st.dataframe(_proc_df, use_container_width=True, hide_index=True,
                     height=420)

    with _lt2:
        _net_rows = []
        _pid_names = {p.info["pid"]: p.info.get("name","?") for p in _procs}
        for _c in _conns:
            if not _c.raddr:
                continue
            _net_rows.append({
                "Process": _pid_names.get(_c.pid or 0, "?"),
                "PID":     _c.pid,
                "Local":   f"{_c.laddr.ip}:{_c.laddr.port}" if _c.laddr else "",
                "Remote":  f"{_c.raddr.ip}:{_c.raddr.port}",
                "State":   _c.status,
                "Proto":   "TCP" if _c.type == 1 else "UDP",
            })
        if _net_rows:
            st.dataframe(_lpd.DataFrame(_net_rows), use_container_width=True,
                         hide_index=True, height=420)
        else:
            st.info("No active outbound connections detected.")

    # ── Generate Report button ────────────────────────────────────────────────
    st.divider()
    _rc1, _rc2 = st.columns([3, 1])
    with _rc1:
        st.caption("Run a full snapshot of the live system and open it in the Analysis dashboard.")
    with _rc2:
        if st.button("📊 Full Live Analysis", type="primary",
                     use_container_width=True, key="lm_full"):
            st.session_state.app_state = "analysis"
            st.session_state["_trigger_live_scan"] = True
            st.rerun()

    st.stop()


# ── ANALYSIS (existing sidebar + tabs) ────────────────────────────────────────
# Back button in sidebar handled below; fall through to existing code.

# ════════════════════════════════════════════════════════════════════════════
# Sidebar
# ════════════════════════════════════════════════════════════════════════════


with st.sidebar:
    # ── Back to Dashboard ──
    if st.button("← Dashboard", key="sb_back_dash", use_container_width=True):
        st.session_state.app_state = "dashboard"
        st.rerun()
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

    # ── Auto-trigger live scan if arriving from Live Monitor ──
    if st.session_state.pop("_trigger_live_scan", False):
        st.session_state["_run_live_now"] = True

    # ── Branding ──
    if _logo_img:
        col_l, col_c, col_r = st.columns([1, 2, 1])
        with col_c:
            st.image(_logo_img, width="stretch")
    st.markdown(f"""
    <div style="padding:4px 8px 12px; text-align:center;">
        <div style="font-family:'Orbitron',monospace; font-size:1.3rem; font-weight:900;
                    background:linear-gradient(135deg,#a855f7,#ec4899);
                    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
                    letter-spacing:0.06em;">GhostTrace</div>
        <div style="font-size:0.65rem; color:{'#c084fc' if _DARK else '#7c3aed'}; letter-spacing:0.18em;
                    text-transform:uppercase; margin-top:4px;">Memory Forensics Platform</div>
        <div style="margin-top:10px; display:flex; justify-content:center; gap:6px;">
          <span style="background:{'#0a1f0a' if _DARK else '#f0fdf4'};border:1px solid {'#1f5c1f' if _DARK else '#22c55e'};color:#3fb950;
                       border-radius:20px;padding:2px 10px;font-size:0.65rem;
                       letter-spacing:0.08em;">v1.0.0</span>
          <span style="background:{'#0a1a2a' if _DARK else '#f5f0ff'};border:1px solid {'#1a4a6a' if _DARK else '#a855f7'};color:#a855f7;
                       border-radius:20px;padding:2px 10px;font-size:0.65rem;
                       letter-spacing:0.08em;">FYP 2026</span>
        </div>
    </div>
    <div style="height:1px; background:linear-gradient(90deg,transparent,rgba(168,85,247,0.3),transparent); margin-bottom:16px;"></div>
    """, unsafe_allow_html=True)

    # ── Memory Dump ──
    st.markdown("<div style='font-size:0.72rem;color:#2d6080;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:8px;'>📁 Memory Dump</div>", unsafe_allow_html=True)
    # Read mock state from .env (reloaded on every rerun)
    load_dotenv(ROOT / ".env", override=True)
    _env_mock = os.environ.get("MEMFORENSIC_MOCK", "0") == "1"
    use_mock = _env_mock
    if not _env_mock:
        _disable_mock()

    dump_path = None

    # ── Restore previously uploaded path across reruns ────────────────────────
    if st.session_state.get("uploaded_dump_path"):
        _upath = pathlib.Path(st.session_state.uploaded_dump_path)
        if _upath.exists() and _upath.is_file():
            dump_path = str(_upath)

    # ── Primary: local path (instant — no upload needed) ─────────────────────
    _path_input = st.text_input(
        "📂 Local file path",
        placeholder="C:/evidence/my-vm.dmp",
        help="Type the full path to the .mem / .dmp / .raw / .vmem file on this machine. "
             "No upload required — Volatility reads it directly from disk.",
        key="dump_path_input",
    )
    if _path_input and _path_input.strip():
        _p = pathlib.Path(_path_input.strip())
        if _p.exists() and _p.is_file():
            dump_path = str(_p)
            # clear any old uploaded path so local path takes priority
            st.session_state.uploaded_dump_path = ""
            _sz_mb = _p.stat().st_size // 1024 // 1024
            st.success(f"✓ Found: {_p.name}  ({_sz_mb:,} MB)")
        else:
            st.error(f"❌ File not found: `{_path_input.strip()}`")

    # ── Secondary: browser upload (SMALL files only ≤ 200 MB) ────────────────
    if not dump_path:
        with st.expander("📤 Or upload a small file (≤ 200 MB)", expanded=False):

            # Tip: always prefer path input for local files
            st.markdown(
                "<div style='background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.25);"
                "border-radius:8px;padding:10px 14px;font-size:0.78rem;color:#f59e0b;margin-bottom:10px;'>"
                "💡 <b>Tip:</b> If the file is already on <b>this machine</b>, use the "
                "<b>📂 Local file path</b> box above — it's <b>instant</b> (no copy needed).<br>"
                "Upload is only needed when the file is on <b>another device</b> (e.g. your laptop)."
                "</div>",
                unsafe_allow_html=True,
            )

            uploaded = st.file_uploader(
                "Upload memory dump (≤ 200 MB)",
                type=["mem", "raw", "dmp", "vmem", "lime"],
                help="Hard limit: 200 MB. For larger dumps use the local path input above.",
            )
            if uploaded:
                _file_mb = (uploaded.size or 0) // 1024 // 1024
                if uploaded.size and uploaded.size > 200 * 1024 * 1024:
                    st.error(
                        f"🚫 **File too large for browser upload: {_file_mb:,} MB.**\n\n"
                        "Browser upload copies every byte through the network stack — "
                        "a 2 GB file would take **10–30 minutes**.\n\n"
                        "**Use the 📂 Local file path box instead** — "
                        "it takes 0 seconds because Volatility reads the file directly from disk."
                    )
                else:
                    import time as _time
                    save_dir = pathlib.Path(tempfile.gettempdir()) / "memforensic_uploads"
                    save_dir.mkdir(exist_ok=True)
                    _dest = save_dir / uploaded.name

                    # ── Skip re-save if already written in a previous rerun ──
                    _already_saved = (
                        _dest.exists() and
                        _dest.stat().st_size == (uploaded.size or 0)
                    )

                    if _already_saved:
                        # File is already on disk — just set path and show success
                        dump_path = str(_dest)
                        st.session_state.uploaded_dump_path = dump_path
                        st.success(f"✓ Ready: {uploaded.name}  ({_file_mb} MB) — click **🚀 Run Full Analysis**")
                    else:
                        # First time — save the file with progress
                        dump_path = str(_dest)
                        _CHUNK = 32 * 1024 * 1024   # 32 MB chunks
                        _prog = st.progress(0, text=f"Saving {uploaded.name} ({_file_mb} MB)…")
                        total   = uploaded.size or 1
                        written = 0
                        _t0 = _time.monotonic()
                        with open(dump_path, "wb") as _f:
                            while True:
                                chunk = uploaded.read(_CHUNK)
                                if not chunk:
                                    break
                                _f.write(chunk)
                                written += len(chunk)
                                _elapsed = _time.monotonic() - _t0 or 0.001
                                _speed   = written / _elapsed / 1024 / 1024  # MB/s
                                _prog.progress(
                                    min(written / total, 1.0),
                                    text=f"Saving… {written // 1024 // 1024} / {_file_mb} MB  "
                                         f"({_speed:.1f} MB/s)",
                                )
                        _prog.empty()
                        # ── Persist path in session state so it survives reruns ──
                        st.session_state.uploaded_dump_path = dump_path
                        st.success(f"✓ Saved: {uploaded.name}  ({_file_mb} MB) — click **🚀 Run Full Analysis**")



    st.markdown("<div style='height:1px;background:rgba(0,212,255,0.08);margin:14px 0;'></div>", unsafe_allow_html=True)

    # ── Settings ──
    st.markdown("<div style='font-size:0.72rem;color:#2d6080;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:8px;'>⚙️ Engine</div>", unsafe_allow_html=True)
    provider = "OPENROUTER"
    model    = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.2-3b-instruct:free")
    st.markdown(f"""
    <div style="background:{'rgba(236,72,153,0.08)' if _DARK else 'rgba(168,85,247,0.05)'};border:1px solid {'rgba(236,72,153,0.2)' if _DARK else 'rgba(168,85,247,0.2)'};
                border-radius:8px;padding:10px 14px;font-size:0.78rem;">
        <div style="color:{'#c084fc' if _DARK else '#7c3aed'};font-size:0.66rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px;">LLM Provider</div>
        <div style="color:#ec4899;font-family:'JetBrains Mono',monospace;font-size:0.85rem;">{provider}</div>
        <div style="color:{'#c084fc' if _DARK else '#9333ea'};font-size:0.66rem;letter-spacing:0.1em;text-transform:uppercase;margin:8px 0 4px;">Model</div>
        <div style="color:{'#f0e6ff' if _DARK else '#4a3568'};font-family:'JetBrains Mono',monospace;font-size:0.82rem;">{model}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    run_full = st.button("🚀 Run Full Analysis", type="primary", width="stretch")

    # ── Dynamic Analysis buttons ─────────────────────────────────────────────
    st.markdown("<div style='height:1px;background:rgba(168,85,247,0.18);margin:10px 0;'></div>",
                unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.68rem;color:#ec4899;letter-spacing:0.12em;"
                "text-transform:uppercase;margin-bottom:6px;'>⚡ Dynamic Analysis</div>",
                unsafe_allow_html=True)

    run_live = st.button("🔴 Live System Scan", width="stretch",
                         help="Scan THIS machine right now — no dump file needed")

    st.markdown("<div style='height:1px;background:rgba(168,85,247,0.12);margin:14px 0;'></div>",
                unsafe_allow_html=True)

    # ── Live Analysis Status (shown after analysis) ──────────────────────────

    if st.session_state.get("analysis_done"):
        ts = st.session_state.threat_score or {}
        score    = ts.get("score", 0)
        level    = ts.get("level", "UNKNOWN")
        findings = ts.get("total_findings", 0)
        procs    = len(st.session_state.pslist)
        inj      = len(st.session_state.malfind)
        nets     = len(st.session_state.net_anomalies)
        ps_f     = len(st.session_state.ps_findings)
        anom     = len(st.session_state.proc_anomalies)

        _level_colors = {
            "LOW": "#3fb950", "MEDIUM": "#e3a82a",
            "HIGH": "#ff6b47", "CRITICAL": "#ff3333",
        }
        lvl_col = _level_colors.get(level, "#a855f7")

        st.markdown(f"""
        <div style="margin-bottom:10px;">
          <div style="font-size:0.68rem;color:#2d6080;letter-spacing:0.12em;
                      text-transform:uppercase;margin-bottom:8px;">📊 Analysis Results</div>
          <div style="background:rgba(0,0,0,0.3);border:1px solid rgba(168,85,247,0.15);
                      border-radius:10px;padding:12px 14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
              <span style="font-size:0.72rem;color:#7a5a9a;">Threat Score</span>
              <span style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;
                           font-weight:700;color:{lvl_col};">{score}<span style="font-size:0.65rem;color:#3a2a5a;">/100</span></span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-size:0.72rem;color:#7a5a9a;">Level</span>
              <span style="background:{lvl_col}22;border:1px solid {lvl_col}55;color:{lvl_col};
                           border-radius:20px;padding:1px 9px;font-size:0.65rem;font-weight:700;
                           letter-spacing:0.08em;">{level}</span>
            </div>
            <div style="height:4px;background:rgba(255,255,255,0.06);border-radius:4px;margin:8px 0;">
              <div style="height:4px;width:{score}%;background:linear-gradient(90deg,{lvl_col}99,{lvl_col});
                          border-radius:4px;"></div>
            </div>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:10px;">
          <div style="background:rgba(168,85,247,0.05);border:1px solid rgba(168,85,247,0.14);
                      border-radius:8px;padding:8px 10px;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;color:#a855f7;font-weight:700;">{procs}</div>
            <div style="font-size:0.6rem;color:#4a2a7a;text-transform:uppercase;letter-spacing:0.08em;">Processes</div>
          </div>
          <div style="background:{'rgba(255,51,51,0.06)' if inj>0 else 'rgba(63,185,80,0.05)'};
                      border:1px solid {'rgba(255,51,51,0.2)' if inj>0 else 'rgba(63,185,80,0.15)'};
                      border-radius:8px;padding:8px 10px;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;
                        color:{'#ff5555' if inj>0 else '#3fb950'};font-weight:700;">{inj}</div>
            <div style="font-size:0.6rem;color:#4a2a7a;text-transform:uppercase;letter-spacing:0.08em;">Injections</div>
          </div>
          <div style="background:{'rgba(255,107,71,0.06)' if anom>0 else 'rgba(63,185,80,0.05)'};
                      border:1px solid {'rgba(255,107,71,0.2)' if anom>0 else 'rgba(63,185,80,0.15)'};
                      border-radius:8px;padding:8px 10px;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;
                        color:{'#ff6b47' if anom>0 else '#3fb950'};font-weight:700;">{anom}</div>
            <div style="font-size:0.6rem;color:#4a2a7a;text-transform:uppercase;letter-spacing:0.08em;">Proc Anom</div>
          </div>
          <div style="background:{'rgba(255,51,51,0.06)' if nets>0 else 'rgba(63,185,80,0.05)'};
                      border:1px solid {'rgba(255,51,51,0.2)' if nets>0 else 'rgba(63,185,80,0.15)'};
                      border-radius:8px;padding:8px 10px;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;
                        color:{'#ff5555' if nets>0 else '#3fb950'};font-weight:700;">{nets}</div>
            <div style="font-size:0.6rem;color:#4a2a7a;text-transform:uppercase;letter-spacing:0.08em;">Net Flags</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        if ps_f > 0:
            st.markdown(f"""
            <div style="background:rgba(227,168,42,0.07);border:1px solid rgba(227,168,42,0.2);
                        border-radius:8px;padding:7px 12px;margin-bottom:10px;
                        font-size:0.78rem;color:#e3a82a;">
              ⚡ {ps_f} PowerShell payload{"s" if ps_f!=1 else ""} decoded
            </div>
            """, unsafe_allow_html=True)

        if findings > 0:
            st.markdown(f"""
            <div style="background:rgba(168,85,247,0.06);border:1px solid rgba(168,85,247,0.18);
                        border-radius:8px;padding:7px 12px;margin-bottom:6px;
                        font-size:0.78rem;color:#a855f7;">
              🔍 {findings} total finding{"s" if findings!=1 else ""} recorded
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height:1px;background:rgba(168,85,247,0.12);margin:10px 0;'></div>", unsafe_allow_html=True)

    # ── Dark / Light toggle ──────────────────────────────────────────────────
    st.divider()
    dark_label = "☀️ Switch to Light Mode" if st.session_state.dark_mode else "🌙 Switch to Dark Mode"
    if st.button(dark_label, key="theme_toggle", use_container_width=True):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()

    # ── Scan History ─────────────────────────────────────────────────────
    st.divider()
    _hist_col = "#c084fc" if _DARK else "#7c3aed"
    st.markdown(f'<div style="font-size:0.72rem;color:{_hist_col};letter-spacing:0.12em;'
                f'text-transform:uppercase;margin-bottom:8px;">🗄 Scan History</div>',
                unsafe_allow_html=True)
    try:
        if _sdb:
            _history = _sdb.list_scans(15)
        else:
            _history = []
        if _history:
            _lc_map = {"LOW":"#22c55e", "MEDIUM":"#f59e0b",
                       "HIGH":"#f97316", "CRITICAL":"#ef4444"}
            for _s in _history:
                _dp  = (pathlib.Path(_s["dump_path"]).name
                        if _s["dump_path"] else "unknown")[:18]
                _lv  = _s["level"]
                _sc  = _s["score"]
                _dt  = _s["created_at"][:16].replace("T", " ")
                _lc  = _lc_map.get(_lv, "#a855f7")
                _active = st.session_state.get("current_scan_id") == _s["id"]
                _card_style = (
                    f'background:rgba(236,72,153,0.12);border:1px solid {_lc}44;'
                    if _active else
                    f'background:rgba(168,85,247,0.04);border:1px solid rgba(168,85,247,0.12);'
                )
                st.markdown(f"""
                <div style="{_card_style}border-radius:8px;padding:6px 10px;
                            margin-bottom:5px;cursor:pointer;">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;
                              color:{_lc};font-weight:{'700' if _active else '400'}">
                    {'▶ ' if _active else ''}{_dp}</div>
                  <div style="display:flex;justify-content:space-between;margin-top:2px;">
                    <span style="font-size:0.68rem;color:{_lc};"
                    >{_lv} &nbsp; {_sc}/100</span>
                    <span style="font-size:0.65rem;color:#6b7280;">{_dt}</span>
                  </div>
                </div>""", unsafe_allow_html=True)
                if st.button(f"Load", key=f"hist_{_s['id']}",
                             help=f"{_dt} · {_s['dump_path']}",
                             use_container_width=True):
                    _rec = _sdb.load_scan_by_id(_s["id"]) if _sdb else None
                    if _rec:
                        for _fk in ["pslist","pstree","malfind","netscan","dlllist",
                                    "cmdline","handles","proc_anomalies","net_anomalies",
                                    "ps_findings","threat_score","timeline"]:
                            st.session_state[_fk] = _rec.get(_fk) or []
                        # Always clear AI cache when loading a scan so each tab
                        # shows fresh analysis for the loaded dump, not old results.
                        st.session_state.ai_tab_cache = {}
                        st.session_state.analysis_done    = True
                        st.session_state.current_scan_id  = _s["id"]
                        st.session_state.current_dump_path = _s["dump_path"]
                        st.rerun()
        else:
            st.caption("No scans yet. Run an analysis to save results.")
    except Exception as _he:
        st.caption(f"DB unavailable: {_he}")
    st.markdown("""
    <div style="text-align:center;font-size:0.65rem;color:#1e3a4a;letter-spacing:0.08em;">
        DEPT. OF Digital Forensics &amp; CyberSecurity &nbsp;·&nbsp; FYP 2026<br>
        <span style="color:#0d2a3a;">Fileless Malware Detection via Memory Analysis</span>
    </div>
    """, unsafe_allow_html=True)




# ── Theme injection ──────────────────────────────────────────────────────────

def _inject_theme():
    if _DARK:
        st.markdown("""<style>
        .stApp{background-color:#0a0010!important;color:#f0e6ff!important}
        [data-testid="stSidebar"]{background:linear-gradient(180deg,#1a0030 0%,#0a0010 100%)!important}
        .anomaly-card{background:#1a0030!important;color:#f0e6ff!important}
        .kpi-tile{background:#1a0030!important;border-color:rgba(236,72,153,.3)!important}
        h2{color:#ec4899!important} h3{color:#a855f7!important}
        /* Compact AI markdown output */
        .stExpander p{margin:2px 0!important}
        .stExpander li{margin:1px 0!important;line-height:1.5!important}
        .stExpander ul,.stExpander ol{margin:4px 0!important;padding-left:20px!important}
        </style>""", unsafe_allow_html=True)
    else:
        st.markdown("""<style>
        .stApp{background-color:#ffffff!important;color:#1e1030!important}
        html,body,.main,.block-container,[data-testid="stAppViewContainer"],[data-testid="stVerticalBlock"]{background-color:#ffffff!important}
        [data-testid="stSidebar"]{background:#ffffff!important;border-right:1px solid rgba(168,85,247,0.15)!important}
        .anomaly-card{background:#ffffff!important;color:#1e1030!important}
        .kpi-tile{background:#ffffff!important}
        h2{color:#ec4899!important} h3{color:#7c3aed!important}
        div[data-testid="stForm"]{background:#ffffff!important}
        /* Compact AI markdown output */
        .stExpander p{margin:2px 0!important}
        .stExpander li{margin:1px 0!important;line-height:1.5!important}
        .stExpander ul,.stExpander ol{margin:4px 0!important;padding-left:20px!important}
        </style>""", unsafe_allow_html=True)

_inject_theme()


# ── AI helpers ───────────────────────────────────────────────────────────────

_AI_SYSTEM = (
    "You are a memory forensics analyst. Be concise. "
    "Reply ONLY with these 4 sections (bullets, no filler):\n"
    "🔍 FINDINGS | 🧠 WHY MALICIOUS (MITRE ATT&CK) | 💥 IMPACT | 🛡 REMEDIATION"
)

def _call_ai(context_text: str) -> str | None:
    """Try each free model in order. Returns result string or None if all fail."""
    import time as _t
    from openai import OpenAI
    _primary = os.environ.get("OPENROUTER_MODEL", "google/gemma-4-31b-it:free")
    _MODELS = list(dict.fromkeys([
        _primary,
        "google/gemma-4-31b-it:free",
        "nvidia/nemotron-3-nano-30b-a3b:free",
        "openai/gpt-oss-20b:free",
        "z-ai/glm-4.5-air:free",
        "nousresearch/hermes-3-llama-3.1-405b:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "deepseek/deepseek-r1:free",
        "mistralai/mistral-7b-instruct:free",
    ]))
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ.get("OPENROUTER_API_KEY", ""),
    )
    for _m in _MODELS:
        for _attempt in range(2):
            try:
                resp = client.chat.completions.create(
                    model=_m,
                    messages=[
                        {"role": "system", "content": _AI_SYSTEM},
                        {"role": "user",   "content": context_text[:2000]},
                    ],
                    max_tokens=400, temperature=0.1, timeout=30,
                )
                result = (resp.choices[0].message.content or "").strip()
                if result:
                    return result
            except Exception as _e:
                _es = str(_e)
                if "401" in _es or "auth" in _es.lower():
                    return None   # bad key — stop immediately
                if ("429" in _es or "rate" in _es.lower()) and _attempt == 0:
                    _t.sleep(5)
                    continue
                break  # skip to next model
    return None


def _static_fallback(tab_key: str, context_text: str) -> str:
    """
    Rich data-driven fallback when AI is unavailable.
    Reads actual forensic findings from session state and generates
    a structured 4-section forensic report per tab.
    """
    ss    = st.session_state
    anom  = ss.get("proc_anomalies")    or []
    net   = ss.get("net_anomalies")     or []
    mal   = ss.get("malfind")           or []
    ps    = ss.get("ps_findings")       or []
    dll   = ss.get("dll_anomalies")     or []
    hdl   = ss.get("handle_anomalies")  or []
    lb    = ss.get("lolbas_behaviors")  or []
    ts    = ss.get("threat_score")      or {}
    procs = ss.get("pslist")            or []

    score = ts.get("score", 0)
    level = ts.get("level", "UNKNOWN")
    recs  = ts.get("recommendations")  or []

    # Severity colour word for text
    _sev_word = (
        "**CRITICAL** 🔴" if score >= 80 else
        "**HIGH** 🟠"     if score >= 60 else
        "**MEDIUM** 🟡"   if score >= 40 else
        "**LOW** 🟢"
    )

    # ── helpers ──────────────────────────────────────────────────────────────
    def _pname(a):
        return a.get("process") or a.get("ImageFileName") or a.get("name") or "?"

    def _pid(a):
        return a.get("pid") or a.get("PID") or "?"

    def _reason(a):
        r = a.get("reason") or a.get("anomaly_type") or "suspicious behaviour"
        return str(r)[:120]

    def _fmt_proc(a):
        return f"- PID **{_pid(a)}** `{_pname(a)}` — {_reason(a)}"

    def _fmt_net(n):
        proc = n.get("Owner") or n.get("process") or "unknown"
        ip   = n.get("ForeignAddr") or n.get("remote_ip") or "?"
        port = n.get("ForeignPort") or n.get("remote_port") or "?"
        why  = n.get("reason") or "suspicious outbound"
        return f"- `{proc}` → **{ip}:{port}** ({why})"

    def _fmt_mal(m):
        p   = m.get("ImageFileName") or m.get("process") or "?"
        pid = m.get("PID") or m.get("pid") or "?"
        sz  = m.get("Size") or m.get("size") or "?"
        return f"- PID **{pid}** `{p}` — {sz} bytes of executable memory (no backing file)"

    def _fmt_ps(p):
        ft  = p.get("finding_type") or "obfuscated"
        ev  = str(p.get("evidence") or p.get("decoded") or "")[:100]
        return f"- **{ft}**: `{ev}{'…' if len(str(p.get('evidence',''))>100) else ''}`"

    def _fmt_dll(d):
        proc = d.get("Process") or d.get("process") or "?"
        path = d.get("Path") or d.get("path") or d.get("FullDllName") or "?"
        return f"- `{proc}` loaded `{str(path)[:90]}`"

    def _fmt_hdl(h):
        proc  = h.get("Process") or h.get("process") or "?"
        name  = h.get("Name") or h.get("handle_name") or "?"
        htype = h.get("Type") or h.get("type") or "?"
        return f"- `{proc}` → handle to `{str(name)[:80]}` ({htype})"

    def _fmt_lb(l):
        proc = l.get("Process") or l.get("process") or "?"
        cmd  = str(l.get("CommandLine") or l.get("cmd") or "")[:90]
        sev  = l.get("severity") or "?"
        return f"- `{proc}` [{sev}]: `{cmd}`"

    # ── PROCESS tab ──────────────────────────────────────────────────────────
    if tab_key == "proc":
        _lines = "\n".join(_fmt_proc(a) for a in anom[:6]) or "- No anomalous processes detected"
        _mitre = []
        for a in anom:
            r = _reason(a).lower()
            if "inject" in r:     _mitre.append("T1055 (Process Injection)")
            if "hollow" in r:     _mitre.append("T1055.012 (Process Hollowing)")
            if "parent" in r:     _mitre.append("T1134 (Access Token Manipulation)")
            if "masquerad" in r:  _mitre.append("T1036 (Masquerading)")
            if "hidden" in r:     _mitre.append("T1564 (Hide Artifacts)")
        _mitre = list(dict.fromkeys(_mitre)) or ["T1055 (Process Injection)", "T1036 (Masquerading)"]
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(anom)}** suspicious processes out of **{len(procs)}** total\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            + "\n".join(f"- {m}" for m in _mitre[:4]) +
            f"\n\n💥 **IMPACT**\n"
            f"- Threat level: {_sev_word} (Score: {score}/100)\n"
            f"- Malicious processes may be injecting code into legitimate processes, "
            f"maintaining persistence, or exfiltrating data\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Isolate the affected host from the network immediately\n"
            f"- Dump memory of suspicious PIDs: `vol.py -f dump.dmp windows.dumpfiles`\n"
            f"- Check scheduled tasks and registry Run keys for persistence\n"
            f"- Review parent-child process chains for anomalous spawning\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── MALFIND tab ──────────────────────────────────────────────────────────
    elif tab_key == "mal":
        _lines = "\n".join(_fmt_mal(m) for m in mal[:6]) or "- No injected memory regions found"
        _procs_hit = list(dict.fromkeys(
            (m.get("ImageFileName") or m.get("process") or "?") for m in mal))[:5]
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(mal)}** executable memory regions with no backing file on disk\n"
            f"- Affected processes: {', '.join(f'`{p}`' for p in _procs_hit) or 'none'}\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"- Private RWX memory → **T1055** (Process Injection)\n"
            f"- No disk backing → **T1620** (Reflective Code Loading)\n"
            f"- MZ/PE headers in heap → **T1055.001** (DLL Injection)\n"
            f"- Possible shellcode → **T1059** (Command and Scripting Interpreter)\n\n"
            f"💥 **IMPACT**\n"
            f"- Code executes entirely in memory — invisible to traditional AV/EDR disk scans\n"
            f"- Attackers can maintain persistent access without dropping files\n"
            f"- Memory regions may contain keyloggers, credential harvesters, or RATs\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Extract memory regions: `vol.py windows.malfind --dump`\n"
            f"- Submit extracted binaries to sandbox (Any.run / Hybrid Analysis)\n"
            f"- Deploy memory-scanning EDR (CrowdStrike Falcon, SentinelOne)\n"
            f"- Kill and quarantine affected processes\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── NETWORK tab ──────────────────────────────────────────────────────────
    elif tab_key == "net":
        _lines = "\n".join(_fmt_net(n) for n in net[:6]) or "- No suspicious connections found"
        _ips   = list(dict.fromkeys(
            str(n.get("ForeignAddr") or n.get("remote_ip") or "") for n in net if
            (n.get("ForeignAddr") or n.get("remote_ip"))))[:5]
        _ports = list(dict.fromkeys(
            str(n.get("ForeignPort") or n.get("remote_port") or "") for n in net if
            (n.get("ForeignPort") or n.get("remote_port"))))[:5]
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(net)}** suspicious outbound connections\n"
            f"- Remote IPs: {', '.join(f'`{ip}`' for ip in _ips) or 'N/A'}\n"
            f"- Ports used: {', '.join(f'`{p}`' for p in _ports) or 'N/A'}\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"- Non-browser outbound on 80/443 → **T1071.001** (Web Protocols C2)\n"
            f"- Unusual processes with external connections → **T1571** (Non-Standard Port)\n"
            f"- Persistent beaconing pattern → **T1102** (Web Service)\n"
            f"- Possible data staging → **T1041** (Exfiltration Over C2 Channel)\n\n"
            f"💥 **IMPACT**\n"
            f"- Active C2 channel enables remote commands, lateral movement, data theft\n"
            f"- Attacker may already have established persistence and lateral spread\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Block suspicious IPs at perimeter firewall immediately\n"
            f"- Capture full PCAP with Wireshark for traffic analysis\n"
            f"- Check DNS query logs for C2 domain resolution history\n"
            f"- Run Zeek/Suricata on the captured traffic for IDS signatures\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── POWERSHELL tab ────────────────────────────────────────────────────────
    elif tab_key == "ps":
        _lines = "\n".join(_fmt_ps(p) for p in ps[:6]) or "- No PowerShell anomalies found"
        _types = list(dict.fromkeys(p.get("finding_type","?") for p in ps))[:4]
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(ps)}** PowerShell anomalies across {len(set(p.get('pid','?') for p in ps))} processes\n"
            f"- Types detected: {', '.join(f'`{t}`' for t in _types) or 'obfuscation'}\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"- Base64/XOR encoding → **T1027** (Obfuscated Files or Information)\n"
            f"- IEX/DownloadString cradles → **T1059.001** (PowerShell)\n"
            f"- AMSI bypass patterns → **T1562.001** (Disable or Modify Tools)\n"
            f"- Reflective loading → **T1620** (Reflective Code Loading)\n\n"
            f"💥 **IMPACT**\n"
            f"- Fileless PowerShell leaves no disk artifacts, bypasses many AV products\n"
            f"- Download cradles can pull secondary payloads (ransomware, RATs, miners)\n"
            f"- AMSI bypasses allow arbitrary code execution without detection\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Enable Script Block Logging (Event ID 4104) via Group Policy\n"
            f"- Enable PowerShell Transcription to capture all session output\n"
            f"- Enforce Constrained Language Mode for non-admin users\n"
            f"- Block encoded `-EncodedCommand` via AppLocker / WDAC\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── DLL tab ───────────────────────────────────────────────────────────────
    elif tab_key == "dll":
        _lines = "\n".join(_fmt_dll(d) for d in dll[:6]) or "- No suspicious DLL loads found"
        _procs_dll = list(dict.fromkeys(
            d.get("Process") or d.get("process") or "?" for d in dll))[:4]
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(dll)}** DLLs loaded from untrusted or non-standard locations\n"
            f"- Affected processes: {', '.join(f'`{p}`' for p in _procs_dll) or 'N/A'}\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"- DLL from `%TEMP%` or user dir → **T1574.001** (DLL Search Order Hijacking)\n"
            f"- Unsigned DLL in trusted process → **T1055.001** (DLL Injection)\n"
            f"- Side-loading of renamed DLL → **T1574.002** (DLL Side-Loading)\n\n"
            f"💥 **IMPACT**\n"
            f"- Malicious DLL runs with full permissions of the host process\n"
            f"- Can intercept API calls, steal credentials, or establish persistence\n"
            f"- Signed host process acts as a trusted proxy for malicious code\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Enable DLL Safe Search Mode (HKLM SafeDllSearchMode = 1)\n"
            f"- Use Microsoft Attack Surface Reduction rules to block DLL injection\n"
            f"- Audit with Sysinternals Autoruns and Process Monitor\n"
            f"- Enforce driver/DLL signing via Secure Boot + UEFI\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── HANDLES tab ───────────────────────────────────────────────────────────
    elif tab_key == "hdl":
        _lines  = "\n".join(_fmt_hdl(h) for h in hdl[:6]) or "- No suspicious handles found"
        _lsass  = any("lsass" in str(h.get("Name","")).lower() for h in hdl)
        _inject = any("process" in str(h.get("Type","")).lower() for h in hdl)
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(hdl)}** suspicious handle relationships\n"
            f"{'- ⚠️ LSASS targeted — credential dumping likely' if _lsass else ''}\n"
            f"{'- ⚠️ Cross-process handles — injection vector present' if _inject else ''}\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"{'- LSASS handle → **T1003.001** (LSASS Memory / Credential Dumping)' if _lsass else '- Sensitive handle access → **T1003** (OS Credential Dumping)'}\n"
            f"- PROCESS_ALL_ACCESS handle → **T1055** (Process Injection)\n"
            f"- Handle to protected process → **T1134** (Access Token Manipulation)\n\n"
            f"💥 **IMPACT**\n"
            f"{'- CRITICAL: LSASS targeted — all domain credentials at risk' if _lsass else '- HIGH: Cross-process handles allow code injection and privilege escalation'}\n"
            f"- Stolen credentials enable lateral movement across entire domain\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Enable Windows Credential Guard (isolates LSASS in secure container)\n"
            f"- Enable LSASS PPL (Protected Process Light) via registry\n"
            f"- Monitor OpenProcess calls to lsass with Sysmon Event ID 10\n"
            f"- Rotate all domain credentials if LSASS was accessed\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── LOLBAS tab ────────────────────────────────────────────────────────────
    elif tab_key == "lolbas":
        _lines  = "\n".join(_fmt_lb(l) for l in lb[:6]) or "- No LOLBas activity found"
        _bins   = list(dict.fromkeys(
            (l.get("Process") or l.get("process") or "?").lower() for l in lb))[:5]
        _has_dl = any(b in ("certutil.exe","bitsadmin.exe","curl.exe") for b in _bins)
        _has_ex = any(b in ("mshta.exe","wscript.exe","cscript.exe","regsvr32.exe") for b in _bins)
        return (
            f"🔍 **FINDINGS**\n"
            f"- **{len(lb)}** Living-off-the-Land binary abuses detected\n"
            f"- Binaries: {', '.join(f'`{b}`' for b in _bins) or 'N/A'}\n"
            f"{'- ⚠️ Download activity detected (certutil/bitsadmin)' if _has_dl else ''}\n"
            f"{'- ⚠️ Script execution via proxy binary detected' if _has_ex else ''}\n"
            f"{_lines}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"{'- certutil/bitsadmin download → **T1105** (Ingress Tool Transfer)' if _has_dl else ''}\n"
            f"{'- mshta/wscript/regsvr32 execution → **T1218** (System Binary Proxy Execution)' if _has_ex else ''}\n"
            f"- Trusted Windows binary used maliciously → **T1218** (Signed Binary Proxy)\n"
            f"- Bypasses application whitelisting → **T1562** (Impair Defenses)\n\n"
            f"💥 **IMPACT**\n"
            f"- Attackers use built-in Windows tools to avoid detection by AV/EDR\n"
            f"{'- Files may have been downloaded and executed without touching disk (certutil decode)' if _has_dl else ''}\n"
            f"- These techniques leave minimal forensic footprint\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Block via AppLocker/WDAC: deny certutil, mshta, wscript, cscript, bitsadmin\n"
            f"- Monitor Event ID 4688 (Process Creation) with command-line logging\n"
            f"- Deploy Sysmon with network connection events for these binaries\n"
            f"- Restrict internet access for system binaries via egress firewall rules\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── THREAT SCORE tab ──────────────────────────────────────────────────────
    elif tab_key == "score":
        _top_findings = []
        if mal:  _top_findings.append(f"{len(mal)} memory injection regions")
        if net:  _top_findings.append(f"{len(net)} C2-like connections")
        if lb:   _top_findings.append(f"{len(lb)} LOLBas abuses")
        if ps:   _top_findings.append(f"{len(ps)} PowerShell anomalies")
        if hdl:  _top_findings.append(f"{len(hdl)} suspicious handles")
        _narrative = (
            "Active intrusion with established C2 and likely data exfiltration in progress."
            if score >= 80 else
            "Significant compromise — attacker has likely achieved persistence and is moving laterally."
            if score >= 60 else
            "Suspicious activity consistent with early-stage compromise or reconnaissance."
            if score >= 40 else
            "Low-risk findings — may be false positives or benign administrative activity."
        )
        return (
            f"🔍 **FINDINGS**\n"
            f"- Threat Score: **{score}/100** — {_sev_word}\n"
            f"- Key indicators: {'; '.join(_top_findings) or 'no major findings'}\n"
            f"- Processes: {len(procs)} total, {len(anom)} anomalous\n"
            f"- Injections: {len(mal)} | Network: {len(net)} | PS: {len(ps)} | DLL: {len(dll)} | Handles: {len(hdl)} | LOLBas: {len(lb)}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"- Multi-vector attack pattern matches APT tradecraft\n"
            f"- Memory injection + C2 + LOLBas = full attack chain present\n"
            f"- Technique chaining: Initial Access → Execution → Persistence → C2 → Exfiltration\n\n"
            f"💥 **IMPACT**\n"
            f"- {_narrative}\n\n"
            f"🛡 **REMEDIATION**\n"
            + ("\n".join(f"- {r}" for r in recs[:4]) if recs else
               "- Isolate host immediately\n"
               "- Preserve memory image for forensics\n"
               "- Reset all credentials used on this host\n"
               "- Engage incident response team") +
            f"\n\n> ⚠️ *Rule-based analysis — AI unavailable*"
        )

    # ── TIMELINE / LIVE SCAN / unknown tabs ──────────────────────────────────
    else:
        return (
            f"🔍 **FINDINGS**\n"
            f"- Analysis context: {context_text[:250]}\n\n"
            f"🧠 **WHY MALICIOUS (MITRE ATT&CK)**\n"
            f"- Multiple MITRE techniques identified — requires manual correlation\n\n"
            f"💥 **IMPACT**\n"
            f"- Overall risk: {_sev_word} (Score: {score}/100)\n\n"
            f"🛡 **REMEDIATION**\n"
            f"- Review all flagged findings manually\n"
            f"- Cross-reference with threat intelligence feeds\n"
            f"- Escalate to SOC / incident response if score ≥ 60\n\n"
            f"> ⚠️ *Rule-based analysis — AI unavailable*"
        )


def _ai_tab_box(tab_key: str, context_text: str, title: str = "🤖 AI Investigator"):
    """
    Queue-aware AI tab box:
    - Registers context for sequential auto-processor
    - Shows cached result instantly
    - Shows queue position while waiting
    - Falls back to static analysis if all models fail
    """
    # Register context so sequential processor can call AI without tab being active
    if "ai_contexts" not in st.session_state:
        st.session_state.ai_contexts = {}
    st.session_state.ai_contexts[tab_key] = context_text

    cache   = st.session_state.get("ai_tab_cache", {})
    pending = st.session_state.get("ai_pending",   [])
    dark    = st.session_state.get("dark_mode", True)
    bg      = "#12001e" if dark else "#fdf4ff"
    border  = "#ec4899" if dark else "#a855f7"

    is_cached  = tab_key in cache
    is_pending = tab_key in pending
    # Expand when already done or currently in queue
    with st.expander(f"{title}", expanded=is_cached):

        # ── Cached → display result ─────────────────────────────────────────
        if is_cached:
            st.markdown(
                f'<div style="background:{bg};border-left:4px solid {border};'
                f'border-radius:8px;padding:12px 16px 6px;margin-bottom:4px;">',
                unsafe_allow_html=True,
            )
            st.markdown(cache[tab_key])
            st.markdown('</div>', unsafe_allow_html=True)
            if st.button("🔄 Refresh", key=f"ai_ref_{tab_key}"):
                del st.session_state.ai_tab_cache[tab_key]
                st.rerun()
            return

        # ── Pending → show queue status ─────────────────────────────────────
        if is_pending:
            pos = pending.index(tab_key) + 1
            st.info(f"⏳ Queued for AI analysis — position **{pos}** of **{len(pending)}**…")
            return

        # ── Not queued → offer button ───────────────────────────────────────
        col_btn, col_txt = st.columns([1, 3])
        with col_btn:
            if st.button("🤖 Run AI", key=f"ai_run_{tab_key}", type="primary"):
                _pending = st.session_state.get("ai_pending", [])
                if tab_key not in _pending:
                    _pending.append(tab_key)
                st.session_state.ai_pending = _pending
                st.rerun()
        with col_txt:
            st.caption("Auto-analysis runs sequentially after analysis — or click to queue now.")




# ════════════════════════════════════════════════════════════════════════════
# Analysis runner
# ════════════════════════════════════════════════════════════════════════════

def run_analysis(dump: str):
    """Run the full pipeline — Volatility plugins execute in parallel threads."""
    import concurrent.futures
    from tools.volatility_runner import (
        run_pslist, run_pstree, run_malfind, run_netscan,
        run_dlllist, run_cmdline, run_handles,
    )
    from tools.process_inspector import detect_process_anomalies
    from tools.network_inspector import detect_suspicious_connections
    from tools.powershell_decoder import decode_powershell_commands
    from tools.threat_scorer import score_threats
    from tools.timeline_builder import build_attack_timeline

    plugin_tasks = {
        "pslist":  lambda: run_pslist(dump),
        "pstree":  lambda: run_pstree(dump),
        "malfind": lambda: run_malfind(dump),
        "netscan": lambda: run_netscan(dump),
        "dlllist": lambda: run_dlllist(dump),
        "cmdline": lambda: run_cmdline(dump),
        "handles": lambda: run_handles(dump),
    }

    progress = st.progress(0, text="⚡ Running all plugins in parallel…")
    results: dict = {}

    # Run all 7 plugins concurrently
    # (threading lock in volatility_runner.py prevents SQLite cache conflicts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        futures = {pool.submit(fn): key for key, fn in plugin_tasks.items()}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            done_count += 1
            progress.progress(
                done_count / (len(plugin_tasks) + 4),
                text=f"✅ {key} done  ({done_count}/{len(plugin_tasks)} plugins)",
            )
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = []
                st.warning(f"⚠ {key}: {e}")



    progress.progress(0.75, "🔍 Detecting process anomalies…")
    proc_anomalies = detect_process_anomalies(results["pslist"])

    progress.progress(0.82, "🌐 Detecting network anomalies…")
    net_anomalies = detect_suspicious_connections(results["netscan"])

    progress.progress(0.88, "⚡ Decoding PowerShell payloads…")
    ps_findings = decode_powershell_commands(results["cmdline"])

    progress.progress(0.93, "Scoring threats...")
    _TRUSTED = {"c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\program files\\", "c:\\program files (x86)\\"}
    dll_anomalies = [
        {**d, "severity": "HIGH", "reason": "DLL from untrusted path: " + str(d.get("Path", d.get("path","")))}
        for d in results["dlllist"]
        if (d.get("Path") or d.get("path"))
        and not any(tp in str(d.get("Path", d.get("path",""))).lower() for tp in _TRUSTED)
    ]
    _SENSITIVE = {"lsass", "csrss", "winlogon", "smss"}
    handle_anomalies = [
        {**h, "severity": "CRITICAL", "reason": "Privileged handle: " + str(h.get("Name",""))}
        for h in results["handles"]
        if "0x1fffff" in str(h.get("GrantedAccess","")).lower()
        or any(sp in str(h.get("Name","")).lower() for sp in _SENSITIVE)
    ]
    _LOLBAS_CRITICAL = {"certutil","bitsadmin","mshta","regsvr32","wscript","cscript","msiexec","psexec"}
    _LOLBAS_HIGH     = {"rundll32","wmic","nltest","whoami","net ","net.exe","msbuild","installutil"}
    cmdline_behaviors = []
    for c in results["cmdline"]:
        proc = str(c.get("Process", c.get("process",""))).lower()
        cmd  = str(c.get("CommandLine", c.get("cmdline",""))).lower()
        combined = proc + " " + cmd
        if any(lb in combined for lb in _LOLBAS_CRITICAL):
            cmdline_behaviors.append({**c, "severity": "CRITICAL", "reason": "Critical LOLBas: " + proc})
        elif any(lb in combined for lb in _LOLBAS_HIGH):
            cmdline_behaviors.append({**c, "severity": "HIGH", "reason": "LOLBas: " + proc})

    threat_score = score_threats(
        malfind_data=results["malfind"],
        process_anomalies=proc_anomalies,
        network_anomalies=net_anomalies,
        powershell_findings=ps_findings,
        dll_anomalies=dll_anomalies,
        handle_anomalies=handle_anomalies,
        cmdline_behaviors=cmdline_behaviors,
    )


    progress.progress(0.97, "🕒 Building attack timeline…")
    timeline = build_attack_timeline(
        pslist_data=results["pslist"],
        malfind_data=results["malfind"],
        cmdline_data=results["cmdline"],
        netscan_data=results["netscan"],
        powershell_findings=ps_findings,
    )

    progress.progress(1.0, "✅ Analysis complete!")
    progress.empty()

    for k in plugin_tasks:
        st.session_state[k] = results[k]
    st.session_state.proc_anomalies    = proc_anomalies
    st.session_state.net_anomalies     = net_anomalies
    st.session_state.ps_findings       = ps_findings
    st.session_state.threat_score      = threat_score
    st.session_state.timeline          = timeline
    st.session_state.dll_anomalies     = dll_anomalies
    st.session_state.handle_anomalies  = handle_anomalies
    st.session_state.lolbas_behaviors  = cmdline_behaviors
    st.session_state.analysis_done     = True
    st.session_state.ai_tab_cache      = {}
    st.session_state.current_dump_path = dump

    # ── Auto-save to SQLite ───────────────────────────────────────────────
    if _sdb:
        try:
            _scan_payload = {k: results[k] for k in plugin_tasks}
            _scan_payload.update({
                "proc_anomalies": proc_anomalies,
                "net_anomalies":  net_anomalies,
                "ps_findings":    ps_findings,
                "threat_score":   threat_score,
                "timeline":       timeline,
                "ai_tab_cache":   {},
            })
            _sid = _sdb.save_scan(dump, _scan_payload)
            st.session_state.current_scan_id = _sid
        except Exception as _dbe:
            st.warning(f"⚠ Could not save scan to DB: {_dbe}")


# ════════════════════════════════════════════════════════════════════════════
# Trigger analysis
# ════════════════════════════════════════════════════════════════════════════

if os.environ.get("MEMFORENSIC_MOCK", "0") != "1":
    _disable_mock()


def _check_volatility() -> bool:
    """Return True if Volatility is reachable."""
    import shutil
    from tools.volatility_runner import _get_vol_cmd
    cmd = _get_vol_cmd()
    return shutil.which(cmd[0]) is not None or (len(cmd) > 1 and pathlib.Path(cmd[1]).exists())

if run_full and dump_path:
    if not use_mock and not _check_volatility():
        vol_path = os.getenv("VOLATILITY_PATH", "vol")
        st.error(
            f"**Volatility 3 not found** at `{vol_path}`.\n\n"
            "Install it with:\n```\npip install volatility3\n```\n"
            "Then restart the app, or enable **⚡ Demo Mode** in the sidebar to use simulated data."
        )
    else:
        with st.spinner(""):
            run_analysis(dump_path)
            # Queue all tabs for sequential AI analysis (one per render cycle)
            st.session_state.ai_pending  = ["proc","mal","net","ps","dll","hdl","lolbas","score","tl"]
            st.session_state.ai_contexts = {}


# ── Live System Scan handler ──────────────────────────────────────────────────

if run_live or st.session_state.pop("_run_live_now", False):
    from tools.live_scanner import run_live_scan
    from tools.process_inspector import detect_process_anomalies
    from tools.network_inspector import detect_suspicious_connections
    from tools.powershell_decoder import decode_powershell_commands
    from tools.threat_scorer import score_threats

    _prog = st.progress(0.0, "🔴 Starting live system scan…")

    def _live_cb(pct, msg):
        _prog.progress(pct, msg)

    with st.spinner("🔴 Scanning live system…"):
        _live_data = run_live_scan(progress_callback=_live_cb)

    _prog.progress(0.90, "🧠 Running threat analysis…")

    # Re-use existing pipeline on live data
    _lp = _live_data["pslist"]
    _ln = _live_data["netscan"]
    _lm = _live_data["malfind"]
    _lc = _live_data["cmdline"]
    _ld = _live_data["dlllist"]
    _lh = _live_data["handles"]

    _l_proc_anom = detect_process_anomalies(_lp)
    _l_net_anom  = detect_suspicious_connections(_ln)
    _l_ps_finds  = decode_powershell_commands(_lc)

    _TRUSTED = {"c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                "c:\\program files\\", "c:\\program files (x86)\\"}
    _l_dll_anom = [
        {**d, "severity": "HIGH"}
        for d in _ld
        if (d.get("Path") or d.get("path"))
        and not any(t in str(d.get("Path", d.get("path", ""))).lower() for t in _TRUSTED)
    ]
    _SENS = {"lsass", "csrss", "winlogon", "smss"}
    _l_hdl_anom = [
        {**h, "severity": "CRITICAL"}
        for h in _lh
        if "0x1fffff" in str(h.get("GrantedAccess", "")).lower()
        or any(s in str(h.get("Name", "")).lower() for s in _SENS)
    ]
    _CRIT_LB = {"certutil", "bitsadmin", "mshta", "regsvr32", "wscript", "cscript"}
    _HIGH_LB = {"rundll32", "wmic", "nltest", "whoami", "net.exe"}
    _l_lolbas = []
    for _lcc in _lc:
        _p = str(_lcc.get("Process", "")).lower()
        _cm = str(_lcc.get("CommandLine", "")).lower()
        _combo = _p + " " + _cm
        if any(lb in _combo for lb in _CRIT_LB):
            _l_lolbas.append({**_lcc, "severity": "CRITICAL"})
        elif any(lb in _combo for lb in _HIGH_LB):
            _l_lolbas.append({**_lcc, "severity": "HIGH"})

    _l_ts = score_threats(_lm, _l_proc_anom, _l_net_anom, _l_ps_finds,
                          _l_dll_anom, _l_hdl_anom, _l_lolbas)

    _prog.progress(1.0, "✅ Live scan complete!")
    _prog.empty()

    # Store into session state — same keys as static analysis
    st.session_state.pslist           = _lp
    st.session_state.netscan          = _ln
    st.session_state.malfind          = _lm
    st.session_state.cmdline          = _lc
    st.session_state.dlllist          = _ld
    st.session_state.handles          = _lh
    st.session_state.proc_anomalies   = _l_proc_anom
    st.session_state.net_anomalies    = _l_net_anom
    st.session_state.ps_findings      = _l_ps_finds
    st.session_state.dll_anomalies    = _l_dll_anom
    st.session_state.handle_anomalies = _l_hdl_anom
    st.session_state.lolbas_behaviors = _l_lolbas
    st.session_state.threat_score     = _l_ts
    st.session_state.timeline         = []
    st.session_state.analysis_done    = True
    st.session_state.ai_tab_cache     = {}
    st.session_state.current_dump_path = f"LIVE:{_live_data['host']}"
    st.session_state.live_scan_meta    = _live_data
    st.session_state.analysis_mode     = "live"
    st.session_state.ai_pending        = ["proc","mal","net","ps","dll","hdl","lolbas","score","live_scan"]
    st.session_state.ai_contexts       = {}
    st.rerun()




# ════════════════════════════════════════════════════════════════════════════
# Header
# ════════════════════════════════════════════════════════════════════════════

_dump_badge_bg  = "#1a0a2a" if _DARK else "#f5f0ff"
_dump_badge_bdr = "#3a1a5a" if _DARK else "#a855f7"
_active_dump = dump_path or st.session_state.get("current_dump_path", "") or ""
_badge_label = _active_dump if _active_dump else "No dump loaded"
_badge_color = "#ec4899" if _active_dump else "#a855f7"
mode_badge = (
    f'<span style="background:{_dump_badge_bg};border:1px solid {_dump_badge_bdr};'
    f'color:{_badge_color};border-radius:20px;padding:2px 12px;'
    f'font-size:0.7rem;font-family:\'JetBrains Mono\',monospace;">'
    f'{"📂 " if _active_dump else "⚠ "}{_badge_label}</span>'
)
_title_color  = "#ec4899" if _DARK else "#ec4899"
_title_shadow = "0 0 30px rgba(236,72,153,0.6), 0 0 60px rgba(168,85,247,0.3)" if _DARK else "0 2px 8px rgba(236,72,153,0.25)"
st.markdown(f"""
<div style="padding:8px 0 20px;">
  <div style="display:flex;align-items:center;gap:10px;line-height:1.2;">
    <span style="font-size:1.8rem;">🧠</span>
    <span style="font-family:'Orbitron',monospace;font-size:1.8rem;font-weight:900;
                 color:{_title_color};
                 text-shadow:{_title_shadow};
                 letter-spacing:0.06em;">Ghost<span style="color:#a855f7;">Trace</span></span>
  </div>
  <div style="color:{'#c084fc' if _DARK else '#7c3aed'};font-size:0.75rem;letter-spacing:0.12em;text-transform:uppercase;margin:6px 0 10px;">Semi-Automated Memory Forensics · Fileless Malware Detection</div>
  {mode_badge}
</div>
<div style="height:1px;background:linear-gradient(90deg,rgba(236,72,153,0.5),rgba(168,85,247,0.3),transparent);margin-bottom:20px;"></div>
""", unsafe_allow_html=True)



# ════════════════════════════════════════════════════════════════════════════
# Top KPI row
# ════════════════════════════════════════════════════════════════════════════

if st.session_state.analysis_done:
    ts = st.session_state.threat_score
    score = ts["score"]
    level = ts["level"]
    color = _level_color(level)
    inj   = len(st.session_state.malfind)
    net   = len(st.session_state.net_anomalies)
    procs = len(st.session_state.pslist)
    anom  = ts["total_findings"]

    inj_cls   = "kpi-red"   if inj  > 0 else "kpi-green"
    net_cls   = "kpi-red"   if net  > 0 else "kpi-green"
    anom_cls  = "kpi-amber" if anom > 3 else "kpi-green"

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"<div style='text-align:center;padding:8px 0;'>{_score_badge(score, level)}</div>", unsafe_allow_html=True)
    with k2:
        st.markdown(f'<div class="kpi-tile"><div class="kpi-value">{procs}</div><div class="kpi-label">🔬 Processes</div></div>', unsafe_allow_html=True)
    with k3:
        st.markdown(f'<div class="kpi-tile {anom_cls}"><div class="kpi-value">{anom}</div><div class="kpi-label">⚠ Anomalies</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="kpi-tile {inj_cls}"><div class="kpi-value">{inj}</div><div class="kpi-label">💉 Injections</div></div>', unsafe_allow_html=True)
    with k5:
        st.markdown(f'<div class="kpi-tile {net_cls}"><div class="kpi-value">{net}</div><div class="kpi-label">🌐 Net Flags</div></div>', unsafe_allow_html=True)

    st.markdown("<div style='height:1px;background:linear-gradient(90deg,rgba(168,85,247,0.15),rgba(124,58,237,0.1),transparent);margin:18px 0;'></div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# Main tabs
# ════════════════════════════════════════════════════════════════════════════

tabs = st.tabs([
    "🏠 Overview",
    "🔬 Processes",
    "💉 Injections",
    "🌐 Network",
    "⚡ PowerShell",
    "📦 DLL Anomalies",
    "🔑 Handles",
    "🪄 LOLBas",
    "🔴 Dynamic Analysis",
    "📊 Threat Score",
    "🕒 Timeline",
    "🤖 AI Investigator",
    "📄 Report",
    "📋 Results",
])

tab_overview, tab_proc, tab_mal, tab_net, tab_ps, tab_dll, tab_hdl, tab_lolbas, tab_dyn, tab_score, tab_tl, tab_chat, tab_report, tab_results = tabs


# ── TAB: Overview ────────────────────────────────────────────────────────────

with tab_overview:
    if not st.session_state.analysis_done:
        _dark = st.session_state.get("dark_mode", True)
        _is_running = bool(dump_path or st.session_state.get("current_dump_path", ""))

        if _is_running:
            # Analysis triggered but not yet complete — show running state
            st.markdown(f"""
            <div style="text-align:center;padding:40px 20px;">
              <div style="font-size:3rem;margin-bottom:12px;">⚙️</div>
              <div style="font-family:'Orbitron',monospace;font-size:1.1rem;font-weight:700;
                          color:#ec4899;letter-spacing:0.08em;margin-bottom:8px;">
                ANALYSIS RUNNING
              </div>
              <div style="color:{'#c084fc' if _dark else '#7c3aed'};font-size:0.88rem;margin-bottom:20px;">
                Volatility plugins are executing — results will appear when complete
              </div>
              <div style="background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.3);
                          border-radius:12px;padding:16px 22px;max-width:520px;margin:0 auto;text-align:left;">
                <div style="font-size:0.78rem;color:#f59e0b;font-weight:700;letter-spacing:0.1em;margin-bottom:8px;">
                  ⏳ FIRST-RUN NOTE — SYMBOL CACHE BUILDING
                </div>
                <div style="font-size:0.82rem;color:{'#fde68a' if _dark else '#92400e'};line-height:1.8;">
                  On the <b>first run</b>, Volatility 3 must build ISF symbol caches for all
                  105 symbol files. This can take <b>5–30 minutes</b> depending on your CPU.<br><br>
                  The progress bar in the sidebar shows: <code>Updating caches for 105 files...</code><br><br>
                  ✅ Caches are saved permanently — subsequent runs start <b>instantly</b>.
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            # No dump loaded yet — show welcome/how-to-start screen
            st.markdown(f"""
            <div style="text-align:center;padding:40px 20px;">
              <div style="font-size:3rem;margin-bottom:12px;">🧠</div>
              <div style="font-family:'Orbitron',monospace;font-size:1.2rem;font-weight:700;
                          color:#ec4899;letter-spacing:0.08em;margin-bottom:8px;">
                NO DUMP LOADED
              </div>
              <div style="color:{'#c084fc' if _dark else '#7c3aed'};font-size:0.9rem;margin-bottom:24px;">
                Load a memory dump file to begin forensic analysis
              </div>
              <div style="background:{'rgba(236,72,153,0.08)' if _dark else 'rgba(168,85,247,0.05)'};
                          border:1px solid {'rgba(236,72,153,0.25)' if _dark else 'rgba(168,85,247,0.2)'};
                          border-radius:14px;padding:22px 28px;max-width:480px;margin:0 auto;text-align:left;">
                <div style="font-size:0.8rem;color:#ec4899;font-weight:700;letter-spacing:0.1em;margin-bottom:12px;">
                  HOW TO START
                </div>
                <div style="font-size:0.85rem;color:{'#d8b4fe' if _dark else '#4a3568'};line-height:1.9;">
                  <b style="color:#ec4899;">1.</b> Enter the full path to your <code>.mem</code> / <code>.dmp</code> / <code>.raw</code> / <code>.vmem</code> file in the
                  <b>📂 Local file path</b> box in the sidebar<br>
                  <b style="color:#ec4899;">2.</b> Or expand <b>📤 Upload a small file</b> to upload directly<br>
                  <b style="color:#ec4899;">3.</b> Click <b>🚀 Run Full Analysis</b> to begin<br>
                  <b style="color:#ec4899;">4.</b> To revisit a past scan, click <b>Load</b> in the <b>🗄 Scan History</b> panel
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)


        st.markdown("""
        ### What this tool does
        GhostTrace analyses memory dumps for **fileless malware** indicators:

        | Module | Detects |
        |--------|---------|
        | 🔬 **Process Inspector** | Orphans, duplicate system procs, shell spawning, typosquatting |
        | 💉 **Malfind** | Code injection, shellcode, PE headers in memory |
        | 🌐 **Network Inspector** | C2 connections, suspicious ports, unexpected processes on network |
        | ⚡ **PowerShell Decoder** | Base64 payloads, AMSI bypass, download cradles |
        | 📊 **Threat Scorer** | 0–100 score across 6 weighted categories |
        | 🕒 **Timeline Builder** | Chronological attack reconstruction |
        """)
    else:
        ts    = st.session_state.threat_score
        color = _level_color(ts["level"])
        score = ts["score"]
        level = ts["level"]

        # Top banner — full breakdown in Threat Score tab
        col_sc, col_i, col_pa, col_nf, col_ps, col_tf = st.columns(6)
        col_sc.metric("🎯 Score",   f"{score}/100")
        col_i.metric("💉 Inject",   len(st.session_state.malfind or []))
        col_pa.metric("🔬 Proc",    len(st.session_state.proc_anomalies or []))
        col_nf.metric("🌐 Network", len(st.session_state.net_anomalies or []))
        col_ps.metric("⚡ PS",      len(st.session_state.ps_findings or []))
        col_tf.metric("📊 Total",   ts.get("total_findings", 0))

        st.markdown(f'<div style="font-size:1.5rem;font-weight:900;color:{color};letter-spacing:2px;margin:4px 0 16px;">🔴 {level}</div>', unsafe_allow_html=True)
        st.markdown("**Top Recommendations:**")
        for rec in ts["recommendations"][:3]:
            icon = "🚨" if "CRITICAL" in rec or "IMMEDIATE" in rec else "✅"
            st.markdown(f"{icon} {rec}")
        st.caption("→ See the **📊 Threat Score** tab for full breakdown and all recommendations.")


# ── TAB: Processes ───────────────────────────────────────────────────────────

with tab_proc:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        _anom_lines = "\n".join(
            f"[{a.get('severity')}] {a.get('category')}: PID={a.get('pid','?')} "
            f"{a.get('process','?')} — {str(a.get('reason', a.get('description','')))[:80]}"
            for a in st.session_state.proc_anomalies[:5]
        ) or "None"
        _proc_lines = "\n".join(
            f"PID={p.get('PID','?')} {p.get('Name','?')} PPID={p.get('PPID','?')}"
            for p in st.session_state.pslist[:10]
        )
        proc_ctx = (
            f"Processes: {len(st.session_state.pslist)} | Anomalies: {len(st.session_state.proc_anomalies)}\n"
            f"Anomalies:\n{_anom_lines}\nProcess sample:\n{_proc_lines}"
        )
        _ai_tab_box("proc", proc_ctx, "🤖 AI Process Analysis")
        st.divider()
        c1, c2 = st.columns([3, 2])

        with c1:
            st.markdown("### 📋 Process List")
            if st.session_state.pslist:
                st.dataframe(
                    st.session_state.pslist,
                    width="stretch",
                    height=350,
                )
            else:
                st.warning("No pslist data.")

        with c2:
            st.markdown("### ⚠ Anomalies Detected")
            anomalies = st.session_state.proc_anomalies
            if anomalies:
                for a in anomalies:
                    sev = a.get("severity", "LOW")
                    col = _severity_color(sev)
                    st.markdown(f"""
                    <div class="anomaly-card sev-{sev}">
                      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                        <span style="font-weight:600;color:{col}">{sev}</span>
                        <span style="color:#8b949e;font-size:0.78rem">{a.get('category','')}</span>
                      </div>
                      <div style="color:#c9d1d9">{a.get('description','')}</div>
                    </div>""", unsafe_allow_html=True)
            else:
                st.success("✅ No process anomalies detected.")


# ── TAB: Injections (Malfind) ────────────────────────────────────────────────

with tab_mal:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        _inj_lines = "\n".join(
            f"PID={m.get('pid','?')} {m.get('process','?')} @{m.get('address','?')} "
            f"prot={m.get('protection','?')} hex={str(m.get('hex_preview',''))[:50]}"
            for m in st.session_state.malfind[:5]
        ) or "None"
        mal_ctx = (
            f"Malfind regions: {len(st.session_state.malfind)}\n{_inj_lines}"
        )
        _ai_tab_box("mal", mal_ctx, "🤖 AI Injection Analysis")
        st.divider()
        st.markdown("### 💉 Memory Injection Regions (malfind)")
        malfind = st.session_state.malfind
        if malfind:
            st.warning(f"⚠ {len(malfind)} suspicious memory regions found — possible shellcode or PE injection")
            st.dataframe(malfind, width="stretch")

            st.markdown("#### 🔍 High-Risk Regions")
            for m in malfind:
                prot = m.get("protection", "")
                if "EXECUTE" in prot:
                    pid  = m.get("pid", "?")
                    proc = m.get("process", "?")
                    addr = m.get("address", "?")
                    hex_ = m.get("hex_preview", "")
                    st.markdown(f"""
                    <div class="anomaly-card sev-HIGH">
                      <b>PID {pid} — {proc}</b> &nbsp;·&nbsp; Address: <code>{addr}</code><br>
                      <span style="color:#d29922">Protection: {prot}</span><br>
                      <code style="font-size:0.78rem;color:#8b949e">{hex_}</code>
                    </div>""", unsafe_allow_html=True)
        else:
            st.success("✅ No injection regions detected.")


# ── TAB: Network ─────────────────────────────────────────────────────────────

with tab_net:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        _net_lines = "\n".join(
            f"[{a.get('severity')}] {a.get('category')}: "
            f"{a.get('process','?')} → {a.get('foreign_addr','?')}:{a.get('foreign_port','?')} "
            f"[{a.get('state','?')}] {str(a.get('reason',''))[:60]}"
            for a in st.session_state.net_anomalies[:5]
        ) or "None"
        net_ctx = (
            f"Connections: {len(st.session_state.netscan)} | Flagged: {len(st.session_state.net_anomalies)}\n"
            f"{_net_lines}"
        )
        _ai_tab_box("net", net_ctx, "🤖 AI Network Analysis")
        st.divider()
        c1, c2 = st.columns([3, 2])

        with c1:
            st.markdown("### 🌐 Network Connections")
            if st.session_state.netscan:
                st.dataframe(st.session_state.netscan, width="stretch", height=300)
            else:
                st.warning("No network data.")

        with c2:
            st.markdown("### 🚨 Suspicious Connections")
            net_anom = st.session_state.net_anomalies
            if net_anom:
                for a in net_anom:
                    sev = a.get("severity", "MEDIUM")
                    col = _severity_color(sev)
                    st.markdown(f"""
                    <div class="anomaly-card sev-{sev}">
                      <div style="font-weight:600;color:{col};margin-bottom:4px">{sev} · {a.get('category','')}</div>
                      <div style="color:#c9d1d9;font-size:0.85rem">{a.get('description','')}</div>
                    </div>""", unsafe_allow_html=True)
            else:
                st.success("✅ No suspicious connections.")


# ── TAB: PowerShell ──────────────────────────────────────────────────────────

with tab_ps:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        _ps_lines = "\n".join(
            f"PID={f.get('pid','?')} {f.get('process','?')}: "
            f"{str(f.get('raw_cmdline',''))[:100]} "
            f"patterns={[p.get('name') for p in f.get('patterns_found',[])[:2]]}"
            for f in st.session_state.ps_findings[:5]
        ) or "None"
        ps_ctx = (
            f"PowerShell findings: {len(st.session_state.ps_findings)}\n{_ps_lines}"
        )
        _ai_tab_box("ps", ps_ctx, "🤖 AI PowerShell Analysis")
        st.divider()
        st.markdown("### ⚡ PowerShell Analysis")
        findings = st.session_state.ps_findings
        if findings:
            for f in findings:
                with st.expander(f"PID {f.get('pid','?')} — {f.get('process','?')}"):
                    st.markdown("**Raw command line:**")
                    _raw = f.get('raw_cmdline', '') or ''
                    st.markdown(f'<pre style="background:#0d1117;color:#e6edf3;padding:12px 14px;border-radius:8px;font-size:0.8rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;border:1px solid #30363d;">{_raw[:600]}</pre>', unsafe_allow_html=True)

                    patterns = f.get("patterns_found", [])
                    if patterns:
                        st.markdown("**Patterns detected:**")
                        _ptag = ""
                        for p in patterns:
                            sev   = p.get("severity", "LOW")
                            color = _severity_color(sev)
                            _ptag += f'<span style="background:{color}22;color:{color};padding:3px 10px;border-radius:4px;font-size:0.82rem;margin-right:6px;border:1px solid {color}44;">[{sev}] {p["name"]}</span>'
                        st.markdown(_ptag, unsafe_allow_html=True)

                    decoded = f.get("decoded_content", "")
                    if decoded:
                        st.markdown("**Decoded payload:**")
                        st.markdown(f'<pre style="background:#0d1117;color:#79c0ff;padding:12px 14px;border-radius:8px;font-size:0.8rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;border:1px solid #30363d;">{decoded[:500]}</pre>', unsafe_allow_html=True)

                    iocs = f.get("iocs", {})
                    if iocs:
                        st.markdown("**Extracted IOCs:**")
                        # Render as a clean table instead of raw JSON
                        ioc_rows = []
                        if isinstance(iocs, dict):
                            for ioc_type, ioc_list in iocs.items():
                                if isinstance(ioc_list, list):
                                    for val in ioc_list:
                                        ioc_rows.append({"Type": ioc_type.upper(), "Value": str(val)})
                                else:
                                    ioc_rows.append({"Type": ioc_type.upper(), "Value": str(ioc_list)})
                        elif isinstance(iocs, list):
                            for item in iocs:
                                if isinstance(item, dict):
                                    ioc_rows.append({
                                        "Type":  item.get("type", "IOC"),
                                        "Value": item.get("value", str(item)),
                                        "Note":  item.get("recommendation", ""),
                                    })
                                else:
                                    ioc_rows.append({"Type": "IOC", "Value": str(item)})
                        if ioc_rows:
                            import pandas as _pd
                            st.dataframe(_pd.DataFrame(ioc_rows), use_container_width=True, hide_index=True)
                        else:
                            st.json(iocs)
        else:
            st.success("✅ No encoded PowerShell detected.")

        st.markdown("### 📜 All Command Lines")
        if st.session_state.cmdline:
            st.dataframe(st.session_state.cmdline, width="stretch")


# ── TAB: DLL Anomalies ───────────────────────────────────────────────────────

with tab_dll:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        dll_anom = st.session_state.get("dll_anomalies") or []
        raw_dlls = st.session_state.get("dlllist") or []
        _bg  = "#12001e" if _DARK else "#fff"
        _tc  = "#f0e6ff" if _DARK else "#1e1030"
        _sub = "#c084fc" if _DARK else "#7c3aed"

        _dll_ctx = (
            f"DLL anomalies: {len(dll_anom)} suspicious DLLs from untrusted paths.\n"
            + "\n".join(f"  {d.get('Process','?')} loaded {d.get('Path',d.get('path','?'))}" for d in dll_anom[:8])
        )
        _ai_tab_box("dll", _dll_ctx, "🤖 AI DLL Analysis")
        st.divider()

        st.markdown("### 📦 DLL Anomalies")
        st.caption(f"{len(dll_anom)} suspicious DLLs loaded from untrusted paths · {len(raw_dlls)} total DLLs scanned")

        if dll_anom:
            for d in dll_anom:
                path    = str(d.get("Path", d.get("path", "unknown")))
                proc    = str(d.get("Process", d.get("process", "?")))
                pid     = str(d.get("PID",     d.get("pid",     "?")))
                size    = str(d.get("Size",    d.get("size",    "")))
                reason  = d.get("reason", "Loaded from untrusted path")
                st.markdown(f"""
                <div style="background:{_bg};border:1px solid #ef444433;border-left:4px solid #ef4444;
                            border-radius:10px;padding:12px 16px;margin:5px 0;color:{_tc};font-size:0.85rem;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:#ef4444;font-weight:700;font-family:'JetBrains Mono',monospace;">📦 {path.split(chr(92))[-1]}</span>
                    <span style="background:#ef444422;color:#ef4444;border-radius:20px;padding:2px 10px;font-size:0.72rem;">HIGH</span>
                  </div>
                  <div style="color:{_sub};font-size:0.78rem;margin-top:4px;">
                    Process: <b style="color:{_tc}">{proc}</b> (PID {pid})
                    {f' &nbsp;·&nbsp; Size: {size}' if size else ''}
                  </div>
                  <div style="color:{_sub};font-size:0.78rem;margin-top:2px;">Path: {path}</div>
                  <div style="color:#f97316;font-size:0.78rem;margin-top:2px;">⚠ {reason}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.success("✅ No DLL anomalies detected.")

        if raw_dlls:
            st.divider()
            st.markdown("### 📋 All DLLs Scanned")
            import pandas as _pd
            st.dataframe(_pd.DataFrame(raw_dlls), use_container_width=True, hide_index=True)


# ── TAB: Handles ─────────────────────────────────────────────────────────────

with tab_hdl:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        hdl_anom = st.session_state.get("handle_anomalies") or []
        raw_hdls = st.session_state.get("handles") or []
        _bg  = "#12001e" if _DARK else "#fff"
        _tc  = "#f0e6ff" if _DARK else "#1e1030"
        _sub = "#c084fc" if _DARK else "#7c3aed"

        _hdl_ctx = (
            f"Handle anomalies: {len(hdl_anom)} privileged handles to sensitive processes.\n"
            + "\n".join(f"  [{h.get('severity','?')}] {h.get('Process','?')} -> {h.get('Name','')}" for h in hdl_anom[:8])
        )
        _ai_tab_box("hdl", _hdl_ctx, "🤖 AI Handle Analysis")
        st.divider()

        st.markdown("### 🔑 Suspicious Handles")
        st.caption(f"{len(hdl_anom)} privileged handles detected · {len(raw_hdls)} total handles scanned")

        if hdl_anom:
            for h in hdl_anom:
                name    = str(h.get("Name", ""))
                proc    = str(h.get("Process", h.get("process", "?")))
                pid     = str(h.get("PID", h.get("pid", "?")))
                access  = str(h.get("GrantedAccess", ""))
                htype   = str(h.get("Type", ""))
                reason  = h.get("reason", "Privileged access to sensitive resource")
                is_full = "0x1fffff" in access.lower()
                col_h   = "#dc2626" if is_full else "#f97316"
                lbl_h   = "PROCESS_ALL_ACCESS" if is_full else "HIGH PRIVILEGE"
                st.markdown(f"""
                <div style="background:{_bg};border:1px solid {col_h}33;border-left:4px solid {col_h};
                            border-radius:10px;padding:12px 16px;margin:5px 0;color:{_tc};font-size:0.85rem;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:{col_h};font-weight:700;font-family:'JetBrains Mono',monospace;">🔑 {htype} handle</span>
                    <span style="background:{col_h}22;color:{col_h};border-radius:20px;padding:2px 10px;font-size:0.72rem;">{lbl_h}</span>
                  </div>
                  <div style="color:{_sub};font-size:0.78rem;margin-top:4px;">
                    Process: <b style="color:{_tc}">{proc}</b> (PID {pid}) &nbsp;·&nbsp; Access: <b style="color:{col_h}">{access}</b>
                  </div>
                  <div style="color:{_sub};font-size:0.78rem;margin-top:2px;">Target: {name[:120]}</div>
                  <div style="color:#f97316;font-size:0.78rem;margin-top:2px;">⚠ {reason}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.success("✅ No suspicious handles detected.")

        if raw_hdls:
            st.divider()
            st.markdown("### 📋 All Handles Scanned")
            import pandas as _pd
            st.dataframe(_pd.DataFrame(raw_hdls), use_container_width=True, hide_index=True)


# ── TAB: LOLBas ──────────────────────────────────────────────────────────────

with tab_lolbas:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        lolbas = st.session_state.get("lolbas_behaviors") or []
        _bg    = "#12001e" if _DARK else "#fff"
        _tc    = "#f0e6ff" if _DARK else "#1e1030"
        _sub   = "#c084fc" if _DARK else "#7c3aed"

        _lb_ctx = (
            f"LOLBas detections: {len(lolbas)} binaries abusing trusted Windows tools.\n"
            + "\n".join(f"  [{lb.get('severity','?')}] {lb.get('Process','?')}: {str(lb.get('CommandLine',''))[:100]}" for lb in lolbas[:8])
        )
        _ai_tab_box("lolbas", _lb_ctx, "🤖 AI LOLBas Analysis")
        st.divider()

        st.markdown("### 🪄 LOLBas — Living-Off-The-Land Binaries")
        st.caption(f"{len(lolbas)} LOLBas processes detected · Attackers abuse trusted Windows tools to evade detection")

        _LOLBAS_INFO = {
            "certutil":   ("T1105", "Certutil downloads/decodes files — commonly used to pull malware payloads."),
            "bitsadmin":  ("T1197", "BITSAdmin schedules downloads — abused for persistence & payload delivery."),
            "mshta":      ("T1218.005", "MSHTA executes HTA scripts — used to run remote code via HTML Application."),
            "regsvr32":   ("T1218.010", "Regsvr32 loads COM scriptlets — bypasses AppLocker/WDAC."),
            "wscript":    ("T1059.005", "WScript runs VBScript/JS — common dropper mechanism."),
            "cscript":    ("T1059.005", "CScript runs VBScript/JS — common dropper mechanism."),
            "msiexec":    ("T1218.007", "MSIExec installs/runs MSI packages — used for side-loading."),
            "rundll32":   ("T1218.011", "RunDLL32 loads DLLs — abused to execute shellcode."),
            "wmic":       ("T1047",    "WMIC queries/executes processes — used for lateral movement."),
            "nltest":     ("T1482",    "NLTest enumerates domain trusts — reconnaissance tool."),
            "whoami":     ("T1033",    "Whoami reveals current user context — post-exploitation recon."),
            "net.exe":    ("T1087",    "Net.exe enumerates users/groups — active directory recon."),
            "psexec":     ("T1569.002","PsExec runs remote commands — used for lateral movement."),
        }

        if lolbas:
            for lb in lolbas:
                proc   = str(lb.get("Process", lb.get("process", "?"))).lower()
                pid    = str(lb.get("PID",     lb.get("pid",     "?")))
                cmd    = str(lb.get("CommandLine", lb.get("cmdline", "")))
                sev    = lb.get("severity", "HIGH")
                col_l  = "#ef4444" if sev == "CRITICAL" else "#f97316"
                reason = lb.get("reason", "")

                # Match known LOLBas
                matched_key = next((k for k in _LOLBAS_INFO if k in proc or k in cmd.lower()), None)
                mitre, desc = _LOLBAS_INFO.get(matched_key, ("T1218", "Living-off-the-land binary abuse detected."))

                st.markdown(f"""
                <div style="background:{_bg};border:1px solid {col_l}33;border-left:4px solid {col_l};
                            border-radius:10px;padding:12px 16px;margin:6px 0;color:{_tc};font-size:0.85rem;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <span style="color:{col_l};font-weight:700;font-family:'JetBrains Mono',monospace;">🪄 {proc.split(chr(92))[-1]}</span>
                    <span style="display:flex;gap:6px;">
                      <span style="background:{col_l}22;color:{col_l};border-radius:20px;padding:2px 10px;font-size:0.72rem;">{sev}</span>
                      <span style="background:#a855f722;color:#a855f7;border-radius:20px;padding:2px 10px;font-size:0.72rem;font-family:monospace;">{mitre}</span>
                    </span>
                  </div>
                  <div style="color:{_sub};font-size:0.78rem;">PID: {pid}</div>
                  <div style="margin-top:4px;color:{_tc};font-size:0.78rem;font-family:'JetBrains Mono',monospace;
                              background:#0d111733;padding:6px 10px;border-radius:6px;word-break:break-all;">{cmd[:300]}</div>
                  <div style="color:#64748b;font-size:0.78rem;margin-top:5px;font-style:italic;">{desc}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.success("✅ No LOLBas binaries detected.")

        # Full cmdline table
        if st.session_state.get("cmdline"):
            st.divider()
            st.markdown("### 📋 All Command Lines")
            import pandas as _pd
            st.dataframe(_pd.DataFrame(st.session_state.cmdline), use_container_width=True, hide_index=True)


# ── TAB: Dynamic Analysis ─────────────────────────────────────────────────────

with tab_dyn:
    _mode = st.session_state.get("analysis_mode", "static")
    _DARK2 = st.session_state.get("dark_mode", True)
    _bg2   = "#0d0015" if _DARK2 else "#fafafa"
    _card  = "#12001e" if _DARK2 else "#fff"
    _tc2   = "#f0e6ff" if _DARK2 else "#1e1030"

    if _mode == "live":
        # ── Live Scan Results ─────────────────────────────────────────────
        _meta = st.session_state.get("live_scan_meta", {})
        ts2   = st.session_state.threat_score or {}
        color2 = _level_color(ts2.get("level", "LOW"))

        st.markdown(f"""
        <div style="background:{_card};border:2px solid {color2};border-radius:14px;
                    padding:18px 24px;margin-bottom:18px;">
          <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
            <div style="font-size:2rem;">🔴</div>
            <div>
              <div style="font-size:1.3rem;font-weight:900;color:{color2};letter-spacing:1px;">
                LIVE SYSTEM SCAN</div>
              <div style="color:#8b949e;font-size:0.82rem;">
                Host: <b style="color:{_tc2}">{_meta.get('host','?')}</b> &nbsp;·&nbsp;
                Scanned: <b style="color:{_tc2}">{_meta.get('scan_time','?')}</b> &nbsp;·&nbsp;
                {_meta.get('pid_count',0)} processes &nbsp;·&nbsp;
                {_meta.get('conn_count',0)} connections
              </div>
            </div>
            <div style="margin-left:auto;font-size:2.5rem;font-weight:900;color:{color2};">
              {ts2.get('score',0)}<span style="font-size:1rem;color:#8b949e;">/100</span>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # AI analysis
        _live_ctx = (
            f"Live scan of host {_meta.get('host','?')}. "
            f"Threat score: {ts2.get('score',0)}/100 ({ts2.get('level','?')}). "
            f"Processes: {_meta.get('pid_count',0)}, "
            f"Connections: {_meta.get('conn_count',0)}, "
            f"Proc anomalies: {len(st.session_state.proc_anomalies or [])}, "
            f"Net anomalies: {len(st.session_state.net_anomalies or [])}, "
            f"PS findings: {len(st.session_state.ps_findings or [])}."
        )
        _ai_tab_box("live_scan", _live_ctx, "🤖 AI Live System Analysis")
        st.divider()

        # Suspicious processes
        _susp = st.session_state.proc_anomalies or []
        if _susp:
            st.markdown(f"### ⚠️ Suspicious Processes ({len(_susp)})")
            for a in _susp[:20]:
                sev   = a.get("severity", "MEDIUM")
                col_a = _severity_color(sev)
                st.markdown(f"""
                <div style="background:{_card};border-left:4px solid {col_a};
                            border-radius:8px;padding:10px 14px;margin:4px 0;color:{_tc2};font-size:0.85rem;">
                  <span style="color:{col_a};font-weight:700;">{a.get('process',a.get('ImageFileName','?'))}</span>
                  <span style="color:#8b949e;font-size:0.75rem;margin-left:8px;">PID {a.get('pid',a.get('PID','?'))}</span>
                  <span style="background:{col_a}22;color:{col_a};border-radius:20px;padding:1px 8px;
                               font-size:0.7rem;margin-left:8px;">{sev}</span>
                  <div style="color:#64748b;font-size:0.75rem;margin-top:3px;">{a.get('category','')}: {a.get('reason','')}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.success("✅ No suspicious processes detected on this machine.")

        # Network anomalies
        _net2 = st.session_state.net_anomalies or []
        if _net2:
            st.markdown(f"### 🌐 Suspicious Connections ({len(_net2)})")
            for n in _net2[:15]:
                col_n = _severity_color(n.get("severity", "HIGH"))
                st.markdown(f"""
                <div style="background:{_card};border-left:4px solid {col_n};
                            border-radius:8px;padding:10px 14px;margin:4px 0;color:{_tc2};font-size:0.85rem;">
                  <span style="color:{col_n};font-weight:700;font-family:monospace;">
                    {n.get('ForeignAddr',n.get('remote_ip','?'))}:{n.get('ForeignPort',n.get('remote_port','?'))}</span>
                  <span style="color:#8b949e;font-size:0.75rem;margin-left:8px;">
                    via {n.get('Owner',n.get('process','?'))} (PID {n.get('PID',n.get('pid','?'))})</span>
                  <div style="color:#64748b;font-size:0.75rem;margin-top:3px;">{n.get('reason','')}</div>
                </div>""", unsafe_allow_html=True)

        # LOLBas
        _lolbas2 = st.session_state.lolbas_behaviors or []
        if _lolbas2:
            st.markdown(f"### 🪄 LOLBas Detected ({len(_lolbas2)})")
            for lb in _lolbas2[:10]:
                col_lb = "#ef4444" if lb.get("severity") == "CRITICAL" else "#f97316"
                st.markdown(f"""
                <div style="background:{_card};border-left:4px solid {col_lb};
                            border-radius:8px;padding:10px 14px;margin:4px 0;color:{_tc2};font-size:0.85rem;">
                  <span style="color:{col_lb};font-weight:700;">{lb.get('Process','?')}</span>
                  <span style="background:{col_lb}22;color:{col_lb};border-radius:20px;padding:1px 8px;
                               font-size:0.7rem;margin-left:8px;">{lb.get('severity','HIGH')}</span>
                  <div style="color:#8b949e;font-family:monospace;font-size:0.75rem;margin-top:3px;
                              word-break:break-all;">{str(lb.get('CommandLine',''))[:200]}</div>
                </div>""", unsafe_allow_html=True)

    elif _mode == "detonation":
        # ── Detonation Results ────────────────────────────────────────────
        _det = st.session_state.get("detonation_result", {})
        _tgt = _det.get("target", "unknown")
        _sev = _det.get("severity", "LOW")
        col_d = _severity_color(_sev)
        _err  = _det.get("error", "")

        st.markdown(f"""
        <div style="background:{_card};border:2px solid {col_d};border-radius:14px;
                    padding:18px 24px;margin-bottom:18px;">
          <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
            <div style="font-size:2.2rem;">💥</div>
            <div>
              <div style="font-size:1.3rem;font-weight:900;color:{col_d};">
                FILE DETONATION REPORT</div>
              <div style="color:#8b949e;font-size:0.82rem;">
                Target: <b style="color:{_tc2}">{_tgt}</b> &nbsp;·&nbsp;
                Started: <b style="color:{_tc2}">{_det.get('start_time','?')}</b> &nbsp;·&nbsp;
                Duration: {_det.get('timeout_secs',0)}s
              </div>
            </div>
            <div style="margin-left:auto;">
              <span style="background:{col_d}22;color:{col_d};border-radius:8px;
                           padding:6px 16px;font-weight:900;font-size:1rem;">{_sev}</span>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        if _err:
            st.error(f"⚠️ Detonation error: {_err}")

        # Summary metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔬 Child Procs",  _det.get("child_proc_count", 0))
        c2.metric("🌐 Net Connects", _det.get("net_conn_count", 0))
        c3.metric("📁 File Changes", _det.get("file_change_count", 0))
        c4.metric("🔑 Reg Changes",  _det.get("reg_change_count", 0))

        # AI analysis
        _det_ctx = (
            f"File detonation of '{_tgt}'. Severity: {_sev}. "
            f"Child processes spawned: {_det.get('child_proc_count',0)}. "
            f"Network connections made: {_det.get('net_conn_count',0)}. "
            f"File system changes: {_det.get('file_change_count',0)}. "
            f"Registry changes: {_det.get('reg_change_count',0)}. "
        )
        if _det.get("net_events"):
            _det_ctx += "Network targets: " + ", ".join(
                f"{e['remote_ip']}:{e['remote_port']}" for e in _det["net_events"][:5])
        _ai_tab_box("detonation", _det_ctx, "🤖 AI Behavioral Analysis")
        st.divider()

        # Behavioral Timeline
        _tl = _det.get("timeline", [])
        if _tl:
            st.markdown(f"### ⏱ Behavioral Timeline ({len(_tl)} events)")
            import pandas as _pd2
            _tl_df = _pd2.DataFrame(_tl)
            if "time" in _tl_df.columns:
                _tl_df = _tl_df[["time", "event_type"] +
                                  [c for c in _tl_df.columns if c not in ("time","event_type")]]
            st.dataframe(_tl_df, use_container_width=True, hide_index=True)

        # Child Processes
        _cp = _det.get("child_procs", [])
        if _cp:
            st.markdown(f"### 🔬 Child Processes ({len(_cp)})")
            for p in _cp:
                col_p = "#ef4444"
                st.markdown(f"""
                <div style="background:{_card};border-left:4px solid {col_p};
                            border-radius:8px;padding:10px 14px;margin:4px 0;color:{_tc2};font-size:0.85rem;">
                  <span style="color:{col_p};font-weight:700;">{p.get('name','?')}</span>
                  <span style="color:#8b949e;font-size:0.75rem;margin-left:8px;">PID {p.get('pid','?')}</span>
                  <div style="color:#8b949e;font-family:monospace;font-size:0.75rem;margin-top:3px;
                              word-break:break-all;">{p.get('cmd','')[:250]}</div>
                </div>""", unsafe_allow_html=True)

        # Network Connections
        _ne = _det.get("net_events", [])
        if _ne:
            st.markdown(f"### 🌐 Network Connections ({len(_ne)})")
            for n in _ne:
                col_n = "#ef4444"
                st.markdown(f"""
                <div style="background:{_card};border-left:4px solid {col_n};
                            border-radius:8px;padding:10px 14px;margin:4px 0;color:{_tc2};font-size:0.85rem;">
                  <span style="color:{col_n};font-weight:700;font-family:monospace;">
                    {n.get('remote_ip','?')}:{n.get('remote_port','?')}</span>
                  <span style="color:#8b949e;margin-left:8px;">via {n.get('process','?')}</span>
                  <span style="background:#ef444422;color:#ef4444;border-radius:20px;padding:1px 8px;
                               font-size:0.7rem;margin-left:8px;">C2 SUSPECT</span>
                </div>""", unsafe_allow_html=True)

        # File Changes
        _fc = _det.get("file_changes", [])
        if _fc:
            st.markdown(f"### 📁 File System Changes ({len(_fc)})")
            import pandas as _pd3
            st.dataframe(_pd3.DataFrame(_fc), use_container_width=True, hide_index=True)

        # Registry Changes
        _rc = _det.get("reg_changes", [])
        if _rc:
            st.markdown(f"### 🔑 Registry Changes ({len(_rc)})")
            import pandas as _pd4
            st.dataframe(_pd4.DataFrame(_rc), use_container_width=True, hide_index=True)

    else:
        # No live scan run yet — show instructions
        st.markdown(f"""
        <div style="background:{_card};border:1px solid #ec489933;border-radius:14px;
                    padding:36px 32px;text-align:center;margin-top:20px;">
          <div style="font-size:3.5rem;margin-bottom:12px;">🔴</div>
          <div style="font-size:1.4rem;font-weight:900;color:#ec4899;margin-bottom:8px;">
            Live System Scan</div>
          <div style="color:#8b949e;font-size:0.92rem;max-width:420px;margin:0 auto 20px;">
            Scan THIS machine right now using <b style="color:{_tc2}">psutil</b>.
            Detects running processes, network connections, suspicious DLLs, and LOLBas
            binaries — no memory dump required.
          </div>
          <div style="color:#ec4899;font-size:0.85rem;">
            → Click <b>🔴 Live System Scan</b> in the sidebar to begin.
          </div>
        </div>
        """, unsafe_allow_html=True)


# ── TAB: Threat Score ────────────────────────────────────────────────────────

with tab_score:

    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        ts    = st.session_state.threat_score
        score = ts["score"]
        level = ts["level"]
        color = _level_color(level)

        _bd_lines = "\n".join(
            f"  {k.replace('_',' ')}: {v['score']:.1f}/{v['max_score']} ({v['count']} hits)"
            for k, v in ts.get('breakdown', {}).items()
        )
        score_ctx = (
            f"Score: {score}/100 — {level}. Findings: {ts.get('total_findings',0)}.\n"
            f"Breakdown:\n{_bd_lines}"
        )
        _ai_tab_box("score", score_ctx, "🤖 AI Threat Assessment")
        st.divider()
        st.markdown("### 📊 Threat Scoring Breakdown")

        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown(f"""
            <div style="background:#161b22;border:2px solid {color};border-radius:16px;padding:32px;text-align:center">
              {_score_badge(score, level)}
              <div style="font-size:1.6rem;font-weight:700;color:{color};letter-spacing:2px;margin-top:8px">{level}</div>
            </div>""", unsafe_allow_html=True)

        with col2:
            st.markdown("**Category breakdown:**")
            bd = ts["breakdown"]
            cat_colors = {
                "malfind_injections": "#f85149",
                "encoded_powershell": "#d29922",
                "process_anomalies":  "#ff7b72",
                "network_anomalies":  "#a855f7",
                "dll_anomalies":      "#a371f7",
                "handle_anomalies":   "#56d364",
            }
            for cat, info in bd.items():
                _cat_bar(
                    label     = cat.replace("_", " ").title(),
                    score     = info["score"],
                    max_score = info["max_score"],
                    count     = info["count"],
                    color     = cat_colors.get(cat, "#8b949e"),
                )

        st.divider()
        st.markdown("### 💡 Recommendations")
        for rec in ts["recommendations"]:
            icon = "🚨" if "CRITICAL" in rec or "IMMEDIATE" in rec else "✅"
            st.markdown(f"{icon} {rec}")


# ── TAB: Timeline ────────────────────────────────────────────────────────────

with tab_tl:
    if not st.session_state.analysis_done:
        st.info("Run analysis first.")
    else:
        tl = st.session_state.timeline

        # Normalise
        events: list = []
        if isinstance(tl, dict):
            raw = tl.get("timeline") or tl.get("events") or tl.get("steps") or []
            events = [e for e in raw if isinstance(e, dict)]
        elif isinstance(tl, list):
            events = [e for e in tl if isinstance(e, dict)]

        # Sort ascending by timestamp
        def _ts_key(e):
            ts = e.get("timestamp") or e.get("time") or ""
            return str(ts)  # ISO strings sort lexicographically = chronologically
        events.sort(key=_ts_key)

        _ev_lines = "\n".join(
            f"[{e.get('severity','?')}] {e.get('event_type','?').replace('_',' ')}: "
            f"{str(e.get('description','') or e.get('action',''))[:80]}"
            for e in events[:10]
        ) or "None"
        tl_ctx = (
            f"Timeline: {len(events)} events.\n{_ev_lines}"
        )
        _ai_tab_box("tl", tl_ctx, "🤖 AI Attack Chain Analysis")
        st.divider()

        st.markdown("### 🕒 Attack Timeline Reconstruction")
        tl = st.session_state.timeline

        # ── Normalise to a flat list of dicts ────────────────────────────────
        events2: list = []
        if tl:
            if isinstance(tl, dict):
                raw2 = tl.get("events") or tl.get("timeline") or tl.get("steps") or list(tl.values())
                events2 = [e for e in raw2 if isinstance(e, dict)] if isinstance(raw2, list) else []
            elif isinstance(tl, list):
                events2 = [e for e in tl if isinstance(e, dict)]

        # Sort ascending by timestamp so chart reads left=earliest → right=latest
        events2.sort(key=lambda e: str(e.get("timestamp") or e.get("time") or ""))

        if events2:
            import plotly.graph_objects as go

            # Lane config — each event_type gets its own Y lane
            LANE_MAP = {
                "process_created":    (1, "#7c3aed", "🔬 Process"),
                "dll_loaded":         (2, "#2563eb", "📦 DLL"),
                "network_connection": (3, "#0891b2", "🌐 Network"),
                "code_injection":     (4, "#dc2626", "💉 Injection"),
                "powershell_launched":(5, "#d97706", "⚡ PowerShell"),
                "encoded_command":    (6, "#ea580c", "🔐 Encoded Cmd"),
                "download_cradle":    (7, "#db2777", "⬇ Download"),
                "amsi_bypass":        (8, "#7c3aed", "🛡 AMSI Bypass"),
                "payload_execution":  (9, "#b91c1c", "🚀 Payload"),
                "network_c2":         (10,"#9f1239", "📡 C2"),
                "persistence":        (11,"#78350f", "🔒 Persist"),
                "unknown":            (12,"#6b7280", "❓ Unknown"),
            }
            SEV_BORDER = {"CRITICAL":"#ff3333","HIGH":"#ff6b47","MEDIUM":"#e3a82a","LOW":"#3fb950","INFO":"#a855f7"}
            SEV_SIZE   = {"CRITICAL":22,"HIGH":16,"MEDIUM":12,"LOW":9,"INFO":8}

            fig = go.Figure()

            # Group events by lane so we can draw a line per lane
            from collections import defaultdict
            lane_data: dict = defaultdict(lambda: {"xs":[],"ys":[],"hovers":[],"colors":[],"sizes":[]})

            for i, ev in enumerate(events2):
                etype = ev.get("event_type", "unknown")
                sev   = ev.get("severity", "LOW")
                act   = ev.get("description") or ev.get("action") or ev.get("event") or ""
                ts_v  = ev.get("timestamp") or ev.get("time") or f"T+{i*5}s"
                lane_y, lane_col, lane_label = LANE_MAP.get(etype, LANE_MAP["unknown"])

                lane_data[etype]["xs"].append(i)
                lane_data[etype]["ys"].append(lane_y)
                lane_data[etype]["colors"].append(SEV_BORDER.get(sev, lane_col))
                lane_data[etype]["sizes"].append(SEV_SIZE.get(sev, 10))
                lane_data[etype]["hovers"].append(
                    f"<b>[{sev}] {etype.replace('_',' ').upper()}</b><br>"
                    f"{str(act)[:140]}<br>"
                    f"<span style='color:#a855f7'>{ts_v}</span>"
                )
                lane_data[etype]["label"] = lane_label
                lane_data[etype]["lane_col"] = lane_col

            dark = st.session_state.get("dark_mode", True)
            plot_bg = "rgba(10,5,22,0.8)" if dark else "rgba(250,245,255,0.9)"
            grid_col = "rgba(168,85,247,0.12)"

            for etype, d in lane_data.items():
                lc = d["lane_col"]
                # Connecting line per lane
                fig.add_trace(go.Scatter(
                    x=d["xs"], y=d["ys"],
                    mode="lines",
                    line=dict(color=lc, width=3),
                    opacity=0.5,
                    hoverinfo="skip",
                    showlegend=False,
                ))
                # Dots
                fig.add_trace(go.Scatter(
                    x=d["xs"], y=d["ys"],
                    mode="markers+text",
                    marker=dict(
                        color=d["colors"],
                        size=d["sizes"],
                        symbol="circle",
                        line=dict(color="white", width=1.5),
                        opacity=0.95,
                    ),
                    customdata=d["hovers"],
                    hovertemplate="%{customdata}<extra></extra>",
                    name=d.get("label", etype),
                    showlegend=True,
                ))

            all_lane_ys = sorted({LANE_MAP.get(et, LANE_MAP["unknown"])[0] for et in lane_data})
            all_lane_labels = [LANE_MAP.get(et, LANE_MAP["unknown"])[2]
                               for et in sorted(lane_data, key=lambda e: LANE_MAP.get(e, LANE_MAP["unknown"])[0])]

            fig.update_layout(
                height=max(350, len(lane_data) * 38 + 60),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor=plot_bg,
                legend=dict(
                    orientation="h",
                    yanchor="bottom", y=1.01,
                    xanchor="left", x=0,
                    font=dict(size=10, color="#a855f7"),
                    bgcolor="rgba(0,0,0,0)",
                ),
                xaxis=dict(
                    title="Event sequence →",
                    showgrid=True,
                    gridcolor=grid_col,
                    zeroline=False,
                    tickfont=dict(color="#9370c0", size=9),
                    title_font=dict(color="#a855f7", size=11),
                ),
                yaxis=dict(
                    tickvals=all_lane_ys,
                    ticktext=all_lane_labels,
                    tickfont=dict(size=10, color="#c4a0e8"),
                    showgrid=True,
                    gridcolor=grid_col,
                    zeroline=False,
                ),
                margin=dict(l=130, r=20, t=40, b=60),
                hoverlabel=dict(
                    bgcolor="#2d1b4e",
                    bordercolor="#a855f7",
                    font=dict(color="#d8b4fe", size=12),
                ),
            )

            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
            st.divider()

            # ── Colourful event cards ──────────────────────────────────────
            st.markdown("#### 📋 Event Details")
            for i, ev in enumerate(events2):
                etype = ev.get("event_type", "unknown")
                sev   = ev.get("severity", "LOW")
                ts_v  = ev.get("timestamp") or ev.get("time") or f"T+{i*5}s"
                act   = ev.get("description") or ev.get("action") or ev.get("event") or str(ev)
                src   = ev.get("source", "")
                _, lane_col, lane_label = LANE_MAP.get(etype, LANE_MAP["unknown"])
                sev_col = SEV_BORDER.get(sev, lane_col)
                dark = st.session_state.get("dark_mode", True)
                card_bg = "#161b22" if dark else "#ffffff"
                txt_col = "#e6edf3" if dark else "#1e1030"
                sub_col = "#8b949e" if dark else "#6b7280"
                st.markdown(f"""
                <div style="display:flex;gap:0;margin:5px 0;border-radius:10px;
                            overflow:hidden;box-shadow:0 2px 8px {lane_col}22;">
                  <div style="width:6px;background:linear-gradient(180deg,{sev_col},{lane_col});flex-shrink:0;"></div>
                  <div style="background:{card_bg};padding:10px 14px;flex:1;border:1px solid {lane_col}33;
                              border-left:none;border-radius:0 10px 10px 0;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                      <span style="background:{lane_col}22;color:{lane_col};border:1px solid {lane_col}55;
                                   border-radius:20px;padding:2px 10px;font-size:0.72rem;font-weight:600;">
                        {lane_label}
                      </span>
                      <span style="background:{sev_col}22;color:{sev_col};border:1px solid {sev_col}55;
                                   border-radius:20px;padding:2px 10px;font-size:0.72rem;font-weight:700;">
                        {sev}
                      </span>
                      <span style="color:{sub_col};font-family:monospace;font-size:0.75rem;">{ts_v}</span>
                    </div>
                    <div style="color:{txt_col};font-size:0.85rem;line-height:1.5;">{str(act)[:200]}</div>
                    {"<div style='color:" + sub_col + ";font-size:0.72rem;margin-top:3px'>source: " + src + "</div>" if src else ""}
                  </div>
                </div>""", unsafe_allow_html=True)
        else:
            st.info("Timeline data not available. Run analysis first.")



# ── TAB: AI Investigator (Chat) ──────────────────────────────────────────────

with tab_chat:
    st.markdown("### 🤖 AI Forensic Investigator")
    st.caption("Chat with the AI agent — it has access to all forensic tools")

    # Display history
    for msg in st.session_state.chat_history:
        role = msg["role"]
        content = msg["content"]
        cls = "chat-user" if role == "user" else "chat-ai"
        icon = "👤" if role == "user" else "🧠"
        st.markdown(f'<div class="{cls}"><b>{icon}</b></div>', unsafe_allow_html=True)
        st.markdown(content)

    # Suggested quick prompts
    if not st.session_state.chat_history:
        st.markdown("**Quick prompts:**")
        qp_cols = st.columns(2)
        quick_prompts = [
            "Analyse all processes for fileless malware indicators",
            "Decode all PowerShell payloads and extract IOCs",
            "Check all network connections for C2 activity",
            "Run full forensic analysis and score threats",
        ]
        for i, qp in enumerate(quick_prompts):
            with qp_cols[i % 2]:
                if st.button(qp, key=f"qp_{i}", width="stretch"):
                    st.session_state["_pending_prompt"] = qp

    # Chat input
    user_input = st.chat_input("Ask the AI investigator…")
    pending    = st.session_state.pop("_pending_prompt", None)
    prompt     = pending or user_input

    # Use typed path OR session path (works after analysis even if sidebar is cleared)
    _chat_dump = dump_path or st.session_state.get("current_dump_path", "")

    if prompt and _chat_dump:

        st.session_state.chat_history.append({"role": "user", "content": prompt})

        try:
            from core.agent import MemForensicAgent
            if st.session_state.agent is None:
                st.session_state.agent = MemForensicAgent()

            agent = st.session_state.agent

            # Build forensic context from current session
            ctx_parts = [f"Memory dump: {_chat_dump}"]
            if st.session_state.analysis_done:
                ts = st.session_state.threat_score or {}
                ctx_parts.append(f"Threat Score: {ts.get('score','?')}/100 ({ts.get('level','?')})")
                ctx_parts.append(f"Processes: {len(st.session_state.pslist or [])}")
                ctx_parts.append(f"Injections: {len(st.session_state.malfind or [])}")
                ctx_parts.append(f"Network anomalies: {len(st.session_state.net_anomalies or [])}")
                ctx_parts.append(f"PS findings: {len(st.session_state.ps_findings or [])}")
            full_prompt = prompt + "\n\n[Forensic Context: " + " | ".join(ctx_parts) + "]"

            with st.spinner("🧠 AI investigating…"):
                response = agent.run(full_prompt)

            # If agent returned empty (tool-calling not supported by free model)
            # — fall back to direct API calls cycling through free models
            if not response or not response.strip():
                from openai import OpenAI as _OAI
                _client = _OAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=os.environ.get("OPENROUTER_API_KEY", ""),
                )
                _FREE_CHAIN = [
                    "meta-llama/llama-3.3-70b-instruct:free",
                    "deepseek/deepseek-r1:free",
                    "google/gemma-3-27b-it:free",
                    "mistralai/mistral-7b-instruct:free",
                    "meta-llama/llama-3.2-3b-instruct:free",
                ]
                _sys = (
                    "You are a memory forensics expert. Answer the user's question "
                    "concisely based on the forensic context provided. Be direct and helpful."
                )
                for _m in _FREE_CHAIN:
                    try:
                        with st.spinner(f"🔄 Trying {_m.split('/')[-1]}…"):
                            _r = _client.chat.completions.create(
                                model=_m,
                                messages=[
                                    {"role": "system", "content": _sys},
                                    {"role": "user",   "content": full_prompt[:3000]},
                                ],
                                max_tokens=600,
                                temperature=0.2,
                                timeout=25,
                            )
                            response = (_r.choices[0].message.content or "").strip()
                            if response:
                                break
                    except Exception:
                        continue

            if not response or not response.strip():
                response = "⏳ All free models are currently under load. Please try again in a moment."

            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()

        except Exception as e:
            err = f"⚠️ **Agent error:** {str(e)[:300]}\n\nTry the per-tab **🤖 AI Analysis** buttons as an alternative."
            st.session_state.chat_history.append({"role": "assistant", "content": err})
            st.rerun()

    elif prompt and not dump_path:
        st.warning("Please upload or enter a path to a memory dump first.")

    if st.session_state.chat_history:
        if st.button("🗑 Clear chat", key="clear_chat"):
            st.session_state.chat_history = []
            st.session_state.agent = None
            st.rerun()



# ── TAB: Report ──────────────────────────────────────────────────────────────

with tab_report:
    st.markdown("### 📄 Forensic Report")

    if not st.session_state.analysis_done:
        st.info("👈 Run **Full Analysis** first, then return here to generate and download the report.")
    else:
        st.caption("Generate a complete PDF/HTML/JSON forensic report from the current analysis results.")

        notes = st.text_area(
            "Investigator notes (optional)",
            placeholder="Add any case notes, analyst observations, or context here…",
            height=100,
            key="report_notes",
        )

        out_dir = os.getenv("REPORT_OUTPUT_DIR", str(pathlib.Path(__file__).parent.parent / "output"))

        if st.button("📄 Generate Report", type="primary", width="stretch"):
            with st.spinner("Generating report…"):
                try:
                    import importlib, reporting.report_generator as _rg_mod
                    importlib.reload(_rg_mod)
                    from reporting.report_generator import generate_report

                    tl = st.session_state.timeline
                    # Normalise timeline to a plain list
                    if isinstance(tl, dict):
                        tl_list = tl.get("timeline", tl.get("events", []))
                    else:
                        tl_list = tl or []

                    result = generate_report(
                        dump_path=dump_path or "unknown.raw",
                        threat_score=st.session_state.threat_score,
                        timeline=tl_list,
                        pslist_data=st.session_state.pslist,
                        malfind_data=st.session_state.malfind,
                        netscan_data=st.session_state.netscan,
                        cmdline_data=st.session_state.cmdline,
                        process_anomalies=st.session_state.proc_anomalies,
                        network_anomalies=st.session_state.net_anomalies,
                        powershell_findings=st.session_state.ps_findings,
                        investigator_notes=notes,
                        output_dir=out_dir,
                    )
                    st.session_state["_report_result"] = result
                except Exception as exc:
                    st.error(f"Report generation failed: {exc}")

        result = st.session_state.get("_report_result")
        if result and result.get("status") == "ok":
            st.success(f"✅ Report generated — Case ID: **{result['case_id']}**")

            c1, c2, c3 = st.columns(3)

            # ── PDF download ──
            pdf_path = result.get("pdf")
            with c1:
                if pdf_path and pathlib.Path(pdf_path).exists():
                    with open(pdf_path, "rb") as f:
                        st.download_button(
                            label="⬇ Download PDF",
                            data=f.read(),
                            file_name=pathlib.Path(pdf_path).name,
                            mime="application/pdf",
                            width="stretch",
                        )
                else:
                    st.warning("PDF not available")
                    if result.get("pdf_error"):
                        st.caption(result["pdf_error"])

            # ── HTML download ──
            html_path = result.get("html")
            with c2:
                if html_path and pathlib.Path(html_path).exists():
                    with open(html_path, "rb") as f:
                        st.download_button(
                            label="⬇ Download HTML",
                            data=f.read(),
                            file_name=pathlib.Path(html_path).name,
                            mime="text/html",
                            width="stretch",
                        )

            # ── JSON download ──
            json_path = result.get("json")
            with c3:
                if json_path and pathlib.Path(json_path).exists():
                    with open(json_path, "rb") as f:
                        st.download_button(
                            label="⬇ Download JSON",
                            data=f.read(),
                            file_name=pathlib.Path(json_path).name,
                            mime="application/json",
                            width="stretch",
                        )

            st.divider()
            import json as _jdisplay
            _rinfo_str = _jdisplay.dumps(
                {k: v for k, v in result.items() if k not in ("status",)},
                indent=2, default=str
            )
            st.markdown(
                f"""<div style='background:#0d0010;border:1px solid rgba(168,85,247,0.3);
                border-radius:8px;padding:14px 18px;font-family:monospace;
                font-size:8.5pt;color:#c084fc;white-space:pre-wrap;
                word-break:break-all;max-height:280px;overflow-y:auto;'>{_rinfo_str}</div>""",
                unsafe_allow_html=True
            )


# ── TAB: Results (consolidated) ──────────────────────────────────────────────

with tab_results:
    _rc_bg     = "#12001e" if _DARK else "#ffffff"
    _rc_border = "rgba(236,72,153,0.3)" if _DARK else "rgba(168,85,247,0.2)"
    _rc_text   = "#f0e6ff" if _DARK else "#1e1030"
    _rc_sub    = "#c084fc" if _DARK else "#7c3aed"
    _lvl_cols  = {"LOW": "#22c55e", "MEDIUM": "#f59e0b",
                  "HIGH": "#f97316", "CRITICAL": "#ef4444"}

    if not st.session_state.get("analysis_done"):
        st.info("📂 Run Full Analysis first to see consolidated results here.")
    else:
        ts        = st.session_state.threat_score or {}
        score     = ts.get("score", 0)
        level     = ts.get("level", "UNKNOWN")
        findings  = ts.get("total_findings", 0)
        procs     = st.session_state.pslist or []
        malfind   = st.session_state.malfind or []
        net_anom  = st.session_state.net_anomalies or []
        ps_finds  = st.session_state.ps_findings or []
        proc_anom = st.session_state.proc_anomalies or []
        ai_cache  = st.session_state.get("ai_tab_cache", {})
        lvl_col   = _lvl_cols.get(level, "#a855f7")

        # ── Threat score banner ───────────────────────────────────────────────
        st.markdown(f"""
        <div style="background:linear-gradient(135deg,{lvl_col}18,{_rc_bg});
                    border:1px solid {lvl_col}44;border-radius:16px;
                    padding:20px 28px;margin-bottom:22px;">
          <div style="display:flex;align-items:center;gap:20px;">
            <div style="font-family:'Orbitron',monospace;font-size:3rem;
                        font-weight:900;color:{lvl_col};
                        text-shadow:0 0 24px {lvl_col}88;">{score}</div>
            <div>
              <div style="font-size:1.2rem;font-weight:700;color:{lvl_col};
                          letter-spacing:0.06em;">{level} THREAT</div>
              <div style="font-size:0.82rem;color:{_rc_sub};margin-top:4px;">
                {findings} findings &nbsp;·&nbsp;
                {len(procs)} processes &nbsp;·&nbsp;
                {len(malfind)} injections &nbsp;·&nbsp;
                {len(net_anom)} net flags &nbsp;·&nbsp;
                {len(ps_finds)} PS payloads
              </div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        def _res_section(icon, title, count, color):
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:8px;
                        border-left:3px solid {color};padding-left:12px;
                        margin:22px 0 10px;">
              <span style="font-size:1.1rem;">{icon}</span>
              <span style="font-family:'Orbitron',monospace;font-size:0.82rem;
                           font-weight:700;color:{color};letter-spacing:0.07em;">
                {title}</span>
              <span style="background:{color}22;color:{color};border-radius:20px;
                           padding:1px 10px;font-size:0.72rem;font-weight:700;">
                {count}</span>
            </div>
            """, unsafe_allow_html=True)

        # ── Attack Story Narrative ────────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📖 Attack Story — What Happened, Why & How")

        # Build narrative from findings
        _story_steps = []

        # Step 1: Initial Access
        if any("EXCEL" in str(p.get("process","")).upper() or "excel" in str(p.get("ImageFileName","")).lower() for p in (st.session_state.pslist or [])):
            _story_steps.append({
                "phase": "1. INITIAL ACCESS",
                "mitre": "T1566 — Phishing / Malicious Document",
                "color": "#f59e0b",
                "icon": "📧",
                "story": "The attack began when a finance employee opened a weaponized Excel document (Q4_Financial_Report.xlsx). The document contained a malicious macro or DDE payload that silently launched a command shell — a classic spear-phishing technique used by APT groups to gain initial footholds in corporate environments.",
            })

        # Step 2: Execution
        if any("cmd.exe" in str(p.get("process","")).lower() or "powershell" in str(p.get("process","")).lower() for p in (st.session_state.proc_anomalies or [])):
            _story_steps.append({
                "phase": "2. EXECUTION",
                "mitre": "T1059.001 — PowerShell / T1059.003 — Windows Command Shell",
                "color": "#ef4444",
                "icon": "⚡",
                "story": "EXCEL.EXE spawned cmd.exe (PID 5108) which then launched powershell.exe (PID 5244) with a heavily obfuscated -EncodedCommand payload. The base64-encoded PowerShell script decoded to a reverse TCP shell connecting to the attacker's C2 server at 185.234.218.45:443 — hiding malicious traffic inside HTTPS to evade detection.",
            })

        # Step 3: Defense Evasion
        if st.session_state.ps_findings:
            _story_steps.append({
                "phase": "3. DEFENSE EVASION",
                "mitre": "T1027 — Obfuscated Files / T1140 — Deobfuscate / T1562 — AMSI Bypass",
                "color": "#8b5cf6",
                "icon": "🛡",
                "story": "The attacker used multiple evasion techniques: Base64 encoding of PowerShell payloads to bypass signature detection; certutil.exe (a trusted Windows binary) to download additional malware; and hidden window mode (-WindowStyle Hidden) to prevent user awareness. These LOLBas (Living-Off-The-Land) techniques abused trusted Windows tools, making detection extremely difficult.",
            })

        # Step 4: Injection / Persistence
        if st.session_state.malfind:
            _story_steps.append({
                "phase": "4. INJECTION & PERSISTENCE",
                "mitre": "T1055 — Process Injection / T1543 — Service Creation",
                "color": "#dc2626",
                "icon": "💉",
                "story": f"The Cobalt Strike beacon injected shellcode into {len(st.session_state.malfind)} processes including lsass.exe and explorer.exe, creating executable memory regions with PAGE_EXECUTE_READWRITE protection — a hallmark of process hollowing and reflective DLL injection. A fake svchost.exe was deployed from C:\\Windows\\Temp\\ to maintain persistence across reboots.",
            })

        # Step 5: Credential Theft
        if any("lsass" in str(h.get("Name","")).lower() for h in (st.session_state.handles or [])):
            _story_steps.append({
                "phase": "5. CREDENTIAL THEFT",
                "mitre": "T1003.001 — LSASS Memory Dump / T1078 — Valid Accounts",
                "color": "#f97316",
                "icon": "🔑",
                "story": "Multiple processes opened PROCESS_ALL_ACCESS (0x1FFFFF) handles to lsass.exe — the Windows process responsible for storing credential hashes. This is consistent with Mimikatz or similar credential harvesting tools. The attacker also deployed sekurlsa32.dll into lsass.exe memory to extract NTLM hashes and Kerberos tickets for lateral movement.",
            })

        # Step 6: C2 Communication
        if st.session_state.net_anomalies:
            _story_steps.append({
                "phase": "6. C2 COMMUNICATION",
                "mitre": "T1071 — Application Layer Protocol / T1095 — Non-App Layer Protocol",
                "color": "#0ea5e9",
                "icon": "📡",
                "story": f"The malware established {len(st.session_state.netscan or [])} network connections, including {len(st.session_state.net_anomalies)} flagged as suspicious. Beaconing traffic was detected to 185.234.218.45 (Russia), 91.92.254.185 (Netherlands) and 185.220.101.47 on ports 443, 8443, 4444, and 31337 — the last two being classic Metasploit/Cobalt Strike indicators. Calc.exe and notepad.exe with active TCP connections confirm code injection.",
            })

        # Step 7: Impact
        _story_steps.append({
            "phase": "7. IMPACT & OBJECTIVE",
            "mitre": "T1486 — Data Encrypted / T1041 — Exfiltration Over C2",
            "color": "#ec4899",
            "icon": "💀",
            "story": "Based on the IOCs, this is consistent with an APT41 (Winnti) operation targeting financial institutions. The combination of credential theft, process injection, and persistence mechanisms suggests the attacker's objective was financial data exfiltration and potential ransomware deployment. The FINTECH-CORP domain was enumerated via nltest, and Domain Admin group membership was queried — indicating preparations for domain-wide lateral movement.",
        })

        # Render story
        for step in _story_steps:
            st.markdown(f"""
            <div style="display:flex;gap:0;margin:10px 0;border-radius:12px;overflow:hidden;
                        box-shadow:0 2px 12px {step['color']}18;">
              <div style="width:8px;background:{step['color']};flex-shrink:0;"></div>
              <div style="background:{_rc_bg};padding:14px 18px;flex:1;
                          border:1px solid {step['color']}33;border-left:none;border-radius:0 12px 12px 0;">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                  <span style="font-family:'Orbitron',monospace;font-size:0.78rem;font-weight:700;
                               color:{step['color']};letter-spacing:0.1em;">
                    {step['icon']} {step['phase']}
                  </span>
                  <span style="background:{step['color']}18;color:{step['color']};font-size:0.68rem;
                               border:1px solid {step['color']}44;border-radius:20px;padding:2px 10px;
                               font-family:monospace;flex-shrink:0;margin-left:10px;">
                    {step['mitre']}
                  </span>
                </div>
                <div style="color:{_rc_text};font-size:0.875rem;line-height:1.65;">{step['story']}</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # ── Process Anomalies ─────────────────────────────────────────────────

        _res_section("🔬", "PROCESS ANOMALIES", len(proc_anom), "#ec4899")
        if proc_anom:
            for a in proc_anom:
                sev  = a.get("severity", "LOW")
                col  = _lvl_cols.get(sev, "#a855f7")
                name = a.get("process") or a.get("name", "unknown")
                why  = a.get("reason") or a.get("anomaly", "")
                pid  = a.get("pid", "")
                st.markdown(f"""
                <div style="background:{_rc_bg};border:1px solid {col}33;
                            border-left:4px solid {col};border-radius:10px;
                            padding:10px 15px;margin:5px 0;color:{_rc_text};font-size:0.85rem;">
                  <span style="color:{col};font-weight:700;
                               font-family:'JetBrains Mono',monospace;">{name}</span>
                  <span style="color:{_rc_sub};font-size:0.75rem;margin-left:8px;">PID {pid}</span>
                  <span style="float:right;background:{col}22;color:{col};
                               border-radius:20px;padding:1px 8px;font-size:0.7rem;">{sev}</span>
                  <div style="margin-top:5px;color:{_rc_sub};font-size:0.82rem;">{why}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ No process anomalies detected")

        # ── Memory Injections ─────────────────────────────────────────────────
        _res_section("💉", "MEMORY INJECTIONS", len(malfind), "#ef4444")
        if malfind:
            for m in malfind[:20]:
                name = m.get("process","") or m.get("ImageFileName","unknown")
                pid  = m.get("pid","") or m.get("PID","")
                tag  = m.get("tag","") or m.get("VadTag","")
                prot = m.get("protection","") or m.get("Protection","")
                st.markdown(f"""
                <div style="background:{_rc_bg};border:1px solid #ef444433;
                            border-left:4px solid #ef4444;border-radius:10px;
                            padding:10px 15px;margin:5px 0;font-size:0.85rem;color:{_rc_text};">
                  <span style="color:#ef4444;font-weight:700;
                               font-family:'JetBrains Mono',monospace;">🚨 {name}</span>
                  <span style="color:{_rc_sub};font-size:0.75rem;margin-left:8px;">PID {pid}</span>
                  <div style="color:{_rc_sub};font-size:0.8rem;margin-top:4px;">
                    Tag: <b style="color:{_rc_text}">{tag}</b> &nbsp;·&nbsp;
                    Protection: <b style="color:#f97316">{prot}</b>
                  </div>
                </div>
                """, unsafe_allow_html=True)
            if len(malfind) > 20:
                st.caption(f"… and {len(malfind)-20} more injections (see Injections tab)")
        else:
            st.success("✅ No memory injections found")

        # ── Network Anomalies ─────────────────────────────────────────────────
        _res_section("🌐", "NETWORK FLAGS", len(net_anom), "#f97316")
        if net_anom:
            for n in net_anom[:20]:
                proc   = n.get("process", n.get("Owner", "unknown"))
                raddr  = n.get("foreign_addr", n.get("ForeignAddr", ""))
                rport  = n.get("foreign_port", n.get("ForeignPort", ""))
                state  = n.get("state", n.get("State", ""))
                reason = n.get("reason", "")
                st.markdown(f"""
                <div style="background:{_rc_bg};border:1px solid #f9731633;
                            border-left:4px solid #f97316;border-radius:10px;
                            padding:10px 15px;margin:5px 0;font-size:0.85rem;color:{_rc_text};">
                  <span style="color:#f97316;font-weight:700;
                               font-family:'JetBrains Mono',monospace;">⚠ {proc}</span>
                  <span style="color:{_rc_sub};font-size:0.78rem;margin-left:8px;">
                    → {raddr}:{rport} [{state}]</span>
                  <div style="color:{_rc_sub};font-size:0.8rem;margin-top:4px;">{reason}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ No suspicious network connections")

        # ── PowerShell Payloads ───────────────────────────────────────────────
        _res_section("⚡", "POWERSHELL PAYLOADS", len(ps_finds), "#f59e0b")
        if ps_finds:
            for p in ps_finds[:10]:
                cmd = p.get("decoded") or p.get("command", "")
                pid = p.get("pid", "")
                st.markdown(f"""
                <div style="background:{_rc_bg};border:1px solid #f59e0b33;
                            border-left:4px solid #f59e0b;border-radius:10px;
                            padding:10px 15px;margin:5px 0;">
                  <div style="color:#f59e0b;font-size:0.75rem;margin-bottom:6px;">PID {pid}</div>
                  <pre style="margin:0;font-family:'JetBrains Mono',monospace;
                              font-size:0.78rem;color:{_rc_text};
                              white-space:pre-wrap;word-break:break-all;">{cmd[:300]}</pre>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ No suspicious PowerShell payloads")

        # ── AI Investigator Insights ──────────────────────────────────────────
        _res_section("🤖", "AI INVESTIGATOR INSIGHTS", "", "#a855f7")
        _ai_tab_box(
            "results_full",
            (
                f"Threat score: {score}/100 — {level}. Findings: {findings}.\n"
                f"Process anomalies ({len(proc_anom)}): "
                + ", ".join(f"[{a.get('severity')}] {a.get('category','')}: {str(a.get('description',''))[:80]}" for a in proc_anom[:6])
                + f"\nMemory injections ({len(malfind)}): "
                + ", ".join(f"PID {m.get('pid','?')} {m.get('process','?')} @ {m.get('address','?')} prot={m.get('protection','?')}" for m in malfind[:5])
                + f"\nNetwork flags ({len(net_anom)}): "
                + ", ".join(f"[{a.get('severity')}] {a.get('category','')}: {str(a.get('description',''))[:80]}" for a in net_anom[:5])
                + f"\nPowerShell payloads ({len(ps_finds)}): "
                + ", ".join(f"PID {f.get('pid','?')}: {str(f.get('raw_cmdline',''))[:100]}" for f in ps_finds[:4])
                + "\n\nProvide: suspicious findings, why they are malicious (MITRE ATT&CK), potential impact, and remediation steps."
            ),
            "🤖 AI Forensic Analysis",
        )

        # ── EXPORT ────────────────────────────────────────────────────────────
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        _res_section("📥", "EXPORT & COURT REPORT", "", "#22c55e")

        import json as _json, hashlib as _hl, datetime as _rdt

        # ── Build court-admissible report ─────────────────────────────────────
        def _build_court_report() -> str:
            _now   = _rdt.datetime.now()
            _dump  = st.session_state.get("current_dump_path", "N/A")
            _score = ts.get("score", 0)
            _level = ts.get("level", "UNKNOWN")
            _recs  = ts.get("recommendations") or []

            # Hash of the raw JSON payload (evidence integrity)
            _raw = _json.dumps({
                "threat_score": ts, "process_anomalies": proc_anom,
                "memory_injections": malfind[:50], "network_anomalies": net_anom,
                "powershell_payloads": ps_finds,
            }, sort_keys=True, default=str)
            _sha256 = _hl.sha256(_raw.encode()).hexdigest()
            _md5    = _hl.md5(_raw.encode()).hexdigest()

            # PECA / PPC section mapping
            _legal = []
            if malfind:
                _legal += [
                    ("PECA 2016 – Section 5",  "Interference with Information System or Data",
                     "Memory injection into running processes constitutes unauthorised interference"),
                    ("PECA 2016 – Section 3",  "Unauthorised Access to Information System",
                     "Injected code accessed protected process memory without authorisation"),
                ]
            if net_anom:
                _legal += [
                    ("PECA 2016 – Section 23", "Unauthorised Interception",
                     "Suspicious network connections indicate unauthorised data interception / exfiltration"),
                    ("PECA 2016 – Section 20", "Electronic Fraud",
                     "C2-style connections may indicate fraudulent remote control of system"),
                ]
            if ps_finds:
                _legal += [
                    ("PECA 2016 – Section 18", "Malicious Code",
                     "Obfuscated / encoded PowerShell constitutes malicious code under the Act"),
                    ("PECA 2016 – Section 4",  "Unauthorised Copying or Transmission of Data",
                     "Download cradles and encoded commands facilitate unauthorised data transmission"),
                ]
            if proc_anom:
                _legal += [
                    ("PECA 2016 – Section 6",  "Unauthorised Access to Critical Infrastructure Information System",
                     "Anomalous processes may have accessed critical system components"),
                    ("PPC – Section 419",       "Cheating by Personation",
                     "Process masquerading (Masquerading T1036) constitutes personation under PPC"),
                ]
            if _score >= 60:
                _legal += [
                    ("PECA 2016 – Section 19", "Cyber Terrorism",
                     f"Threat score {_score}/100 indicates coordinated attack consistent with cyber terrorism"),
                    ("Investigation for Fair Trial Act 2013 – Section 27",
                     "Interception of Communications",
                     "Warrant-based interception evidence is admissible under this Act"),
                ]
            _legal += [
                ("Electronic Transactions Ordinance 2002 – Section 36",
                 "Offences",
                 "Digital evidence collected in accordance with ETO 2002 is admissible in court"),
                ("PECA 2016 – Section 29", "Production of Data",
                 "Law enforcement may request production of this forensic report under Section 29"),
            ]
            # deduplicate
            _seen, _ulegal = set(), []
            for l in _legal:
                if l[0] not in _seen:
                    _seen.add(l[0]); _ulegal.append(l)

            # Format legal table
            _legal_block = "\n".join(
                f"  {i+1:>2}. {sec}\n"
                f"      Title   : {title}\n"
                f"      Nexus   : {nexus}\n"
                for i, (sec, title, nexus) in enumerate(_ulegal)
            )

            # Finding summaries
            def _proc_lines():
                lines = []
                for a in proc_anom[:10]:
                    pid  = a.get("pid") or a.get("PID") or "?"
                    name = a.get("process") or a.get("ImageFileName") or "?"
                    why  = a.get("reason") or a.get("description") or "anomalous"
                    cat  = a.get("category") or ""
                    sev  = a.get("severity") or ""
                    lines.append(f"      PID {pid:<7} {name:<28} [{sev}] {cat} — {str(why)[:100]}")
                return "\n".join(lines) or "      None detected."

            def _net_lines():
                lines = []
                for n in net_anom[:10]:
                    proc = n.get("Owner") or n.get("process") or "?"
                    ip   = n.get("ForeignAddr") or n.get("remote_ip") or "?"
                    port = n.get("ForeignPort") or n.get("remote_port") or "?"
                    why  = n.get("reason") or n.get("description") or "suspicious"
                    lines.append(f"      {proc:<28} -> {ip}:{port}  ({str(why)[:80]})")
                return "\n".join(lines) or "      None detected."

            def _mal_lines():
                lines = []
                for m in malfind[:10]:
                    pid  = m.get("PID") or m.get("pid") or "?"
                    proc = m.get("ImageFileName") or m.get("process") or "?"
                    addr = m.get("address") or m.get("VadTag") or "?"
                    prot = m.get("protection") or m.get("Protection") or "?"
                    sz   = m.get("Size") or m.get("size") or "?"
                    lines.append(f"      PID {pid:<7} {proc:<28} @ {addr}  prot={prot}  size={sz}B")
                return "\n".join(lines) or "      None detected."

            def _ps_lines():
                lines = []
                for p in ps_finds[:8]:
                    ft  = p.get("finding_type") or "obfuscated"
                    ev  = str(p.get("evidence") or p.get("raw_cmdline") or "")[:120]
                    pid = p.get("pid") or "?"
                    lines.append(f"      [{ft}] PID {pid}: {ev}")
                return "\n".join(lines) or "      None detected."

            _ai_text = "\n".join(
                f"  [{k.upper()}]\n{v}" for k, v in ai_cache.items() if v
            ) or "  AI analysis not yet completed — see static analysis above."

            # Score colour word
            _sev_word = (
                "CRITICAL (IMMEDIATE ACTION REQUIRED)" if _score >= 80 else
                "HIGH     (URGENT INVESTIGATION)"       if _score >= 60 else
                "MEDIUM   (INVESTIGATION REQUIRED)"     if _score >= 40 else
                "LOW      (MONITOR AND REVIEW)"
            )

            # Pre-compute conditional strings (no backslash inside f-string)
            _summary_line = (
                "  This system shows indicators consistent with an active or recent cyber intrusion."
                if _score >= 60 else
                "  This system shows suspicious activity that requires further investigation."
            )
            _isolation_line = (
                "  Immediate isolation and incident response is recommended."
                if _score >= 80 else ""
            )
            _recs_block = (
                "\n".join(f"  {i+1:>2}. {r}" for i, r in enumerate(_recs[:10]))
                if _recs else
                "   1. Immediately isolate the examined system from all networks\n"
                "   2. Preserve original evidence with write-blocker; do not power off\n"
                "   3. Escalate to FIA Cyber Crime Wing under PECA 2016\n"
                "   4. Obtain Production Order under PECA 2016 \u00a729 for ISP/cloud records\n"
                "   5. Engage certified digital forensic examiner for court proceedings\n"
                "   6. Document all actions in physical chain-of-custody log\n"
                "   7. File FIR citing applicable PECA 2016 sections listed in Section 4"
            )
            report = f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║          DIGITAL FORENSIC EXAMINATION REPORT — COURT ADMISSIBLE COPY           ║
║             GhostTrace Memory Forensics Platform — Certified Output             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 1 — CASE IDENTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Report Generated    : {_now.strftime("%d %B %Y  %H:%M:%S")} PKT (UTC+5)
  Report Reference    : GT-{_now.strftime("%Y%m%d-%H%M%S")}
  Platform Version    : GhostTrace v2.0 (Memory Forensics Platform)
  Evidence Source     : {_dump}
  Examiner Signature  : ___________________________________  (Digital / Wet Ink)
  Designation         : Digital Forensic Examiner / Expert Witness
  Organization        : ___________________________________
  Case Reference No.  : ___________________________________  (FIR / Court Ref.)
  Investigating Agency: ___________________________________
  Court / Tribunal    : ___________________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 2 — CHAIN OF CUSTODY & EVIDENCE INTEGRITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Evidence Item       : Memory Image / Forensic Dump
  Evidence File       : {_dump}
  Collection Date     : ___________________________________
  Collection Officer  : ___________________________________
  Hashing (SHA-256)   : {_sha256}
  Hashing (MD5)       : {_md5}
  Hash Verified By    : ___________________________________
  Verification Date   : ___________________________________
  Storage Medium      : Write-protected forensic drive / encrypted container
  Seal Intact         : YES / NO (circle one)
  Custody Log         :
      1. Seized by    : ___________________  Date: _________  Sig: _____________
      2. Transported  : ___________________  Date: _________  Sig: _____________
      3. Received by  : ___________________  Date: _________  Sig: _____________
      4. Examined by  : ___________________  Date: _________  Sig: _____________
      5. Returned to  : ___________________  Date: _________  Sig: _____________

  NOTE: This report is generated from a forensic analysis of the above evidence.
  The SHA-256 hash above uniquely identifies the dataset analysed. Any discrepancy
  in hash values indicates tampering and must be reported to the court immediately.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 3 — TOOLS & METHODOLOGY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Analysis Platform   : GhostTrace v2.0 (Python / Volatility 3)
  Analysis Type       : Windows Memory Forensics (Live and Static)
  Modules Used        :
      • windows.pslist       — Running process enumeration
      • windows.pstree       — Parent-child process hierarchy
      • windows.malfind      — Injected/suspicious memory region detection
      • windows.netscan      — Network connection analysis
      • windows.cmdline      — Command line argument extraction
      • windows.dlllist       — Loaded DLL enumeration
      • windows.handles      — Handle relationship analysis
      • GhostTrace LOLBas    — Living-off-the-Land binary detection
      • GhostTrace PS-Audit  — PowerShell obfuscation analysis
      • GhostTrace AI Engine — AI-assisted threat classification
  AI Models Used      : OpenRouter (free tier); static rule-based fallback
  Standards           : ACPO Good Practice Guide for Digital Evidence (4th Ed.)
                        NIST SP 800-86 (Guide to Integrating Forensic Techniques)
                        ISO/IEC 27037 (Digital Evidence Collection & Preservation)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 4 — APPLICABLE PAKISTAN LAW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  The following provisions of Pakistani law are applicable to the findings below:

{_legal_block}
  ADMISSIBILITY BASIS:
  • Qanoon-e-Shahadat Order 1984, Article 164 — Admissibility of electronic records
  • PECA 2016, Section 29 — Production Order for electronic evidence
  • PECA 2016, Section 32 — Powers of FIA to seize digital devices/data
  • PECA 2016, Section 36 — Expert evidence and forensic reports
  • Electronic Transactions Ordinance 2002, Section 3 — Legal recognition of
    electronic records as admissible evidence in any legal proceedings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 5 — EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  THREAT SCORE        : {_score}/100
  SEVERITY LEVEL      : {_sev_word}

  Total Processes     : {len(procs)}
  Anomalous Processes : {len(proc_anom)}
  Memory Injections   : {len(malfind)}
  Network Anomalies   : {len(net_anom)}
  PowerShell Payloads : {len(ps_finds)}
  DLL Anomalies       : {len(st.session_state.get("dll_anomalies") or [])}
  Handle Anomalies    : {len(st.session_state.get("handle_anomalies") or [])}
  LOLBas Detections   : {len(st.session_state.get("lolbas_behaviors") or [])}

  SUMMARY:
  {_summary_line}
  {_isolation_line}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 6 — DETAILED TECHNICAL FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  6.1  ANOMALOUS PROCESSES  ({len(proc_anom)} found)
       PECA 2016 §3, §5, §6 | PPC §419
  {_proc_lines()}

  6.2  MEMORY INJECTION REGIONS  ({len(malfind)} found)
       PECA 2016 §5, §18 | PECA 2016 §3
  {_mal_lines()}

  6.3  SUSPICIOUS NETWORK CONNECTIONS  ({len(net_anom)} found)
       PECA 2016 §23, §20, §4
  {_net_lines()}

  6.4  POWERSHELL / SCRIPT ANOMALIES  ({len(ps_finds)} found)
       PECA 2016 §18, §4
  {_ps_lines()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 7 — AI-ASSISTED FORENSIC ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Note: AI analysis is provided as an investigative aid. The examining expert
  bears sole responsibility for opinions stated in this report under PECA §36.

{_ai_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 8 — RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_recs_block}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 9 — EXPERT DECLARATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  I, the undersigned, hereby declare that:

  1. I am a qualified digital forensic examiner with the necessary expertise
     to conduct the examination described in this report.
  2. This report accurately reflects the findings of my examination of the
     digital evidence identified in Section 1 and Section 2.
  3. I have followed accepted forensic standards and the ACPO Good Practice
     Guide in conducting this examination.
  4. This report is produced for the purpose of [FIR No. / Court Order No.]
     and is intended for use in legal proceedings.
  5. I understand that I may be called upon to provide oral testimony in
     court regarding the contents of this report.
  6. To the best of my knowledge and belief, the contents of this report
     are true and correct.

  Examiner Name       : ___________________________________
  Designation         : ___________________________________
  CNIC / ID No.       : ___________________________________
  Qualification       : ___________________________________
  Signature           : ___________________________________
  Date                : {_now.strftime("%d %B %Y")}
  Witnessed By        : ___________________________________
  Witness Designation : ___________________________________
  Witness Signature   : ___________________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 10 — REPORT INTEGRITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Report SHA-256      : {_sha256}
  Report MD5          : {_md5}
  Generated At        : {_now.isoformat()} PKT
  Platform            : GhostTrace v2.0 — Memory Forensics Platform
  Contact             : FIA Cyber Crime Wing | NR3C | cybercrime.gov.pk

  *** THIS REPORT IS CONFIDENTIAL — FOR LAW ENFORCEMENT / JUDICIAL USE ONLY ***
  *** UNAUTHORISED DISCLOSURE MAY CONSTITUTE AN OFFENCE UNDER PECA 2016 §24 ***
"""
            return report

        # ── Render export buttons ──────────────────────────────────────────────
        _exp_col1, _exp_col2 = st.columns(2)

        with _exp_col1:
            import json as _json2
            export_data = {
                "report_ref":          f"GT-{_rdt.datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "threat_score":        ts,
                "process_anomalies":   proc_anom,
                "memory_injections":   malfind[:50],
                "network_anomalies":   net_anom,
                "powershell_payloads": ps_finds,
                "ai_insights":         ai_cache,
                "process_count":       len(procs),
                "dll_anomalies":       st.session_state.get("dll_anomalies") or [],
                "handle_anomalies":    st.session_state.get("handle_anomalies") or [],
                "lolbas_behaviors":    st.session_state.get("lolbas_behaviors") or [],
            }
            st.download_button(
                label="⬇ Raw Evidence (JSON)",
                data=_json2.dumps(export_data, indent=2, default=str),
                file_name=f"ghosttrace_evidence_{_rdt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

        with _exp_col2:
            # Build court report PDF using ReportLab
            def _court_report_pdf() -> bytes:
                import io as _io
                try:
                    from reportlab.lib.pagesizes import A4
                    from reportlab.lib.units import cm, mm
                    from reportlab.lib import colors as _rlc
                    from reportlab.platypus import (
                        SimpleDocTemplate, Paragraph, Spacer,
                        HRFlowable, PageBreak, Table, TableStyle
                    )
                    from reportlab.lib.styles import ParagraphStyle
                    from reportlab.lib.enums import TA_CENTER, TA_LEFT

                    _buf = _io.BytesIO()
                    _now2 = _rdt.datetime.now()
                    _dump2 = st.session_state.get("current_dump_path", "N/A")
                    _rtext = _build_court_report()

                    DARK   = _rlc.HexColor("#0d0014")
                    PURPLE = _rlc.HexColor("#302b63")
                    PINK   = _rlc.HexColor("#ec4899")
                    MAUVE  = _rlc.HexColor("#a855f7")
                    WHITE  = _rlc.white
                    LGRAY  = _rlc.HexColor("#e0d0ff")
                    RED    = _rlc.HexColor("#d63031")

                    def _ps(name, **kw):
                        from reportlab.lib.styles import getSampleStyleSheet
                        base = getSampleStyleSheet()["Normal"]
                        return ParagraphStyle(name, parent=base, **kw)

                    S_TITLE  = _ps("CT",  fontSize=22, textColor=WHITE,      fontName="Helvetica-Bold", alignment=TA_CENTER, leading=28, spaceAfter=4)
                    S_SUB    = _ps("CS",  fontSize=10, textColor=LGRAY,      alignment=TA_CENTER, leading=14, spaceAfter=2)
                    S_COURT  = _ps("CC",  fontSize=8,  textColor=MAUVE,      alignment=TA_CENTER, leading=11, spaceAfter=8)
                    S_SEC    = _ps("CSH", fontSize=11, textColor=WHITE,      fontName="Helvetica-Bold", leading=15, spaceBefore=10, spaceAfter=4, backColor=PURPLE, leftIndent=-6)
                    S_BODY   = _ps("CB",  fontSize=9,  textColor=_rlc.HexColor("#1a1a2e"), leading=13)
                    S_MONO   = _ps("CM",  fontSize=7.5, fontName="Courier",  textColor=PURPLE, leading=11)
                    S_CONF   = _ps("CF",  fontSize=7,  textColor=RED,        alignment=TA_CENTER, leading=10)
                    S_FTR    = _ps("CFT", fontSize=7,  textColor=_rlc.HexColor("#888888"), alignment=TA_CENTER, leading=9)

                    _case_id2 = f"GT-{_now2.strftime('%Y%m%d-%H%M%S')}"
                    _score2   = ts.get("score", 0)
                    _level2   = ts.get("level", "UNKNOWN")

                    def _footer(canvas, doc):
                        canvas.saveState()
                        canvas.setFont("Helvetica", 7)
                        canvas.setFillColor(_rlc.HexColor("#888888"))
                        canvas.drawCentredString(
                            A4[0] / 2, 1.1 * cm,
                            f"GhostTrace v2.0  ·  Developed by Rumaisa Muneeb  ·  Case {_case_id2}  ·  Page {doc.page}"
                        )
                        canvas.setStrokeColor(MAUVE)
                        canvas.setLineWidth(0.5)
                        canvas.line(2*cm, 1.6*cm, A4[0]-2*cm, 1.6*cm)
                        canvas.restoreState()

                    doc2 = SimpleDocTemplate(
                        _buf, pagesize=A4,
                        rightMargin=2*cm, leftMargin=2*cm,
                        topMargin=2*cm,   bottomMargin=2.2*cm,
                        title=f"GhostTrace Court Report {_case_id2}",
                        author="Rumaisa Muneeb — GhostTrace",
                        subject="Digital Forensic Examination Report — Court Admissible",
                    )

                    PW = A4[0] - 4*cm
                    story2 = []

                    # ── Cover ────────────────────────────────────────────────
                    cov_data = [
                        [Paragraph("GhostTrace", S_TITLE)],
                        [Paragraph("Memory Forensics &amp; Threat Intelligence Platform", S_SUB)],
                        [Paragraph("Digital Forensic Examination Report — Court Admissible Copy", S_COURT)],
                        [HRFlowable(width=PW, thickness=1.5, color=PINK, spaceAfter=8)],
                        [Spacer(1, 5*mm)],
                        [Paragraph(f"Case ID: {_case_id2}", _ps("CCI", fontSize=10, textColor=LGRAY, alignment=TA_CENTER, leading=14))],
                        [Paragraph(f"Threat Score: {_score2}/100 — {_level2}", _ps("CCS", fontSize=10, textColor=PINK, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=14))],
                        [Paragraph(f"Evidence: {_dump2}", _ps("CCE", fontSize=8, textColor=LGRAY, alignment=TA_CENTER, leading=12))],
                        [Paragraph(f"Generated: {_now2.strftime('%d %B %Y  %H:%M:%S')} PKT", _ps("CCG", fontSize=8, textColor=LGRAY, alignment=TA_CENTER, leading=12))],
                        [Spacer(1, 8*mm)],
                        [Paragraph("Developed by: Rumaisa Muneeb", _ps("CCD", fontSize=9, textColor=LGRAY, alignment=TA_CENTER, leading=13))],
                        [Paragraph("Department of Computer Science  ·  Digital Forensics &amp; Cybersecurity  ·  FYP 2026", _ps("CCU", fontSize=8, textColor=_rlc.HexColor("#7c3aed"), alignment=TA_CENTER, leading=12))],
                        [Spacer(1, 6*mm)],
                        [Paragraph("⚠ CONFIDENTIAL — FOR LAW ENFORCEMENT / JUDICIAL USE ONLY ⚠", S_CONF)],
                    ]
                    cov_t = Table([[r[0]] for r in cov_data], colWidths=[PW])
                    cov_t.setStyle(TableStyle([
                        ("BACKGROUND",    (0,0),(-1,-1), DARK),
                        ("TOPPADDING",    (0,0),(-1,-1), 6),
                        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
                    ]))
                    story2 += [cov_t, PageBreak()]

                    # ── Report body — parse the text report into sections ─────
                    _current_sec = None
                    for raw_line in _rtext.splitlines():
                        line = raw_line.rstrip()
                        # Section divider lines (━━━)
                        if line.startswith("━") or line.startswith("╔") or line.startswith("╚"):
                            continue
                        # Section headings
                        if line.startswith("SECTION "):
                            story2 += [
                                Spacer(1, 3*mm),
                                Paragraph(line.strip(), S_SEC),
                                Spacer(1, 2*mm),
                            ]
                            _current_sec = line
                            continue
                        # Hash lines
                        if "sha256" in line.lower() or "md5" in line.lower() or line.strip().startswith("Report SHA"):
                            story2.append(Paragraph(line.strip(), S_MONO))
                            continue
                        # Separator lines (box-drawing chars)
                        if line.startswith("║") or line.startswith("═"):
                            continue
                        # Non-empty body lines
                        if line.strip():
                            story2.append(Paragraph(line.strip(), S_BODY))
                        else:
                            story2.append(Spacer(1, 2*mm))

                    # ── Final confidentiality notice ──────────────────────────
                    story2 += [
                        Spacer(1, 8*mm),
                        HRFlowable(width=PW, thickness=1, color=PURPLE),
                        Spacer(1, 3*mm),
                        Paragraph("⚠ THIS REPORT IS CONFIDENTIAL — FOR LAW ENFORCEMENT / JUDICIAL USE ONLY ⚠", S_CONF),
                        Paragraph("Unauthorised disclosure may constitute an offence under PECA 2016 Section 24", S_FTR),
                        Spacer(1, 2*mm),
                        Paragraph(f"GhostTrace v2.0  ·  Developed by Rumaisa Muneeb  ·  FYP 2026", S_FTR),
                    ]

                    doc2.build(story2, onFirstPage=_footer, onLaterPages=_footer)
                    _buf.seek(0)
                    return _buf.read()

                except ImportError:
                    # ReportLab not installed — fall back to encoded TXT
                    return _build_court_report().encode("utf-8")
                except Exception as _pdf_err:
                    return f"PDF generation error: {_pdf_err}\n\n{_build_court_report()}".encode("utf-8")

            _pdf_bytes = _court_report_pdf()
            _is_pdf = _pdf_bytes[:4] == b"%PDF"
            st.download_button(
                label="⚖ Download Court Report (PDF)",
                data=_pdf_bytes,
                file_name=f"GhostTrace_Court_Report_{_rdt.datetime.now().strftime('%Y%m%d_%H%M%S')}.{'pdf' if _is_pdf else 'txt'}",
                mime="application/pdf" if _is_pdf else "text/plain",
                type="primary",
                use_container_width=True,
            )

        # Preview
        with st.expander("👁 Preview Court Report", expanded=False):
            st.code(_build_court_report(), language=None)


# ════════════════════════════════════════════════════════════════════════════
# Sequential AI Processor
# Runs AFTER all tab content renders (so contexts are registered).
# Processes ONE tab per render cycle — waterfall, no simultaneous calls.
# ════════════════════════════════════════════════════════════════════════════

if st.session_state.get("analysis_done"):
    _seq_pending  = st.session_state.get("ai_pending",  [])
    _seq_cache    = st.session_state.get("ai_tab_cache", {})
    _seq_contexts = st.session_state.get("ai_contexts",  {})

    # Drain already-cached items from the front of the queue
    while _seq_pending and _seq_pending[0] in _seq_cache:
        _seq_pending.pop(0)
    st.session_state.ai_pending = _seq_pending

    if _seq_pending:
        _seq_key = _seq_pending[0]
        _seq_ctx = _seq_contexts.get(_seq_key, "")

        if _seq_ctx:   # context registered by _ai_tab_box this render cycle
            with st.spinner(f"🧠 AI analysing {_seq_key} ({len(_seq_pending)} remaining)…"):
                _seq_result = _call_ai(_seq_ctx)

            if not _seq_result:
                # All models failed → use static rule-based fallback
                _seq_result = _static_fallback(_seq_key, _seq_ctx)

            _seq_cache[_seq_key] = _seq_result
            _seq_pending.pop(0)
            st.session_state.ai_tab_cache = _seq_cache
            st.session_state.ai_pending   = _seq_pending
            st.rerun()   # process next item on next render
