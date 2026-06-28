"""
GhostTrace CTF — Memory Forensics CTF Solver
A dedicated tool for solving CTF challenges based on memory dumps.
Run: streamlit run ctf_tool.py
"""

import os, re, base64, subprocess, datetime, hashlib, binascii
import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GhostTrace CTF",
    page_icon="🚩",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background: #080012;
    color: #e0d0ff;
}
.stApp { background: #080012; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#0d0020,#12002a) !important;
    border-right: 1px solid rgba(168,85,247,0.2);
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: #0d0020;
    border-radius: 10px;
    padding: 4px;
    gap: 4px;
    flex-wrap: wrap;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: #a855f7;
    border-radius: 8px;
    padding: 6px 14px;
    font-size: 0.78rem;
    font-weight: 600;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg,#7c3aed,#a855f7) !important;
    color: white !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg,#7c3aed,#a855f7);
    color: white; border: none; border-radius: 8px;
    font-weight: 600; transition: all 0.2s;
}
.stButton > button:hover { opacity: 0.85; transform: translateY(-1px); }
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg,#c026d3,#ec4899);
}

/* Code blocks */
code, pre, .stCode { font-family: 'JetBrains Mono', monospace !important; }
.stCodeBlock { border-radius: 8px !important; }

/* Expanders */
.streamlit-expanderHeader {
    background: #150025 !important;
    border: 1px solid rgba(168,85,247,0.25) !important;
    border-radius: 8px !important;
    color: #c084fc !important;
    font-weight: 600;
}

/* Text input */
.stTextInput input, .stSelectbox select, .stTextArea textarea {
    background: #150025 !important;
    border: 1px solid rgba(168,85,247,0.3) !important;
    color: #e0d0ff !important;
    border-radius: 8px !important;
}

/* Cards */
.ctf-card {
    background: linear-gradient(135deg,#0d0020,#160030);
    border: 1px solid rgba(168,85,247,0.3);
    border-radius: 12px;
    padding: 16px 20px;
    margin: 8px 0;
}
.flag-found {
    background: linear-gradient(135deg,#001a00,#002800);
    border: 2px solid #00b894;
    border-radius: 10px;
    padding: 14px 18px;
    margin: 6px 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.1rem;
    color: #00e676;
    word-break: break-all;
}
.hint-critical { border-left: 4px solid #d63031; background: #1a0010; padding: 8px 14px; border-radius: 0 8px 8px 0; margin: 4px 0; color: #ffb3b3; font-size: 0.84rem; }
.hint-high     { border-left: 4px solid #e17055; background: #1a0a00; padding: 8px 14px; border-radius: 0 8px 8px 0; margin: 4px 0; color: #ffd4c0; font-size: 0.84rem; }
.hint-medium   { border-left: 4px solid #fdcb6e; background: #1a1400; padding: 8px 14px; border-radius: 0 8px 8px 0; margin: 4px 0; color: #fff3c0; font-size: 0.84rem; }
.hint-info     { border-left: 4px solid #74b9ff; background: #001020; padding: 8px 14px; border-radius: 0 8px 8px 0; margin: 4px 0; color: #c0e0ff; font-size: 0.84rem; }
.answer-row {
    background: #100020;
    border: 1px solid rgba(168,85,247,0.2);
    border-radius: 8px;
    padding: 10px 14px;
    margin: 5px 0;
    display: flex;
    justify-content: space-between;
}
</style>
""", unsafe_allow_html=True)

# ── Session state init ────────────────────────────────────────────────────────
for _k, _v in {
    "dump_path": "",
    "plugin_outputs": {},   # {plugin_name: raw_text}
    "notes": "",
    "flags_found": [],
}.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Volatility runner ─────────────────────────────────────────────────────────
def run_plugin(dump: str, plugin: str, args: list | None = None, timeout: int = 300) -> str:
    vol  = os.getenv("VOLATILITY_PATH", "vol")
    ver  = os.getenv("VOLATILITY_VERSION", "vol3").lower()
    syms = os.getenv("VOLATILITY_SYMBOL_DIRS", "")
    sym_args = ["-s", syms] if syms else []

    base = ["python", vol] if vol.endswith(".py") else [vol]
    cmd  = (base + sym_args + ["-f", dump, plugin] + (args or [])
            if ver != "vol2"
            else base + ["-f", dump, plugin] + (args or []))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        # Filter Volatility noise from stderr
        useful_err = "\n".join(
            l for l in err.splitlines()
            if not any(x in l for x in ["WARNING", "Volatility", "PDB", "symbol", "progress"])
        )
        if not out and useful_err:
            return f"[stderr]\n{useful_err}"
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return "[ERROR] Volatility not found — set VOLATILITY_PATH in .env"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Flag detection ────────────────────────────────────────────────────────────
_FLAG_PATTERNS = [
    r'[A-Z0-9_]{2,12}\{[A-Za-z0-9_\-@!#$%^&*()+=,.?/\\|~`<>:\'";\[\]{}]+\}',
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'THM\{[^}]+\}',
    r'DUCTF\{[^}]+\}',
    r'ECSC\{[^}]+\}',
    r'HackTheBox\{[^}]+\}',
]
_FLAG_RE = re.compile("|".join(_FLAG_PATTERNS), re.IGNORECASE)

def find_flags(text: str, extra_pattern: str | None = None) -> list[str]:
    """Find flags using built-in patterns + optional user-supplied pattern."""
    patterns = list(_FLAG_PATTERNS)
    # Add user-defined prefix pattern from session state
    custom_prefix = st.session_state.get("flag_prefix", "").strip()
    if custom_prefix and custom_prefix not in ("Auto-detect all", ""):
        safe = re.escape(custom_prefix.rstrip("{"))
        patterns.append(rf"{safe}{{[^}}]+}}")
    combined_re = re.compile("|".join(patterns), re.IGNORECASE)
    results = list(dict.fromkeys(combined_re.findall(text)))
    if extra_pattern:
        try:
            results += re.findall(extra_pattern, text, re.IGNORECASE)
        except re.error:
            pass
    return list(dict.fromkeys(results))


# ── CTF Answer Engine ─────────────────────────────────────────────────────────
def extract_answers(outputs: dict[str, str]) -> list[dict]:
    answers = []
    all_text = "\n".join(outputs.values())
    all_low  = all_text.lower()

    # ── Process questions ─────────────────────────────────────────────────────
    def _procs():
        raw = outputs.get("windows.pslist", outputs.get("windows.psscan", ""))
        rows = []
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit():
                rows.append({"name": parts[0], "pid": parts[1], "ppid": parts[2]})
        return rows

    procs = _procs()

    # Parent of suspicious processes
    for proc_name in ["cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe"]:
        for p in procs:
            if p["name"].lower() == proc_name:
                parent = next((x["name"] for x in procs if x["pid"] == p["ppid"]), "?")
                answers.append({
                    "q": f"Parent process of {proc_name}?",
                    "a": f"{parent} (PPID {p['ppid']})",
                    "src": "pslist",
                    "sev": "🔴"
                })

    # Number of processes
    if procs:
        answers.append({
            "q": "Total number of running processes?",
            "a": str(len(procs)),
            "src": "pslist",
            "sev": "🔵"
        })

    # ── Network ───────────────────────────────────────────────────────────────
    net = outputs.get("windows.netscan", outputs.get("windows.netstat", ""))
    if net:
        conns = []
        for line in net.splitlines():
            if "ESTABLISHED" in line or "LISTEN" in line:
                conns.append(line.strip())
        if conns:
            answers.append({
                "q": "Active/established network connections?",
                "a": f"{len(conns)} found (see Network tab)",
                "src": "netscan",
                "sev": "🟡"
            })
        # Suspicious ports
        for port in ["4444", "1234", "9999", "5555", "8888", "31337"]:
            if f":{port}" in net:
                for line in net.splitlines():
                    if f":{port}" in line:
                        answers.append({
                            "q": f"Process on suspicious port {port}?",
                            "a": line.strip(),
                            "src": "netscan",
                            "sev": "💀"
                        })

    # ── Cmdline / encoded payloads ────────────────────────────────────────────
    cmd = outputs.get("windows.cmdline", "")
    if cmd:
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        for line in cmd.splitlines():
            if "-enc" in line.lower() or "-e " in line.lower():
                m = b64_pattern.search(line)
                if m:
                    try:
                        decoded = base64.b64decode(m.group()).decode("utf-16-le", errors="ignore").strip()
                        answers.append({
                            "q": "Decoded PowerShell encoded command?",
                            "a": decoded[:300],
                            "src": "cmdline",
                            "sev": "💀"
                        })
                    except Exception:
                        pass

    # ── Hash dump ─────────────────────────────────────────────────────────────
    hd = outputs.get("windows.hashdump", "")
    if hd:
        for line in hd.splitlines():
            if ":" in line and len(line) > 30:
                answers.append({
                    "q": f"NTLM hash for user '{line.split(':')[0]}'?",
                    "a": line.strip(),
                    "src": "hashdump",
                    "sev": "🔴"
                })

    # ── Malfind ───────────────────────────────────────────────────────────────
    mf = outputs.get("windows.malfind", "")
    if mf:
        inject_procs = set()
        for line in mf.splitlines():
            if "PAGE_EXECUTE_READWRITE" in line or "MZ" in line:
                m = re.search(r"(\w+\.exe)", line, re.IGNORECASE)
                if m:
                    inject_procs.add(m.group(1))
        if inject_procs:
            answers.append({
                "q": "Processes with code injection?",
                "a": ", ".join(inject_procs),
                "src": "malfind",
                "sev": "💀"
            })

    # ── Registry run keys ─────────────────────────────────────────────────────
    reg = outputs.get("windows.registry.printkey", "")
    if reg:
        for line in reg.splitlines():
            if ".exe" in line.lower() or "powershell" in line.lower():
                answers.append({
                    "q": "Persistence via Run key?",
                    "a": line.strip(),
                    "src": "registry.printkey",
                    "sev": "🔴"
                })

    # ── DLLs ─────────────────────────────────────────────────────────────────
    dll = outputs.get("windows.dlllist", "")
    if dll:
        temp_dlls = [l.strip() for l in dll.splitlines() if "\\temp\\" in l.lower() or "\\appdata\\" in l.lower()]
        if temp_dlls:
            answers.append({
                "q": "DLLs loaded from suspicious locations?",
                "a": f"{len(temp_dlls)} DLL(s) from TEMP/AppData",
                "src": "dlllist",
                "sev": "🔴"
            })

    # ── OS info ───────────────────────────────────────────────────────────────
    info = outputs.get("windows.info", "")
    if info:
        for line in info.splitlines():
            if "NtBuildLab" in line or "NtMajorVersion" in line or "NtSystemRoot" in line:
                answers.append({
                    "q": f"System {line.split()[0]}?",
                    "a": " ".join(line.split()[1:]),
                    "src": "info",
                    "sev": "🔵"
                })

    return answers


# ── CTF plugin list ───────────────────────────────────────────────────────────
CTF_PLUGINS = [
    ("windows.info",              "🖥 System Info",     "OS version, build, architecture"),
    ("windows.pslist",            "📋 Process List",    "All running processes"),
    ("windows.pstree",            "🌲 Process Tree",    "Parent-child hierarchy"),
    ("windows.psscan",            "🔎 Process Scan",    "Finds hidden/terminated processes"),
    ("windows.cmdline",           "💻 Command Lines",   "Full cmdline for every process"),
    ("windows.envars",            "📦 Env Vars",        "Environment variables per process"),
    ("windows.getsids",           "🆔 SIDs",            "Security IDs — spot priv escalation"),
    ("windows.privileges",        "🔑 Privileges",      "Token privs — SeDebugPrivilege etc."),
    ("windows.malfind",           "💉 Malfind",         "RWX/injected memory — shellcode, DLL injection"),
    ("windows.dlllist",           "📚 DLL List",        "Loaded DLLs per process"),
    ("windows.modscan",           "🔩 Module Scan",     "Kernel modules — finds hidden drivers"),
    ("windows.modules",           "⚙ Modules",          "Loaded kernel modules"),
    ("windows.netscan",           "🌐 Network Scan",    "TCP/UDP connections with PIDs"),
    ("windows.netstat",           "📡 Netstat",         "Active connections (alt method)"),
    ("windows.filescan",          "📁 File Scan",       "Open file handles in kernel pool"),
    ("windows.mftscan.MFTScan",   "📂 MFT Scan",        "File creation timeline artifacts"),
    ("windows.registry.hivelist", "🗂 Registry Hives",  "Loaded registry hives"),
    ("windows.hashdump",          "🔓 Hash Dump",       "NTLM hashes — crack with hashcat"),
    ("windows.lsadump",           "🔐 LSA Dump",        "LSA secrets, cached credentials"),
    ("windows.handles",           "🤝 Handles",         "File/registry/event/mutex handles"),
    ("windows.mutantscan",        "🧬 Mutex Scan",      "Named mutants — malware beaconing"),
    ("windows.svcscan",           "⚙ Services",         "Windows services — persistence"),
    ("windows.ssdt",              "🛡 SSDT",             "Syscall table — rootkit hooks"),
    ("windows.callbacks",         "📞 Callbacks",        "Kernel callbacks — rootkit detection"),
    ("windows.strings",           "📝 Strings",          "ASCII/Unicode strings in memory"),
]


# ════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:16px 0 8px;'>
      <div style='font-size:2.5rem;'>🚩</div>
      <div style='font-size:1.4rem;font-weight:700;
           background:linear-gradient(135deg,#ec4899,#a855f7);
           -webkit-background-clip:text;-webkit-text-fill-color:transparent;'>
        GhostTrace CTF
      </div>
      <div style='color:#c084fc;font-size:0.75rem;margin-top:2px;'>
        Memory Forensics · CTF Solver
      </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    # Dump file
    st.markdown("### 🗂 Memory Dump")
    dump_input = st.text_input(
        "Path to dump",
        value=st.session_state.dump_path,
        placeholder="C:\\path\\to\\dump.dmp",
        key="dump_input_sidebar",
    )
    if dump_input != st.session_state.dump_path:
        st.session_state.dump_path = dump_input
        st.session_state.plugin_outputs = {}
        st.session_state.flags_found = []
        st.rerun()

    if st.session_state.dump_path and os.path.exists(st.session_state.dump_path):
        sz = os.path.getsize(st.session_state.dump_path) / (1024**3)
        st.success(f"✅ Loaded — {sz:.2f} GB")
        sha = hashlib.md5(open(st.session_state.dump_path, "rb").read(65536)).hexdigest()
        st.caption(f"MD5 (first 64K): `{sha}`")
    elif st.session_state.dump_path:
        st.error("❌ File not found")

    st.divider()

    # Quick actions
    st.markdown("### ⚡ Quick Actions")
    if st.button("🚀 Auto-Solve CTF", type="primary", use_container_width=True):
        if st.session_state.dump_path:
            st.session_state["_auto_solve"] = True

    if st.button("🚩 Hunt for Flags", use_container_width=True):
        if st.session_state.dump_path:
            st.session_state["_hunt_flags"] = True

    if st.button("🗑 Clear All Results", use_container_width=True):
        st.session_state.plugin_outputs = {}
        st.session_state.flags_found = []
        st.rerun()

    st.divider()

    # CTF notes
    st.markdown("### 📝 My Notes")
    st.session_state.notes = st.text_area(
        "notes",
        value=st.session_state.notes,
        placeholder="Paste challenge description, questions, hints here...",
        height=200,
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("GhostTrace CTF · Volatility 3")


# ════════════════════════════════════════════════════════════════════════════
# AUTO-SOLVE: run essential plugins in sequence
# ════════════════════════════════════════════════════════════════════════════
ESSENTIAL = [
    "windows.info", "windows.pslist", "windows.psscan",
    "windows.cmdline", "windows.malfind", "windows.netscan",
    "windows.hashdump", "windows.lsadump",
    "windows.registry.hivelist", "windows.dlllist",
    "windows.modules", "windows.svcscan",
]

if st.session_state.get("_auto_solve") and st.session_state.dump_path:
    st.session_state["_auto_solve"] = False
    prog = st.progress(0, "🚀 Auto-solving CTF…")
    for i, plug in enumerate(ESSENTIAL):
        prog.progress((i+1)/len(ESSENTIAL), f"Running {plug} ({i+1}/{len(ESSENTIAL)})")
        if plug not in st.session_state.plugin_outputs:
            out = run_plugin(st.session_state.dump_path, plug)
            st.session_state.plugin_outputs[plug] = out
    prog.empty()
    # Hunt flags in all outputs
    all_out = "\n".join(st.session_state.plugin_outputs.values())
    st.session_state.flags_found = find_flags(all_out)
    st.success(f"✅ Auto-solve complete — {len(st.session_state.flags_found)} flag(s) found!")
    st.rerun()

if st.session_state.get("_hunt_flags") and st.session_state.dump_path:
    st.session_state["_hunt_flags"] = False
    all_out = "\n".join(st.session_state.plugin_outputs.values())
    st.session_state.flags_found = find_flags(all_out)
    st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# MAIN TABS
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div style='background:linear-gradient(135deg,#0a001a,#150030);
     border:1px solid rgba(168,85,247,0.35);border-radius:14px;
     padding:16px 24px;margin-bottom:16px;'>
  <h1 style='color:#ec4899;margin:0;font-size:1.6rem;letter-spacing:1px;'>
    🚩 GhostTrace CTF — Memory Forensics Solver
  </h1>
  <p style='color:#a78bfa;margin:4px 0 0;font-size:0.82rem;'>
    Load a .dmp / .raw / .mem file → Run All → Get your answers
  </p>
</div>
""", unsafe_allow_html=True)

(tab_solve, tab_flags, tab_plugins,
 tab_decoder, tab_search, tab_notes) = st.tabs([
    "🧩 Auto-Solve",
    "🚩 Flag Hunter",
    "⚡ Plugins",
    "🔓 Decoder",
    "🔍 Search All",
    "📝 Notes",
])


# ── TAB: Auto-Solve ──────────────────────────────────────────────────────────
with tab_solve:
    if not st.session_state.dump_path:
        st.info("👈 Load a memory dump from the sidebar first.")
    else:
        col_btn1, col_btn2, _ = st.columns([1, 1, 2])
        with col_btn1:
            if st.button("🚀 Auto-Solve CTF", type="primary", use_container_width=True, key="solve_main"):
                st.session_state["_auto_solve"] = True
                st.rerun()
        with col_btn2:
            if st.button("🔄 Refresh Answers", use_container_width=True):
                st.rerun()

        # Flags banner
        if st.session_state.flags_found:
            st.markdown("## 🎉 FLAGS FOUND!")
            for f in st.session_state.flags_found:
                st.markdown(f"<div class='flag-found'>🚩 {f}</div>", unsafe_allow_html=True)
            st.divider()

        # CTF Answer sheet
        answers = extract_answers(st.session_state.plugin_outputs)
        if answers:
            st.markdown("## 📋 CTF Answer Sheet")
            st.caption("Auto-extracted from plugin outputs — check each answer carefully")

            sev_order = {"💀": 0, "🔴": 1, "🟡": 2, "🔵": 3}
            answers.sort(key=lambda x: sev_order.get(x.get("sev","🔵"), 3))

            for ans in answers:
                sev = ans.get("sev", "🔵")
                css = ("hint-critical" if sev == "💀" else
                       "hint-high"     if sev == "🔴" else
                       "hint-medium"   if sev == "🟡" else "hint-info")
                st.markdown(f"""
                <div class='{css}' style='margin-bottom:6px;'>
                  <strong>{sev} {ans['q']}</strong><br>
                  <code style='font-size:0.85rem;color:#e0d0ff;background:transparent;'>{ans['a']}</code>
                  <span style='float:right;font-size:0.7rem;color:#888;'>src: {ans['src']}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Click **Auto-Solve CTF** to run essential plugins and extract answers.")

        # Quick stats
        if st.session_state.plugin_outputs:
            st.divider()
            st.markdown("## 📊 Quick Stats")
            s1, s2, s3, s4 = st.columns(4)
            all_out = "\n".join(st.session_state.plugin_outputs.values())
            with s1:
                st.metric("Plugins Run", len(st.session_state.plugin_outputs))
            with s2:
                st.metric("Flags Found", len(st.session_state.flags_found))
            with s3:
                procs_raw = st.session_state.plugin_outputs.get("windows.pslist","")
                n_procs = sum(1 for l in procs_raw.splitlines() if l.strip() and l.split()[1:2] and l.split()[1].isdigit())
                st.metric("Processes", n_procs)
            with s4:
                net_raw = st.session_state.plugin_outputs.get("windows.netscan","")
                n_conn = sum(1 for l in net_raw.splitlines() if "ESTABLISHED" in l or "LISTEN" in l)
                st.metric("Connections", n_conn)



# ── TAB: Flag Hunter ─────────────────────────────────────────────────────────
with tab_flags:
    st.markdown("## 🚩 Flag Hunter")

    # ── Step 1: Flag format box ───────────────────────────────────────────────
    st.markdown("""
    <div style='background:linear-gradient(135deg,#0a001a,#1a0030);
         border:2px solid rgba(236,72,153,0.5);border-radius:12px;
         padding:18px 22px;margin-bottom:16px;'>
      <h4 style='color:#ec4899;margin:0 0 6px;font-size:1.05rem;'>
        🎯 Step 1 — What is the Flag Format for this CTF?
      </h4>
      <p style='color:#c084fc;font-size:0.82rem;margin:0;'>
        Select the platform or type a custom prefix so the hunter knows exactly what pattern to search.<br>
        e.g. <code>picoCTF{abc123}</code> &nbsp;|&nbsp; <code>HTB{s0me_fl4g}</code> &nbsp;|&nbsp; <code>CTF{y0ur_flag}</code>
      </p>
    </div>
    """, unsafe_allow_html=True)

    _PLATFORMS = [
        ("Auto-detect all",   "Tries CTF{}, flag{}, picoCTF{}, HTB{}, THM{} and more automatically"),
        ("CTF{...}",          "Generic CTF — most common format"),
        ("flag{...}",         "Lowercase flag — common in many events"),
        ("picoCTF{...}",      "PicoCTF / Carnegie Mellon"),
        ("HTB{...}",          "HackTheBox"),
        ("THM{...}",          "TryHackMe"),
        ("DUCTF{...}",        "DownUnderCTF"),
        ("ECSC{...}",         "European Cyber Security Challenge"),
        ("LACTF{...}",        "LA CTF"),
        ("DawgCTF{...}",      "DawgCTF"),
        ("nahamcon{...}",     "NahamCon CTF"),
        ("Custom prefix...",  "Type your own flag prefix"),
    ]

    fmt_col1, fmt_col2 = st.columns([5, 4])

    with fmt_col1:
        _fmt_labels = [p[0] for p in _PLATFORMS]
        chosen_fmt  = st.selectbox(
            "CTF Platform / Flag Format",
            _fmt_labels,
            index=0,
            key="flag_format_select",
        )
        _desc = next(d for lbl, d in _PLATFORMS if lbl == chosen_fmt)
        st.caption(f"ℹ {_desc}")

    with fmt_col2:
        if chosen_fmt == "Custom prefix...":
            custom_pfx = st.text_input(
                "Custom prefix  (text before the `{`)",
                placeholder="e.g.  MyEvent2024   →  MyEvent2024{flag_here}",
                key="flag_custom_prefix_input",
            )
            if custom_pfx.strip():
                _clean_pfx = custom_pfx.strip().rstrip("{")
                st.session_state["flag_prefix"] = _clean_pfx
                st.markdown(
                    f"<div style='margin-top:8px;padding:10px 14px;background:#001a00;"
                    f"border:1px solid #00b894;border-radius:8px;"
                    f"font-family:monospace;color:#00e676;font-size:0.95rem;'>"
                    f"Hunting for: <b>{_clean_pfx}" + "{...}</b></div>",
                    unsafe_allow_html=True
                )
            else:
                st.session_state["flag_prefix"] = ""
        else:
            _clean_pfx = chosen_fmt.replace("{...}", "").rstrip("{")
            st.session_state["flag_prefix"] = "" if chosen_fmt == "Auto-detect all" else _clean_pfx
            _preview = chosen_fmt if chosen_fmt != "Auto-detect all" else "CTF{...} / flag{...} / HTB{...} / ..."
            st.markdown(
                f"<div style='margin-top:28px;padding:10px 14px;background:#001a00;"
                f"border:1px solid #00b894;border-radius:8px;"
                f"font-family:monospace;color:#00e676;font-size:0.95rem;'>"
                f"Hunting for: <b>{_preview}</b></div>",
                unsafe_allow_html=True
            )

    _active_pfx = st.session_state.get("flag_prefix", "")
    if _active_pfx:
        _pfx_esc = re.escape(_active_pfx)
        st.code(f"Regex: {_pfx_esc}" + r"{[^}]+}", language="text")
    else:
        st.caption("Mode: **Auto-detect all** — scans for all common flag formats simultaneously")

    st.markdown("---")

    # ── Step 2: Extra text ───────────────────────────────────────────────────
    st.markdown("""
    <div style='background:#0a001a;border:1px solid rgba(168,85,247,0.3);
         border-radius:10px;padding:14px 18px;margin-bottom:12px;'>
      <h4 style='color:#a855f7;margin:0 0 6px;font-size:0.95rem;'>
        📄 Step 2 — Paste Extra Text to Scan
        <span style='font-weight:400;font-size:0.8rem;color:#888;'>(optional)</span>
      </h4>
      <p style='color:#c084fc;font-size:0.8rem;margin:0;'>
        Plugin outputs are scanned automatically.
        Add any extra strings, memory contents, or suspected encoded text here too.
      </p>
    </div>
    """, unsafe_allow_html=True)

    sc1, sc2 = st.columns([3, 2])
    with sc1:
        paste_text = st.text_area(
            "Extra text",
            placeholder="Paste memory strings, command output, encoded text...",
            height=130,
            key="flag_paste_area",
            label_visibility="collapsed",
        )
    with sc2:
        extra_re_input = st.text_input(
            "Additional regex (optional)",
            placeholder=r"password\s*=\s*\S+",
            key="flag_extra_re",
            help="Extra regex — also matches passwords, keys, secrets",
        )
        st.caption("Works alongside the platform pattern")

    if st.button("🔍 Hunt for Flags Now", type="primary", use_container_width=True):
        texts     = list(st.session_state.plugin_outputs.values())
        if paste_text.strip():
            texts.append(paste_text)
        combined  = "\n".join(texts)
        extra_pat = extra_re_input.strip() or None
        found     = find_flags(combined, extra_pattern=extra_pat)
        st.session_state.flags_found = found
        st.rerun()

    # ── Results ──────────────────────────────────────────────────────────────
    st.markdown("---")
    if st.session_state.flags_found:
        st.markdown(f"### 🎉 {len(st.session_state.flags_found)} Flag(s) Found!")
        for _f in st.session_state.flags_found:
            st.markdown(f"<div class='flag-found'>🚩 {_f}</div>", unsafe_allow_html=True)
            _fc1, _fc2 = st.columns([5, 1])
            with _fc1:
                st.code(_f, language=None)
            with _fc2:
                st.download_button("⬇", data=_f, file_name="flag.txt",
                                   key=f"flagdl_{abs(hash(_f))}", use_container_width=True)
    elif st.session_state.plugin_outputs:
        st.info("No flags matched yet — try adjusting the format or paste extra text above.")
    else:
        st.info("Run **Auto-Solve** or the **Plugins** tab first, then hunt here.")

    # ── String scanner ────────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🧵 String Scanner")
    st.caption("Search keywords inside the `windows.strings` plugin output")
    str_search  = st.text_input("Keyword", placeholder="password, flag, secret, admin...", key="str_srch")
    strings_out = st.session_state.plugin_outputs.get("windows.strings", "")
    if str_search and strings_out:
        matched = [l for l in strings_out.splitlines() if str_search.lower() in l.lower()]
        st.code("\n".join(matched[:300]) if matched else "(no match)", language="text")
        if len(matched) > 300:
            st.caption(f"Showing 300 of {len(matched)} matches")
    elif str_search and not strings_out:
        st.warning("Run `windows.strings` from the **Plugins** tab first.")


# ── TAB: Plugins ─────────────────────────────────────────────────────────────
with tab_plugins:
    st.markdown("## ⚡ Volatility Plugin Runner")

    if not st.session_state.dump_path:
        st.info("👈 Load a memory dump from the sidebar.")
    else:
        # Run All
        p1, p2, p3 = st.columns([2, 1, 1])
        with p1:
            plug_filter = st.text_input("🔍 Filter", placeholder="net, hash, proc…", key="plug_filter").lower()
        with p2:
            if st.button("▶ Run ALL Plugins", type="primary", use_container_width=True):
                prog = st.progress(0, "Running…")
                visible = [p for p in CTF_PLUGINS if not plug_filter
                           or plug_filter in p[0].lower() or plug_filter in p[1].lower()]
                for i, (plug, lbl, _) in enumerate(visible):
                    prog.progress((i+1)/len(visible), f"{lbl} ({i+1}/{len(visible)})")
                    st.session_state.plugin_outputs[plug] = run_plugin(
                        st.session_state.dump_path, plug
                    )
                prog.empty()
                st.session_state.flags_found = find_flags(
                    "\n".join(st.session_state.plugin_outputs.values())
                )
                st.success("Done!")
                st.rerun()
        with p3:
            if st.button("🗑 Clear", use_container_width=True):
                st.session_state.plugin_outputs = {}
                st.rerun()

        # Plugin cards
        visible_plugs = [p for p in CTF_PLUGINS
                         if not plug_filter
                         or plug_filter in p[0].lower()
                         or plug_filter in p[1].lower()
                         or plug_filter in p[2].lower()]

        for plug, lbl, desc in visible_plugs:
            output = st.session_state.plugin_outputs.get(plug)
            flags_in = find_flags(output) if output else []
            badge = f" 🚩 {len(flags_in)} flag(s)!" if flags_in else ""
            done = "✅" if output else "⬜"

            with st.expander(f"{done} {lbl}  `{plug}`{badge}", expanded=bool(flags_in)):
                st.caption(f"📋 {desc}")

                ec1, ec2, ec3 = st.columns([1, 1, 1])
                with ec1:
                    if st.button("▶ Run", key=f"run_{plug}", use_container_width=True):
                        with st.spinner(f"Running {lbl}…"):
                            out = run_plugin(st.session_state.dump_path, plug)
                        st.session_state.plugin_outputs[plug] = out
                        if find_flags(out):
                            st.session_state.flags_found += find_flags(out)
                            st.session_state.flags_found = list(dict.fromkeys(
                                st.session_state.flags_found))
                        st.rerun()
                with ec2:
                    # Run with extra args
                    xarg = st.text_input("Extra args", key=f"xarg_{plug}", placeholder="--pid 1234")
                with ec3:
                    if st.button("▶ Run w/ args", key=f"runx_{plug}", use_container_width=True):
                        args = xarg.split() if xarg.strip() else None
                        with st.spinner(f"Running {lbl}…"):
                            out = run_plugin(st.session_state.dump_path, plug, args)
                        st.session_state.plugin_outputs[plug] = out
                        st.rerun()

                if output:
                    lines = output.splitlines()
                    st.caption(f"{len(lines)} lines · {len(output)} bytes")

                    if flags_in:
                        for f in flags_in:
                            st.markdown(f"<div class='flag-found'>🚩 {f}</div>",
                                        unsafe_allow_html=True)

                    # Highlight suspicious keywords
                    HIGHLIGHT = [
                        "PAGE_EXECUTE_READWRITE", "MZ", "mimikatz",
                        ":4444", ":1234", ":9999", ":31337",
                        "-enc", "iex", "bypass", "downloadstring",
                        "aad3b435", "31d6cfe0", "UNKNOWN",
                        "\\temp\\", "\\appdata\\",
                    ]
                    disp = output
                    for kw in HIGHLIGHT:
                        disp = disp.replace(kw, f"⚠{kw}⚠")

                    st.code(disp, language="text")

                    # Download
                    st.download_button(
                        "⬇ Download .txt",
                        data=output,
                        file_name=f"{plug.replace('.','_')}.txt",
                        key=f"dl_{plug}",
                        use_container_width=True,
                    )

        # ── Custom plugin ─────────────────────────────────────────────────────
        st.divider()
        st.markdown("### 🛠 Custom Plugin")
        cc1, cc2 = st.columns([4, 1])
        with cc1:
            cust = st.text_input(
                "Plugin + args",
                placeholder="windows.registry.printkey --key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                key="cust_plug"
            )
        with cc2:
            cust_go = st.button("▶ Run", type="primary", use_container_width=True, key="cust_go")
        if cust_go and cust.strip() and st.session_state.dump_path:
            parts = cust.strip().split()
            with st.spinner(f"Running {parts[0]}…"):
                cout = run_plugin(st.session_state.dump_path, parts[0], parts[1:] or None)
            st.session_state.plugin_outputs[parts[0]] = cout
            st.code(cout, language="text")
            st.download_button("⬇ Download", cout,
                               file_name=f"{parts[0].replace('.','_')}.txt",
                               key="cust_dl")


# ── TAB: Decoder ─────────────────────────────────────────────────────────────
with tab_decoder:
    st.markdown("## 🔓 CTF Decoder")
    st.caption("Decode base64, hex, XOR, rot13, and more — essential for CTF answers")

    raw_input = st.text_area("Input", height=120, placeholder="Paste encoded text here…", key="dec_input")
    dc1, dc2, dc3, dc4 = st.columns(4)

    def _safe(fn, *a):
        try: return fn(*a)
        except Exception as e: return f"[Error: {e}]"

    if raw_input.strip():
        with dc1:
            st.markdown("**Base64 → Text**")
            padded = raw_input.strip() + "=="
            r1 = _safe(lambda: base64.b64decode(padded).decode("utf-8", errors="replace"))
            st.code(r1, language="text")
            st.markdown("**Base64 → UTF-16LE** *(PowerShell)*")
            r2 = _safe(lambda: base64.b64decode(padded).decode("utf-16-le", errors="replace"))
            st.code(r2, language="text")

        with dc2:
            st.markdown("**Hex → Text**")
            cleaned = re.sub(r"[^0-9a-fA-F]", "", raw_input.strip())
            if len(cleaned) % 2:
                cleaned = "0" + cleaned
            r3 = _safe(lambda: bytes.fromhex(cleaned).decode("utf-8", errors="replace"))
            st.code(r3, language="text")
            st.markdown("**Hex → Bytes (hex dump)**")
            r4 = _safe(lambda: " ".join(f"{b:02x}" for b in bytes.fromhex(cleaned)))
            st.code(r4[:500], language="text")

        with dc3:
            st.markdown("**ROT13**")
            r5 = _safe(lambda: raw_input.encode().decode("rot_13"))
            st.code(r5, language="text")
            st.markdown("**URL Decode**")
            from urllib.parse import unquote
            r6 = _safe(lambda: unquote(raw_input.strip()))
            st.code(r6, language="text")

        with dc4:
            st.markdown("**XOR with key**")
            xor_key = st.text_input("XOR key (hex e.g. 0x41 or 'A')", key="xor_key")
            if xor_key.strip():
                try:
                    if xor_key.startswith("0x"):
                        key_byte = int(xor_key, 16)
                        xored = bytes(b ^ key_byte for b in bytes.fromhex(
                            re.sub(r"[^0-9a-fA-F]", "", raw_input)) )
                    else:
                        key_bytes = xor_key.encode()
                        data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", raw_input)) if re.fullmatch(r"[0-9a-fA-F\s]+", raw_input.strip()) else raw_input.encode()
                        xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
                    st.code(xored.decode("utf-8", errors="replace"), language="text")
                except Exception as ex:
                    st.error(f"XOR error: {ex}")
            st.markdown("**MD5 / SHA256**")
            enc = raw_input.encode()
            st.code(f"MD5:    {hashlib.md5(enc).hexdigest()}\nSHA256: {hashlib.sha256(enc).hexdigest()}", language="text")


# ── TAB: Search All ──────────────────────────────────────────────────────────
with tab_search:
    st.markdown("## 🔍 Search All Plugin Outputs")
    st.caption("Grep across everything at once — great for finding process names, IPs, file paths")

    sa_col1, sa_col2 = st.columns([3, 1])
    with sa_col1:
        search_term = st.text_input("Search term", placeholder="mimikatz, 4444, lsass, password…", key="global_search")
    with sa_col2:
        case_sensitive = st.checkbox("Case sensitive", value=False)

    if search_term and st.session_state.plugin_outputs:
        results = {}
        for plug, out in st.session_state.plugin_outputs.items():
            matched = [
                (i+1, line) for i, line in enumerate(out.splitlines())
                if (search_term in line if case_sensitive else search_term.lower() in line.lower())
            ]
            if matched:
                results[plug] = matched

        if results:
            total = sum(len(v) for v in results.values())
            st.success(f"Found **{total}** match(es) across **{len(results)}** plugin(s)")
            for plug, hits in results.items():
                lbl = next((l for p, l, _ in CTF_PLUGINS if p == plug), plug)
                with st.expander(f"**{lbl}** — {len(hits)} hit(s)", expanded=True):
                    disp = "\n".join(f"[L{ln}] {line}" for ln, line in hits)
                    st.code(disp, language="text")
        else:
            st.warning(f"No matches for `{search_term}` in {len(st.session_state.plugin_outputs)} plugin output(s)")
    elif not st.session_state.plugin_outputs:
        st.info("Run some plugins first, then search here.")
    else:
        st.info("Type a search term above to grep across all outputs.")


# ── TAB: Notes ───────────────────────────────────────────────────────────────
with tab_notes:
    st.markdown("## 📝 CTF Notes")
    st.caption("Use this to track the challenge questions, your findings, and answers")

    st.session_state.notes = st.text_area(
        "Notes",
        value=st.session_state.notes,
        height=500,
        placeholder="""Challenge: [Event Name] - [Challenge Title]
Dump file: memory.dmp

Questions:
1. What is the name of the suspicious process?
   Answer: 

2. What is the PID of the malicious process?
   Answer: 

3. What is the flag?
   Answer: CTF{...}

Findings:
- 
- 
""",
        label_visibility="collapsed",
    )

    # Export notes
    if st.session_state.notes.strip():
        st.download_button(
            "⬇ Export Notes (.txt)",
            data=st.session_state.notes,
            file_name=f"ctf_notes_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            use_container_width=True,
        )
