

# ════════════════════════════════════════════════════════════════════════════
# TAB: CTF Mode — All Volatility plugins + raw output + hints
# ════════════════════════════════════════════════════════════════════════════
import subprocess as _sp
import datetime   as _ctf_dt

_CTF_PLUGINS = [
    # (plugin_name, label, description)  — optional 4th element = extra_args list
    ("windows.info",              "System Info",    "OS version, architecture, uptime"),
    ("windows.pslist",            "Process List",   "All running processes (PID, PPID, name, threads)"),
    ("windows.pstree",            "Process Tree",   "Parent-child hierarchy of all processes"),
    ("windows.psscan",            "Process Scan",   "Pool-tag scan — finds hidden/terminated processes"),
    ("windows.cmdline",           "Command Lines",  "Full cmdline arguments for every process"),
    ("windows.envars",            "Env Vars",       "Environment variables per process"),
    ("windows.getsids",           "SIDs",           "Security Identifiers — spot privilege escalation"),
    ("windows.privileges",        "Privileges",     "Token privileges — look for SeDebugPrivilege"),
    ("windows.malfind",           "Malfind",        "RWX / injected memory regions — shellcode & DLL injection"),
    ("windows.vadinfo",           "VAD Info",       "Virtual Address Descriptor tree for all processes"),
    ("windows.dlllist",           "DLL List",       "Loaded DLLs per process"),
    ("windows.modscan",           "Module Scan",    "Pool scan for kernel modules — finds hidden drivers"),
    ("windows.modules",           "Modules",        "Currently loaded kernel modules and drivers"),
    ("windows.driverirp",         "Driver IRP",     "IRP function pointers — rootkit DKOM detection"),
    ("windows.ssdt",              "SSDT",           "System Service Descriptor Table — syscall hooking"),
    ("windows.callbacks",         "Callbacks",      "Kernel notification callbacks — rootkit hooks"),
    ("windows.netscan",           "Network Scan",   "Active + recent TCP/UDP connections with PID mapping"),
    ("windows.netstat",           "Netstat",        "Network connections (alternate scan method)"),
    ("windows.filescan",          "File Scan",      "Open file handles in kernel pool"),
    ("windows.mftscan.MFTScan",   "MFT Scan",       "Master File Table — file creation timeline"),
    ("windows.mftscan.ADS",       "ADS Scan",       "Alternate Data Streams — hidden files"),
    ("windows.registry.hivelist", "Registry Hives", "Loaded registry hives with addresses"),
    ("windows.hashdump",          "Hash Dump",      "SAM NTLM hashes — crack with hashcat/john"),
    ("windows.handles",           "Handles",        "Open handles: files, registry, events, mutants"),
    ("windows.mutantscan",        "Mutant Scan",    "Named mutex objects — malware artifacts"),
    ("windows.svcscan",           "Service Scan",   "Windows services — common persistence location"),
    ("windows.bigpools",          "Big Pools",      "Large kernel pool allocations"),
]

_CTF_HINTS = {
    "windows.pslist": [
        ("cmd.exe",     "🔴 cmd.exe — check parent PID (legit: explorer; suspicious: office/browser)"),
        ("powershell",  "🔴 PowerShell — check cmdline for -enc, iex, DownloadString"),
        ("mimikatz",    "💀 Mimikatz process — credential dumping in progress"),
        ("rundll32",    "🟡 rundll32 — common DLL-based payload execution"),
        ("regsvr32",    "🟡 regsvr32 — Squiblydoo / COM-based execution"),
        ("mshta",       "🟡 mshta — HTA file abuse, malware delivery"),
        ("wscript",     "🟡 wscript/cscript — scripting engine abuse"),
        ("cscript",     "🟡 wscript/cscript — scripting engine abuse"),
        ("lsass",       "🔵 lsass.exe — credential dump target — check malfind output"),
    ],
    "windows.malfind": [
        ("MZ",                     "💀 MZ header in injected region — reflective DLL / PE injection"),
        ("PAGE_EXECUTE_READWRITE",  "🔴 RWX page — classic shellcode staging"),
        ("VadS",                    "🟡 VadS VAD tag — private anonymous allocation typical in injection"),
    ],
    "windows.cmdline": [
        ("-enc",           "🔴 Encoded PowerShell (-EncodedCommand) — decode with base64"),
        ("iex",            "🔴 Invoke-Expression — remote code execution"),
        ("downloadstring", "🔴 DownloadString — in-memory fileless payload download"),
        ("bypass",         "🔴 ExecutionPolicy bypass"),
        ("hidden",         "🟡 -WindowStyle Hidden — stealth execution"),
        ("net user",       "🔴 net user — account enumeration/creation"),
        ("whoami",         "🟡 whoami — attacker recon"),
        ("\\temp\\",       "🟡 Execution from TEMP directory"),
        ("\\appdata\\",    "🟡 Execution from AppData — malware staging"),
    ],
    "windows.netscan": [
        (":4444",      "💀 Port 4444 — Metasploit default reverse shell"),
        (":1234",      "💀 Port 1234 — common reverse shell port"),
        (":8080",      "🟡 Port 8080 — C2 beacon or proxy pivot"),
        ("CLOSE_WAIT", "🟡 CLOSE_WAIT — possible beaconing artifact"),
    ],
    "windows.hashdump": [
        ("aad3b435", "🔴 Empty NTLM hash (aad3b435) — blank password"),
        ("31d6cfe0", "🔴 Empty NTLM hash — blank password"),
    ],
    "windows.callbacks": [
        ("UNKNOWN", "🔴 UNKNOWN callback owner — likely rootkit/unsigned driver"),
    ],
    "windows.ssdt": [
        ("UNKNOWN", "🔴 Hooked syscall with UNKNOWN owner — SSDT hooking rootkit"),
    ],
    "windows.svcscan": [
        ("UNKNOWN",  "🟡 UNKNOWN service binary — possible rootkit driver"),
        ("\\temp\\", "🔴 Service binary in TEMP — highly suspicious persistence"),
    ],
}

_CTF_HIGHLIGHT_KWS = [
    "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
    "MZ", "mimikatz", ":4444", ":1234",
    "-enc", "iex", "bypass", "downloadstring",
    "UNKNOWN", "aad3b435", "31d6cfe0",
    "CLOSE_WAIT", "VadS",
]


def _run_vol_raw(dump_path: str, plugin: str, extra_args=None) -> str:
    """Run a Volatility plugin, return raw text output."""
    import os as _os
    vol_path = _os.getenv("VOLATILITY_PATH", "vol")
    version  = _os.getenv("VOLATILITY_VERSION", "vol3").lower()
    sym_dir  = _os.getenv("VOLATILITY_SYMBOL_DIRS", "")
    timeout  = int(_os.getenv("VOL_TIMEOUT", "300"))

    base_cmd = ["python", vol_path] if vol_path.endswith(".py") else [vol_path]
    sym_args = ["-s", sym_dir] if sym_dir else []

    if version == "vol2":
        cmd = base_cmd + ["-f", dump_path, plugin] + (extra_args or [])
    else:
        cmd = base_cmd + sym_args + ["-f", dump_path, plugin] + (extra_args or [])

    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout.strip()
        err = r.stderr.strip()
        if not out and err:
            return f"[stderr]\n{err}"
        return out or "(no output)"
    except _sp.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s — increase VOL_TIMEOUT in .env]"
    except FileNotFoundError:
        return "[ERROR] Volatility not found. Set VOLATILITY_PATH in your .env file."
    except Exception as _ex:
        return f"[ERROR] {_ex}"


def _ctf_hints_for(plugin: str, output: str) -> list:
    hints = []
    lo = output.lower()
    for kw, msg in _CTF_HINTS.get(plugin, []):
        if kw.lower() in lo:
            hints.append(msg)
    return hints


with tab_ctf:
    st.markdown("""
    <div style='background:linear-gradient(135deg,#0a001a,#1a0030);
         border:1px solid rgba(168,85,247,0.4);border-radius:12px;
         padding:18px 24px;margin-bottom:18px;'>
      <h2 style='color:#ec4899;margin:0 0 6px;font-size:1.4rem;'>
        \U0001f6a9 CTF Mode \u2014 Volatility Command Centre
      </h2>
      <p style='color:#c084fc;margin:0;font-size:0.85rem;'>
        Run any Volatility 3 plugin on your memory dump and view the raw output instantly.
        Suspicious keywords are highlighted with CTF hints automatically.
      </p>
    </div>
    """, unsafe_allow_html=True)

    _ctf_dump = st.session_state.get("current_dump_path", "")

    if not _ctf_dump:
        st.warning("\u26a0 No dump loaded \u2014 select a memory image in the sidebar first.")
    else:
        st.info(f"\U0001f5c2 **Dump:** `{_ctf_dump}`")

        # Controls
        _cc1, _cc2, _cc3 = st.columns([3, 1, 1])
        with _cc1:
            _ctf_filter_raw = st.text_input(
                "\U0001f50d Filter plugins",
                placeholder="pslist, network, hash, registry, malfind\u2026",
                key="ctf_filter"
            )
            _ctf_filter = _ctf_filter_raw.lower().strip()
        with _cc2:
            _run_all_btn = st.button("\u25b6 Run All", type="primary", use_container_width=True, key="ctf_run_all")
        with _cc3:
            if st.button("\U0001f5d1 Clear", use_container_width=True, key="ctf_clear"):
                st.session_state["ctf_results"] = {}
                st.rerun()

        if "ctf_results" not in st.session_state:
            st.session_state["ctf_results"] = {}

        # Filter plugin list
        _vis = []
        for _entry in _CTF_PLUGINS:
            _p   = _entry[0]
            _lbl = _entry[1]
            _dsc = _entry[2]
            _xa  = list(_entry[3]) if len(_entry) > 3 else None
            if (not _ctf_filter
                    or _ctf_filter in _p.lower()
                    or _ctf_filter in _lbl.lower()
                    or _ctf_filter in _dsc.lower()):
                _vis.append((_p, _lbl, _dsc, _xa))

        st.caption(f"{len(_vis)} plugin(s) shown")

        # Run All
        if _run_all_btn:
            _prog = st.progress(0, "Starting\u2026")
            for _pi, (_p, _lbl, _dsc, _xa) in enumerate(_vis):
                _prog.progress((_pi + 1) / len(_vis), f"Running {_lbl} ({_pi+1}/{len(_vis)})\u2026")
                _out = _run_vol_raw(_ctf_dump, _p, _xa)
                st.session_state["ctf_results"][_p] = {
                    "output": _out,
                    "ts":     _ctf_dt.datetime.now().strftime("%H:%M:%S"),
                    "hints":  _ctf_hints_for(_p, _out),
                }
            _prog.empty()
            st.success(f"\u2705 Ran {len(_vis)} plugins")
            st.rerun()

        # Plugin cards
        for _p, _lbl, _dsc, _xa in _vis:
            _res   = st.session_state["ctf_results"].get(_p)
            _hints = _res.get("hints", []) if _res else []

            _badge = ""
            if _hints:
                _sev = ("💀" if any("💀" in h for h in _hints) else
                        "🔴" if any("🔴" in h for h in _hints) else
                        "🟡" if any("🟡" in h for h in _hints) else "🔵")
                _badge = f"  {_sev} {len(_hints)} hint(s)"

            with st.expander(
                f"{'✅' if _res else '⬜'} **{_lbl}** \u00a0`{_p}`{_badge}",
                expanded=bool(_hints)
            ):
                st.caption(f"📋 {_dsc}")
                _bc1, _bc2 = st.columns(2)
                with _bc1:
                    if st.button("▶ Run", key=f"ctfr_{_p}", use_container_width=True):
                        with st.spinner(f"Running `{_p}`\u2026"):
                            _out = _run_vol_raw(_ctf_dump, _p, _xa)
                        st.session_state["ctf_results"][_p] = {
                            "output": _out,
                            "ts":     _ctf_dt.datetime.now().strftime("%H:%M:%S"),
                            "hints":  _ctf_hints_for(_p, _out),
                        }
                        st.rerun()
                with _bc2:
                    if _res:
                        st.download_button(
                            "⬇ .txt",
                            data=_res["output"],
                            file_name=f"{_p.replace('.','_')}.txt",
                            mime="text/plain",
                            key=f"ctfd_{_p}",
                            use_container_width=True,
                        )

                if _res:
                    _lines = _res["output"].splitlines()
                    st.caption(f"\u23f1 {_res['ts']}  |  {len(_lines)} lines  |  {len(_res['output'])} bytes")

                    if _hints:
                        st.markdown("**🚨 CTF Hints:**")
                        for _h in _hints:
                            _sc = ("#d63031" if "💀" in _h else
                                   "#e17055" if "🔴" in _h else
                                   "#fdcb6e" if "🟡" in _h else "#74b9ff")
                            st.markdown(
                                f"<div style='background:#150010;border-left:4px solid {_sc};"
                                f"padding:7px 12px;border-radius:0 6px 6px 0;"
                                f"margin:3px 0;font-size:0.83rem;color:#f0e0ff;'>{_h}</div>",
                                unsafe_allow_html=True
                            )

                    # Highlight suspicious keywords in output
                    _disp = _res["output"]
                    for _kw in _CTF_HIGHLIGHT_KWS:
                        _disp = _disp.replace(_kw, f">>>{_kw}<<<")

                    st.code(_disp, language="text")

                    _ls = st.text_input("\U0001f50d Search output", key=f"ctfls_{_p}", placeholder="grep\u2026")
                    if _ls:
                        _matched = [ln for ln in _lines if _ls.lower() in ln.lower()]
                        st.code("\n".join(_matched) if _matched else "(no match)", language="text")

        # Custom plugin runner
        st.markdown("---")
        st.markdown("### \U0001f6e0 Custom Plugin Runner")
        st.caption("Run any Volatility plugin with full argument support")
        _cpc1, _cpc2 = st.columns([4, 1])
        with _cpc1:
            _cust_in = st.text_input(
                "Plugin + args",
                placeholder="windows.registry.printkey --key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                key="ctf_custom_in"
            )
        with _cpc2:
            _cust_go = st.button("▶ Run", key="ctf_cust_go", type="primary", use_container_width=True)

        if _cust_go and _cust_in.strip() and _ctf_dump:
            _cparts  = _cust_in.strip().split()
            _cplugin = _cparts[0]
            _cargs   = _cparts[1:] or None
            with st.spinner(f"Running `{_cplugin}`\u2026"):
                _cout = _run_vol_raw(_ctf_dump, _cplugin, _cargs)
            st.code(_cout, language="text")
            st.download_button(
                "\u2b07 Download",
                data=_cout,
                file_name=f"custom_{_cplugin.replace('.','_')}.txt",
                mime="text/plain",
                key="ctf_cust_dl",
            )
