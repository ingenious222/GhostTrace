"""tests/test_process_inspector.py — Unit tests for process anomaly detection."""
import pytest
from tools.process_inspector import (
    detect_process_anomalies,
    _detect_orphans,
    _detect_duplicates,
    _detect_shell_spawning,
    _detect_name_spoofing,
    _is_typosquat,
    _build_pid_map,
)


SAMPLE_PSLIST = [
    {"PID": "4",    "PPID": "0",    "Name": "System"},
    {"PID": "360",  "PPID": "4",    "Name": "smss.exe"},
    {"PID": "480",  "PPID": "360",  "Name": "csrss.exe"},
    {"PID": "520",  "PPID": "360",  "Name": "wininit.exe"},
    {"PID": "572",  "PPID": "520",  "Name": "services.exe"},
    {"PID": "600",  "PPID": "520",  "Name": "lsass.exe"},
    {"PID": "800",  "PPID": "572",  "Name": "svchost.exe"},
    {"PID": "1234", "PPID": "572",  "Name": "svchost.exe"},
    {"PID": "2000", "PPID": "1234", "Name": "explorer.exe"},
]


class TestOrphanDetection:
    def test_no_orphans_in_clean_pslist(self):
        pid_map = _build_pid_map(SAMPLE_PSLIST)
        result = _detect_orphans(SAMPLE_PSLIST, pid_map)
        assert len(result) == 0

    def test_detects_orphan_process(self):
        pslist = SAMPLE_PSLIST + [
            {"PID": "9999", "PPID": "8888", "Name": "malware.exe"}  # 8888 doesn't exist
        ]
        pid_map = _build_pid_map(pslist)
        result = _detect_orphans(pslist, pid_map)
        orphan_pids = [r["pid"] for r in result]
        assert "9999" in orphan_pids


class TestDuplicateDetection:
    def test_no_alert_for_multiple_svchost(self):
        # svchost.exe can be multiple — only single-instance processes flagged
        result = _detect_duplicates(SAMPLE_PSLIST)
        names = [r["process"] for r in result]
        assert "svchost.exe" not in names

    def test_detects_duplicate_lsass(self):
        pslist = SAMPLE_PSLIST + [
            {"PID": "666", "PPID": "520", "Name": "lsass.exe"}
        ]
        result = _detect_duplicates(pslist)
        names = [r["process"] for r in result]
        assert "lsass.exe" in names
        dup = next(r for r in result if r["process"] == "lsass.exe")
        assert dup["severity"] == "CRITICAL"


class TestShellSpawning:
    def test_detects_word_spawning_powershell(self):
        pslist = [
            {"PID": "100",  "PPID": "0",   "Name": "System"},
            {"PID": "1000", "PPID": "100", "Name": "winword.exe"},
            {"PID": "2000", "PPID": "1000","Name": "powershell.exe"},
        ]
        pid_map = _build_pid_map(pslist)
        result = _detect_shell_spawning(pslist, pid_map)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["parent"] == "winword.exe"

    def test_no_alert_for_services_spawning_svchost(self):
        # services.exe → svchost.exe is legitimate
        pslist = SAMPLE_PSLIST
        pid_map = _build_pid_map(pslist)
        # svchost is not in shell_processes set so no alert
        result = _detect_shell_spawning(pslist, pid_map)
        assert len(result) == 0


class TestNameSpoofing:
    def test_detects_typosquat(self):
        # svch0st.exe is an unambiguous 1-char-substitution typosquat of svchost.exe
        pslist = [{"PID": "999", "PPID": "1", "Name": "svch0st.exe"}]
        result = _detect_name_spoofing(pslist)
        assert len(result) == 1
        assert result[0]["category"] == "name_spoofing"
        # The spoofed target must be a known system process
        from tools.process_inspector import SYSTEM_PROCESS_NAMES
        assert result[0]["spoofed_target"] in SYSTEM_PROCESS_NAMES

    def test_detects_extra_char_typosquat(self):
        # lsasss.exe has 1 extra char compared to lsass.exe
        pslist = [{"PID": "998", "PPID": "1", "Name": "lsasss.exe"}]
        result = _detect_name_spoofing(pslist)
        assert len(result) >= 1  # should detect at least one spoofing match

    def test_no_false_positive_on_exact_match(self):
        pslist = [{"PID": "600", "PPID": "1", "Name": "lsass.exe"}]
        result = _detect_name_spoofing(pslist)
        assert len(result) == 0

    def test_is_typosquat_logic(self):
        assert _is_typosquat("lsasss.exe", "lsass.exe") is True
        assert _is_typosquat("svch0st.exe", "svchost.exe") is True
        assert _is_typosquat("totally_different.exe", "lsass.exe") is False
        assert _is_typosquat("lsass.exe", "lsass.exe") is False


class TestFullDetection:
    def test_full_detection_on_clean_list(self):
        result = detect_process_anomalies(SAMPLE_PSLIST)
        # Suspicious-shell-spawn and duplicate-system-process should not appear
        shell_spawn = [r for r in result if r["category"] == "suspicious_shell_spawn"]
        duplicates  = [r for r in result if r["category"] == "duplicate_system_process"]
        assert len(shell_spawn) == 0
        assert len(duplicates) == 0
