"""tests/test_threat_scorer.py — Unit tests for the threat scoring model."""
import pytest
from tools.threat_scorer import score_threats, _classify


def test_empty_input_scores_zero():
    result = score_threats()
    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_malfind_raises_score():
    malfind = [
        {"pid": "1234", "process": "svchost.exe", "address": "0x1000", "protection": "PAGE_EXECUTE_READWRITE"},
        {"pid": "5678", "process": "notepad.exe", "address": "0x2000", "protection": "PAGE_EXECUTE_READWRITE"},
        {"pid": "9999", "process": "explorer.exe", "address": "0x3000", "protection": "PAGE_EXECUTE"},
        {"pid": "1111", "process": "cmd.exe", "address": "0x4000", "protection": "PAGE_EXECUTE_READWRITE"},
        {"pid": "2222", "process": "powershell.exe", "address": "0x5000", "protection": "PAGE_EXECUTE_READWRITE"},
    ]
    result = score_threats(malfind_data=malfind)
    # 5 items at max → full malfind weight (30)
    assert result["breakdown"]["malfind_injections"]["score"] == 30.0
    assert result["score"] >= 30


def test_powershell_critical_raises_score():
    ps_findings = [{
        "pid": "1234",
        "process": "powershell.exe",
        "raw_cmdline": "powershell -EncodedCommand ...",
        "patterns_found": [
            {"name": "EncodedCommand", "severity": "CRITICAL", "description": "test"},
            {"name": "AMSIBypass", "severity": "CRITICAL", "description": "test"},
        ],
        "decoded_content": "IEX (New-Object Net.WebClient).DownloadString(...)",
        "iocs": [],
    }]
    result = score_threats(powershell_findings=ps_findings)
    assert result["breakdown"]["encoded_powershell"]["score"] > 0


def test_classify_thresholds():
    assert _classify(0)   == "LOW"
    assert _classify(30)  == "LOW"
    assert _classify(31)  == "MEDIUM"
    assert _classify(65)  == "MEDIUM"
    assert _classify(66)  == "HIGH"
    assert _classify(89)  == "HIGH"
    assert _classify(90)  == "CRITICAL"
    assert _classify(100) == "CRITICAL"


def test_critical_anomalies_produce_critical_score():
    proc_anomalies = [
        {"severity": "CRITICAL", "category": "duplicate_system_process", "description": "two lsass"},
        {"severity": "CRITICAL", "category": "suspicious_shell_spawn", "description": "winword → powershell"},
    ]
    net_anomalies = [
        {"severity": "CRITICAL", "category": "unexpected_process_connection", "description": "notepad on net"},
        {"severity": "HIGH",     "category": "suspicious_port_connection", "description": "port 4444"},
    ]
    malfind = [{"pid": "1"} for _ in range(5)]
    ps = [{"pid": "1", "process": "ps", "raw_cmdline": "x", "patterns_found": [
        {"name": "EncodedCommand", "severity": "CRITICAL", "description": "enc"},
        {"name": "AMSIBypass",     "severity": "CRITICAL", "description": "bypass"},
    ], "decoded_content": "iex(...)", "iocs": []}]

    result = score_threats(
        malfind_data=malfind,
        process_anomalies=proc_anomalies,
        network_anomalies=net_anomalies,
        powershell_findings=ps,
    )
    assert result["level"] in ("HIGH", "CRITICAL")
    assert result["score"] >= 66


def test_recommendations_present():
    result = score_threats()
    assert isinstance(result["recommendations"], list)
    assert len(result["recommendations"]) > 0


def test_breakdown_keys():
    result = score_threats()
    expected_keys = {
        "malfind_injections", "encoded_powershell", "process_anomalies",
        "network_anomalies", "dll_anomalies", "handle_anomalies", "lolbas_execution",
    }
    assert set(result["breakdown"].keys()) == expected_keys
