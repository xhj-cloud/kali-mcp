"""Tests for output formatting (head+tail truncation) and nmap exclusion list.

Background: scan tools (nmap, nikto, ffuf, ...) emit their findings at the
END of the output while the useful context (open ports, service versions)
sits at the start. A plain head cut hides the findings, so _truncate keeps
both ends. nmap_vuln_scan must additionally exclude network-wide pre-scan
scripts (300s+ budget burners on single-host scans) and the
http-slowloris-check DoS script for every non-'all' category.
"""

import asyncio

import pytest

import kali_mcp.pentest as pentest
from kali_mcp.executor import CommandResult
from kali_mcp.tools import _MAX_OUTPUT, _fmt, _truncate


def _run(coro):
    return asyncio.run(coro)


class TestTruncate:
    def test_short_text_unchanged(self):
        assert _truncate("hello\nworld") == "hello\nworld"

    def test_exact_limit_unchanged(self):
        text = "x" * _MAX_OUTPUT
        assert _truncate(text) == text

    def test_long_text_keeps_head_and_tail(self):
        head = "PORT STATE SERVICE\n22/tcp open ssh\n"
        body = "filler\n" * 3000
        tail = "Nmap done: 1 host up, findings at the end\n"
        out = _truncate(head + body + tail)
        assert out.startswith("PORT STATE SERVICE")
        assert out.rstrip().endswith("Nmap done: 1 host up, findings at the end")
        assert "truncated" in out

    def test_marker_reports_omitted_bytes(self):
        text = "x" * (_MAX_OUTPUT + 500)
        out = _truncate(text)
        assert "500 bytes" in out

    def test_output_bounded(self):
        out = _truncate("x" * 100_000)
        assert len(out) < _MAX_OUTPUT + 100


class TestFmtLongOutput:
    def test_findings_at_tail_survive(self):
        stdout = (
            "22/tcp open ssh\n"
            + "filler\n" * 3000
            + "| vuln found: CVE-2024-1234\n"
        )
        result = CommandResult(stdout=stdout, stderr="", returncode=0, success=True)
        out = _fmt("nmap Vuln Scan", "1.2.3.4", "nmap ...", result)
        assert "22/tcp open ssh" in out
        assert "CVE-2024-1234" in out
        assert "truncated" in out


class _CaptureExecutor:
    """Fake executor that records the command and returns canned output."""

    def __init__(self, stdout="ok"):
        self.cmd = None
        self.stdout = stdout

    async def run(self, cmd, timeout=None, input_data=None):
        self.cmd = cmd
        return CommandResult(
            stdout=self.stdout, stderr="", returncode=0, success=True
        )


class TestNmapVulnExclusions:
    def _run_scan(self, monkeypatch, category, ports=""):
        fake = _CaptureExecutor()
        monkeypatch.setattr(pentest, "get_executor", lambda **kw: fake)
        params = pentest.NmapVulnInput(target="192.168.0.73", category=category, ports=ports)
        _run(pentest.nmap_vuln_scan(params))
        return fake.cmd

    @pytest.mark.parametrize("category", ["vuln", "safe", "auth", "default"])
    def test_exclusions_applied(self, monkeypatch, category):
        cmd = self._run_scan(monkeypatch, category)
        script_args = [a for a in cmd if a.startswith("--script=")]
        assert len(script_args) == 1
        expr = script_args[0]
        for needle in [
            "and not broadcast-*",
            "and not targets-*",
            "and not multicast-*",
            "and not url-snarf",
            "and not eap-info",
            "and not http-slowloris-check",
        ]:
            assert needle in expr, f"{needle!r} missing from {expr}"

    def test_all_category_unfiltered(self, monkeypatch):
        cmd = self._run_scan(monkeypatch, "all")
        assert "--script=all" in cmd

    def test_discovery_category_rejected(self):
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            pentest.NmapVulnInput(target="192.168.0.73", category="discovery")
