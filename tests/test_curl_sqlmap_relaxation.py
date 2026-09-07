"""Tests for the validator relaxation (2026-09-07 fixes).

Bug 1: http_request over-blocked '&' etc. in url/data/headers even though
curl is invoked list-form (no shell) — multi-field form POSTs were
impossible via MCP.
Bug 2: follow_redirects defaulted to true → curl exit 47 (TOO_MANY_REDIRECTS)
on method-preserving 307 loops.
②-b: sqlmap_scan gained a `data` param so POST-only forms can be tested.

Covers:
  - _no_nul / _no_nul_or_newline helpers
  - CurlInput: data with '&<>;|$(backticks)' allowed, NUL rejected,
    url/headers still single-line + http(s) prefix enforced
  - CurlInput.follow_redirects default False
  - SqlmapInput.data validation + sqlmap --data flag construction
  - _no_shell_meta unchanged (still strict for shell-context inputs)
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from kali_mcp import pentest
from kali_mcp.executor import CommandResult
from kali_mcp.pentest import SqlmapInput, sqlmap_scan
from kali_mcp.tools import (
    CurlInput,
    _no_nul,
    _no_nul_or_newline,
    _no_shell_meta,
)


def _run(coro):
    return asyncio.run(coro)


# ===================================================================
# Helpers
# ===================================================================


class TestNulHelpers:
    def test_no_nul_allows_metacharacters(self):
        s = "a=1&b=%3Cscript%3E;c|d$(e)`f`>g<h>{i}"
        assert _no_nul(s) == s

    def test_no_nul_rejects_nul(self):
        with pytest.raises(ValueError):
            _no_nul("a\x00b")

    def test_no_nul_or_newline_allows_metacharacters(self):
        assert _no_nul_or_newline("https://x/?a=1&b=2;3|4") == "https://x/?a=1&b=2;3|4"

    def test_no_nul_or_newline_rejects_newline_nul(self):
        for bad in ("a\nb", "a\rb", "a\x00b"):
            with pytest.raises(ValueError):
                _no_nul_or_newline(bad)

    def test_shell_meta_still_strict(self):
        # Inputs that reach a shell context keep the old strict filter.
        with pytest.raises(ValueError):
            _no_shell_meta("a&b")
        assert _no_shell_meta("plain-value") == "plain-value"


# ===================================================================
# CurlInput relaxation
# ===================================================================


class TestCurlInputRelaxation:
    def test_data_form_body_allowed(self):
        m = CurlInput(
            url="http://192.168.0.77/products/",
            method="POST",
            data=(
                "name=<script>alert(1)</script>&price=9.99"
                "&note=$(id);rm -rf / `touch /tmp/x`"
            ),
        )
        assert "&" in m.data and "<script>" in m.data and "`" in m.data

    def test_data_nul_rejected(self):
        with pytest.raises(ValidationError):
            CurlInput(url="http://x/", data="a\x00b")

    def test_data_max_length_enforced(self):
        with pytest.raises(ValidationError):
            CurlInput(url="http://x/", data="a" * 8193)

    def test_url_still_requires_http_prefix(self):
        with pytest.raises(ValidationError):
            CurlInput(url="ftp://x/")
        with pytest.raises(ValidationError):
            CurlInput(url="--help http://x/")  # no: must START with http

    def test_url_allows_query_metacharacters(self):
        m = CurlInput(url="http://x/p?a=1&b=2;3|4")
        assert m.url == "http://x/p?a=1&b=2;3|4"

    def test_url_newline_rejected(self):
        with pytest.raises(ValidationError):
            CurlInput(url="http://x/\nHost: evil")

    def test_headers_allow_ampersand(self):
        m = CurlInput(
            url="http://x/",
            headers='{"X-Custom": "a=1&b=2", "X-Other": "<val>"}',
        )
        assert "a=1&b=2" in m.headers

    def test_headers_newline_rejected(self):
        with pytest.raises(ValidationError):
            CurlInput(url="http://x/", headers='{"X": "a\nb"}')

    def test_follow_redirects_default_false(self):
        assert CurlInput(url="http://x/").follow_redirects is False
        assert CurlInput(url="http://x/", follow_redirects=True).follow_redirects is True


# ===================================================================
# sqlmap data param
# ===================================================================


class FakeExecutor:
    def __init__(self, result: CommandResult):
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, cmd, timeout=None, input_data=None, hold_stdin=False,
                  env=None):
        self.calls.append(list(cmd))
        return self.result


class TestSqlmapData:
    def test_input_accepts_form_data(self):
        m = SqlmapInput(
            url="http://192.168.0.77/report/",
            data="report_type=daily&period=2026-09-06&x=%3Cscript%3E",
        )
        assert "&" in m.data

    def test_input_nul_rejected(self):
        with pytest.raises(ValidationError):
            SqlmapInput(url="http://x/", data="a\x00b")

    def test_cmd_includes_data_flag(self, monkeypatch):
        exec_ = FakeExecutor(CommandResult(
            stdout="no injection", stderr="", returncode=0, success=True))
        monkeypatch.setattr(
            pentest, "get_executor", lambda timeout=600: exec_)
        _run(sqlmap_scan(SqlmapInput(
            url="http://192.168.0.77/report/",
            action="detect",
            data="report_type=daily&period=2026-09-06",
        )))
        cmd, = exec_.calls
        assert "--data=report_type=daily&period=2026-09-06" in cmd

    def test_cmd_without_data_flag(self, monkeypatch):
        exec_ = FakeExecutor(CommandResult(
            stdout="no injection", stderr="", returncode=0, success=True))
        monkeypatch.setattr(
            pentest, "get_executor", lambda timeout=600: exec_)
        _run(sqlmap_scan(SqlmapInput(
            url="http://192.168.0.77/?id=1", action="detect")))
        cmd, = exec_.calls
        assert not any(c.startswith("--data") for c in cmd)
