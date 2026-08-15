"""Tests for input validation helpers and Pydantic models (tools.py)."""

import pytest
from pydantic import ValidationError

from kali_mcp.tools import (
    NmapInput,
    _is_valid_domain,
    _is_valid_target,
    _no_shell_meta,
)


class TestNoShellMeta:
    def test_accepts_plain_string(self):
        assert _no_shell_meta("192.168.1.1") == "192.168.1.1"

    @pytest.mark.parametrize(
        "bad", ["1.2.3.4; rm -rf /", "a|b", "`id`", "a$(id)b", "a&b", "a\nb"]
    )
    def test_rejects_shell_metacharacters(self, bad):
        with pytest.raises(ValueError):
            _no_shell_meta(bad)


class TestIsValidTarget:
    @pytest.mark.parametrize(
        "value",
        [
            "192.168.1.1",
            "10.0.0.0/24",
            "scanme.nmap.org",
            "localhost",
            "--localnet",
        ],
    )
    def test_accepts_valid_targets(self, value):
        assert _is_valid_target(value) is True

    @pytest.mark.parametrize(
        "value",
        ["1.2.3.4;id", "bad host", "", "1.2.3.4/33", "http://example.com"],
    )
    def test_rejects_invalid_targets(self, value):
        assert _is_valid_target(value) is False


class TestIsValidDomain:
    @pytest.mark.parametrize(
        "value",
        ["example.com", "sub.example.co.uk", "localhost", "a-b.example.com"],
    )
    def test_accepts_valid_domains(self, value):
        assert _is_valid_domain(value) is True

    @pytest.mark.parametrize(
        "value", ["exa mple.com", "-bad.com", "exa..mple.com", ""]
    )
    def test_rejects_invalid_domains(self, value):
        assert _is_valid_domain(value) is False


class TestNmapInput:
    def test_accepts_normal_extra_args(self):
        m = NmapInput(
            target="192.168.1.1", extra_args="-sV --version-intensity 5"
        )
        assert m.extra_args == "-sV --version-intensity 5"

    def test_accepts_open_flag(self):
        # Regression guard: "--open" must NOT be rejected by the "-o" prefix check
        m = NmapInput(target="192.168.1.1", extra_args="--open")
        assert m.extra_args == "--open"

    def test_rejects_script_flag(self):
        with pytest.raises(ValidationError):
            NmapInput(target="192.168.1.1", extra_args="--script vuln")

    @pytest.mark.parametrize("bad", ["-oA out", "-oN out", "-oX out", "-oG out"])
    def test_rejects_output_flags(self, bad):
        with pytest.raises(ValidationError):
            NmapInput(target="192.168.1.1", extra_args=bad)

    def test_rejects_shell_meta_in_target(self):
        with pytest.raises(ValidationError):
            NmapInput(target="192.168.1.1;whoami")

    def test_rejects_bad_timing(self):
        with pytest.raises(ValidationError):
            NmapInput(target="192.168.1.1", timing="T9")
