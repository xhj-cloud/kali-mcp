"""Tests for input validation helpers and Pydantic models (tools.py)."""

import asyncio

import pytest
from pydantic import ValidationError

from kali_mcp.executor import CommandResult
from kali_mcp.tools import (
    MasscanInput,
    NmapInput,
    _is_valid_domain,
    _is_valid_masscan_ports,
    _is_valid_target,
    _masscan_output_summary,
    _no_shell_meta,
    masscan_scan,
)


def _run(coro):
    return asyncio.run(coro)


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


class TestDdosInput:
    def test_default_method_syn(self):
        from kali_mcp.pentest import DdosInput

        m = DdosInput(target="192.168.1.1")
        assert m.method == "syn"

    def test_icmpv6_accepts_ipv6_target(self):
        from kali_mcp.pentest import DdosInput

        m = DdosInput(target="2400:3200::1", method="icmpv6")
        assert m.method == "icmpv6"

    def test_icmpv6_accepts_zoned_ipv6(self):
        from kali_mcp.pentest import DdosInput

        m = DdosInput(target="fe80::1%eth0", method="icmpv6")
        assert m.method == "icmpv6"

    def test_icmpv6_rejects_ipv4_target(self):
        from kali_mcp.pentest import DdosInput

        with pytest.raises(ValidationError):
            DdosInput(target="192.168.1.1", method="icmpv6")

    def test_icmpv6_rejects_hostname(self):
        from kali_mcp.pentest import DdosInput

        with pytest.raises(ValidationError):
            DdosInput(target="example.com", method="icmpv6")

    def test_other_methods_still_allow_hostnames(self):
        from kali_mcp.pentest import DdosInput

        assert DdosInput(target="example.com", method="icmp").method == "icmp"


class TestMasscanPorts:
    @pytest.mark.parametrize(
        "ports",
        [
            "80",
            "80,443",
            "1-10000",
            "22,80,443,8000-8080",
            "1-65535",
            "443,8000-8080,8443",
            # protocol-prefixed parts (masscan(8): --ports U:161,U:1024-1100)
            "T:80",
            "U:53",
            "T:22,U:53",
            "U:161,U:1024-1100",
        ],
    )
    def test_accepts_valid_port_specs(self, ports):
        assert _is_valid_masscan_ports(ports) is True

    @pytest.mark.parametrize(
        "ports",
        [
            "",            # empty
            "80 443",      # space separator
            "top-100",     # named set
            "65536",       # port out of range
            "1-70000",     # range end out of range
            "U:70000",     # prefixed port out of range
            "100-1",       # inverted range
            "1-2-3",       # malformed range
            "80:443",      # colon separator (not a protocol prefix)
            "X:80",        # unknown protocol prefix
            "1,,2",        # empty element
            "-80",         # leading dash
            "80,",         # trailing comma
            "a-b",         # letters
        ],
    )
    def test_rejects_invalid_port_specs(self, ports):
        assert _is_valid_masscan_ports(ports) is False


class TestMasscanInput:
    def test_defaults(self):
        m = MasscanInput(target="192.168.1.1")
        assert m.ports == "80,443"
        assert m.rate == 100
        assert m.banner is False
        assert m.interface == ""
        assert m.timeout == 120

    def test_accepts_prefixed_ports(self):
        assert MasscanInput(target="10.0.0.1", ports="T:22,U:53").ports == "T:22,U:53"

    @pytest.mark.parametrize(
        "target",
        [
            "192.168.1.1",
            "192.168.1.0/24",
            "10.0.0.0/16",
            "scanme.nmap.org",
            "2409:8931:1259:9be::1",
            "2409:8931:1259:9be::/112",
        ],
    )
    def test_accepts_bounded_targets(self, target):
        assert MasscanInput(target=target).target == target

    @pytest.mark.parametrize(
        "target",
        [
            "10.0.0.0/8",       # too wide (v4)
            "192.168.0.0/15",   # too wide (v4)
            "0.0.0.0/0",        # whole internet
            "2409:8931::/32",   # too wide (v6)
            "2409:8931:1259::/64",  # typical /64 — still too wide for masscan
            "192.168.1.1;id",   # shell meta
            "bad host",         # space
        ],
    )
    def test_rejects_unbounded_or_invalid_targets(self, target):
        with pytest.raises(ValidationError):
            MasscanInput(target=target)

    @pytest.mark.parametrize("rate", [0, 10001])
    def test_rejects_rate_out_of_bounds(self, rate):
        with pytest.raises(ValidationError):
            MasscanInput(target="10.0.0.1", rate=rate)

    def test_rate_upper_bound_accepted(self):
        assert MasscanInput(target="10.0.0.1", rate=10000).rate == 10000

    @pytest.mark.parametrize("timeout", [5, 601])
    def test_rejects_timeout_out_of_bounds(self, timeout):
        with pytest.raises(ValidationError):
            MasscanInput(target="10.0.0.1", timeout=timeout)

    def test_rejects_shell_meta_in_interface(self):
        with pytest.raises(ValidationError):
            MasscanInput(target="10.0.0.1", interface="eth0;id")


class TestMasscanCmd:
    """Command construction for masscan_scan."""

    def _capture(self, monkeypatch, params):
        import kali_mcp.tools as t

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = cmd
                captured["timeout"] = timeout
                return CommandResult(stdout="", stderr="", returncode=0, success=True)

        monkeypatch.setattr(t, "get_executor", lambda timeout=None: _CapEx())
        out = _run(masscan_scan(params))
        assert isinstance(out, str)
        return captured, out

    def test_tcp_default_cmd(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, MasscanInput(target="192.168.1.0/24")
        )
        cmd = captured["cmd"]
        assert cmd[0] == "masscan"
        assert "-sU" not in cmd
        assert "--rate" in cmd and str(captured["cmd"][cmd.index("--rate") + 1]) == "100"
        assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "80,443"
        assert cmd[-1] == "192.168.1.0/24"
        assert "--banners" not in cmd

    def test_udp_via_port_prefix(self, monkeypatch):
        """UDP is expressed via the U: port prefix — masscan has no -sU flag."""
        captured, _ = self._capture(
            monkeypatch, MasscanInput(target="10.0.0.1", ports="U:53")
        )
        cmd = captured["cmd"]
        assert cmd[cmd.index("-p") + 1] == "U:53"
        assert "-sU" not in cmd

    def test_banner_and_interface_flags(self, monkeypatch):
        """Regression: masscan(8) uses --banners (plural) and -e IFNAME —
        there is no --banner or --interface flag."""
        captured, _ = self._capture(
            monkeypatch,
            MasscanInput(
                target="10.0.0.1", banner=True, interface="eth0", rate=500
            ),
        )
        cmd = captured["cmd"]
        assert "--banners" in cmd
        assert "--banner" not in cmd  # singular is not a masscan flag
        assert "-e" in cmd and cmd[cmd.index("-e") + 1] == "eth0"
        assert "--interface" not in cmd  # wrong flag name
        assert cmd[cmd.index("--rate") + 1] == "500"

    def test_timeout_forwarded(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, MasscanInput(target="10.0.0.1", timeout=300)
        )
        assert captured["timeout"] == 300


class TestMasscanOutput:
    """Output parsing/summary for masscan_scan."""

    def test_summary_table_rendered(self, monkeypatch):
        import kali_mcp.tools as t

        sample = (
            "Starting masscan 1.3.2 (https://bitbucket.org/robertdavidheath/masscan)\n"
            "Starting 100.0/s scan of 192.168.1.0/24 ports:80,443\n"
            "Discovered 192.168.1.10:80   Open\n"
            "Discovered 192.168.1.10:443  Open\n"
            "Discovered 192.168.1.20:80   Open\n"
        )

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                return CommandResult(
                    stdout=sample, stderr="", returncode=0, success=True
                )

        monkeypatch.setattr(t, "get_executor", lambda timeout=None: _CapEx())
        out = _run(masscan_scan(MasscanInput(target="192.168.1.0/24")))
        assert "### 📋 开放端口汇总" in out
        # 192.168.1.10 has two ports (80,443); 192.168.1.20 has one
        assert "| `192.168.1.10` | 80, 443 |" in out
        assert "| `192.168.1.20` | 80 |" in out
        assert "nmap_scan" in out  # follow-up hint

    def test_no_open_ports_note(self, monkeypatch):
        import kali_mcp.tools as t

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                return CommandResult(
                    stdout="Starting masscan 1.3.2\nFinished scan",
                    stderr="",
                    returncode=0,
                    success=True,
                )

        monkeypatch.setattr(t, "get_executor", lambda timeout=None: _CapEx())
        out = _run(masscan_scan(MasscanInput(target="192.168.1.1")))
        assert "未发现开放端口" in out
        assert "### 📋 开放端口汇总" not in out

    def test_summary_helper_empty(self):
        assert _masscan_output_summary([]) == ""

    def test_summary_helper_groups_and_sorts(self):
        s = _masscan_output_summary(
            [("10.0.0.2", 443), ("10.0.0.1", 80), ("10.0.0.2", 80)]
        )
        # host 10.0.0.1 listed before 10.0.0.2; ports sorted ascending
        assert s.index("10.0.0.1") < s.index("10.0.0.2")
        assert "| `10.0.0.2` | 80, 443 |" in s
