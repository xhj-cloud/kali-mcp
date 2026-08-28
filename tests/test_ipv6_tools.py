"""Tests for IPv6 tool input validation, parsing helpers, and registry."""

import asyncio

import pytest
from pydantic import ValidationError

from kali_mcp.executor import CommandResult
from kali_mcp.ipv6 import (
    IPV6_TOOLS,
    Ipv6DigInput,
    Ipv6DoctorInput,
    Ipv6PingInput,
    Ipv6RaInspectInput,
    Ipv6RouteDebugInput,
    Ipv6ScanInput,
    Ipv6TracerouteInput,
    _analyze_addr_config,
    _classify_ipv6,
    _count_nft_rules,
    _extract_v6_tables,
    _is_valid_ipv6,
    _own_v6_sweep_prefixes,
    _parse_dig_answers,
    _parse_nmap6_hosts,
    _parse_ra_output,
    _parse_route_get,
)


class _Ex:
    """Minimal fake executor for async helper tests."""

    def __init__(self, responses=None, success=True):
        self.responses = responses or {}
        self.success = success

    async def run(self, cmd, timeout=None, input_data=None):
        stdout = ""
        for key, val in self.responses.items():
            if key in cmd:
                stdout = val
                break
        return CommandResult(
            stdout=stdout, stderr="",
            returncode=0 if self.success else 1, success=self.success,
        )


def _run(coro):
    return asyncio.run(coro)


class TestIsValidIpv6:
    @pytest.mark.parametrize(
        "value",
        [
            "2001:4860:4860::8888",
            "2400:3200::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::abcd",
            "::1",
            "2402:4e00::",
        ],
    )
    def test_accepts_valid_ipv6(self, value):
        assert _is_valid_ipv6(value) is True

    @pytest.mark.parametrize(
        "value",
        ["192.168.1.1", "1.2.3.4", "2001:db8:::1", "example.com", "2001:db8::/64", ""],
    )
    def test_rejects_invalid(self, value):
        assert _is_valid_ipv6(value) is False


class TestClassifyIpv6:
    def test_global(self):
        assert _classify_ipv6("2400:3200::1") == "global"

    def test_global_with_prefix(self):
        assert _classify_ipv6("2001:db8::1/64") == "global"

    def test_ula_fc(self):
        assert _classify_ipv6("fc00::1") == "ULA"

    def test_ula_fd(self):
        assert _classify_ipv6("fd12:3456::1") == "ULA"

    def test_link_local(self):
        assert _classify_ipv6("fe80::1") == "link-local"

    def test_loopback(self):
        # ::1 必须单独归类，不能计入"公网"（否则误报有公网地址）
        assert _classify_ipv6("::1") == "loopback"

    def test_garbage(self):
        assert _classify_ipv6("not-an-address") == "unknown"


class TestIpv6PingInput:
    def test_default_target_is_none(self):
        p = Ipv6PingInput()
        assert p.target is None
        assert p.count == 4
        assert p.timeout == 3

    def test_accepts_valid_ipv6(self):
        p = Ipv6PingInput(target="2400:3200::1")
        assert p.target == "2400:3200::1"

    @pytest.mark.parametrize("bad", ["192.168.1.1", "example.com", "1.2.3.4"])
    def test_rejects_non_ipv6(self, bad):
        with pytest.raises(ValidationError):
            Ipv6PingInput(target=bad)

    def test_rejects_shell_meta(self):
        with pytest.raises(ValidationError):
            Ipv6PingInput(target="2400:3200::1;id")

    def test_rejects_bad_count(self):
        with pytest.raises(ValidationError):
            Ipv6PingInput(count=0)
        with pytest.raises(ValidationError):
            Ipv6PingInput(count=999)


class TestIpv6TracerouteInput:
    def test_accepts_ipv6(self):
        p = Ipv6TracerouteInput(target="2400:3200::1")
        assert p.target == "2400:3200::1"

    def test_accepts_domain(self):
        p = Ipv6TracerouteInput(target="baidu.com")
        assert p.target == "baidu.com"

    def test_rejects_garbage(self):
        with pytest.raises(ValidationError):
            Ipv6TracerouteInput(target="not a host")

    def test_rejects_shell_meta(self):
        with pytest.raises(ValidationError):
            Ipv6TracerouteInput(target="baidu.com|id")


class TestIpv6DigInput:
    def test_accepts_domain(self):
        p = Ipv6DigInput(domain="baidu.com")
        assert p.domain == "baidu.com"
        assert p.dns_server is None

    def test_accepts_v6_dns_server(self):
        p = Ipv6DigInput(domain="baidu.com", dns_server="2400:3200::1")
        assert p.dns_server == "2400:3200::1"

    def test_accepts_v4_dns_server(self):
        p = Ipv6DigInput(domain="baidu.com", dns_server="8.8.8.8")
        assert p.dns_server == "8.8.8.8"

    def test_rejects_bad_domain(self):
        with pytest.raises(ValidationError):
            Ipv6DigInput(domain="exa mple.com")

    def test_rejects_bad_dns_server(self):
        with pytest.raises(ValidationError):
            Ipv6DigInput(domain="baidu.com", dns_server="not-an-ip")


class TestParseDigAnswers:
    def test_parses_aaaa(self):
        out = """
;; ANSWER SECTION:
baidu.com.\t\t300\tIN\tAAAA\t2400:3200:bfff::1
;; AUTHORITY SECTION:
baidu.com.\t\t300\tIN\tNS\tns1.baidu.com.
"""
        assert _parse_dig_answers(out) == ["2400:3200:bfff::1"]

    def test_parses_multiple_a(self):
        out = """
;; ANSWER SECTION:
example.com.\t\t300\tIN\tA\t93.184.216.34
example.com.\t\t300\tIN\tA\t192.0.2.1
"""
        assert _parse_dig_answers(out) == ["93.184.216.34", "192.0.2.1"]

    def test_no_answer(self):
        out = """
;; ->>HEADER<<- opcode: QUERY
;; ANSWER SECTION:
"""
        assert _parse_dig_answers(out) == []

    def test_empty(self):
        assert _parse_dig_answers("") == []


class TestExtractV6Tables:
    def test_extracts_ip6_and_inet(self):
        ruleset = """table ip filter {
    chain in {
        type filter hook input priority 0; policy accept;
        tcp dport 22 accept
    }
}

table ip6 v6sec {
    chain in6 {
        type filter hook input priority 0; policy drop;
        ip6 daddr fe80::/10 accept
    }
}

table inet dual {
    chain all {
        type filter hook input priority 0; policy accept;
        udp dport 53 accept
    }
}
"""
        out = _extract_v6_tables(ruleset)
        assert "table ip6 v6sec" in out
        assert "table inet dual" in out
        assert "table ip filter" not in out  # v4-only family excluded

    def test_empty(self):
        assert _extract_v6_tables("") == ""

    def test_no_v6_tables(self):
        ruleset = "table ip foo {\n    chain c { policy accept; }\n}\n"
        assert _extract_v6_tables(ruleset) == ""


class TestCountNftRules:
    def test_counts_verdict_lines(self):
        text = """chain in6 {
    type filter hook input priority 0; policy drop;
    ip6 daddr fe80::/10 accept
    udp dport 22 drop
    tcp dport 80 reject
}
"""
        # policy line excluded, 3 verdict rules counted
        assert _count_nft_rules(text) == 3

    def test_empty(self):
        assert _count_nft_rules("") == 0


class TestRegistry:
    def test_ten_tools(self):
        assert len(IPV6_TOOLS) == 10

    def test_expected_names(self):
        assert set(IPV6_TOOLS) == {
            "ipv6_status",
            "ipv6_ping",
            "ipv6_traceroute",
            "ipv6_dig",
            "ipv6_neigh",
            "ipv6_firewall",
            "ipv6_scan",
            "ipv6_doctor",
            "ipv6_ra_inspect",
            "ipv6_route_debug",
        }

    def test_models_match(self):
        assert IPV6_TOOLS["ipv6_ping"][1] is Ipv6PingInput
        assert IPV6_TOOLS["ipv6_traceroute"][1] is Ipv6TracerouteInput
        assert IPV6_TOOLS["ipv6_dig"][1] is Ipv6DigInput
        assert IPV6_TOOLS["ipv6_status"][1] is None
        assert IPV6_TOOLS["ipv6_neigh"][1] is None
        assert IPV6_TOOLS["ipv6_firewall"][1] is None
        assert IPV6_TOOLS["ipv6_scan"][1] is Ipv6ScanInput
        assert IPV6_TOOLS["ipv6_doctor"][1] is Ipv6DoctorInput
        assert IPV6_TOOLS["ipv6_ra_inspect"][1] is Ipv6RaInspectInput
        assert IPV6_TOOLS["ipv6_route_debug"][1] is Ipv6RouteDebugInput


# ---------------------------------------------------------------------------
# ipv6_scan
# ---------------------------------------------------------------------------


class TestIpv6ScanInput:
    def test_defaults(self):
        p = Ipv6ScanInput()
        assert p.subnet is None
        assert p.interface is None
        assert p.auto_sweep is False
        assert p.timeout == 180

    def test_accepts_small_prefix(self):
        assert Ipv6ScanInput(subnet="fd00:beef::/80").subnet == "fd00:beef::/80"

    def test_accepts_link_local_with_zone(self):
        assert Ipv6ScanInput(subnet="fe80::/120%eth0").subnet == "fe80::/120%eth0"

    def test_accepts_single_address(self):
        assert Ipv6ScanInput(subnet="fe80::1").subnet == "fe80::1"

    def test_accepts_empty_string_as_none(self):
        assert Ipv6ScanInput(subnet="").subnet is None

    def test_accepts_120_prefix(self):
        # /120 = 256 addresses — small enough to sweep
        assert Ipv6ScanInput(subnet="fd00:beef::/120").subnet == "fd00:beef::/120"

    @pytest.mark.parametrize(
        "bad", ["fd00:beef::/64", "fd00:beef::/79", "192.168.0.0/24", "not-an-ipv6"]
    )
    def test_rejects_too_big_or_invalid(self, bad):
        with pytest.raises(ValidationError):
            Ipv6ScanInput(subnet=bad)

    def test_rejects_shell_meta(self):
        with pytest.raises(ValidationError):
            Ipv6ScanInput(subnet="fd00:beef::/80;id")


SAMPLE_NMAP6 = """Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-28 16:39 +0800
Nmap scan report for fe80::d6e8:53ff:fe66:656f
Host is up (0.0062s latency).
MAC Address: D4:E8:53:66:65:6F (Hangzhou Hikvision Digital Technology)
Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
"""


class TestParseNmap6Hosts:
    def test_single_host_with_mac(self):
        hosts = _parse_nmap6_hosts(SAMPLE_NMAP6)
        assert hosts == [
            {"ip": "fe80::d6e8:53ff:fe66:656f", "mac": "D4:E8:53:66:65:6F"}
        ]

    def test_hostname_form_strips_parens(self):
        out = (
            "Nmap scan report for cam (fd00:beef::5)\n"
            "Host is up.\n"
            "MAC Address: aa:bb:cc:dd:ee:09 (Unknown)\n"
        )
        hosts = _parse_nmap6_hosts(out)
        assert hosts[0]["ip"] == "fd00:beef::5"
        assert hosts[0]["mac"] == "AA:BB:CC:DD:EE:09"

    def test_multiple_hosts(self):
        out = (
            "Nmap scan report for fe80::1\nHost is up.\n"
            "MAC Address: aa:bb:cc:dd:ee:01 (x)\n"
            "Nmap scan report for fe80::2\nHost is up.\n"
        )
        hosts = _parse_nmap6_hosts(out)
        assert [h["ip"] for h in hosts] == ["fe80::1", "fe80::2"]
        assert hosts[1]["mac"] == ""  # no MAC line → empty

    def test_no_hosts(self):
        out = "Starting Nmap...\nNmap done: 2 IP addresses (0 hosts up) scanned\n"
        assert _parse_nmap6_hosts(out) == []


# ---------------------------------------------------------------------------
# ipv6_ra_inspect
# ---------------------------------------------------------------------------

# Real tcpdump 4.99.6 -vv capture of two RAs (one with M+O flags, prefix,
# MTU, SLLA; one bare) — captured on a live Kali box.
SAMPLE_RA_TCPDUMP = """16:42:22.845160 IP6 (hlim 255, next-header ICMPv6 (58), payload length 64) fe80::1 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 64
\thop limit 64, Flags [managed, other stateful], pref high, router lifetime 1800s, reachable time 0ms, retrans timer 0ms
\t  prefix info option (3), length 32 (4): fd00:beef:cafe::/64, Flags [onlink], valid time 86400s, pref. time 30000s
\t    0x0000:  4080 0001 5180 0000 7530 0000 0000 fd00
\t    0x0010:  beef cafe 0000 0000 0000 0000 0000 0000
\t  mtu option (5), length 8 (1):  1280
\t    0x0000:  0000 0000 0500
\t  source link-address option (1), length 8 (1): aa:bb:cc:dd:ee:01
\t    0x0000:  aabb ccdd ee01
16:42:22.870418 IP6 (hlim 255, next-header ICMPv6 (58), payload length 16) fe80::2 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 16
\thop limit 64, Flags [none], pref high, router lifetime 1800s, reachable time 0ms, retrans timer 0ms
"""


class TestParseRaOutput:
    def test_two_ras(self):
        ras = _parse_ra_output(SAMPLE_RA_TCPDUMP)
        assert len(ras) == 2

    def test_full_ra_parsed(self):
        ra = _parse_ra_output(SAMPLE_RA_TCPDUMP)[0]
        assert ra["src"] == "fe80::1"
        assert ra["dst"] == "ff02::1"
        assert ra["hop_limit"] == 64
        assert ra["flags"] == "managed, other stateful"
        assert ra["router_lifetime"] == 1800
        assert ra["mtu"] == 1280
        assert ra["lla"] == "AA:BB:CC:DD:EE:01"
        assert ra["prefixes"] == [
            {
                "prefix": "fd00:beef:cafe::/64",
                "flags": "onlink",
                "valid": 86400,
                "preferred": 30000,
            }
        ]

    def test_bare_ra_no_options(self):
        ra = _parse_ra_output(SAMPLE_RA_TCPDUMP)[1]
        assert ra["src"] == "fe80::2"
        assert ra["flags"] == "none"
        assert ra["prefixes"] == []
        assert ra["mtu"] is None
        assert ra["lla"] is None

    def test_empty(self):
        assert _parse_ra_output("") == []

    def test_non_ra_lines_ignored(self):
        out = (
            "10:00:00.0 IP6 (hlim 255, next-header ICMPv6 (58), payload length 32) "
            "fe80::1 > ff02::1: ICMP6, neighbor solicitation, who has fe80::2\n"
        )
        assert _parse_ra_output(out) == []


class TestIpv6RaInspectInput:
    def test_defaults(self):
        p = Ipv6RaInspectInput()
        assert p.interface is None
        assert p.duration == 30
        assert p.max_packets == 20

    def test_rejects_bad_iface(self):
        with pytest.raises(ValidationError):
            Ipv6RaInspectInput(interface="eth0;reboot")

    def test_rejects_bad_duration(self):
        with pytest.raises(ValidationError):
            Ipv6RaInspectInput(duration=1)


# ---------------------------------------------------------------------------
# ipv6_route_debug
# ---------------------------------------------------------------------------


class TestParseRouteGet:
    def test_routed_line(self):
        out = (
            "fe80::d6e8:53ff:fe66:656f from :: dev tailscale0 proto kernel "
            "src fe80::913a:1f1e:1f68:559 metric 256 pref medium"
        )
        info = _parse_route_get(out)
        assert info["from"] == "::"
        assert info["dev"] == "tailscale0"
        assert info["src"] == "fe80::913a:1f1e:1f68:559"
        assert info["metric"] == "256"
        assert info["via"] is None

    def test_local_line(self):
        out = (
            "local fd7a:115c:a1e0::4f36:243d from :: dev lo table local proto kernel "
            "src fd7a:115c:a1e0::4f36:243d metric 0 pref medium"
        )
        info = _parse_route_get(out)
        assert info["dev"] == "lo"
        assert info["src"] == "fd7a:115c:a1e0::4f36:243d"
        assert info["metric"] == "0"

    def test_empty(self):
        info = _parse_route_get("")
        assert all(v is None for v in info.values())


class TestIpv6RouteDebugInput:
    def test_default_target_none(self):
        assert Ipv6RouteDebugInput().target is None

    def test_accepts_ipv6(self):
        assert Ipv6RouteDebugInput(target="2400:3200::1").target == "2400:3200::1"

    def test_accepts_domain(self):
        assert Ipv6RouteDebugInput(target="baidu.com").target == "baidu.com"

    def test_rejects_garbage(self):
        with pytest.raises(ValidationError):
            Ipv6RouteDebugInput(target="not a host")

    def test_rejects_shell_meta(self):
        with pytest.raises(ValidationError):
            Ipv6RouteDebugInput(target="2400:3200::1|id")


# ---------------------------------------------------------------------------
# ipv6_doctor
# ---------------------------------------------------------------------------


class TestIpv6DoctorInput:
    def test_defaults(self):
        p = Ipv6DoctorInput()
        assert p.domain == "baidu.com"
        assert p.timeout == 6

    def test_rejects_bad_domain(self):
        with pytest.raises(ValidationError):
            Ipv6DoctorInput(domain="exa mple.com")

    def test_rejects_bad_timeout(self):
        with pytest.raises(ValidationError):
            Ipv6DoctorInput(timeout=1)


# ---------------------------------------------------------------------------
# ipv6_status config-source analysis
# ---------------------------------------------------------------------------


def _row(iface, raw, cls, flags, prefix=None):
    # Real code sets prefix = ip_interface(raw).network (the /64 network),
    # not the full address — mirror that unless a test overrides it.
    import ipaddress as _ip

    if prefix is None:
        try:
            prefix = str(_ip.ip_interface(raw).network)
        except ValueError:
            prefix = raw
    return {"iface": iface, "raw": raw, "cls": cls, "flags": flags, "prefix": prefix}


class TestAnalyzeAddrConfig:
    def test_static_address(self):
        out = _analyze_addr_config([_row("eth0", "fd00::5/64", "ULA", [])])
        assert len(out) == 1
        assert "静态" in out[0]["verdict"]

    def test_single_dynamic_is_ambiguous(self):
        out = _analyze_addr_config(
            [_row("eth0", "2408:abcd::1/64", "global", ["dynamic", "mngtmpaddr"])]
        )
        assert "SLAAC 或 DHCPv6" in out[0]["verdict"]
        assert "mngtmpaddr" in out[0]["verdict"]

    def test_two_dynamic_is_slaac_with_temp(self):
        rows = [
            _row("eth0", "2408:abcd::1/64", "global", ["dynamic", "mngtmpaddr"]),
            _row("eth0", "2408:abcd::2/64", "global", ["dynamic", "mngtmpaddr"]),
        ]
        out = _analyze_addr_config(rows)
        assert len(out) == 2
        assert all("SLAAC" in r["verdict"] for r in out)
        assert all("隐私扩展" in r["verdict"] for r in out)

    def test_link_local_excluded(self):
        assert _analyze_addr_config([_row("eth0", "fe80::1/64", "link-local", [])]) == []

    def test_loopback_excluded(self):
        assert _analyze_addr_config([_row("lo", "::1/128", "loopback", [])]) == []


# ---------------------------------------------------------------------------
# ipv6_scan sweep-prefix discovery
# ---------------------------------------------------------------------------

# Real `ip -6 addr show` from a live Kali box: LL on eth0, ULA /64 on eth0
# (hypothetical), /128 Tailscale ULA (must be excluded), ::1 on lo.
SAMPLE_IP6_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN qlen 1000
    inet6 ::1/128 scope host noprefixroute 
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
    inet6 fe80::250:56ff:fe27:ce21/64 scope link noprefixroute 
    inet6 2408:abcd:1234::1/64 scope global dynamic mngtmpaddr noprefixroute 
4: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 state UNKNOWN qlen 500
    inet6 fd7a:115c:a1e0::4f36:243d/128 scope global 
"""


class TestOwnV6SweepPrefixes:
    def test_finds_sweepable_64_prefixes(self):
        ex = _Ex({"addr": SAMPLE_IP6_ADDR})
        targets = _run(_own_v6_sweep_prefixes(ex))
        assert targets == ["fe80::/80%eth0", "2408:abcd:1234::/80"]

    def test_excludes_128_point_to_point(self):
        # Tailscale /128 must never produce a sweep scope
        ex = _Ex({"addr": SAMPLE_IP6_ADDR})
        targets = _run(_own_v6_sweep_prefixes(ex))
        assert all("fd7a" not in t for t in targets)

    def test_excludes_loopback(self):
        # lo's ::1/128 must never yield a bare "::/80" sweep scope
        ex = _Ex({"addr": SAMPLE_IP6_ADDR})
        targets = _run(_own_v6_sweep_prefixes(ex))
        assert all(t.split("%")[0] != "::/80" for t in targets)

    def test_failed_command_empty(self):
        ex = _Ex(success=False)
        assert _run(_own_v6_sweep_prefixes(ex)) == []


# ---------------------------------------------------------------------------
# ipv6_ra_inspect command construction
# ---------------------------------------------------------------------------

class TestRaInspectCommand:
    def test_listen_bounded_by_timeout_wrapper(self, monkeypatch):
        """The RA listen must end at the requested duration via
        `timeout -s INT` (clean SIGINT exit, rc 124) with -l line buffering,
        so captured RAs are never discarded by the executor backstop kill."""
        import kali_mcp.ipv6 as v6
        from kali_mcp.executor import CommandResult

        recorded = []

        class _FakeEx:
            async def run(self, cmd, timeout=None, input_data=None):
                recorded.append((list(cmd), timeout))
                return CommandResult(
                    stdout="", stderr="", returncode=124, success=False
                )

        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: _FakeEx())
        params = Ipv6RaInspectInput(interface="eth0", duration=20)
        out = _run(v6.ipv6_ra_inspect(params))

        cmd, exec_timeout = recorded[0]
        assert cmd[:4] == ["timeout", "-s", "INT", "20"]
        assert cmd[4] == "tcpdump"
        assert "-l" in cmd
        assert "icmp6[0] == 134" in cmd
        assert exec_timeout == 30  # backstop = duration + 10
        # graceful-stop path: no RAs parsed, rc 124 must not error out
        assert "0 个 RA" in out
