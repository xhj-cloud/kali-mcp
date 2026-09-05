"""Tests for IPv6 tool input validation, parsing helpers, and registry."""

import asyncio

import pytest
from pydantic import ValidationError

from kali_mcp.executor import CommandResult
from kali_mcp.ipv6 import (
    IPV6_PENTEST_TOOLS,
    IPV6_TOOLS,
    Ipv6DigInput,
    Ipv6DoctorInput,
    Ipv6PingInput,
    Ipv6RaInspectInput,
    Ipv6RouteDebugInput,
    Ipv6ReconInput,
    Ipv6ScanInput,
    Ipv6ServiceScanInput,
    Ipv6TracerouteInput,
    _analyze_addr_config,
    _classify_ipv6,
    _count_nft_rules,
    _extract_v6_tables,
    _is_valid_ipv6,
    _local_v6_prefixes,
    _mac_to_eui64_iid,
    _own_v6_sweep_prefixes,
    _parse_dig_answers,
    _parse_nmap6_hosts,
    _parse_nmap6_service,
    _parse_ra_output,
    _parse_rdisc_output,
    _parse_route_get,
    _slaac_candidate,
    _validate_v6_subnet,
    _v4_neigh_macs,
    ipv6_doctor,
    ipv6_recon,
    ipv6_service_scan,
    ipv6_traceroute,
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


class TestIpv6TracerouteCmd:
    """Regression: traceroute6 不接受 -6 选项（会报 "无效的选项 -- 6"）。"""

    def test_cmd_has_no_dashesix_flag(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = cmd
                return CommandResult(stdout="", stderr="", returncode=0, success=True)

        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: _CapEx())
        out = _run(ipv6_traceroute(Ipv6TracerouteInput(target="2400:3200::1")))
        assert isinstance(out, str)
        cmd = captured["cmd"]
        assert "traceroute6" in cmd
        assert "-6" not in cmd, "traceroute6 是 IPv6 专用，-6 是非法选项"
        assert "2400:3200::1" in cmd


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


class TestIpv6DoctorCmds:
    """Regression: iputils ping 的 -W 单位是秒；传毫秒（*1000）会超上限，
    报 "ping: bad linger time: 6000"。"""

    def test_l4_ping_wait_is_in_seconds(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        captured: list = []

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None):
                captured.append(list(cmd))
                joined = " ".join(cmd)
                if joined.startswith("ip -6 addr"):
                    out = (
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                        "    inet6 2409:8931:1247:7f4:250:56ff:fe27:ce21/64 "
                        "scope global dynamic mngtmpaddr\n"
                        "    inet6 fe80::250:56ff:fe27:ce21/64 scope link\n"
                    )
                elif "route" in joined:
                    out = "default via fe80::905b:f4ff:fe9a:f655 dev eth0"
                elif "dig" in joined:
                    # +short 会混入 CNAME 行，只有最后一个是真实 AAAA
                    out = "www-apple-com.v.aaplimg.com.\n2400:3200::1\n"
                elif "ping" in joined:
                    out = (
                        "2 packets transmitted, 2 received, 0% packet loss\n"
                        "rtt min/avg/max/mdev = 40.0/41.0/42.0/1.0 ms\n"
                    )
                elif "curl" in joined:
                    out = "2409:8931:1247:7f4:250:56ff:fe27:ce21"
                else:
                    out = ""
                return CommandResult(stdout=out, stderr="", returncode=0, success=True)

        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: _CapEx())
        out = _run(ipv6_doctor(Ipv6DoctorInput()))
        assert isinstance(out, str)
        ping_cmds = [c for c in captured if c and c[0] == "ping"]
        assert ping_cmds, "doctor 应执行 L4 公网 ping"
        c = ping_cmds[0]
        w = int(c[c.index("-W") + 1])
        assert w <= 30, f"-W 应为秒（默认 timeout=6），实际 {w}"
        # L3 结论行不应把 CNAME 域名显示为 AAAA 结果（raw 证据区除外）
        l3_line = next(l for l in out.splitlines() if l.startswith("| L3 "))
        assert "aaplimg" not in l3_line
        assert "2400:3200::1" in l3_line
        # L5 用可解析的 api6.ipify.org 端点
        curl_cmds = [c for c in captured if c and c[0] == "curl"]
        assert curl_cmds and "api6.ipify.org" in " ".join(curl_cmds[0])


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


# ---------------------------------------------------------------------------
# 🟡 ipv6_recon / ipv6_service_scan — pentest tier
# ---------------------------------------------------------------------------


class TestValidateV6Subnet:
    def test_none_passes_through(self):
        assert _validate_v6_subnet(None) is None
        assert _validate_v6_subnet("") is None
        assert _validate_v6_subnet("   ") is None

    def test_accepts_small_prefix(self):
        assert _validate_v6_subnet("fd00:beef::/80") == "fd00:beef::/80"

    def test_accepts_single_address(self):
        assert _validate_v6_subnet("2408:4000:1::1") == "2408:4000:1::1"

    def test_rejects_64(self):
        with pytest.raises(ValidationError):
            Ipv6ReconInput(subnet="2408:4000:1::/64")

    def test_rejects_garbage(self):
        with pytest.raises(ValidationError):
            Ipv6ReconInput(subnet="not-an-ip")

    def test_rejects_shell_meta(self):
        with pytest.raises(ValidationError):
            Ipv6ReconInput(subnet="2408:4000:1::1; rm -rf /")


class TestMacToEui64:
    def test_flips_ul_bit_and_inserts_fffe(self):
        assert _mac_to_eui64_iid("00:1a:2b:3c:4d:5e") == "011a:2bff:fe3c:4d5e"

    def test_another_mac(self):
        assert _mac_to_eui64_iid("d4:e8:53:66:65:6f") == "d5e8:53ff:fe66:656f"

    def test_already_local_bit(self):
        # u/l bit (0x01) already set → flipping clears it
        assert _mac_to_eui64_iid("01:1a:2b:3c:4d:5e") == "001a:2bff:fe3c:4d5e"

    @pytest.mark.parametrize("bad", ["zz:1a:2b:3c:4d:5e", "00:1a:2b", "", "001a:2b:3c:4d:5e"])
    def test_malformed(self, bad):
        assert _mac_to_eui64_iid(bad) is None


class TestSlaacCandidate:
    def test_global_prefix(self):
        assert (
            _slaac_candidate("2001:db8::/64", "011a:2bff:fe3c:4d5e")
            == "2001:db8::11a:2bff:fe3c:4d5e"
        )

    def test_ula_prefix(self):
        assert (
            _slaac_candidate("fd12:3456::/64", "011a:2bff:fe3c:4d5e")
            == "fd12:3456::11a:2bff:fe3c:4d5e"
        )

    def test_non_zero_network(self):
        assert (
            _slaac_candidate("2408:abcd:1234:5::/64", "011a:2bff:fe3c:4d5e")
            == "2408:abcd:1234:5:11a:2bff:fe3c:4d5e"
        )


SAMPLE_RDISC = """Soliciting ff02::2 (ff02::2) on eth0...
Router advertisement received from fe80::1 with hop limit 64:
Hop limit                 :       64
Stateful address conf.    :          valid
Stateful other conf.      :          invalid
Mobile home agent         :          invalid
Router preference         :       medium
Neighbor discovery proxy  :          invalid
Router lifetime           :      1800 (0x00000708) seconds
Reachable time            : unspecified (0x00000000)
Retransmit time           : unspecified (0x00000000)
 Source link-layer address: AA:BB:CC:DD:EE:FF
 Prefix                   :  2408:abcd:1234::/64
  On-link                 :          valid
  Autonomous address conf.:          valid
  Valid time              :    300000 (0x000493e0) seconds
  Pref. time              :    300000 (0x000493e0) seconds
 MTU                      :      1500 bytes (0x05dc)
 Prefix                   :  2408:abcd:1235::/64
  On-link                 :          invalid
  Autonomous address conf.:          invalid
  Valid time              :    300000 (0x000493e0) seconds
  Pref. time              :    300000 (0x000493e0) seconds
 Route                    : 2408:abcd:99::/64
  Route preference        :       high
  Route lifetime          :      1800 (0x00000708) seconds
 Recursive DNS server     : 2400:3200::1
  DNS server lifetime     :      1800 (0x00000708) seconds
 DNS search list          : example.com
  DNS search list lifetime:      1800 (0x00000708) seconds
 NAT64 prefix             : 64:ff9b::/96
  NAT64 prefix lifetime   :      1800 (0x00000708) seconds
"""


class TestParseRdiscOutput:
    def test_parses_full_ra(self):
        routers = _parse_rdisc_output(SAMPLE_RDISC)
        assert len(routers) == 1
        rt = routers[0]
        assert rt["src"] == "fe80::1"
        assert rt["hop_limit"] == 64
        assert rt["stateful_addr"] is True
        assert rt["stateful_other"] is False
        assert rt["mha"] is False
        assert rt["proxy"] is False
        assert rt["pref"] == "medium"
        assert rt["lifetime"] == 1800
        assert rt["reachable"] is None  # unspecified (0x00000000)
        assert rt["lla"] == "AA:BB:CC:DD:EE:FF"
        assert rt["mtu"] == 1500

    def test_prefixes(self):
        rt = _parse_rdisc_output(SAMPLE_RDISC)[0]
        assert len(rt["prefixes"]) == 2
        p0 = rt["prefixes"][0]
        assert p0["prefix"] == "2408:abcd:1234::"
        assert p0["plen"] == 64
        assert p0["onlink"] is True
        assert p0["autoconf"] is True
        assert p0["valid"] == 300000
        assert p0["pref"] == 300000
        p1 = rt["prefixes"][1]
        assert p1["prefix"] == "2408:abcd:1235::"
        assert p1["onlink"] is False
        assert p1["autoconf"] is False

    def test_routes_rdns_nat64(self):
        rt = _parse_rdisc_output(SAMPLE_RDISC)[0]
        assert rt["routes"][0]["prefix"] == "2408:abcd:99::"
        assert rt["routes"][0]["plen"] == 64
        assert rt["routes"][0]["pref"] == "high"
        assert rt["routes"][0]["lifetime"] == 1800
        assert rt["rdns"][0]["server"] == "2400:3200::1"
        assert rt["rdns"][0]["lifetime"] == 1800
        assert rt["search_lists"][0]["list"] == "example.com"
        assert rt["nat64"][0]["prefix"] == "64:ff9b::"
        assert rt["nat64"][0]["plen"] == 96

    def test_no_response(self):
        out = "Soliciting ff02::2 (ff02::2) on eth0...\nTimed out.\nTimed out.\nNo response."
        assert _parse_rdisc_output(out) == []

    def test_empty(self):
        assert _parse_rdisc_output("") == []

    def test_two_routers(self):
        out = (
            "Router advertisement received from fe80::1 with hop limit 64:\n"
            "Hop limit                 :       64\n"
            " Prefix                   :  2001:db8::/64\n"
            "  On-link                 :          valid\n"
            "Router advertisement received from fe80::2 with hop limit 64:\n"
            "Hop limit                 :       255\n"
        )
        routers = _parse_rdisc_output(out)
        assert [r["src"] for r in routers] == ["fe80::1", "fe80::2"]
        assert routers[0]["prefixes"][0]["prefix"] == "2001:db8::"
        assert routers[1]["prefixes"] == []

    def test_fallback_header(self):
        # Unrecognised header shape, ending in a v6 address
        out = "Got RA from fe80::254\nHop limit                 :       64\n"
        routers = _parse_rdisc_output(out)
        assert len(routers) == 1
        assert routers[0]["src"] == "fe80::254"
        assert routers[0]["hop_limit"] == 64


# Real rdisc6 1.0.8 (ndisc6) capture — no "received from" header; the
# router source arrives as an indented " from <addr>" line at the END of
# the block, booleans are Yes/No.
SAMPLE_RDISC_REAL = """Soliciting ff02::2 (ff02::2) on eth0...

Hop limit                 :          254 (      0xfe)
Stateful address conf.    :           No
Stateful other conf.      :           No
Mobile home agent         :           No
Router preference         :         high
Neighbor discovery proxy  :           No
Router lifetime           :         7200 (0x00001c20) seconds
Reachable time            :  unspecified (0x00000000)
Retransmit time           :  unspecified (0x00000000)
 Source link-layer address: 92:5B:F4:9A:F6:55
 MTU                      :         1500 bytes (valid)
 Prefix                   : 2409:8931:1247:7f4::/64
  On-link                 :          Yes
  Autonomous address conf.:          Yes
  Valid time              :         7200 (0x00001c20) seconds
  Pref. time              :         7200 (0x00001c20) seconds
 Recursive DNS server     : 2409:8931:1247:7f4::77
  DNS server lifetime     :         7200 (0x00001c20) seconds
 from fe80::905b:f4ff:fe9a:f655
"""


class TestParseRdiscRealFormat:
    def test_parses_real_ra(self):
        routers = _parse_rdisc_output(SAMPLE_RDISC_REAL)
        assert len(routers) == 1
        rt = routers[0]
        assert rt["src"] == "fe80::905b:f4ff:fe9a:f655"
        assert rt["hop_limit"] == 254
        assert rt["stateful_addr"] is False
        assert rt["stateful_other"] is False
        assert rt["mha"] is False
        assert rt["proxy"] is False
        assert rt["pref"] == "high"
        assert rt["lifetime"] == 7200
        assert rt["reachable"] is None
        assert rt["retrans"] is None
        assert rt["lla"] == "92:5B:F4:9A:F6:55"
        assert rt["mtu"] == 1500
        assert "_sealed" not in rt

    def test_real_prefix_and_rdns(self):
        rt = _parse_rdisc_output(SAMPLE_RDISC_REAL)[0]
        assert len(rt["prefixes"]) == 1
        p = rt["prefixes"][0]
        assert p["prefix"] == "2409:8931:1247:7f4::"
        assert p["plen"] == 64
        assert p["onlink"] is True
        assert p["autoconf"] is True
        assert p["valid"] == 7200
        assert p["pref"] == 7200
        assert rt["rdns"] == [
            {"server": "2409:8931:1247:7f4::77", "lifetime": 7200}
        ]

    def test_two_real_blocks(self):
        # Second RA block (no re-printed "Soliciting" line between blocks)
        out = SAMPLE_RDISC_REAL + (
            "Hop limit                 :          255 (      0xff)\n"
            "Router lifetime           :         1800 (0x00000708) seconds\n"
            " Prefix                   : 2409:8931:1247:7f5::/64\n"
            "  On-link                 :          Yes\n"
            " from fe80::aa\n"
        )
        routers = _parse_rdisc_output(out)
        assert [r["src"] for r in routers] == [
            "fe80::905b:f4ff:fe9a:f655",
            "fe80::aa",
        ]
        assert len(routers[1]["prefixes"]) == 1
        assert routers[1]["prefixes"][0]["prefix"] == "2409:8931:1247:7f5::"
        assert routers[1]["hop_limit"] == 255


SAMPLE_NMAP6_SVC = """Starting Nmap 7.92 ( https://nmap.org ) at 2025-01-01 00:00 UTC
Nmap scan report for 2408:4000:1::1
Host is up (0.0045s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Intel Corporate)
Not shown: 997 closed tcp ports
PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 8.9p1 (protocol 2.9)
| ssh-host-key:
|_  256 aa:bb:cc:dd (ECDSA)
80/tcp   open   http        Apache httpd 2.4.52
|_http-title: Site doesn't have a page (text/html)
8080/tcp filtered http-proxy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""


class TestParseNmap6Service:
    def test_full_parse(self):
        hosts = _parse_nmap6_service(SAMPLE_NMAP6_SVC)
        assert len(hosts) == 1
        h = hosts[0]
        assert h["host"] == "2408:4000:1::1"
        assert h["up"] is True
        assert h["not_shown"] == "997 closed tcp ports"
        assert h["mac"] == "AA:BB:CC:DD:EE:FF"
        assert len(h["ports"]) == 3
        p22, p80, p8080 = h["ports"]
        assert p22 == {
            "port": "22", "proto": "tcp", "state": "open",
            "service": "ssh", "version": "OpenSSH 8.9p1 (protocol 2.9)",
            "scripts": ["ssh-host-key:", "256 aa:bb:cc:dd (ECDSA)"],
        }
        assert p80["port"] == "80"
        assert p80["version"] == "Apache httpd 2.4.52"
        assert p80["scripts"] == ["http-title: Site doesn't have a page (text/html)"]
        assert p8080["state"] == "filtered"
        assert p8080["service"] == "http-proxy"
        assert p8080["version"] == ""
        assert h["service_info"][0].startswith("OS: Linux")

    def test_no_hosts(self):
        assert _parse_nmap6_service("Nmap done: 0 IP addresses (0 hosts up) scanned in 1.2 seconds\n") == []

    def test_two_hosts(self):
        out = (
            "Nmap scan report for 2408::1\n"
            "Host is up (0.001s latency).\n"
            "22/tcp   open   ssh\n"
            "Nmap scan report for 2408::2\n"
            "Host does not appear to be up.\n"
        )
        hosts = _parse_nmap6_service(out)
        assert [h["host"] for h in hosts] == ["2408::1", "2408::2"]
        assert hosts[0]["up"] is True
        assert hosts[1]["up"] is False


SAMPLE_V4_NEIGH = """192.168.0.5 dev eth0 lladdr d4:e8:53:66:65:6f STALE
192.168.0.21 dev eth0 lladdr 6c:f1:7e:e5:47:b9 REACHABLE
"""

SAMPLE_V6_NEIGH = """2408:abcd:1234::99 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
"""


class _CmdEx:
    """Fake executor keyed on substrings of the joined command."""

    def __init__(self, mapping):
        self.mapping = mapping  # list of (substring, CommandResult)
        self.calls: list[list[str]] = []

    async def run(self, cmd, timeout=None, input_data=None):
        self.calls.append(list(cmd))
        joined = " ".join(cmd)
        for key, res in self.mapping:
            if key in joined:
                return res
        return CommandResult(stdout="", stderr="", returncode=0, success=True)


def _cr(stdout="", stderr="", rc=0):
    return CommandResult(
        stdout=stdout, stderr=stderr, returncode=rc, success=(rc == 0)
    )


# str(IPv6Address) does not compress a single zero group, so the 4th group
# stays "0" (not "::") when the prefix is 2408:abcd:1234::/64.
CAND_HIT = "2408:abcd:1234:0:d5e8:53ff:fe66:656f"
CAND_MISS = "2408:abcd:1234:0:6df1:7eff:fee5:47b9"


class TestLocalV6Prefixes:
    def test_finds_global_64(self):
        ex = _Ex({"addr": SAMPLE_IP6_ADDR})
        assert _run(_local_v6_prefixes(ex)) == [("2408:abcd:1234::/64", "eth0")]

    def test_failed_command_empty(self):
        assert _run(_local_v6_prefixes(_Ex(success=False))) == []


class TestV4NeighMacs:
    def test_parses(self):
        ex = _CmdEx([("ip neigh", _cr(SAMPLE_V4_NEIGH))])
        assert _run(_v4_neigh_macs(ex)) == {
            "D4:E8:53:66:65:6F": "192.168.0.5",
            "6C:F1:7E:E5:47:B9": "192.168.0.21",
        }


class TestIpv6ReconTool:
    def test_full_run_with_hit(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        ex = _CmdEx(
            [
                ("rdisc6", _cr(SAMPLE_RDISC)),
                ("ip -6 addr", _cr(SAMPLE_IP6_ADDR)),
                ("ip -6 neigh", _cr(SAMPLE_V6_NEIGH)),
                ("ip neigh", _cr(SAMPLE_V4_NEIGH)),
                (CAND_HIT, _cr("1 packets transmitted, 1 received", rc=0)),
                (CAND_MISS, _cr("1 packets transmitted, 0 received", rc=1)),
            ]
        )
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(ipv6_recon(Ipv6ReconInput()))

        assert "路由发现（rdisc6）" in out
        assert "`fe80::1`" in out
        assert "前缀 `2408:abcd:1234::/64`" in out
        assert "RDNSS" in out and "2400:3200::1" in out
        assert "SLAAC 命中 1" in out
        assert f"`{CAND_HIT}`" in out
        assert "SLAAC 猜测" in out
        # NDP rows present
        assert "2408:abcd:1234::99" in out
        # v4 cross-reference for the SLAAC hit
        assert "192.168.0.5" in out
        # both candidate pings were issued
        assert any(CAND_HIT in " ".join(c) for c in ex.calls)
        assert any(CAND_MISS in " ".join(c) for c in ex.calls)

    def test_rdisc6_no_response(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        ex = _CmdEx(
            [
                (
                    "rdisc6",
                    _cr(
                        "Soliciting ff02::2 (ff02::2) on eth0...\nTimed out.\nNo response.",
                        rc=2,
                    ),
                ),
                ("ip -6 addr", _cr(SAMPLE_IP6_ADDR)),
                ("ip -6 neigh", _cr(SAMPLE_V6_NEIGH)),
                ("ip neigh", _cr(SAMPLE_V4_NEIGH)),
            ]
        )
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(ipv6_recon(Ipv6ReconInput(slaac_guess=False)))
        assert "未收到任何路由器通告" in out
        assert "已关闭（slaac_guess=false）" in out

    def test_rdisc6_missing(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        ex = _CmdEx(
            [
                (
                    "rdisc6",
                    _cr(
                        stderr="Tool 'rdisc6' not found. Install it with: sudo apt install rdisc6",
                        rc=-1,
                    ),
                ),
                ("ip -6 addr", _cr("")),
                ("ip -6 neigh", _cr("")),
                ("ip neigh", _cr("")),
            ]
        )
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(ipv6_recon(Ipv6ReconInput()))
        assert "rdisc6 未安装" in out
        assert "ndisc6" in out

    def test_with_bounded_sweep(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        nmap_out = (
            "Nmap scan report for 2408:abcd:1234::5\n"
            "Host is up (0.001s latency).\n"
        )
        ex = _CmdEx(
            [
                ("rdisc6", _cr(SAMPLE_RDISC)),
                ("ip -6 addr", _cr(SAMPLE_IP6_ADDR)),
                ("ip -6 neigh", _cr("")),
                ("ip neigh", _cr("")),
                ("nmap -sn", _cr(nmap_out)),
            ]
        )
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(
            ipv6_recon(Ipv6ReconInput(subnet="2408:abcd:1234::/96", slaac_guess=False))
        )
        assert "有界扫描" in out
        assert "2408:abcd:1234::5" in out
        assert any(c[0] == "nmap" for c in ex.calls)


class TestIpv6ServiceScanInput:
    def test_accepts_address(self):
        assert Ipv6ServiceScanInput(target="2408:4000:1::1").target == "2408:4000:1::1"

    def test_accepts_small_cidr(self):
        assert Ipv6ServiceScanInput(target="2408:4000:1::/90").target == "2408:4000:1::/90"

    def test_rejects_64(self):
        with pytest.raises(ValidationError):
            Ipv6ServiceScanInput(target="2408:4000:1::/64")

    def test_rejects_shell_meta(self):
        with pytest.raises(ValidationError):
            Ipv6ServiceScanInput(target="2408:4000:1::1; id")

    @pytest.mark.parametrize("ports", ["80,443", "1-1024", "top-100", "80", "53,80,443"])
    def test_accepts_ports(self, ports):
        assert Ipv6ServiceScanInput(target="2408::1", ports=ports).ports == ports

    @pytest.mark.parametrize("ports", ["80;rm", "top", "-6", "80 443", "80,44;3"])
    def test_rejects_ports(self, ports):
        with pytest.raises(ValidationError):
            Ipv6ServiceScanInput(target="2408::1", ports=ports)

    def test_timing_normalized(self):
        assert Ipv6ServiceScanInput(target="2408::1", timing="t3").timing == "T3"

    def test_rejects_bad_timing(self):
        with pytest.raises(ValidationError):
            Ipv6ServiceScanInput(target="2408::1", timing="X1")


class TestIpv6ServiceScanTool:
    def test_full_run(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        ex = _CmdEx([("nmap", _cr(SAMPLE_NMAP6_SVC))])
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(ipv6_service_scan(Ipv6ServiceScanInput(target="2408:4000:1::1")))

        cmd = ex.calls[0]
        assert cmd[0] == "nmap"
        assert "-6" in cmd and "-sV" in cmd and "-sC" in cmd and "-T4" in cmd
        assert cmd[-1] == "2408:4000:1::1"

        assert "| 22/tcp | open | ssh | OpenSSH 8.9p1 (protocol 2.9) |" in out
        assert "| 80/tcp | open | http | Apache httpd 2.4.52 |" in out
        assert "| 8080/tcp | filtered | http-proxy | - |" in out
        assert "256 aa:bb:cc:dd (ECDSA)" in out
        assert "MAC: AA:BB:CC:DD:EE:FF" in out
        assert "2 个开放端口" in out

    def test_link_local_gets_zone(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        class _ZoneEx(_CmdEx):
            async def run(self, cmd, timeout=None, input_data=None):
                self.calls.append(list(cmd))
                if "nmap" in " ".join(cmd):
                    return _cr(SAMPLE_NMAP6_SVC)
                if "ip route" in " ".join(cmd):
                    return _cr("default via 192.168.0.1 dev eth0 proto static \n")
                return _cr()

        ex = _ZoneEx([])
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        _run(ipv6_service_scan(Ipv6ServiceScanInput(target="fe80::1")))
        assert ex.calls[-1][-1] == "fe80::1%eth0"

    def test_no_hosts_shows_stderr(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        ex = _CmdEx(
            [("nmap", _cr(stderr="Warning: No open ports found", rc=0))]
        )
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(ipv6_service_scan(Ipv6ServiceScanInput(target="2408::99")))
        assert "无扫描结果" in out
        assert "No open ports found" in out

    def test_large_prefix_warning(self, monkeypatch):
        import kali_mcp.ipv6 as v6

        ex = _CmdEx([("nmap", _cr(SAMPLE_NMAP6_SVC))])
        monkeypatch.setattr(v6, "get_executor", lambda timeout=None: ex)
        out = _run(
            ipv6_service_scan(Ipv6ServiceScanInput(target="2408:4000:1::/80"))
        )
        assert "前缀较大" in out


class TestIpv6PentestRegistry:
    def test_two_tools(self):
        assert len(IPV6_PENTEST_TOOLS) == 2

    def test_expected_names(self):
        assert set(IPV6_PENTEST_TOOLS) == {"ipv6_recon", "ipv6_service_scan"}

    def test_models_match(self):
        assert IPV6_PENTEST_TOOLS["ipv6_recon"][1] is Ipv6ReconInput
        assert IPV6_PENTEST_TOOLS["ipv6_service_scan"][1] is Ipv6ServiceScanInput

    def test_base_registry_unchanged(self):
        assert len(IPV6_TOOLS) == 10
