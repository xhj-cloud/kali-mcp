"""Tests for IPv6 tool input validation, parsing helpers, and registry."""

import pytest
from pydantic import ValidationError

from kali_mcp.ipv6 import (
    IPV6_TOOLS,
    Ipv6DigInput,
    Ipv6PingInput,
    Ipv6TracerouteInput,
    _classify_ipv6,
    _count_nft_rules,
    _extract_v6_tables,
    _is_valid_ipv6,
    _parse_dig_answers,
)


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
    def test_six_tools(self):
        assert len(IPV6_TOOLS) == 6

    def test_expected_names(self):
        assert set(IPV6_TOOLS) == {
            "ipv6_status",
            "ipv6_ping",
            "ipv6_traceroute",
            "ipv6_dig",
            "ipv6_neigh",
            "ipv6_firewall",
        }

    def test_models_match(self):
        assert IPV6_TOOLS["ipv6_ping"][1] is Ipv6PingInput
        assert IPV6_TOOLS["ipv6_traceroute"][1] is Ipv6TracerouteInput
        assert IPV6_TOOLS["ipv6_dig"][1] is Ipv6DigInput
        assert IPV6_TOOLS["ipv6_status"][1] is None
        assert IPV6_TOOLS["ipv6_neigh"][1] is None
        assert IPV6_TOOLS["ipv6_firewall"][1] is None
