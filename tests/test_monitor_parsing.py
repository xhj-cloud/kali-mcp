"""Tests for network monitoring parsing logic (monitor.py)."""

import pytest

from kali_mcp.monitor import (
    _PKT6_RE,
    _PKT_RE,
    _normalize_proto,
    _split_v6_endpoint,
)


class TestPacketRegex:
    def test_parses_udp_line(self):
        line = (
            "1700000000.123456 IP 192.168.1.5.54321 > 8.8.8.8.53: "
            "UDP, length 62"
        )
        m = _PKT_RE.match(line)
        assert m is not None
        assert m.group(1) == "192.168.1.5"
        assert m.group(2) == "54321"
        assert m.group(3) == "8.8.8.8"
        assert m.group(4) == "53"
        # `\S+` keeps the trailing comma; _normalize_proto strips it
        assert m.group(5) == "UDP,"
        assert _normalize_proto(m.group(5)) == "UDP"

    def test_parses_tcp_flags_line(self):
        line = (
            "1700000000.654321 IP 10.0.0.2.443 > 10.0.0.99.55555: "
            "Flags [S.], seq 1, ack 1, win 64240, length 0"
        )
        m = _PKT_RE.match(line)
        assert m is not None
        assert m.group(1) == "10.0.0.2"
        assert m.group(2) == "443"
        assert m.group(3) == "10.0.0.99"
        assert m.group(4) == "55555"
        assert m.group(5) == "Flags"

    @pytest.mark.parametrize("bad", ["not a packet line", "", "IP 1.2.3.4"])
    def test_does_not_match_garbage(self, bad):
        assert _PKT_RE.match(bad) is None

    def test_does_not_match_v6_line(self):
        # "IP6" must not be swallowed by the IPv4 regex ("IP " requires a space)
        line = "1700000000.1 IP6 2408::1.443 > 2400:3200::1.53: UDP, length 48"
        assert _PKT_RE.match(line) is None


class TestPacket6Regex:
    def test_parses_udp_with_ports(self):
        line = "1700000000.123456 IP6 2408::1.443 > 2400:3200::1.53: UDP, length 48"
        m = _PKT6_RE.match(line)
        assert m is not None
        assert _split_v6_endpoint(m.group(1)) == ("2408::1", "443")
        assert _split_v6_endpoint(m.group(2)) == ("2400:3200::1", "53")
        assert _normalize_proto(m.group(3)) == "UDP"

    def test_parses_icmp6_without_ports(self):
        line = (
            "1700000000.222222 IP6 fe80::1 > ff02::1: ICMP6, neighbor "
            "solicitation, who has fe80::2, length 32"
        )
        m = _PKT6_RE.match(line)
        assert m is not None
        assert _split_v6_endpoint(m.group(1)) == ("fe80::1", "")
        assert _split_v6_endpoint(m.group(2)) == ("ff02::1", "")
        assert _normalize_proto(m.group(3)) == "ICMPv6"

    @pytest.mark.parametrize(
        "bad", ["not a v6 line", "", "1700000000.1 IP 1.2.3.4.5 > 5.6.7.8.9: UDP, length 1"]
    )
    def test_does_not_match_non_v6(self, bad):
        assert _PKT6_RE.match(bad) is None


class TestSplitV6Endpoint:
    def test_with_port(self):
        assert _split_v6_endpoint("2408::1.443") == ("2408::1", "443")

    def test_without_port(self):
        assert _split_v6_endpoint("fe80::1") == ("fe80::1", "")

    def test_multihop_address_kept(self):
        # a bare v6 address has no dots → returned unchanged
        assert _split_v6_endpoint("2400:3200::1") == ("2400:3200::1", "")


class TestNormalizeProto:
    @pytest.mark.parametrize(
        ("first_word", "expected"),
        [
            ("Flags", "TCP"),
            ("flags", "TCP"),
            ("udp", "UDP"),
            ("icmp", "ICMP"),
            ("icmp6", "ICMPv6"),
            ("ICMP6,", "ICMPv6"),
            ("igmp", "IGMP"),
            ("esp", "ESP"),
            ("gre", "GRE"),
            ("something_unknown", "TCP"),
        ],
    )
    def test_normalization(self, first_word, expected):
        assert _normalize_proto(first_word) == expected


class TestNethogsParsing:
    def test_rate_to_bps(self):
        from kali_mcp.monitor import _rate_to_bps
        assert _rate_to_bps("34.5MiB/s") == pytest.approx(34.5 * 1024**2)
        assert _rate_to_bps("1.2KiB/s") == pytest.approx(1.2 * 1024)
        assert _rate_to_bps("0.0B/s") == 0.0
        assert _rate_to_bps("garbage") == 0.0

    def test_row_regex_matches_data_line(self):
        from kali_mcp.monitor import _NETHOGS_ROW_RE
        line = " 12345 chrome      34.5MiB/s   2.1MiB/s  36.6MiB/s         0.0KiB/s   12.3GiB   12.3GiB"
        m = _NETHOGS_ROW_RE.match(line)
        assert m is not None
        assert m.group(1) == "12345"
        assert m.group(2) == "chrome"
        assert m.group(3) == "34.5MiB/s"
        assert m.group(4) == "2.1MiB/s"

    def test_row_regex_rejects_header_and_legend(self):
        from kali_mcp.monitor import _NETHOGS_ROW_RE
        assert _NETHOGS_ROW_RE.match("  TID   PROGRAM     [R]ECEIVED  [S]ENT") is None
        assert _NETHOGS_ROW_RE.match("Legend: [R]eceived [S]ent  =  rate of read/write activity") is None

    def test_parse_trace_format(self):
        from kali_mcp.monitor import _parse_nethogs_output
        out = (
            "Adding local address: 192.168.0.189\n"
            "Ethernet link detected\n"
            "\n"
            "Refreshing:\n"
            "/usr/sbin/tailscaled/965/0\t0.157617\t0.0318359\n"
            "unknown TCP/0/0\t0\t0\n"
        )
        procs = _parse_nethogs_output(out)
        assert len(procs) == 2
        t = next(p for p in procs if p["pid"] == 965)
        assert t["program"] == "/usr/sbin/tailscaled"
        assert t["total_bps"] > 0

    def test_parse_keeps_latest_frame(self):
        from kali_mcp.monitor import _parse_nethogs_output
        out = (
            "Refreshing:\n"
            "chrome/1234/0\t1.0\t2.0\n"
            "Refreshing:\n"
            "chrome/1234/0\t5.0\t6.0\n"
        )
        procs = _parse_nethogs_output(out)
        assert len(procs) == 1
        assert procs[0]["total_bps"] == (5.0 + 6.0) * 1024

    def test_parse_mixed_formats(self):
        from kali_mcp.monitor import _parse_nethogs_output
        out = " 777 chrome      34.5MiB/s   2.1MiB/s\nfirefox/888/0\t10.0\t0.5\n"
        procs = {p["pid"]: p for p in _parse_nethogs_output(out)}
        assert set(procs) == {777, 888}
        assert procs[777]["recv"] == "34.5MiB/s"
        assert procs[888]["program"] == "firefox"


# ---------------------------------------------------------------------------
# traffic_stats capture command construction
# ---------------------------------------------------------------------------

class TestTrafficStatsCommand:
    def test_capture_bounded_by_timeout_wrapper(self, monkeypatch):
        """tcpdump must be bounded by `timeout -s INT {duration}` so the
        capture ends at the requested duration with a clean SIGINT exit
        (returncode 124) instead of relying on the executor backstop kill."""
        import asyncio

        import kali_mcp.monitor as mon
        from kali_mcp.executor import CommandResult

        recorded = []

        class _FakeEx:
            async def run(self, cmd, timeout=None, input_data=None):
                recorded.append((list(cmd), timeout))
                return CommandResult(
                    stdout="", stderr="", returncode=124, success=False
                )

        monkeypatch.setattr(mon, "get_executor", lambda timeout=None: _FakeEx())
        params = mon.TrafficStatsInput(interface="eth0", duration=12, count=200)
        out = asyncio.run(mon.traffic_stats(params))

        cmd, exec_timeout = recorded[0]
        assert cmd[:4] == ["timeout", "-s", "INT", "12"]
        assert cmd[4] == "tcpdump"
        assert "-l" in cmd and "-tt" in cmd
        assert exec_timeout == 22  # backstop = duration + 10
        # graceful-stop path: rc 124 must not break the (empty) report
        assert "**捕获:** 0 包" in out
