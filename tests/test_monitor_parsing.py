"""Tests for network monitoring parsing logic (monitor.py)."""

import pytest

from kali_mcp.monitor import _PKT_RE, _normalize_proto


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


class TestNormalizeProto:
    @pytest.mark.parametrize(
        ("first_word", "expected"),
        [
            ("Flags", "TCP"),
            ("flags", "TCP"),
            ("udp", "UDP"),
            ("icmp", "ICMP"),
            ("igmp", "IGMP"),
            ("esp", "ESP"),
            ("gre", "GRE"),
            ("something_unknown", "TCP"),
        ],
    )
    def test_normalization(self, first_word, expected):
        assert _normalize_proto(first_word) == expected
