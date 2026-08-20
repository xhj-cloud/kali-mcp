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
