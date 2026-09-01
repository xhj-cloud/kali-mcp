"""Tests for the shared network-detection layer (netinfo.py).

Covers the logic that used to be copy-pasted across tools.py,
monitor.py and pentest.py:
- detect_default_iface / detect_subnet / detect_gateway
- arp_scan_devices (parse + classify, MAC uppercasing, .1 → gateway)
- arp_mermaid_lines (incl. the no-gateway NameError regression)
- arp_class_stats_lines
"""

import asyncio

from kali_mcp.executor import CommandResult
from kali_mcp.netinfo import (
    arp_class_stats_lines,
    arp_mermaid_lines,
    arp_scan_devices,
    classify_device,
    detect_default_iface,
    detect_gateway,
    detect_subnet,
    merge_ndp_devices,
    ndp_devices,
)


class FakeExecutor:
    """Canned responses keyed by a substring matched against the cmd list."""

    def __init__(self, responses=None, success=True):
        self.calls: list[list[str]] = []
        self.responses = responses or {}
        self.success = success

    async def run(self, cmd, timeout=None, input_data=None):
        self.calls.append(list(cmd))
        stdout = ""
        for key, val in self.responses.items():
            if key in cmd:
                stdout = val
                break
        return CommandResult(
            stdout=stdout,
            stderr="",
            returncode=0 if self.success else 1,
            success=self.success,
        )


# Output of `ip -4 addr show eth0` (only that interface)
SAMPLE_IP_ADDR = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.0.99/24 brd 192.168.0.255 scope global eth0
       valid_lft forever preferred_lft forever
"""

# Output of `arp-scan` (tab-separated columns)
SAMPLE_ARP = "\n".join([
    "192.168.0.1\taa:bb:cc:dd:ee:01\tTP-Link Technologies Co.",
    "192.168.0.23\taa:bb:cc:dd:ee:02\tApple",
    "192.168.0.45\taa:bb:cc:dd:ee:03\tUbiquiti Inc.",
    "192.168.0.77\taa:bb:cc:dd:ee:04",
    "not-an-ip line\taa:bb:cc:dd:ee:05\tJunk",
])


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# classify_device
# ---------------------------------------------------------------------------


class TestClassifyDevice:
    def test_router_vendor(self):
        assert classify_device("TP-Link Technologies") == ("router", "🌐")

    def test_network_vendor(self):
        assert classify_device("H3C") == ("network", "🔀")

    def test_computer_vendor(self):
        assert classify_device("Apple") == ("computer", "💻")

    def test_unknown_vendor(self):
        assert classify_device("Some Random LLC") == ("unknown", "❓")

    def test_empty_vendor(self):
        assert classify_device("") == ("unknown", "❓")


# ---------------------------------------------------------------------------
# detect_default_iface / detect_subnet / detect_gateway
# ---------------------------------------------------------------------------


class TestDetectDefaultIface:
    def test_finds_dev(self):
        ex = FakeExecutor({"route": "default via 192.168.0.1 dev eth0  proto static"})
        assert run(detect_default_iface(ex)) == "eth0"

    def test_fallback_eth0_on_no_match(self):
        ex = FakeExecutor({"route": "some other route"})
        assert run(detect_default_iface(ex)) == "eth0"


class TestDetectSubnet:
    def test_explicit_subnet_wins(self):
        ex = FakeExecutor()
        assert run(detect_subnet(ex, "10.0.0.0/8")) == "10.0.0.0/8"
        # no commands should even be issued
        assert ex.calls == []

    def test_explicit_whitespace_is_ignored(self):
        ex = FakeExecutor(
            {"route": "default via 192.168.0.1 dev eth0", "addr": SAMPLE_IP_ADDR}
        )
        assert run(detect_subnet(ex, "   ")) == "192.168.0.0/24"

    def test_auto_detect_from_default_route(self):
        ex = FakeExecutor(
            {"route": "default via 192.168.0.1 dev eth0", "addr": SAMPLE_IP_ADDR}
        )
        assert run(detect_subnet(ex, "")) == "192.168.0.0/24"

    def test_detection_failure_returns_none(self):
        """No hardcoded fallback subnet: when auto-detect fails the caller
        must ask for an explicit subnet instead of assuming a network."""
        # ip route gives an iface but ip addr has no inet line
        ex = FakeExecutor({"route": "default via 192.168.0.1 dev eth0", "addr": ""})
        assert run(detect_subnet(ex, None)) is None

    def test_bad_inet_returns_none(self):
        ex = FakeExecutor(
            {"route": "default via 192.168.0.1 dev eth0",
             "addr": "inet not-an-address scope global eth0"}
        )
        assert run(detect_subnet(ex, None)) is None


class TestDetectGateway:
    def test_via_address(self):
        ex = FakeExecutor({"route": "default via 192.168.0.1 dev eth0"})
        assert run(detect_gateway(ex, "192.168.0.99")) == "192.168.0.1"

    def test_no_via_uses_target_segment(self):
        ex = FakeExecutor({"route": "default dev eth0"})
        assert run(detect_gateway(ex, "10.1.2.5")) == "10.1.2.1"

    def test_no_via_no_target_uses_detected_subnet(self):
        ex = FakeExecutor(
            {"route": "default dev eth0", "addr": SAMPLE_IP_ADDR}
        )
        assert run(detect_gateway(ex, None)) == "192.168.0.1"

    def test_no_via_no_target_detection_failed_returns_empty(self):
        """Nothing to fall back on → empty string; callers surface a
        request for an explicit gateway instead of guessing .1."""
        ex = FakeExecutor({"route": "default dev eth0", "addr": ""})
        assert run(detect_gateway(ex, None)) == ""


# ---------------------------------------------------------------------------
# arp_scan_devices
# ---------------------------------------------------------------------------


class TestArpScan:
    def test_parses_and_classifies(self):
        ex = FakeExecutor({"arp-scan": SAMPLE_ARP})
        result, devices = run(arp_scan_devices(ex, "192.168.0/24"))
        assert result.success
        assert len(devices) == 4

        by_ip = {d["ip"]: d for d in devices}
        # .1 is forced to gateway even when vendor says router
        assert by_ip["192.168.0.1"]["class"] == "gateway"
        assert by_ip["192.168.0.1"]["icon"] == "🏠"
        assert by_ip["192.168.0.1"]["mac"] == "AA:BB:CC:DD:EE:01"  # uppercased
        assert by_ip["192.168.0.23"]["class"] == "computer"
        assert by_ip["192.168.0.45"]["class"] == "ap"
        # missing vendor column
        assert by_ip["192.168.0.77"]["vendor"] == "Unknown"
        assert by_ip["192.168.0.77"]["class"] == "unknown"
        # non-IP line skipped
        assert all(d["ip"] != "not-an-ip" for d in devices)

    def test_failed_scan_returns_empty(self):
        ex = FakeExecutor(success=False)
        result, devices = run(arp_scan_devices(ex, "192.168.0/24"))
        assert not result.success
        assert devices == []


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _devices():
    return [
        {"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:01", "vendor": "TP-Link",
         "class": "gateway", "icon": "🏠"},
        {"ip": "192.168.0.45", "mac": "AA:BB:CC:DD:EE:03", "vendor": "Ubiquiti Inc.",
         "class": "ap", "icon": "📶"},
        {"ip": "192.168.0.23", "mac": "AA:BB:CC:DD:EE:02", "vendor": "Apple",
         "class": "computer", "icon": "💻"},
    ]


class TestArpMermaidLines:
    def test_gateway_ap_device_hierarchy(self):
        text = "\n".join(arp_mermaid_lines(_devices()))
        assert text.startswith("```mermaid")
        assert "graph TD" in text
        assert 'internet --- gw_192_168_0_1' in text
        # AP hangs off the gateway node id
        assert 'gw_192_168_0_1 --- ap_192_168_0_45' in text
        # device hangs off the AP
        assert 'ap_192_168_0_45 --- dev_192_168_0_23' in text

    def test_no_gateway_does_not_raise(self):
        # Regression: the old network_topology crashed with NameError when
        # no .1 device was present (gw_id assigned only inside the loop).
        devs = _devices()[1:]  # drop the gateway
        text = "\n".join(arp_mermaid_lines(devs))
        # placeholder gw node is used instead of crashing
        assert 'gw --- ap_192_168_0_45' in text
        assert 'ap_192_168_0_45 --- dev_192_168_0_23' in text

    def test_no_ap_devices_hang_on_gateway(self):
        devs = [d for d in _devices() if d["class"] != "ap"]
        text = "\n".join(arp_mermaid_lines(devs))
        assert 'gw_192_168_0_1 --- dev_192_168_0_23' in text

    def test_empty_devices_still_renders(self):
        text = "\n".join(arp_mermaid_lines([]))
        assert "```mermaid" in text
        assert 'internet(("🌍 Internet"))' in text


class TestArpClassStatsLines:
    def test_counts_and_icons(self):
        rows = arp_class_stats_lines(_devices())
        assert rows[0] == "| 类别 | 数量 |"
        joined = "\n".join(rows)
        assert "🏠 gateway | 1" in joined
        assert "💻 computer | 1" in joined
        assert "📶 ap | 1" in joined

    def test_empty(self):
        rows = arp_class_stats_lines([])
        assert rows == ["| 类别 | 数量 |", "|------|------|"]


# ---------------------------------------------------------------------------
# NDP (IPv6 neighbour table)
# ---------------------------------------------------------------------------

# Realistic `ip -6 neigh show` output (from a live Kali box)
SAMPLE_NEIGH = "\n".join([
    "fe80::d6e8:53ff:fe66:656f dev eth0 lladdr d4:e8:53:66:65:6f STALE",
    "fe80::1a68:cbff:fe2b:3727 dev eth0 lladdr 18:68:cb:2b:37:27 REACHABLE",
    "fe80::beef dev eth0 FAILED",
    "some garbage line",
])


class TestNdpDevices:
    def test_parses_entries(self):
        ex = FakeExecutor({"neigh": SAMPLE_NEIGH})
        devices = run(ndp_devices(ex))
        assert len(devices) == 2  # FAILED entry (no lladdr) + garbage skipped
        assert devices[0]["ip"] == "fe80::d6e8:53ff:fe66:656f"
        assert devices[0]["mac"] == "D4:E8:53:66:65:6F"  # uppercased
        assert devices[0]["vendor"] == "NDP"
        assert devices[1]["mac"] == "18:68:CB:2B:37:27"

    def test_skips_entry_without_lladdr(self):
        ex = FakeExecutor({"neigh": SAMPLE_NEIGH})
        devices = run(ndp_devices(ex))
        assert all(d["ip"] != "fe80::beef" for d in devices)

    def test_iface_filter_appended(self):
        ex = FakeExecutor({"neigh": SAMPLE_NEIGH})
        run(ndp_devices(ex, "eth1"))
        assert ex.calls[0] == ["ip", "-6", "neigh", "show", "dev", "eth1"]

    def test_failed_command_empty(self):
        ex = FakeExecutor(success=False)
        assert run(ndp_devices(ex)) == []


class TestMergeNdpDevices:
    def _arp(self):
        return [
            {"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:01", "vendor": "TP-Link",
             "class": "gateway", "icon": "🏠"},
            {"ip": "192.168.0.23", "mac": "AA:BB:CC:DD:EE:02", "vendor": "Apple",
             "class": "computer", "icon": "💻"},
        ]

    def _ndp(self):
        return [
            # MAC shared with the ARP gateway → NOT v6-only
            {"ip": "fe80::aa01", "mac": "AA:BB:CC:DD:EE:01", "vendor": "NDP",
             "class": "unknown", "icon": "❓"},
            # MAC absent from ARP → v6-only
            {"ip": "fe80::d6e8:53ff:fe66:656f", "mac": "D4:E8:53:66:65:6F",
             "vendor": "NDP", "class": "unknown", "icon": "❓"},
        ]

    def test_flags_v6_only_devices(self):
        merged, v6_only = merge_ndp_devices(self._arp(), self._ndp())
        assert len(merged) == 3
        assert len(v6_only) == 1
        assert v6_only[0]["ip"] == "fe80::d6e8:53ff:fe66:656f"
        assert v6_only[0]["class"] == "ipv6-only"
        assert v6_only[0]["icon"] == "🔮"

    def test_shared_mac_not_duplicated(self):
        merged, v6_only = merge_ndp_devices(self._arp(), self._ndp())
        assert all(d["ip"] != "fe80::aa01" for d in merged)
        assert all(d["ip"] != "fe80::aa01" for d in v6_only)

    def test_inputs_not_mutated(self):
        arp, ndp = self._arp(), self._ndp()
        merge_ndp_devices(arp, ndp)
        assert len(arp) == 2
        assert ndp[1]["class"] == "unknown"

    def test_empty_lists(self):
        merged, v6_only = merge_ndp_devices([], [])
        assert merged == [] and v6_only == []

    def test_v6_only_device_renders_in_mermaid(self):
        # Regression: v6 addresses contain ':' which would break mermaid
        # node ids (dev_fe80::xxx). _safe_node_id must sanitize them.
        merged, _ = merge_ndp_devices(self._arp(), self._ndp())
        text = "\n".join(arp_mermaid_lines(merged))
        assert "dev_fe80__d6e8_53ff_fe66_656f" in text
