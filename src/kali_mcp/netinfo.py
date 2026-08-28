"""
netinfo.py — 共享的本机网络探测与 ARP 分析层。

Single source of truth for "what is my local network":

- detect_default_iface : 默认路由所在网卡（ip route → dev）
- detect_subnet        : 显式子网，或从默认路由网卡自动探测
- detect_gateway       : 默认路由网关（ip route → via），含回退策略
- arp_scan_devices     : arp-scan 扫描 + 解析 + 分类 → 设备 dict 列表
- ndp_devices          : IPv6 邻居表（NDP）→ 与 arp 同构的设备 dict 列表
- merge_ndp_devices    : 把 NDP-only 设备并入 ARP 列表，标出"仅 IPv6 可见"设备
- arp_mermaid_lines    : 设备列表 → Mermaid 拓扑块（共享渲染）
- arp_class_stats_lines: 设备类别分布表行
- classify_device      : 厂商名 → (类别, 图标)

消费者：
- tools.py    : network_topology, snmp_topology
- monitor.py  : network_diff, nethogs_bandwidth
- pentest.py  : arpspoof_mitm, arpspoof_disconnect
"""

from __future__ import annotations

import ipaddress
import logging
import re

from kali_mcp.executor import CommandResult

logger = logging.getLogger(__name__)

#: 探测失败时的兜底子网
DEFAULT_SUBNET = "192.168.0.0/24"


# ---------------------------------------------------------------------------
# Detection: interface / subnet / gateway
# ---------------------------------------------------------------------------


async def detect_default_iface(executor) -> str:
    """Interface carrying the default route; ``eth0`` as last resort."""
    r = await executor.run(["ip", "route", "show", "default"])
    m = re.search(r"dev\s+(\S+)", r.stdout)
    return m.group(1) if m else "eth0"


async def detect_subnet(executor, subnet: str | None = None) -> str:
    """Resolve the subnet to scan.

    An explicit non-empty ``subnet`` always wins. Otherwise auto-detect:
    default-route interface → its IPv4 address → network CIDR.
    Falls back to :data:`DEFAULT_SUBNET` if detection fails.
    """
    if subnet and subnet.strip():
        return subnet.strip()

    iface = await detect_default_iface(executor)
    r = await executor.run(["ip", "-4", "addr", "show", iface])
    m = re.search(r"inet\s+(\S+)", r.stdout)
    if m:
        try:
            return str(ipaddress.IPv4Network(m.group(1), strict=False))
        except ValueError:
            logger.warning(
                "Cannot parse IPv4 network from %r (iface %s)", m.group(1), iface
            )
    logger.warning("Subnet auto-detect failed; falling back to %s", DEFAULT_SUBNET)
    return DEFAULT_SUBNET


async def detect_gateway(executor, target: str | None = None) -> str:
    """Gateway IP: the ``via`` address of the default route.

    Falls back to ``<target 的网段>.1`` (or the detected subnet's ``.1``
    when no target is given).
    """
    r = await executor.run(["ip", "route", "show", "default"])
    m = re.search(r"via\s+(\S+)", r.stdout)
    if m:
        return m.group(1)
    if target:
        base = target.rsplit(".", 1)[0]
    else:
        base = (await detect_subnet(executor)).rsplit(".", 1)[0]
    return base + ".1"


# ---------------------------------------------------------------------------
# ARP scan + device classification
# ---------------------------------------------------------------------------

_DEVICE_CLASSES = {
    "tp-link": ("router", "🌐"),
    "cisco": ("router", "🌐"),
    "aruba": ("ap", "📶"),
    "ubiquiti": ("ap", "📶"),
    "hikvision": ("camera", "📷"),
    "uniview": ("camera", "📷"),
    "dahua": ("camera", "📷"),
    "vivo": ("phone", "📱"),
    "samsung": ("phone", "📱"),
    "apple": ("computer", "💻"),
    "intel": ("computer", "💻"),
    "dell": ("computer", "🖥️"),
    "hewlett": ("computer", "🖥️"),
    "giga-byte": ("computer", "🖥️"),
    "vmware": ("vm", "🖳"),
    "oray.com": ("iot", "🔌"),
    "espres": ("iot", "🔌"),
    "fn-link": ("iot", "🔌"),
    "ai-link": ("iot", "🔌"),
    "tmall": ("iot", "🔌"),
    "patria": ("industrial", "🏭"),
    "ieee": ("industrial", "🏭"),
    "mobiltex": ("industrial", "🏭"),
    "h3c": ("network", "🔀"),
    "new h3c": ("network", "🔀"),
}


def classify_device(vendor: str) -> tuple[str, str]:
    """Classify device by vendor name → (category, icon)."""
    vendor_lower = vendor.lower().strip()
    for key, (dtype, icon) in _DEVICE_CLASSES.items():
        if key in vendor_lower:
            return dtype, icon
    return "unknown", "❓"


async def arp_scan_devices(
    executor, subnet: str, timeout: int = 60
) -> tuple[CommandResult, list[dict]]:
    """Scan a subnet with arp-scan; parse and classify each device.

    Returns ``(raw_result, devices)``. Each device is a dict with keys
    ``ip, mac (uppercase), vendor, class, icon``. ``devices`` is empty
    when the scan fails — check ``raw_result.success``.
    """
    result = await executor.run(["arp-scan", subnet], timeout=timeout)
    devices: list[dict] = []
    if result.success:
        for line in result.stdout.split("\n"):
            parts = line.strip().split("\t")
            if len(parts) < 2:
                continue
            ip = parts[0].strip()
            if not re.match(r"\d+\.\d+\.\d+\.\d+$", ip):
                continue
            mac = parts[1].strip().upper()
            vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
            dclass, icon = classify_device(vendor)
            # Heuristic: .1 in the subnet is the gateway
            if ip.endswith(".1"):
                dclass, icon = "gateway", "🏠"
            devices.append(
                {"ip": ip, "mac": mac, "vendor": vendor, "class": dclass, "icon": icon}
            )
    return result, devices


# ---------------------------------------------------------------------------
# NDP (IPv6 neighbour discovery) — IPv6 版的 ARP 表
# ---------------------------------------------------------------------------


async def ndp_devices(executor, iface: str | None = None) -> list[dict]:
    """Read the IPv6 neighbour table (NDP) into device dicts.

    Returns dicts with the same keys as :func:`arp_scan_devices`
    (``ip, mac, vendor, class, icon``) so the two lists can be merged.
    Entries without a ``lladdr`` (no MAC learned yet) are skipped.
    """
    cmd = ["ip", "-6", "neigh", "show"]
    if iface:
        cmd.extend(["dev", iface])
    result = await executor.run(cmd, timeout=10)
    devices: list[dict] = []
    if result.success:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3 or parts[1] != "dev":
                continue
            mac = ""
            for i, p in enumerate(parts):
                if p == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1].upper()
                    break
            if not mac:
                continue
            dclass, icon = classify_device("Unknown")
            devices.append(
                {"ip": parts[0], "mac": mac, "vendor": "NDP", "class": dclass, "icon": icon}
            )
    return devices


def merge_ndp_devices(
    arp_devices: list[dict], ndp_devices: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Merge NDP-only devices into the ARP device list.

    A device is "IPv6-only" when its MAC appears in the NDP table but not
    in the ARP table — i.e. it is invisible to IPv4 ARP scanning.
    Returns ``(merged, v6_only)``; the input lists are not mutated.
    """
    v4_macs = {d["mac"] for d in arp_devices}
    merged = list(arp_devices)
    v6_only: list[dict] = []
    for d in ndp_devices:
        if d["mac"] in v4_macs:
            continue
        nd = dict(d)
        nd["class"] = "ipv6-only"
        nd["icon"] = "🔮"
        merged.append(nd)
        v6_only.append(nd)
    return merged, v6_only


# ---------------------------------------------------------------------------
# Rendering (shared by network_topology and snmp_topology fallback)
# ---------------------------------------------------------------------------


def _safe_node_id(ip: str) -> str:
    """Sanitize an address into a Mermaid-safe node id (v6 has colons)."""
    return re.sub(r"[^0-9A-Za-z]", "_", ip)


def arp_mermaid_lines(devices: list[dict]) -> list[str]:
    """Render ARP devices as a Mermaid graph block.

    Hierarchy: Internet → gateway → AP → devices (devices attach
    round-robin to APs, or directly to the gateway when there are none).
    Uses a placeholder ``gw`` node when no gateway was detected, so the
    diagram always renders. IPv6-only devices (v6 addresses with colons)
    are safe via :func:`_safe_node_id`.
    """
    lines = ["```mermaid", "graph TD"]
    lines.append('    internet(("🌍 Internet"))')

    gateways = [d for d in devices if d["class"] == "gateway"]
    aps = [d for d in devices if d["class"] in ("ap", "router", "network")]
    others = [
        d for d in devices if d["class"] not in ("gateway", "ap", "router", "network")
    ]

    gw_id = f'gw_{_safe_node_id(gateways[0]["ip"])}' if gateways else "gw"

    for g in gateways:
        gid = f'gw_{_safe_node_id(g["ip"])}'
        lines.append(f'    internet --- {gid}["{g["icon"]} 网关\\n{g["ip"]}"]')

    for ap in aps:
        lines.append(
            f'    {gw_id} --- ap_{_safe_node_id(ap["ip"])}'
            f'["{ap["icon"]} {ap["vendor"][:12]}\\n{ap["ip"]}"]'
        )

    ap_ids = [f'ap_{_safe_node_id(ap["ip"])}' for ap in aps]
    for i, dev in enumerate(others):
        node_id = f'dev_{_safe_node_id(dev["ip"])}'
        parent = ap_ids[i % len(ap_ids)] if ap_ids else gw_id
        vendor_label = dev["vendor"][:15] if dev["vendor"] != "Unknown" else "未知设备"
        lines.append(
            f'    {parent} --- {node_id}["{dev["icon"]} {vendor_label}\\n{dev["ip"]}"]'
        )

    lines.append("```")
    return lines


def arp_class_stats_lines(devices: list[dict]) -> list[str]:
    """Markdown table rows for the device-class distribution."""
    from collections import Counter

    stats = Counter(d["class"] for d in devices)
    lines = ["| 类别 | 数量 |", "|------|------|"]
    for cls, cnt in stats.most_common():
        icon = next((d["icon"] for d in devices if d["class"] == cls), "?")
        lines.append(f"| {icon} {cls} | {cnt} |")
    return lines
