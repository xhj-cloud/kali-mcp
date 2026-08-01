"""
Kali Linux network monitoring tools — persistent device & traffic awareness.

Provides three monitoring capabilities:
  1. network_diff  — Detect new/missing/changed devices vs. a saved ARP snapshot
  2. traffic_stats — Capture & analyze live traffic (top talkers, protocols, ports)
  3. port_monitor  — Track port open/closed status over time on a target

All tools are 🟢 network-maintenance level (always enabled).
State files are stored under ~/.kali-mcp/monitor/ .
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import CommandResult, get_executor
from kali_mcp.tools import (
    _fmt,
    _no_shell_meta,
    _is_valid_target,
    _MAX_OUTPUT,
)

# ---------------------------------------------------------------------------
# State directory
# ---------------------------------------------------------------------------


def _state_dir() -> Path:
    """Get or create the monitor state directory."""
    path = Path.home() / ".kali-mcp" / "monitor"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _snapshot_path(label: str, subnet: str) -> Path:
    """File path for a device snapshot."""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", f"{label}_{subnet.replace('/', '_')}")
    return _state_dir() / f"snapshot_{safe}.json"


def _port_state_path(target: str) -> Path:
    """File path for port monitor state."""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    return _state_dir() / f"ports_{safe}.json"


# ===================================================================
# Tool 1: Network Device Change Detection
# ===================================================================


class NetworkDiffInput(BaseModel):
    """Input for network device change detection."""

    subnet: str = Field(
        default="",
        description="Subnet CIDR (e.g. '192.168.0.0/24'). Empty = auto-detect from routing table.",
        max_length=32,
    )
    label: str = Field(
        default="default",
        description="Snapshot label for this baseline (e.g. 'baseline', 'morning', 'night'). Different labels = different baselines.",
        max_length=64,
    )

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        _no_shell_meta(v)
        return v


async def network_diff(params: NetworkDiffInput) -> str:
    """Detect network device changes — who joined, who left, who changed MAC.

    Runs an ARP scan and compares the result with a previously saved snapshot.
    Reports three categories of changes:
    - 🆕 New devices (present now but not in the snapshot)
    - 🚫 Missing devices (in snapshot but not responding now)
    - 🔄 Changed devices (same IP, different MAC — possible IP conflict or reassignment)

    On first run for a label, saves an initial baseline and reports all found
    devices. Subsequent runs show only the diff.

    Use this to:
    - Detect rogue/unknown devices joining your network
    - Track when known devices go offline
    - Spot IP conflicts (MAC changes at same IP)
    - Maintain device inventory over time

    Requires: arp-scan (sudo apt install arp-scan)
    """
    import ipaddress

    executor = get_executor(timeout=60)
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

    # 1. Resolve subnet
    subnet = params.subnet
    if not subnet:
        r = await executor.run(["ip", "route", "show", "default"])
        m = re.search(r"dev\s+(\S+)", r.stdout)
        iface = m.group(1) if m else "eth0"
        r2 = await executor.run(["ip", "-4", "addr", "show", iface])
        m2 = re.search(r"inet\s+(\S+)", r2.stdout)
        if m2:
            try:
                net = ipaddress.IPv4Network(m2.group(1), strict=False)
                subnet = str(net)
            except Exception:
                subnet = "192.168.0.0/24"

    # 2. Run ARP scan
    arp_cmd = ["arp-scan", subnet]
    result = await executor.run(arp_cmd, timeout=60)

    if not result.success:
        return _fmt("Network Diff", subnet, " ".join(arp_cmd), result)

    # 3. Parse current devices
    current: dict[str, tuple[str, str]] = {}  # ip -> (mac, vendor)
    for line in result.stdout.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[0].strip()):
            ip = parts[0].strip()
            mac = parts[1].strip() if len(parts) > 1 else "??:??:??:??:??:??"
            vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
            current[ip] = (mac, vendor)

    # 4. Load previous snapshot
    snap_file = _snapshot_path(params.label, subnet)
    previous: dict[str, tuple[str, str]] = {}
    prev_ts = "never"
    is_first_run = True

    if snap_file.exists():
        try:
            data = json.loads(snap_file.read_text())
            prev_ts = data.get("timestamp", "unknown")
            for dev in data.get("devices", []):
                previous[dev["ip"]] = (dev["mac"], dev["vendor"])
            is_first_run = False
        except (json.JSONDecodeError, KeyError):
            pass

    # 5. Compute diff
    new_devices: dict[str, tuple[str, str]] = {}      # in current, not in previous
    missing_devices: dict[str, tuple[str, str]] = {}   # in previous, not in current
    changed_devices: dict[str, dict] = {}               # same ip, different mac

    for ip, (mac, vendor) in current.items():
        if ip not in previous:
            new_devices[ip] = (mac, vendor)
        elif previous[ip][0] != mac:
            changed_devices[ip] = {
                "old_mac": previous[ip][0],
                "old_vendor": previous[ip][1],
                "new_mac": mac,
                "new_vendor": vendor,
            }

    for ip, (mac, vendor) in previous.items():
        if ip not in current:
            missing_devices[ip] = (mac, vendor)

    # 6. Save new snapshot
    snapshot = {
        "label": params.label,
        "subnet": subnet,
        "timestamp": now,
        "device_count": len(current),
        "devices": [
            {"ip": ip, "mac": mac, "vendor": vendor}
            for ip, (mac, vendor) in sorted(current.items())
        ],
    }
    snap_file.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False))

    # 7. Build output
    lines = [
        f"## 🔍 网络设备变更检测 — {subnet}",
        f"**标签:** `{params.label}` | **扫描时间:** {now}",
        f"**当前在线:** {len(current)} 台 | **上次快照:** {prev_ts}",
        "",
    ]

    if is_first_run:
        lines.append("> ℹ️ 首次扫描（已保存基线快照）。后续扫描将显示差异。")
        lines.append("")
        lines.append("### 📋 当前在线设备（基线）")
    else:
        total_changes = len(new_devices) + len(missing_devices) + len(changed_devices)
        if total_changes == 0:
            lines.append("> ✅ 与上次快照相比，**无变化**。网络状态稳定。")
            lines.append("")
            lines.append("### 📋 当前在线设备")
        else:
            lines.append(f"### ⚠️ 检测到 {total_changes} 项变化")
            lines.append("")

            if new_devices:
                lines.append("#### 🆕 新设备上线")
                lines.append("| IP | MAC | 厂商 |")
                lines.append("|------|------|------|")
                for ip, (mac, vendor) in sorted(new_devices.items()):
                    lines.append(f"| {ip} | {mac} | {vendor} |")
                lines.append("")

            if missing_devices:
                lines.append("#### 🚫 设备离线")
                lines.append("| IP | MAC | 厂商 |")
                lines.append("|------|------|------|")
                for ip, (mac, vendor) in sorted(missing_devices.items()):
                    lines.append(f"| {ip} | {mac} | {vendor} |")
                lines.append("")

            if changed_devices:
                lines.append("#### 🔄 MAC 地址变更（IP 冲突或设备更换）")
                lines.append("| IP | 旧 MAC | 旧厂商 | → 新 MAC | 新厂商 |")
                lines.append("|------|------|------|------|------|")
                for ip, info in sorted(changed_devices.items()):
                    lines.append(
                        f"| {ip} | {info['old_mac']} | {info['old_vendor']} | "
                        f"→ {info['new_mac']} | {info['new_vendor']} |"
                    )
                lines.append("")

            lines.append("### 📋 当前在线设备")

    lines.append("| IP | MAC | 厂商 |")
    lines.append("|------|------|------|")
    for ip, (mac, vendor) in sorted(current.items()):
        lines.append(f"| {ip} | {mac} | {vendor} |")

    lines.append("")
    lines.append(f"💾 快照已保存: `{snap_file}`")

    return "\n".join(lines)


# ===================================================================
# Tool 2: Live Traffic Statistics
# ===================================================================


class TrafficStatsInput(BaseModel):
    """Input for live traffic capture and analysis."""

    interface: str = Field(
        default="eth0",
        description="Network interface to capture on (e.g. eth0, wlan0, any)",
        max_length=32,
    )
    duration: int = Field(
        default=30,
        description="Capture duration in seconds",
        ge=5,
        le=300,
    )
    count: int = Field(
        default=100,
        description="Maximum packets to capture (reduced if duration expires first)",
        ge=50,
        le=10000,
    )
    filter_expr: str = Field(
        default="",
        description="Optional BPF filter (e.g. 'port 80', 'host 192.168.0.1', 'tcp')",
        max_length=512,
    )
    top_n: int = Field(
        default=10,
        description="Show top N talkers in the summary",
        ge=3,
        le=30,
    )

    @field_validator("interface")
    @classmethod
    def validate_iface(cls, v: str) -> str:
        _no_shell_meta(v)
        return v

    @field_validator("filter_expr")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
            if "-w" in v or "-C" in v or "-G" in v:
                raise ValueError("tcpdump write/output flags are not allowed")
        return v


# Pre-compiled regex for parsing tcpdump -tt output
# Format: unix_ts IP src_ip.src_port > dst_ip.dst_port: first_word [...], length N
_PKT_RE = re.compile(
    r"[\d.]+\s+IP\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)?\s+>\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)?:\s*"
    r"(\S+)"
)


def _normalize_proto(first_word: str) -> str:
    """Normalize the first word after ':' in tcpdump output to a protocol name."""
    w = first_word.lower().rstrip(",")
    if w == "flags":
        return "TCP"
    elif w in ("udp", "icmp", "igmp", "esp", "ah", "gre"):
        return w.upper()
    return "TCP"


async def traffic_stats(params: TrafficStatsInput) -> str:
    """Capture live network traffic and analyze per-IP statistics.

    Captures packets for a configurable duration, then reports:
    - Top talkers by packet count (who's generating the most traffic)
    - Protocol distribution (TCP, UDP, ICMP, ARP, etc.)
    - Top destination ports (which services are being accessed)
    - Packet size distribution

    Useful for:
    - Identifying bandwidth hogs on your network
    - Spotting unusual traffic patterns (malware, crypto miners)
    - Understanding which services are in use
    - Baseline network activity profiling

    Requires: tcpdump (pre-installed on Kali)
    """
    executor = get_executor(timeout=params.duration + 30)
    now = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")

    # 1. Capture packets
    cmd = [
        "tcpdump",
        "-i", params.interface,
        "-c", str(params.count),
        "-l", "-n", "-tt",
    ]

    if params.filter_expr:
        cmd.extend(params.filter_expr.split())

    timeout = params.duration + 10
    result = await executor.run(cmd, timeout=timeout)

    # 2. Parse: extract IPs, ports, protocol, and packet length
    ip_counter: Counter = Counter()
    proto_counter: Counter = Counter()
    port_counter: Counter = Counter()
    size_counter: Counter = Counter()
    packet_count = 0

    for line in result.stdout.split("\n"):
        m = _PKT_RE.match(line)
        if m:
            packet_count += 1
            src_ip = m.group(1)
            dst_ip = m.group(3)
            dst_port = m.group(4)
            proto = _normalize_proto(m.group(5))

            ip_counter[src_ip] += 1
            ip_counter[dst_ip] += 1
            proto_counter[proto] += 1
            if dst_port:
                port_counter[dst_port] += 1

        # Extract packet length ("length N")
        size_m = re.search(r"length\s+(\d+)", line)
        if size_m:
            size = int(size_m.group(1))
            bucket = f"{size // 100 * 100}-{(size // 100 + 1) * 100 - 1}B"
            size_counter[bucket] += 1

    # 3. Build output
    lines = [
        f"## 📊 实时流量统计",
        f"**接口:** `{params.interface}` | **时长:** {params.duration}s | **捕获:** {packet_count} 包",
        f"**时间:** {now}",
    ]
    if params.filter_expr:
        lines.append(f"**过滤器:** `{params.filter_expr}`")
    lines.append("")

    if packet_count == 0:
        lines.append("> ⚠️ 未捕获到任何数据包。网络可能比较安静，或过滤器过严。")
        return "\n".join(lines)

    # Top talkers
    lines.append(f"### 🗣️ Top {params.top_n} 活跃 IP（按发包数）")
    lines.append("| IP | 包数 | 占比 |")
    lines.append("|------|------|------|")
    total_packets = sum(ip_counter.values()) or 1
    for ip, cnt in ip_counter.most_common(params.top_n):
        pct = cnt / total_packets * 100
        bar = "█" * min(int(pct / 2), 25)
        lines.append(f"| {ip} | {cnt} | {bar} {pct:.1f}% |")
    lines.append("")

    # Protocol distribution
    lines.append("### 📡 协议分布")
    lines.append("| 协议 | 包数 | 占比 |")
    lines.append("|------|------|------|")
    for proto, cnt in proto_counter.most_common():
        pct = cnt / packet_count * 100
        lines.append(f"| {proto} | {cnt} | {pct:.1f}% |")
    lines.append("")

    # Top ports
    if port_counter:
        lines.append(f"### 🔌 Top 目标端口")
        lines.append("| 端口 | 服务 | 包数 |")
        lines.append("|------|------|------|")
        for port, cnt in port_counter.most_common(10):
            svc = {
                "80": "HTTP", "443": "HTTPS", "53": "DNS",
                "22": "SSH", "21": "FTP", "25": "SMTP",
                "3389": "RDP", "8080": "HTTP-Alt", "445": "SMB",
                "137": "NetBIOS", "138": "NetBIOS", "139": "NetBIOS",
                "123": "NTP", "1900": "UPnP", "5353": "mDNS",
                "8000": "HTTP-Alt", "554": "RTSP", "3306": "MySQL",
                "5432": "PostgreSQL", "6379": "Redis",
            }.get(port, "?")
            lines.append(f"| {port} | {svc} | {cnt} |")
        lines.append("")

    # Size distribution
    if size_counter and len(size_counter) > 1:
        lines.append("### 📦 包大小分布")
        lines.append("| 大小范围 | 包数 |")
        lines.append("|------|------|")
        for bucket in sorted(size_counter.keys(), key=lambda x: int(x.split("-")[0])):
            lines.append(f"| {bucket} | {size_counter[bucket]} |")

    return "\n".join(lines)


# ===================================================================
# Tool 3: Port Status Monitor
# ===================================================================


class PortMonitorInput(BaseModel):
    """Input for port status monitoring."""

    target: str = Field(
        ...,
        description="Target IP or hostname to monitor",
        min_length=1,
        max_length=256,
    )
    ports: str = Field(
        default="22,80,443,3389,8080,8000",
        description="Comma-separated ports to check (e.g. '22,80,443'). Default: common service ports.",
        max_length=256,
    )
    label: str = Field(
        default="default",
        description="Label for tracking history (e.g. 'router', 'nas'). Same label = compare with previous check.",
        max_length=64,
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        _no_shell_meta(v)
        for p in v.split(","):
            p = p.strip()
            if not p or not p.isdigit() or int(p) < 1 or int(p) > 65535:
                raise ValueError(f"Invalid port: {p}")
        return v

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        _no_shell_meta(v)
        return v


# Port → service name mapping
_PORT_SERVICES = {
    "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
    "53": "DNS", "80": "HTTP", "110": "POP3", "123": "NTP",
    "135": "RPC", "139": "NetBIOS", "143": "IMAP", "161": "SNMP",
    "389": "LDAP", "443": "HTTPS", "445": "SMB", "554": "RTSP",
    "587": "SMTP-SSL", "993": "IMAPS", "995": "POP3S",
    "1433": "MSSQL", "1521": "Oracle", "1723": "PPTP",
    "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL",
    "5900": "VNC", "6379": "Redis", "8000": "HTTP-Alt",
    "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "9090": "HTTP-Alt",
    "27017": "MongoDB",
}


async def port_monitor(params: PortMonitorInput) -> str:
    """Monitor port open/closed status on a target and track changes over time.

    Performs a quick port scan on the specified ports, compares with the
    previous check (same label), and reports:
    - Which ports are currently open/closed
    - Newly opened ports (service started)
    - Newly closed ports (service stopped)
    - Uptime of continuously open ports

    Useful for:
    - Monitoring critical services (is the web server still up?)
    - Detecting unexpected service starts (security concern)
    - Tracking service restarts and availability

    Requires: nmap (pre-installed on Kali)
    """
    executor = get_executor(timeout=60)
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

    # 1. Quick nmap scan of specific ports
    cmd = ["nmap", "-sS", "-T5", "-p", params.ports, params.target]
    result = await executor.run(cmd, timeout=55)

    if not result.success:
        return _fmt("Port Monitor", params.target, " ".join(cmd), result)

    # 2. Parse current port states
    current_ports: dict[str, str] = {}
    for line in result.stdout.split("\n"):
        m = re.match(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S*)", line)
        if m:
            port = m.group(1)
            state = m.group(3)
            service = m.group(4).strip() or _PORT_SERVICES.get(port, "?")
            current_ports[port] = f"{state} ({service})"

    for p in params.ports.split(","):
        p = p.strip()
        if p not in current_ports:
            current_ports[p] = "filtered (no response)"

    # 3. Load previous state
    state_file = _port_state_path(f"{params.target}_{params.label}")
    previous_ports: dict[str, str] = {}
    prev_ts = "never"
    is_first = True

    if state_file.exists():
        try:
            data = json.loads(state_file.read_text())
            prev_ts = data.get("timestamp", "unknown")
            previous_ports = data.get("ports", {})
            is_first = False
        except (json.JSONDecodeError, KeyError):
            pass

    # 4. Compute changes
    newly_opened: dict[str, str] = {}
    newly_closed: dict[str, str] = {}

    for port, status in current_ports.items():
        prev_status = previous_ports.get(port, "")
        if "open" in status and "open" not in prev_status:
            newly_opened[port] = status

    for port, status in previous_ports.items():
        if port in current_ports:
            cur = current_ports[port]
            if "open" in status and "open" not in cur:
                newly_closed[port] = cur
        else:
            if "open" in status:
                newly_closed[port] = "filtered (no response)"

    # 5. Save current state
    state_data = {
        "target": params.target,
        "label": params.label,
        "timestamp": now,
        "ports": current_ports,
    }
    state_file.write_text(json.dumps(state_data, indent=2, ensure_ascii=False))

    # 6. Build output
    open_count = sum(1 for s in current_ports.values() if "open" in s)
    total = len(current_ports)

    lines = [
        f"## 🔌 端口监控 — {params.target}",
        f"**标签:** `{params.label}` | **检查时间:** {now}",
        f"**端口状态:** {open_count}/{total} 开放 | **上次检查:** {prev_ts}",
        "",
    ]

    if is_first:
        lines.append("> ℹ️ 首次检查（已保存基线）。后续检查将显示端口状态变化。")
        lines.append("")
    else:
        changes = len(newly_opened) + len(newly_closed)
        if changes == 0:
            lines.append("> ✅ 与上次检查相比，**端口状态无变化**。")
            lines.append("")
        else:
            lines.append(f"### ⚠️ 检测到 {changes} 项变化")
            lines.append("")

            if newly_opened:
                lines.append("#### 🟢 端口新开放（服务启动）")
                lines.append("| 端口 | 服务 |")
                lines.append("|------|------|")
                for port, status in sorted(newly_opened.items()):
                    svc = _PORT_SERVICES.get(port, "?")
                    lines.append(f"| {port} | {svc} — {status} |")
                lines.append("")

            if newly_closed:
                lines.append("#### 🔴 端口已关闭（服务停止）")
                lines.append("| 端口 | 当前状态 |")
                lines.append("|------|------|")
                for port, status in sorted(newly_closed.items()):
                    svc = _PORT_SERVICES.get(port, "?")
                    lines.append(f"| {port} | {svc} — {status} |")
                lines.append("")

    # Current status table
    lines.append("### 📋 当前端口状态")
    lines.append("| 端口 | 状态 | 服务 |")
    lines.append("|------|------|------|")
    for port in sorted(current_ports.keys(), key=lambda p: int(p)):
        status = current_ports[port]
        svc = _PORT_SERVICES.get(port, "?")
        icon = "🟢" if "open" in status else "🔴" if "closed" in status else "🟡"
        lines.append(f"| {port} | {icon} {status} | {svc} |")

    lines.append("")
    lines.append(f"💾 状态已保存: `{state_file}`")

    return "\n".join(lines)


# ===================================================================
# Registry
# ===================================================================

MONITOR_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "network_diff": (network_diff, NetworkDiffInput),
    "traffic_stats": (traffic_stats, TrafficStatsInput),
    "port_monitor": (port_monitor, PortMonitorInput),
}
