"""
Kali Linux network tools exposed as MCP tools.

Each tool wraps a Kali command-line utility with:
- Pydantic input validation to prevent injection
- Safe command construction (list-based, never shell)
- Timeout-bounded execution
- Structured output formatting for AI consumption
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import CommandResult, get_executor
from kali_mcp.netinfo import (
    arp_class_stats_lines,
    arp_mermaid_lines,
    arp_scan_devices,
    classify_device,
    detect_subnet,
    merge_ndp_devices,
    ndp_devices,
)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_SHELL_META = set(";|&`$(){}<>\n\r")


def _no_shell_meta(v: str) -> str:
    """Reject strings containing shell metacharacters."""
    if any(c in v for c in _SHELL_META):
        raise ValueError("Input contains forbidden shell metacharacters")
    return v


def _is_valid_target(v: str) -> bool:
    """Validate IP address, CIDR range, or hostname."""
    # Allow --localnet for arp-scan
    if v == "--localnet":
        return True
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        pass
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-.]*[a-zA-Z0-9])?$", v):
        return True
    return False


def _is_valid_domain(v: str) -> bool:
    """Validate domain name format.

    Accepts:
    - FQDN: example.com, sub.example.co.uk
    - Single-label: localhost, myhost (common in LAN environments)
    """
    return bool(
        re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$",
            v,
        )
    )


_MASSCAN_PORT_PART_RE = re.compile(r"^(?:[TU]:)?\d+(?:-\d+)?$")


def _is_valid_masscan_ports(v: str) -> bool:
    """Validate a masscan port spec: comma-separated ports and a-b ranges.

    masscan's port spec understands an optional per-part protocol prefix
    (``U:`` UDP, ``T:`` TCP — bare parts are TCP), e.g. '80,443' or
    'T:22,U:53' (see the masscan(8) man page: --ports U:161,U:1024-1100).
    It does NOT understand named sets (top-100) or spaces.
    """
    v = v.strip()
    if not v:
        return False
    for part in v.split(","):
        if not _MASSCAN_PORT_PART_RE.match(part):
            return False
        num_part = part.split(":", 1)[1] if ":" in part else part
        lo_s, _, hi_s = num_part.partition("-")
        lo, hi = int(lo_s), int(hi_s or lo_s)
        if lo > 65535 or hi > 65535 or lo > hi:
            return False
    return True


def _validate_masscan_target(v: str) -> str:
    """Validate and bound the masscan target.

    masscan is built for large-scale sweeps, so the green-tier wrapper
    caps address-space size: v4 networks must be /16 or smaller
    (<= 65,536 hosts), v6 networks /112 or smaller. Single IPs and
    hostnames are always allowed.
    """
    _no_shell_meta(v)
    if not _is_valid_target(v):
        raise ValueError(f"Invalid target: {v}")
    if "/" in v:
        net = ipaddress.ip_network(v, strict=False)
        limit = 16 if net.version == 4 else 112
        if net.prefixlen < limit:
            raise ValueError(
                f"Target range too large for masscan: use /{limit} or "
                f"smaller (fewer hosts); got {v}"
            )
    return v


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_MAX_OUTPUT = 8000
_MAX_STDERR = 2000


def _truncate(text: str, limit: int = _MAX_OUTPUT) -> str:
    """Truncate long output, keeping BOTH the head and the tail.

    Scan tools (nmap, nikto, ffuf, ...) emit their findings at the END of
    the output, while the useful context (open ports, service versions)
    sits at the start — a plain head cut would hide the findings. Keep
    ~40% head + ~60% tail with an explicit omission marker.
    """
    if len(text) <= limit:
        return text
    head = int(limit * 0.4)
    tail = limit - head
    omitted_lines = text.count("\n", head, len(text) - tail)
    omitted_bytes = len(text) - head - tail
    return (
        text[:head]
        + f"\n... [{omitted_lines} lines / {omitted_bytes} bytes truncated] ...\n"
        + text[-tail:]
    )


def _fmt(
    tool: str,
    target: str,
    cmd_str: str,
    result: CommandResult,
) -> str:
    """Format command output for AI consumption."""
    status = "✓ Success" if result.success else f"✗ Failed (exit code: {result.returncode})"
    lines = [
        f"## {tool}",
        f"**Target:** `{target}`",
        f"**Command:** `{cmd_str}`",
        f"**Status:** {status}",
        "",
    ]
    if result.stdout:
        lines.append("```")
        lines.append(_truncate(result.stdout))
        lines.append("```")
    else:
        lines.append("_(no output)_")
    if result.stderr:
        lines.append(f"\n**Diagnostics:**\n```\n{result.stderr[:_MAX_STDERR]}\n```")
    return "\n".join(lines)


# ===================================================================
# Pydantic input models
# ===================================================================


class NmapInput(BaseModel):
    """Input for nmap port scanning."""

    target: str = Field(
        ...,
        description="Target IP address, hostname, or CIDR range (e.g. 192.168.1.1, scanme.nmap.org, 10.0.0.0/24)",
        min_length=1,
        max_length=256,
    )
    ports: str = Field(
        default="",
        description="Port specification (e.g. '22,80,443', '1-1000', 'top-100'). Empty = common ports.",
        max_length=256,
    )
    scan_type: str = Field(
        default="syn",
        description="Scan technique: syn (stealth), tcp (connect), udp, ping (discovery), version (service detection), os (OS detection), comprehensive (all ports + version + scripts)",
        pattern=r"^(syn|tcp|udp|ping|version|os|comprehensive)$",
    )
    timing: str = Field(
        default="T4",
        description="Timing template: T0 (paranoid) to T5 (insane). T4 is fast for LAN.",
        pattern=r"^T[0-5]$",
    )
    extra_args: str = Field(
        default="",
        description='Extra nmap flags (e.g. "-sV --version-intensity 5"). Shell chars forbidden.',
        max_length=256,
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v

    @field_validator("extra_args")
    @classmethod
    def validate_extra(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
            # Reject dangerous nmap flags using per-arg prefix match
            # (avoids false positives like "--open" matching "-o")
            dangerous_prefixes = [
                "--script",
                "-oN", "-oX", "-oG", "-oA", "-oS",
            ]
            for arg in v.split():
                arg_lower = arg.lower()
                for prefix in dangerous_prefixes:
                    if arg_lower.startswith(prefix.lower()):
                        raise ValueError(
                            f"Dangerous nmap flag rejected: {arg}"
                        )
        return v


class ArpScanInput(BaseModel):
    """Input for ARP network discovery."""

    target: str = Field(
        default="--localnet",
        description="IP range to scan (e.g. '192.168.1.0/24') or '--localnet' for local subnet",
        max_length=256,
    )
    interface: str = Field(
        default="",
        description="Network interface (e.g. eth0, wlan0). Auto-detect if empty.",
        max_length=32,
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v

    @field_validator("interface")
    @classmethod
    def validate_iface(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


class PingInput(BaseModel):
    """Input for ICMP ping test."""

    target: str = Field(
        ..., description="Target IP or hostname", min_length=1, max_length=256
    )
    count: int = Field(default=4, description="Number of packets", ge=1, le=100)
    timeout: int = Field(default=5, description="Per-packet timeout in seconds", ge=1, le=60)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v


class TracerouteInput(BaseModel):
    """Input for traceroute path tracing."""

    target: str = Field(
        ..., description="Target IP or hostname", min_length=1, max_length=256
    )
    max_hops: int = Field(default=30, description="Maximum hops", ge=1, le=64)
    timeout: int = Field(default=5, description="Per-hop timeout in seconds", ge=1, le=30)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v


class MtrInput(BaseModel):
    """Input for MTR combined ping/traceroute report."""

    target: str = Field(
        ..., description="Target IP or hostname", min_length=1, max_length=256
    )
    count: int = Field(default=10, description="Number of pings per hop", ge=1, le=100)
    report: bool = Field(default=True, description="Generate a one-shot report (recommended)")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v


class DigInput(BaseModel):
    """Input for DNS dig queries."""

    domain: str = Field(
        ..., description="Domain name to query (e.g. google.com)", min_length=1, max_length=256
    )
    record_type: str = Field(
        default="A",
        description="DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, ANY",
        pattern=r"^(A|AAAA|MX|NS|TXT|CNAME|SOA|PTR|ANY)$",
    )
    dns_server: str = Field(
        default="",
        description="Specific DNS server to query (e.g. 8.8.8.8). Uses system default if empty.",
        max_length=256,
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_domain(v):
            raise ValueError(f"Invalid domain name: {v}")
        return v

    @field_validator("dns_server")
    @classmethod
    def validate_dns(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid DNS server IP: {v}")
        return v


class WhoisInput(BaseModel):
    """Input for WHOIS lookup."""

    target: str = Field(
        ..., description="Domain name or IP address to look up", min_length=1, max_length=256
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        # Accept domain, IP, or something domain-like
        if not (_is_valid_domain(v) or _is_valid_target(v)):
            raise ValueError(f"Invalid WHOIS target: {v}")
        return v


class NetConnsInput(BaseModel):
    """Input for network connection listing."""

    state: str = Field(
        default="all",
        description="Connection state filter: all, listening, established",
        pattern=r"^(all|listening|established)$",
    )
    protocol: str = Field(
        default="all",
        description="Protocol filter: all, tcp, udp",
        pattern=r"^(all|tcp|udp)$",
    )
    resolve: bool = Field(default=False, description="Resolve IPs to hostnames (slower)")


class TcpdumpInput(BaseModel):
    """Input for packet capture with tcpdump."""

    interface: str = Field(
        default="any",
        description="Network interface (e.g. eth0, wlan0, any). 'any' captures all.",
        max_length=32,
    )
    count: int = Field(default=100, description="Packets to capture", ge=1, le=10000)
    filter_expr: str = Field(
        default="",
        description="BPF filter expression (e.g. 'port 80', 'host 192.168.1.1', 'tcp and port 443')",
        max_length=512,
    )
    duration: int = Field(default=10, description="Max capture duration in seconds", ge=1, le=300)
    resolve: bool = Field(default=False, description="Resolve hostnames (slower)")

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
            # Block write-to-file attempts
            if "-w" in v or "-C" in v or "-G" in v:
                raise ValueError("tcpdump write/output flags are not allowed")
        return v


class CurlInput(BaseModel):
    """Input for HTTP requests via curl."""

    url: str = Field(..., description="Full URL to request", min_length=1, max_length=2048)
    method: str = Field(default="GET", description="HTTP method", pattern=r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)$")
    headers: str = Field(
        default="",
        description='JSON object of headers (e.g. \'{"Authorization":"Bearer xyz"}\')',
        max_length=2048,
    )
    data: str = Field(
        default="",
        description="Request body data (for POST/PUT/PATCH)",
        max_length=8192,
    )
    timeout: int = Field(default=30, description="Request timeout in seconds", ge=1, le=120)
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    insecure: bool = Field(default=False, description="Allow insecure SSL connections")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        _no_shell_meta(v)
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v

    @field_validator("data")
    @classmethod
    def validate_data(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


# ===================================================================
# Tool implementations
# ===================================================================


async def nmap_scan(params: NmapInput) -> str:
    """Port scanning and service discovery using nmap.

    Performs network reconnaissance - discover open ports, running services,
    OS detection, and more. Supports all major nmap scan types.

    Use cases:
    - Discover devices and open ports on a network
    - Identify running services and versions
    - Detect operating systems
    - Audit firewall rules

    Requires: nmap (pre-installed on Kali)
    """
    cmd = ["nmap"]

    # Map scan type to nmap flags
    scan_map: dict[str, list[str]] = {
        "syn": ["-sS"],
        "tcp": ["-sT"],
        "udp": ["-sU"],
        "ping": ["-sP"],
        "version": ["-sV"],
        "os": ["-O", "--osscan-guess"],
        "comprehensive": ["-sS", "-sV", "-sC", "-p-"],
    }
    cmd.extend(scan_map.get(params.scan_type, ["-sS"]))

    # Add ports (skip for ping scan and comprehensive which has its own -p-)
    if params.ports and params.scan_type not in ("ping", "comprehensive"):
        cmd.extend(["-p", params.ports])

    # Timing
    cmd.append(f"-{params.timing}")

    # Extra args
    if params.extra_args:
        cmd.extend(params.extra_args.split())

    # Target
    cmd.append(params.target)

    executor = get_executor(timeout=180)
    result = await executor.run(cmd, timeout=180)
    return _fmt("nmap Scan", params.target, " ".join(cmd), result)


async def arp_scan(params: ArpScanInput) -> str:
    """ARP-based network discovery using arp-scan.

    Discovers all active devices on the local network segment by sending
    ARP requests. Shows IP addresses, MAC addresses, and vendor information.

    Faster and more reliable than ping scans for local networks because
    ARP is required for communication and can't be blocked by firewalls.

    Requires: arp-scan (sudo apt install arp-scan)
    """
    cmd = ["arp-scan"]

    if params.interface:
        cmd.extend(["--interface", params.interface])

    cmd.append(params.target)

    executor = get_executor(timeout=60)
    result = await executor.run(cmd, timeout=60)
    desc = f"{params.target}" + (f" on {params.interface}" if params.interface else "")
    return _fmt("ARP Scan", desc, " ".join(cmd), result)


async def ping_host(params: PingInput) -> str:
    """ICMP ping test to check host reachability and measure latency.

    Sends ICMP echo requests to verify if a target host is reachable
    and measures round-trip time. Standard network diagnostic tool.

    Requires: ping (pre-installed)
    """
    cmd = [
        "ping",
        "-c", str(params.count),
        # iputils ping 的 -W 单位是秒（新版 iputils 会严格校验取值，
        # 传入毫秒级数值会被拒绝："bad linger time"）
        "-W", str(params.timeout),
        params.target,
    ]

    executor = get_executor(timeout=params.count * params.timeout + 10)
    result = await executor.run(cmd)
    return _fmt("Ping Test", params.target, " ".join(cmd), result)


async def traceroute_host(params: TracerouteInput) -> str:
    """Trace the network path to a target host using traceroute.

    Maps the route packets take from this Kali host to the destination,
    showing each intermediate hop with latency measurements.

    Useful for:
    - Identifying network bottlenecks
    - Debugging routing issues
    - Mapping network topology

    Requires: traceroute (pre-installed on Kali)
    """
    cmd = [
        "traceroute",
        "-m", str(params.max_hops),
        "-w", str(params.timeout),
        params.target,
    ]

    executor = get_executor(timeout=params.max_hops * params.timeout + 15)
    result = await executor.run(cmd)
    return _fmt("Traceroute", params.target, " ".join(cmd), result)


async def mtr_report(params: MtrInput) -> str:
    """Combined ping + traceroute report using MTR.

    Provides a comprehensive network path analysis combining the best of
    ping and traceroute in a single report. Shows per-hop packet loss and
    latency statistics.

    Requires: mtr (sudo apt install mtr)
    """
    cmd = ["mtr", "-r", "-c", str(params.count), params.target]

    executor = get_executor(timeout=params.count * 5 + 30)
    result = await executor.run(cmd, timeout=params.count * 5 + 30)
    return _fmt("MTR Report", params.target, " ".join(cmd), result)


async def dig_query(params: DigInput) -> str:
    """DNS query using dig - lookup domain records.

    Queries DNS servers to retrieve various record types (A, AAAA, MX, NS,
    TXT, etc.). Essential for DNS troubleshooting and domain recon.

    Requires: dig / dnsutils (sudo apt install dnsutils)
    """
    cmd = ["dig", "+short", params.domain, params.record_type]

    if params.dns_server:
        cmd.append(f"@{params.dns_server}")

    executor = get_executor(timeout=15)
    result = await executor.run(cmd)
    desc = f"{params.record_type} {params.domain}"
    if params.dns_server:
        desc += f" @{params.dns_server}"
    return _fmt("DNS Dig Query", desc, " ".join(cmd), result)


async def whois_lookup(params: WhoisInput) -> str:
    """WHOIS domain/IP lookup for registration and ownership info.

    Retrieves domain registration details, IP allocation records,
    registrar information, nameservers, and more.

    Requires: whois (sudo apt install whois)
    """
    cmd = ["whois", params.target]

    executor = get_executor(timeout=30)
    result = await executor.run(cmd)
    return _fmt("WHOIS Lookup", params.target, " ".join(cmd), result)


async def network_connections(params: NetConnsInput) -> str:
    """List active network connections and listening ports using ss.

    Shows all current TCP/UDP connections, listening services, and their
    process associations. Modern replacement for netstat.

    Requires: ss / iproute2 (pre-installed on Kali)
    """
    cmd = ["ss", "-tulpn" if params.resolve else "-tulp"]

    # Filter by state
    if params.state == "established":
        cmd.append("state")
        cmd.append("established")
    # "listening" and "all" are already covered by -l flag in -tulpn

    # Filter by protocol (narrow down from default -t -u both)
    if params.protocol == "tcp":
        cmd.insert(1, "-t")
    elif params.protocol == "udp":
        cmd.insert(1, "-u")

    executor = get_executor(timeout=10)
    result = await executor.run(cmd)
    desc = f"state={params.state}, proto={params.protocol}"
    return _fmt("Network Connections", desc, " ".join(cmd), result)


async def network_interfaces() -> str:
    """Show all network interfaces with IP addresses and statistics.

    Lists every network interface, its IP addresses (v4/v6), MAC address,
    link state, and traffic counters.

    Requires: ip / iproute2 (pre-installed on Kali)
    """
    cmd = ["ip", "-brief", "addr", "show"]

    executor = get_executor(timeout=10)
    result = await executor.run(cmd)

    # Also get detailed link info
    cmd2 = ["ip", "-s", "link", "show"]
    result2 = await executor.run(cmd2)

    combined = result.stdout
    if result2.stdout:
        combined += "\n\n--- Link Statistics ---\n" + result2.stdout

    final = CommandResult(
        stdout=combined,
        stderr=result.stderr or result2.stderr,
        returncode=result.returncode or result2.returncode,
        success=result.success and result2.success,
    )
    return _fmt("Network Interfaces", "all", "ip addr show + ip link show", final)


async def routing_table() -> str:
    """Show the kernel IP routing table.

    Displays all routes configured on the system, including default gateway,
    network routes, and their associated interfaces. Essential for
    understanding traffic flow and diagnosing routing issues.

    Requires: ip / iproute2 (pre-installed on Kali)
    """
    cmd = ["ip", "route", "show", "table", "all"]

    executor = get_executor(timeout=10)
    result = await executor.run(cmd)
    return _fmt("Routing Table", "all tables", " ".join(cmd), result)


# ---------------------------------------------------------------------------
# Firewall rules (read-only inspection of nftables / iptables / ufw)
# ---------------------------------------------------------------------------

#: A line in an `nft list ruleset` output is a rule when it carries a verdict.
_NFT_VERDICT_RE = re.compile(r"\b(accept|drop|reject)\b")
#: Chain header lines ("... policy accept;") are not rules — exclude them.
_NFT_POLICY_RE = re.compile(r"\bpolicy\s+(accept|drop)\b")


def _count_nft_rules(ruleset: str) -> int:
    """Count rule lines in nftables ruleset output (verdict-keyword heuristic)."""
    count = 0
    for line in ruleset.splitlines():
        if _NFT_POLICY_RE.search(line):
            continue
        if _NFT_VERDICT_RE.search(line):
            count += 1
    return count


async def firewall_rules() -> str:
    """Show active firewall rules on this Kali host (read-only).

    Inspects nftables, iptables (filter + nat tables) and ufw to report
    every rule currently in effect. Useful for:
    - Auditing what traffic is allowed/dropped
    - Verifying rules left behind by MITM tools (ettercap/sslstrip)
    - Troubleshooting "why can't I reach port X"

    Requires: nftables / iptables (pre-installed on Kali); ufw optional.
    """
    executor = get_executor(timeout=15)
    sections: list[tuple[str, str, int]] = []  # (title, raw output, rule count)

    # --- nftables (modern default backend) ---
    r_nft = await executor.run(["nft", "list", "ruleset"])
    if r_nft.success and r_nft.stdout.strip():
        sections.append(
            ("nftables (`nft list ruleset`)", r_nft.stdout, _count_nft_rules(r_nft.stdout))
        )

    # --- iptables (compat layer; also shows nft-backed rules) ---
    for table in ("filter", "nat"):
        r = await executor.run(["iptables", "-t", table, "-S"])
        if r.success and r.stdout.strip():
            count = sum(1 for line in r.stdout.splitlines() if line.startswith("-A"))
            sections.append((f"iptables -t {table}", r.stdout, count))

    # --- ufw (optional front-end) ---
    r_u = await executor.run(["ufw", "status", "verbose"])
    if r_u.success and r_u.stdout.strip() and "Status: active" in r_u.stdout:
        sections.append(("ufw (`ufw status verbose`)", r_u.stdout, -1))

    lines = ["## Firewall Rules", ""]

    if not sections:
        lines.append(
            "_No firewall output — nftables/iptables may be missing or the "
            "service lacks CAP_NET_ADMIN._"
        )
        return "\n".join(lines)

    total = sum(c for _, _, c in sections if c >= 0)
    summary_parts = [f"{title.split(' (')[0]}: {c}" + (" rules" if c >= 0 else " active")
                     for title, _, c in sections]
    lines.append(f"**Summary:** {' | '.join(summary_parts)}")
    lines.append("")

    for title, raw, count in sections:
        lines.append(f"### {title}")
        lines.append("")
        if count >= 0 and count == 0:
            lines.append("_No rules (only default policies)._")
            lines.append("")
        lines.append("```")
        lines.append(raw.strip())
        lines.append("```")
        lines.append("")

    if total == 0:
        lines.append(
            "**Note:** No active firewall rules — all traffic is allowed by "
            "default. Check the sections above for default policies."
        )

    return "\n".join(lines)


async def tcpdump_capture(params: TcpdumpInput) -> str:
    """Capture and analyze live network packets using tcpdump.

    Captures network traffic in real-time with BPF filter support.
    Displays packet headers with timestamps, source/destination, protocol,
    and flags. Use for network troubleshooting and traffic analysis.

    IMPORTANT: Requires root/sudo. On Kali, run with appropriate privileges.
    Also check that user has capability: sudo setcap cap_net_raw+ep /usr/bin/tcpdump

    Requires: tcpdump (pre-installed on Kali)
    """
    # Bound the capture at `duration`: SIGINT makes tcpdump flush and exit
    # cleanly (all packet lines already written with -l); -c count still
    # ends it early when the quota is met. Same pattern as traffic_stats.
    cmd = [
        "timeout", "-s", "INT", str(params.duration),
        "tcpdump",
        "-i", params.interface,
        "-c", str(params.count),
        "-l",
    ]

    if not params.resolve:
        cmd.append("-n")

    if params.filter_expr:
        cmd.extend(params.filter_expr.split())

    timeout = params.duration + 10
    executor = get_executor(timeout=timeout)
    result = await executor.run(cmd, timeout=timeout)

    # rc 124 = the duration limit was hit. If any packets were captured,
    # that's a partial success — report it as such, not "Failed".
    if result.returncode == 124 and result.stdout:
        result.success = True
        result.returncode = 0
        result.stdout = (
            f"Note: capture stopped at the {params.duration}s duration limit "
            f"before reaching {params.count} packets (partial capture):\n"
            + result.stdout
        )
    elif result.returncode == 124:
        # Duration elapsed with zero packets — say so plainly.
        result.stderr = (
            f"No packets captured within the {params.duration}s duration — "
            f"the interface was idle or the filter matched nothing."
            + (f"\n{result.stderr}" if result.stderr else "")
        )

    desc = f"if={params.interface}, duration={params.duration}s, count={params.count}"
    if params.filter_expr:
        desc += f", filter='{params.filter_expr}'"
    return _fmt("tcpdump Capture", desc, " ".join(cmd), result)


async def http_request(params: CurlInput) -> str:
    """Make HTTP requests using curl for web service testing.

    Performs HTTP requests to test web services, APIs, and check
    connectivity. Supports all standard methods, custom headers,
    and request bodies.

    Equivalent to: curl -X {method} {url} -H '...' -d '...'

    Requires: curl (pre-installed on Kali)
    """
    cmd = ["curl", "-s", "-X", params.method]

    if params.follow_redirects:
        cmd.append("-L")
    if params.insecure:
        cmd.append("-k")

    cmd.extend(["--connect-timeout", str(params.timeout)])
    cmd.extend(["--max-time", str(params.timeout)])

    # Headers
    if params.headers:
        import json

        try:
            header_dict = json.loads(params.headers)
            for key, value in header_dict.items():
                cmd.extend(["-H", f"{key}: {value}"])
        except json.JSONDecodeError:
            return (
                f"## HTTP Request\n"
                f"**Target:** `{params.url}`\n"
                f"**Status:** ✗ Error\n\n"
                f"Invalid JSON in headers: {params.headers}"
            )

    # Request body
    if params.data:
        cmd.extend(["-d", params.data])

    cmd.append(params.url)

    executor = get_executor(timeout=params.timeout + 5)
    result = await executor.run(cmd, timeout=params.timeout + 5)
    return _fmt("HTTP Request", params.url, " ".join(cmd), result)


# ===================================================================
# Network Topology Mapper
# ===================================================================


class TopologyInput(BaseModel):
    """Input for network topology mapping."""

    subnet: str = Field(
        default="",
        description="Subnet to map (e.g. '192.168.0.0/24'). Empty = auto-detect from routing table.",
        max_length=32,
    )
    detail: bool = Field(
        default=True, description="Include detailed device info (ports, OS) in the output"
    )

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        _no_shell_meta(v)
        return v


# Device classification (_DEVICE_CLASSES / classify_device) lives in
# kali_mcp.netinfo — shared with snmp_topology and the monitor tools.


async def network_topology(params: TopologyInput) -> str:
    """Map the local network topology and generate a Mermaid diagram.

    Scans the subnet with arp-scan, classifies devices by vendor/type,
    and outputs a visual topology graph (Mermaid format) plus a summary
    table. Also merges the IPv6 NDP neighbour table so devices that are
    only reachable over IPv6 (invisible to ARP) show up, flagged 🔮.
    Renders directly in Cherry Studio and Markdown viewers.

    Use this to:
    - Visualize your LAN structure
    - Identify device roles (router, AP, camera, PC, phone, IoT)
    - Spot rogue or unknown devices (including IPv6-only devices)

    Requires: arp-scan (sudo apt install arp-scan)
    """
    executor = get_executor(timeout=60)

    # 1. Resolve subnet (explicit value wins, else auto-detect)
    subnet = await detect_subnet(executor, params.subnet)
    if subnet is None:
        return (
            "❌ 无法自动探测本机子网（默认路由网卡未找到 IPv4 地址）。\n"
            "请通过 subnet 参数显式指定要扫描的网段（如 192.168.1.0/24）。"
        )

    # 2. ARP scan + parse + classify (shared with snmp_topology fallback)
    t0 = time.monotonic()
    result, devices = await arp_scan_devices(executor, subnet)
    elapsed = time.monotonic() - t0

    if not result.success:
        return _fmt("Network Topology", subnet, f"arp-scan {subnet}", result)

    # 2b. Merge IPv6 NDP neighbours; flag devices invisible to IPv4 ARP
    devices, v6_only = merge_ndp_devices(devices, await ndp_devices(executor))

    # 3. Summary (stats + shared Mermaid rendering + device list)
    summary = [
        f"## 🌐 网络拓扑 — {subnet}",
        f"**设备总数:** {len(devices)} | **扫描耗时:** {elapsed:.1f}s",
        "",
        "### 设备分布",
        *arp_class_stats_lines(devices),
        "",
        "### 拓扑图",
        "",
        *arp_mermaid_lines(devices),
        "",
        "### 设备清单",
        "| IP | MAC | 厂商 | 类型 |",
        "|------|------|------|------|",
    ]
    for d in devices:
        summary.append(f"| {d['ip']} | {d['mac']} | {d['vendor']} | {d['icon']} {d['class']} |")

    if v6_only:
        summary.extend(
            [
                "",
                f"### 🔮 仅 IPv6 可见设备（{len(v6_only)} 台，IPv4 ARP 扫不到）",
                "| IPv6 地址 | MAC |",
                "|------|------|",
            ]
        )
        for d in v6_only:
            summary.append(f"| `{d['ip']}` | {d['mac']} |")

    return "\n".join(summary)


# ===================================================================
# SNMP Topology — precise switch-level mapping
# ===================================================================


class SnmpTopologyInput(BaseModel):
    """Input for SNMP-based topology mapping."""

    subnet: str = Field(
        default="",
        description="Subnet CIDR (e.g. '192.168.0.0/24'). Empty = auto-detect.",
        max_length=32,
    )
    switches: str = Field(
        default="",
        description="Comma-separated switch IPs to query via SNMP (e.g. '192.168.0.1,192.168.0.9'). Empty = scan common IPs.",
        max_length=256,
    )
    community: str = Field(
        default="public",
        description="SNMP community string. Default: public.",
        max_length=64,
    )

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


async def snmp_topology(params: SnmpTopologyInput) -> str:
    """Precise network topology via SNMP (falls back to ARP if SNMP unavailable).

    Attempts SNMP to read switch MAC-address tables, mapping each device
    to its exact switch port. Generates a Mermaid diagram with port-level
    accuracy.

    If SNMP is unavailable (unmanaged switches), falls back to ARP-based
    topology with best-effort device classification.

    Requires: snmpwalk (sudo apt install snmp), arp-scan
    """
    from collections import defaultdict

    executor = get_executor(timeout=60)

    # 1. Resolve subnet (explicit value wins, else auto-detect)
    subnet = await detect_subnet(executor, params.subnet)
    if subnet is None:
        return (
            "❌ 无法自动探测本机子网（默认路由网卡未找到 IPv4 地址）。\n"
            "请通过 subnet 参数显式指定要扫描的网段（如 192.168.1.0/24）。"
        )

    # 2. ARP scan for all devices (shared parse+classify) + NDP merge
    _, arp_devices = await arp_scan_devices(executor, subnet)
    arp_devices, v6_only = merge_ndp_devices(arp_devices, await ndp_devices(executor))

    # 3. Find switches to query
    switch_ips = []
    if params.switches:
        switch_ips = [s.strip() for s in params.switches.split(",") if s.strip()]
    else:
        # Try all TP-Link, H3C, or .1 addresses
        for d in arp_devices:
            vl = d["vendor"].lower()
            if any(k in vl for k in ["tp-link", "h3c", "cisco", "aruba", "switch", "ubiquit"]):
                switch_ips.append(d["ip"])
        if not switch_ips:
            # Fallback: try common gateway IPs
            parts = subnet.split(".")[0:3]
            for last in ["1", "254"]:
                switch_ips.append(".".join(parts + [last]))

    # 4. Try SNMP on each switch
    snmp_data = {}  # {switch_ip: {mac: port_name}}
    snmp_working = False

    for sw_ip in switch_ips[:5]:  # Limit to 5 switches
        # Test SNMP reachability
        test = await executor.run(
            ["snmpwalk", "-v2c", "-c", params.community, "-t", "3", "-r", "1",
             sw_ip, "1.3.6.1.2.1.1.5.0"],
            timeout=10,
        )
        if not test.success or "No Such Object" in test.stdout or "Timeout" in test.stderr:
            continue

        snmp_working = True
        mac_to_port = {}

        # Query dot1d MAC table: OID .1.3.6.1.2.1.17.4.3.1.2 = dot1dTpFdbPort
        # Format: .1.3.6.1.2.1.17.4.3.1.2.<vlan>.<mac_decimal> = port
        mac_walk = await executor.run(
            ["snmpwalk", "-v2c", "-c", params.community, "-t", "5", "-r", "1",
             sw_ip, "1.3.6.1.2.1.17.4.3.1.2"],
            timeout=20,
        )

        if mac_walk.success:
            for line in mac_walk.stdout.split("\n"):
                m = re.search(
                    r"\.1\.3\.6\.1\.2\.1\.17\.4\.3\.1\.2\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\s*=\s*(\d+)",
                    line,
                )
                if m:
                    mac_hex = ":".join(f"{int(m.group(n)):02X}" for n in range(2, 8))
                    port_num = int(m.group(8))
                    mac_to_port[mac_hex] = f"Port {port_num}"

        # Query interface names: IF-MIB::ifName
        port_names = {}
        iface_walk = await executor.run(
            ["snmpwalk", "-v2c", "-c", params.community, "-t", "3", "-r", "1",
             sw_ip, "1.3.6.1.2.1.31.1.1.1.1"],
            timeout=10,
        )
        if iface_walk.success:
            for line in iface_walk.stdout.split("\n"):
                m = re.search(r"\.1\.3\.6\.1\.2\.1\.31\.1\.1\.1\.1\.(\d+)\s*=\s*STRING:\s*(.+)", line)
                if m:
                    port_names[int(m.group(1))] = m.group(2).strip()

        # Query switch hostname
        hostname = sw_ip
        host_walk = await executor.run(
            ["snmpwalk", "-v2c", "-c", params.community, "-t", "3", "-r", "1",
             sw_ip, "1.3.6.1.2.1.1.5.0"],
            timeout=5,
        )
        if host_walk.success:
            hm = re.search(r'STRING:\s*"?(.+?)"?\s*$', host_walk.stdout)
            if hm:
                hostname = hm.group(1)

        snmp_data[sw_ip] = {
            "hostname": hostname,
            "mac_to_port": mac_to_port,
            "port_names": port_names,
        }

    # 5. Build output
    lines = []

    if snmp_working:
        lines.append(f"## 🎯 SNMP 精确拓扑 — {subnet}")
        lines.append("")
        lines.append("```mermaid")
        lines.append("graph TD")
        lines.append('    internet(("🌍 Internet"))')

        # Map ARP devices to switch ports
        switch_devices = defaultdict(list)
        unmapped_ips = set(d["ip"] for d in arp_devices)
        unmapped_ips.discard(subnet.rsplit(".", 1)[0] + ".1")

        for d in arp_devices:
            for sw_ip, sdata in snmp_data.items():
                if d["mac"] in sdata["mac_to_port"]:
                    port = sdata["mac_to_port"][d["mac"]]
                    if d["mac"] in sdata["port_names"]:
                        port = f"{port} ({sdata['port_names'][d['mac']]})"
                    switch_devices[sw_ip].append((d["ip"], d["mac"], d["vendor"], port))
                    unmapped_ips.discard(d["ip"])
                    break

        # Draw gateway
        gw_ip = subnet.rsplit(".", 1)[0] + ".1"
        lines.append(f'    internet --- gw["🏠 网关\\n{gw_ip}"]')

        # Draw each switch with its ports and devices
        for sw_ip, sdata in snmp_data.items():
            sw_id = f'sw_{sw_ip.replace(".","_")}'
            hn = sdata["hostname"][:15]
            port_count = len(sdata["mac_to_port"])
            lines.append(f'    gw --- {sw_id}["🔀 {hn}\\n{sw_ip}\\n{port_count} devices"]')

            for ip, mac, vendor, port in switch_devices.get(sw_ip, []):
                dev_id = f'd_{ip.replace(".","_")}'
                icon = classify_device(vendor)[1]
                label = f'{icon} {vendor[:12] if vendor[:3] != "(Un" else "设备"}\\n{ip}\\n{port}'
                lines.append(f'    {sw_id} --- {dev_id}["{label}"]')

        # Draw unmapped devices under gateway
        if unmapped_ips:
            lines.append(f'    gw --- unmapped["❓ 未映射\\n{len(unmapped_ips)} devices"]')

        lines.append("```")
        lines.append("")

        # Summary table
        lines.append("### SNMP 交换机详情")
        for sw_ip, sdata in snmp_data.items():
            lines.append(f"\n**{sdata['hostname']}** ({sw_ip})")
            lines.append("| MAC | IP | 端口 | 厂商 |")
            lines.append("|------|------|------|------|")
            for ip, mac, vendor, port in switch_devices.get(sw_ip, []):
                lines.append(f"| {mac} | {ip} | {port} | {vendor[:25]} |")

        if unmapped_ips:
            lines.append(f"\n⚠️ {len(unmapped_ips)} 台设备未匹配到任何 SNMP 交换机端口（可能是通过傻瓜交换机连接的）。")

    else:
        # SNMP failed — fall back to ARP topology (shared rendering with
        # network_topology via netinfo — no duplicated draw logic here)
        lines.append(f"## 🌐 网络拓扑 — {subnet}（SNMP 不可用，ARP 推测）")
        lines.append("")
        lines.append("> ⚠️ 未检测到 SNMP。显示 ARP 推测拓扑。精确映射需要交换机开启 SNMP v2c。")
        lines.append("")
        for sw_ip in switch_ips:
            lines.append(f"- `{sw_ip}`: SNMP 无响应")
        lines.append("")
        lines.extend(arp_mermaid_lines(arp_devices))
        lines.append("")
        lines.append("### 设备分布")
        lines.extend(arp_class_stats_lines(arp_devices))
        if v6_only:
            lines.extend(
                [
                    "",
                    f"### 🔮 仅 IPv6 可见设备（{len(v6_only)} 台，IPv4 ARP 扫不到）",
                    "| IPv6 地址 | MAC |",
                    "|------|------|",
                ]
            )
            for d in v6_only:
                lines.append(f"| `{d['ip']}` | {d['mac']} |")

    return "\n".join(lines)




class MasscanInput(BaseModel):
    """Input for high-speed masscan port scanning."""

    target: str = Field(
        ...,
        description="Target IP, hostname, or CIDR (v4: /16 or smaller; v6: /112 or smaller), e.g. 192.168.1.0/24, 10.0.0.0/16",
        min_length=1,
        max_length=256,
    )
    ports: str = Field(
        default="80,443",
        description=(
            "Ports to scan: comma-separated ports and ranges, each part may "
            "carry a protocol prefix — 'T:' TCP (default when bare) or 'U:' "
            "UDP (e.g. '80,443', '1-10000', 'T:22,U:53')"
        ),
        max_length=512,
    )
    rate: int = Field(
        default=100,
        description="Probe rate in packets per second (masscan default 100; capped at 10000)",
        ge=1,
        le=10000,
    )
    banner: bool = Field(
        default=False,
        description="Attempt service banner detection on open ports (slower)",
    )
    interface: str = Field(
        default="",
        description="Network interface to use (e.g. eth0). Auto-detect if empty.",
        max_length=32,
    )
    timeout: int = Field(
        default=120,
        description="Maximum scan duration in seconds (partial results are kept)",
        ge=10,
        le=600,
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_masscan_target(v)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        if not _is_valid_masscan_ports(v):
            raise ValueError(f"Invalid port spec: {v!r}")
        return v

    @field_validator("interface")
    @classmethod
    def validate_iface(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


def _parse_masscan_found(stdout: str) -> list[tuple[str, int]]:
    """Extract (host, port) pairs from masscan 'Discovered' output lines."""
    found: list[tuple[str, int]] = []
    for line in stdout.splitlines():
        m = re.match(r"^Discovered\s+(\S+):(\d+)\s+Open", line)
        if m:
            found.append((m.group(1), int(m.group(2))))
    return found


def _masscan_output_summary(found: list[tuple[str, int]]) -> str:
    """Render the open-port summary table from parsed (host, port) pairs."""
    if not found:
        return ""
    by_host: dict[str, set[int]] = {}
    for host, port in found:
        by_host.setdefault(host, set()).add(port)
    lines = [
        "",
        "### 📋 开放端口汇总",
        "",
        "| 主机 | 开放端口 |",
        "|------|----------|",
    ]
    for host in sorted(by_host):
        ports = ", ".join(str(p) for p in sorted(by_host[host]))
        lines.append(f"| `{host}` | {ports} |")
    lines.append("")
    lines.append(
        "> 后续建议：对以上主机用 `nmap_scan`（scan_type=version）做服务详查。"
    )
    return "\n".join(lines)


async def masscan_scan(params: MasscanInput) -> str:
    """High-speed port scanning with masscan (thousands of ports per second).

    masscan is a parallelized high-speed scanner: it sweeps port ranges
    across a whole subnet far faster than nmap. Ideal for a quick
    'what is up, which ports are open' pass — then use nmap for detailed
    service/version checks on the hosts it finds.

    Bounded by design (green tier):
    - v4 targets limited to /16 or smaller, v6 to /112 or smaller
    - probe rate capped at 10000 pps (default 100)
    - wall-clock timeout; partial results are kept on timeout

    Use cases:
    - Quick open-port sweep of a /24 or /16
    - Find which hosts in a range answer on web ports
    - Fast pre-scan before a detailed nmap pass

    Requires: masscan (sudo apt install masscan)
    """
    # Flag names follow the masscan(8) man page exactly:
    #   -p PORTS          (bare parts are TCP; prefix parts with U: for UDP)
    #   --rate RATE       (packets per second)
    #   --banners         (note: PLURAL in masscan)
    #   -e IFNAME         (adapter/interface; there is no --interface flag)
    cmd = ["masscan", "-p", params.ports]
    cmd.extend(["--rate", str(params.rate)])
    if params.banner:
        cmd.append("--banners")
    if params.interface:
        cmd.extend(["-e", params.interface])
    cmd.append(params.target)

    executor = get_executor(timeout=params.timeout)
    result = await executor.run(cmd, timeout=params.timeout)
    out = _fmt("masscan Scan", params.target, " ".join(cmd), result)

    found = _parse_masscan_found(result.stdout)
    if found:
        out += "\n" + _masscan_output_summary(found)
    elif result.success:
        out += "\n\n_(扫描完成 — 未发现开放端口)_"
    return out


# ===================================================================
# Registry — maps tool names to (async_function, PydanticModel)
# ===================================================================

TOOL_REGISTRY: dict[str, tuple[callable, type[BaseModel]]] = {
    "nmap_scan": (nmap_scan, NmapInput),
    "masscan_scan": (masscan_scan, MasscanInput),
    "arp_scan": (arp_scan, ArpScanInput),
    "ping_host": (ping_host, PingInput),
    "traceroute_host": (traceroute_host, TracerouteInput),
    "mtr_report": (mtr_report, MtrInput),
    "dig_query": (dig_query, DigInput),
    "whois_lookup": (whois_lookup, WhoisInput),
    "network_connections": (network_connections, NetConnsInput),
    "network_interfaces": (network_interfaces, None),
    "routing_table": (routing_table, None),
    "firewall_rules": (firewall_rules, None),
    "tcpdump_capture": (tcpdump_capture, TcpdumpInput),
    "http_request": (http_request, CurlInput),
    "network_topology": (network_topology, TopologyInput),
    "snmp_topology": (snmp_topology, SnmpTopologyInput),
}
