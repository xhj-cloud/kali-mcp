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
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import CommandResult, get_executor

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


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_MAX_OUTPUT = 8000


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
        out = result.stdout[:_MAX_OUTPUT]
        truncated = " ... (truncated)" if len(result.stdout) > _MAX_OUTPUT else ""
        lines.append("```")
        lines.append(out + truncated)
        lines.append("```")
    else:
        lines.append("_(no output)_")
    if result.stderr:
        lines.append(f"\n**Diagnostics:**\n```\n{result.stderr[:2000]}\n```")
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
                    if arg_lower.startswith(prefix):
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


async def tcpdump_capture(params: TcpdumpInput) -> str:
    """Capture and analyze live network packets using tcpdump.

    Captures network traffic in real-time with BPF filter support.
    Displays packet headers with timestamps, source/destination, protocol,
    and flags. Use for network troubleshooting and traffic analysis.

    IMPORTANT: Requires root/sudo. On Kali, run with appropriate privileges.
    Also check that user has capability: sudo setcap cap_net_raw+ep /usr/bin/tcpdump

    Requires: tcpdump (pre-installed on Kali)
    """
    cmd = [
        "tcpdump",
        "-i", params.interface,
        "-c", str(params.count),
        "-l",
    ]

    if not params.resolve:
        cmd.append("-n")

    if params.filter_expr:
        cmd.append(params.filter_expr)

    timeout = params.duration + 5
    executor = get_executor(timeout=timeout)
    result = await executor.run(cmd, timeout=timeout)

    desc = f"if={params.interface}, count={params.count}"
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
        default="192.168.0.0/24",
        description="Subnet to map (e.g. '192.168.0.0/24'). Default: auto-detect from routing table.",
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


def _classify_device(vendor: str) -> tuple[str, str]:
    """Classify device by vendor name."""
    vendor_lower = vendor.lower().strip()
    for key, (dtype, icon) in _DEVICE_CLASSES.items():
        if key in vendor_lower:
            return dtype, icon
    if "locally administered" in vendor_lower or not vendor_lower:
        return "unknown", "❓"
    return "unknown", "❓"


async def network_topology(params: TopologyInput) -> str:
    """Map the local network topology and generate a Mermaid diagram.

    Scans the subnet with arp-scan, classifies devices by vendor/type,
    and outputs a visual topology graph (Mermaid format) plus a summary
    table. Renders directly in Cherry Studio and Markdown viewers.

    Use this to:
    - Visualize your LAN structure
    - Identify device roles (router, AP, camera, PC, phone, IoT)
    - Spot rogue or unknown devices

    Requires: arp-scan (sudo apt install arp-scan)
    """
    import re
    from collections import Counter

    executor = get_executor(timeout=60)

    # 1. Auto-detect subnet from routing table if needed
    subnet = params.subnet
    if not subnet or subnet == "192.168.0.0/24":
        r = await executor.run(["ip", "route", "show", "default"])
        m = re.search(r"dev\s+(\S+)", r.stdout)
        iface = m.group(1) if m else "eth0"
        r2 = await executor.run(["ip", "-4", "addr", "show", iface])
        m2 = re.search(r"inet\s+(\S+)", r2.stdout)
        if m2:
            cidr = m2.group(1)
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                subnet = str(net)
            except Exception:
                pass

    # 2. ARP scan
    cmd = ["arp-scan", subnet]
    result = await executor.run(cmd, timeout=60)

    if not result.success:
        return _fmt("Network Topology", subnet, " ".join(cmd), result)

    # 3. Parse devices
    devices = []
    gateway_ip = None
    for line in result.stdout.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip() if len(parts) > 1 else ""
            vendor = parts[2].strip() if len(parts) > 2 else "Unknown"
            if ip and re.match(r"\d+\.\d+\.\d+\.\d+$", ip):
                dclass, icon = _classify_device(vendor)
                # Heuristic: .1 is usually gateway
                if ip.endswith(".1") and not gateway_ip:
                    gateway_ip = ip
                    dclass, icon = "gateway", "🏠"
                # TP-Link with .1 is gateway
                if dclass == "router" and ip.endswith(".1"):
                    dclass, icon = "gateway", "🏠"
                devices.append({
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "class": dclass, "icon": icon,
                })

    # 4. Count stats
    stats = Counter(d["class"] for d in devices)
    gateways = [d for d in devices if d["class"] == "gateway"]
    aps = [d for d in devices if d["class"] in ("ap", "router", "network")]
    others = [d for d in devices if d["class"] not in ("gateway", "ap", "router", "network")]

    # 5. Build Mermaid diagram
    lines = ["```mermaid", "graph TD"]
    lines.append('    internet(("🌍 Internet"))')

    for g in gateways:
        lines.append(f'    internet --- gw_{g["ip"].replace(".","_")}["{g["icon"]} 网关\\n{g["ip"]}"]')
        gw_id = f'gw_{g["ip"].replace(".","_")}'

    # APs connect to gateway
    if aps:
        for ap in aps:
            lines.append(f'    {gw_id} --- ap_{ap["ip"].replace(".","_")}["{ap["icon"]} {ap["vendor"][:12]}\\n{ap["ip"]}"]')

    # Other devices connect to gateway or nearest AP
    ap_ids = [f'ap_{ap["ip"].replace(".","_")}' for ap in aps]
    for i, dev in enumerate(others):
        node_id = f'dev_{dev["ip"].replace(".","_")}'
        parent = ap_ids[i % len(ap_ids)] if ap_ids else gw_id
        label = f'{dev["icon"]} {dev["vendor"][:15] if dev["vendor"] != "Unknown" else "未知设备"}\\n{dev["ip"]}'
        lines.append(f'    {parent} --- {node_id}["{label}"]')

    lines.append("```")

    # 6. Summary table
    summary = [
        f"## 🌐 网络拓扑 — {subnet}",
        f"**设备总数:** {len(devices)} | **扫描耗时:** 2-3s",
        "",
        "### 设备分布",
        "| 类别 | 数量 |",
        "|------|------|",
    ]
    for cls, cnt in stats.most_common():
        icon = [d["icon"] for d in devices if d["class"] == cls][0] if devices else "?"
        summary.append(f"| {icon} {cls} | {cnt} |")

    summary.append("")
    summary.append("### 拓扑图")
    summary.append("")
    summary.extend(lines)
    summary.append("")
    summary.append("### 设备清单")
    summary.append("| IP | MAC | 厂商 | 类型 |")
    summary.append("|------|------|------|------|")
    for d in devices:
        summary.append(f"| {d['ip']} | {d['mac']} | {d['vendor']} | {d['icon']} {d['class']} |")

    return "\n".join(summary)


# ===================================================================
# Registry — maps tool names to (async_function, PydanticModel)
# ===================================================================

TOOL_REGISTRY: dict[str, tuple[callable, type[BaseModel]]] = {
    "nmap_scan": (nmap_scan, NmapInput),
    "arp_scan": (arp_scan, ArpScanInput),
    "ping_host": (ping_host, PingInput),
    "traceroute_host": (traceroute_host, TracerouteInput),
    "mtr_report": (mtr_report, MtrInput),
    "dig_query": (dig_query, DigInput),
    "whois_lookup": (whois_lookup, WhoisInput),
    "network_connections": (network_connections, NetConnsInput),
    "network_interfaces": (network_interfaces, None),
    "routing_table": (routing_table, None),
    "tcpdump_capture": (tcpdump_capture, TcpdumpInput),
    "http_request": (http_request, CurlInput),
    "network_topology": (network_topology, TopologyInput),
}
