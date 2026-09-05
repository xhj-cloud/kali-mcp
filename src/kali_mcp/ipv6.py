"""
Kali Linux IPv6 network maintenance tools.

Ten 🟢 IPv6 diagnostics (always enabled) plus two 🟡 active-recon
tools (PENTEST_ENABLED). The original six are single-host / remote
checks; the four added 🟢 tools cover LAN-level discovery and
end-to-end diagnosis; the two 🟡 tools are the pentest tier:

  1. ipv6_status     — IPv6 overview: per-interface addresses (incl.
                       config-source analysis: SLAAC / DHCPv6 / static),
                       default gateway, sysctl kernel parameters
  2. ipv6_ping       — ICMPv6 reachability (custom target, or automatic
                       test against public IPv6 DNS servers)
  3. ipv6_traceroute — IPv6 path tracing with traceroute6
  4. ipv6_dig        — DNS AAAA lookup, compared against the A record
  5. ipv6_neigh      — IPv6 neighbour table (NDP, the IPv6 equivalent of ARP)
  6. ipv6_firewall   — IPv6 firewall audit (ip6tables + nftables v6 families)
  7. ipv6_scan       — IPv6 device discovery: passive NDP neighbour table +
                       optional bounded nmap -sn -6 sweep, cross-referenced
                       with IPv4 ARP to flag IPv6-only devices
  8. ipv6_doctor     — one-shot end-to-end IPv6 health check: local address
                       → default route → AAAA resolution → public ping →
                       v6 HTTP egress IP, with per-layer conclusions
  9. ipv6_ra_inspect — passive Router Advertisement listener: what prefixes
                       does the router actually advertise (SLAAC/DHCPv6)?
 10. ipv6_route_debug— `ip -6 route get` source-address selection diagnosis
 11. ipv6_recon      — 🟡 active IPv6 recon: rdisc6 router discovery
                       (advertised prefixes / RDNSS / NAT64) + passive NDP
                       + MAC→SLAAC EUI-64 address guessing (verified by
                       parallel ping) + optional bounded nmap -sn sweep
 12. ipv6_service_scan — 🟡 nmap -6 -sV -sC service/version/NSE-script
                       scan of v6 hosts (single address or /80-or-smaller
                       CIDR — /64 = 2^64 hosts, full scan infeasible)

Requires: iproute2, iputils-ping, traceroute, dnsutils, ip6tables/nftables,
nmap, tcpdump, curl — all pre-installed on a standard Kali install;
rdisc6 (package ``ndisc6``) for ipv6_recon.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import CommandResult, get_executor
from kali_mcp.netinfo import (
    arp_scan_devices,
    detect_default_iface,
    detect_subnet,
    ndp_devices,
)
from kali_mcp.tools import _fmt, _is_valid_domain, _no_shell_meta, _MAX_OUTPUT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_valid_ipv6(v: str) -> bool:
    """Validate a bare IPv6 address (no zone, no CIDR)."""
    try:
        ipaddress.IPv6Address(v)
        return True
    except ValueError:
        return False


def _classify_ipv6(addr: str) -> str:
    """Classify an IPv6 address as global / ULA / link-local."""
    a = addr.split("/")[0].split("%")[0].lower()
    try:
        ip = ipaddress.IPv6Address(a)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private and (a.startswith("fc") or a.startswith("fd")):
        return "ULA"
    return "global"


def _parse_dig_answers(output: str) -> list[str]:
    """Extract record values from a `dig` ANSWER SECTION."""
    records: list[str] = []
    in_answer = False
    for line in output.splitlines():
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if in_answer:
            if line.startswith(";;"):
                in_answer = False
                continue
            parts = line.split()
            # name ttl class type value
            if len(parts) >= 5:
                records.append(parts[4])
    return records


_NFT_V6_TABLE_RE = re.compile(r"^table\s+(ip6|inet)\s+\S+")
_NFT_VERDICT_RE = re.compile(r"\b(accept|drop|reject)\b")
_NFT_POLICY_RE = re.compile(r"\bpolicy\s+(accept|drop)\b")


def _extract_v6_tables(ruleset: str) -> str:
    """Extract `table ip6 ...` and `table inet ...` blocks from `nft list ruleset`.

    The inet family carries both IPv4 and IPv6 rules; ip6 is v6-only.
    A balanced-brace scan keeps the extraction robust to nested chains.
    """
    blocks: list[str] = []
    cur: list[str] | None = None
    depth = 0
    for line in ruleset.splitlines():
        stripped = line.strip()
        if cur is None:
            if _NFT_V6_TABLE_RE.match(stripped):
                cur = [line]
                depth = line.count("{") - line.count("}")
                if depth <= 0:
                    blocks.append(line)
                    cur = None
        else:
            cur.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                blocks.append("\n".join(cur))
                cur = None
    return "\n\n".join(blocks)


def _count_nft_rules(ruleset: str) -> int:
    """Count rule lines (verdict keyword heuristic, skips chain policy lines)."""
    count = 0
    for line in ruleset.splitlines():
        if _NFT_POLICY_RE.search(line):
            continue
        if _NFT_VERDICT_RE.search(line):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Parsing helpers for the discovery / diagnosis tools
# ---------------------------------------------------------------------------


def _parse_nmap6_hosts(output: str) -> list[dict]:
    """Parse ``nmap -sn -6`` output → ``[{'ip', 'mac'}, ...]``."""
    hosts: list[dict] = []
    cur: dict | None = None
    for line in output.splitlines():
        if line.startswith("Nmap scan report for "):
            if cur is not None:
                hosts.append(cur)
            # Last token is either "addr" or "(addr)"
            cur = {"ip": line.rsplit(None, 1)[-1].strip("()"), "mac": ""}
            continue
        if cur is not None:
            m = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})", line)
            if m:
                cur["mac"] = m.group(1).upper()
    if cur is not None:
        hosts.append(cur)
    return hosts


_RA_HDR_RE = re.compile(
    r"^\S+\s+IP6 \(hlim \d+, next-header ICMPv6 \(\d+\), payload length \d+\)\s+"
    r"(\S+)\s+>\s+(\S+):\s*(?:\[[^\]]*\]\s*)?ICMP6, router advertisement, length \d+"
)
_RA_DETAIL_RE = re.compile(
    r"hop limit (\d+), Flags \[([^\]]*)\], pref \w+, router lifetime (\d+)s"
)
_RA_PREFIX_RE = re.compile(
    r"prefix info option \(3\), length \d+ \(\d+\):\s*(\S+),\s*"
    r"Flags \[([^\]]*)\],\s*valid time (\d+)s,\s*pref\. time (\d+)s"
)
_RA_MTU_RE = re.compile(r"mtu option \(5\), length \d+ \(\d+\):\s*(\d+)")
_RA_LLA_RE = re.compile(
    r"source link-address option \(1\), length \d+ \(\d+\):\s*"
    r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
)


def _parse_ra_output(output: str) -> list[dict]:
    """Parse a ``tcpdump -vv`` Router Advertisement capture.

    Returns one dict per RA packet: ``src, dst, hop_limit, flags,
    router_lifetime, prefixes[{prefix, flags, valid, preferred}], mtu, lla``.
    """
    ras: list[dict] = []
    cur: dict | None = None
    for line in output.splitlines():
        m = _RA_HDR_RE.match(line)
        if m:
            if cur is not None:
                ras.append(cur)
            cur = {
                "src": m.group(1),
                "dst": m.group(2),
                "hop_limit": None,
                "flags": "",
                "router_lifetime": None,
                "prefixes": [],
                "mtu": None,
                "lla": None,
            }
            continue
        if cur is None or line.lstrip().startswith("0x"):
            continue
        m = _RA_DETAIL_RE.search(line)
        if m:
            cur["hop_limit"] = int(m.group(1))
            cur["flags"] = m.group(2)
            cur["router_lifetime"] = int(m.group(3))
            continue
        m = _RA_PREFIX_RE.search(line)
        if m:
            cur["prefixes"].append(
                {
                    "prefix": m.group(1),
                    "flags": m.group(2),
                    "valid": int(m.group(3)),
                    "preferred": int(m.group(4)),
                }
            )
            continue
        m = _RA_MTU_RE.search(line)
        if m:
            cur["mtu"] = int(m.group(1))
            continue
        m = _RA_LLA_RE.search(line)
        if m:
            cur["lla"] = m.group(1).upper()
    if cur is not None:
        ras.append(cur)
    return ras


def _parse_route_get(stdout: str) -> dict:
    """Parse ``ip -6 route get`` output → {from, via, dev, src, metric}."""
    info = {"from": None, "via": None, "dev": None, "src": None, "metric": None}
    for key, pat in (
        ("from", r"\bfrom\s+(\S+)"),
        ("via", r"\bvia\s+(\S+)"),
        ("dev", r"\bdev\s+(\S+)"),
        ("src", r"\bsrc\s+(\S+)"),
        ("metric", r"\bmetric\s+(\d+)"),
    ):
        m = re.search(pat, stdout)
        if m:
            info[key] = m.group(1)
    return info


def _analyze_addr_config(addr_rows: list[dict]) -> list[dict]:
    """Heuristic config-source analysis for global/ULA addresses.

    ``addr_rows`` items: ``{iface, raw, cls, flags, prefix}``. Verdicts:
    - no ``dynamic`` flag           → manual / static configuration
    - ``dynamic``, 2+ on one prefix → SLAAC with privacy-extension temp addr
    - ``dynamic``, single on prefix → SLAAC or DHCPv6 (indistinguishable)
    """
    from collections import defaultdict

    per_prefix: dict[tuple[str, str], int] = defaultdict(int)
    for row in addr_rows:
        if row["cls"] in ("global", "ULA") and "dynamic" in row["flags"]:
            per_prefix[(row["iface"], row["prefix"])] += 1

    results = []
    for row in addr_rows:
        if row["cls"] not in ("global", "ULA"):
            continue
        if "dynamic" not in row["flags"]:
            verdict = "手动/静态配置（无 dynamic 标志）"
        elif per_prefix[(row["iface"], row["prefix"])] >= 2:
            verdict = "SLAAC 自动配置；隐私扩展生效（同前缀多个地址：1 永久 + 临时）"
        else:
            verdict = "自动分配（SLAAC 或 DHCPv6 — 用 ipv6_ra_inspect 看路由器通告确认）"
        if "mngtmpaddr" in row["flags"]:
            verdict += "；有 mngtmpaddr 标志（可能涉及 DHCPv6）"
        results.append({**row, "verdict": verdict})
    return results


async def _own_v6_sweep_prefixes(executor) -> list[str]:
    """First /80 of each real /64 prefix on this host, for a bounded sweep.

    Only /64 (or larger) prefixes qualify — a /128 point-to-point address
    (e.g. Tailscale) is not a usable sweep scope. Link-local prefixes get
    an interface zone appended.
    """
    r = await executor.run(["ip", "-6", "addr", "show"])
    targets: list[str] = []
    if not r.success:
        return targets
    iface = ""
    seen: set[str] = set()
    for line in r.stdout.splitlines():
        m_if = re.match(r"^\d+:\s+([^:]+):", line)
        if m_if:
            iface = m_if.group(1)
            continue
        m_addr = re.match(r"\s+inet6\s+(\S+)", line)
        if not m_addr or iface in ("", "lo"):
            continue
        try:
            net = ipaddress.ip_interface(m_addr.group(1)).network
        except ValueError:
            continue
        if net.prefixlen > 64:
            continue
        sweep = ipaddress.IPv6Network((net.network_address, 80))
        target = str(sweep)
        if net.is_link_local:
            target += f"%{iface}"
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def _validate_v6_subnet(v: Optional[str]) -> Optional[str]:
    """Validate an optional active-scan target.

    Accepts a bare IPv6 address or a CIDR of /80 or smaller (a /64 holds
    2^64 addresses — a full sweep is infeasible, so larger prefixes are
    rejected). Shared by Ipv6ScanInput and Ipv6ReconInput.
    """
    if v is None or v.strip() == "":
        return None
    v = _no_shell_meta(v)
    bare = v.split("%", 1)[0]
    try:
        if "/" in bare:
            net = ipaddress.IPv6Network(bare, strict=False)
            if net.prefixlen < 80:
                raise ValueError(
                    f"扫描前缀太大（/{net.prefixlen}）：/64 有 2^64 个地址无法全扫，"
                    "请指定 /80 或更小的前缀，或留空用自动模式"
                )
        else:
            ipaddress.IPv6Address(bare)
    except ValueError as e:
        if "太大" in str(e):
            raise ValueError(str(e))
        raise ValueError(
            "必须是有效 IPv6 地址或 /80 或更小的 CIDR（如 fd00:beef::/80）"
        ) from None
    return v


# Public IPv6 DNS used by the automatic reachability check.
PUBLIC_IPV6_DNS: list[tuple[str, str]] = [
    ("Google", "2001:4860:4860::8888"),
    ("阿里", "2400:3200::1"),
    ("腾讯", "2402:4e00::"),
]

_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
_PING_AVG_RE = re.compile(r"min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms")

# ===================================================================
# Pydantic input models
# ===================================================================


class Ipv6PingInput(BaseModel):
    """Input for IPv6 ping."""

    target: Optional[str] = Field(
        None,
        description=(
            "要 ping 的 IPv6 地址（如 2400:3200::1）；留空则自动测试三家公共 "
            "IPv6 DNS（Google/阿里/腾讯）判断本机 IPv6 是否可用"
        ),
    )
    count: int = Field(4, ge=1, le=20, description="每个目标 ping 次数（默认 4）")
    timeout: int = Field(3, ge=1, le=10, description="单包超时秒数（默认 3）")

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v)
        if not _is_valid_ipv6(v):
            raise ValueError(
                "target must be a valid IPv6 address, e.g. 2001:4860:4860::8888"
            )
        return v


class Ipv6TracerouteInput(BaseModel):
    """Input for IPv6 traceroute."""

    target: str = Field(
        ...,
        description="目标 IPv6 地址或域名（如 2400:3200::1、baidu.com）",
        min_length=1,
        max_length=256,
    )
    max_hops: int = Field(30, ge=1, le=60, description="最大跳数（默认 30）")
    timeout: int = Field(5, ge=1, le=30, description="每跳等待秒数（默认 5）")

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: str) -> str:
        v = _no_shell_meta(v)
        if _is_valid_ipv6(v) or _is_valid_domain(v):
            return v
        raise ValueError("target must be a valid IPv6 address or domain name")


class Ipv6DigInput(BaseModel):
    """Input for DNS AAAA lookup."""

    domain: str = Field(
        ...,
        description="域名（如 baidu.com、github.com）",
        min_length=1,
        max_length=253,
    )
    dns_server: Optional[str] = Field(
        None,
        description="指定 DNS 服务器（IPv4/IPv6 地址，如 2400:3200::1）；留空用系统默认",
    )

    @field_validator("domain")
    @classmethod
    def _v_domain(cls, v: str) -> str:
        v = _no_shell_meta(v)
        if not _is_valid_domain(v):
            raise ValueError("invalid domain name")
        return v

    @field_validator("dns_server")
    @classmethod
    def _v_server(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v)
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("dns_server must be an IPv4 or IPv6 address")


class Ipv6ScanInput(BaseModel):
    """Input for IPv6 device discovery."""

    subnet: Optional[str] = Field(
        None,
        description=(
            "主动扫描前缀：/80 或更小的 IPv6 CIDR（如 fd00:beef::/80、fe80::/120%eth0）"
            "或单个 IPv6 地址。/64 有 2^64 个地址无法全扫，必须缩小范围；"
            "留空 = 自动模式（NDP 邻居表 + IPv4 ARP 对照）"
        ),
        max_length=64,
    )
    interface: Optional[str] = Field(
        None,
        description="扫描链路本地前缀所用网卡（如 eth0）；留空 = 自动探测默认路由网卡",
        max_length=32,
    )
    auto_sweep: bool = Field(
        False,
        description="自动模式下额外主动 ping 本机每个 /64 前缀的前 16384 个地址（/80，耗时 1-3 分钟，产生真实 ICMPv6 流量）",
    )
    timeout: int = Field(180, ge=10, le=600, description="单次主动扫描超时（秒）")

    @field_validator("subnet")
    @classmethod
    def _v_subnet(cls, v: Optional[str]) -> Optional[str]:
        return _validate_v6_subnet(v)

    @field_validator("interface")
    @classmethod
    def _v_iface(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v)
        if not re.match(r"^[A-Za-z0-9._-]{1,32}$", v):
            raise ValueError("invalid interface name")
        return v


class Ipv6DoctorInput(BaseModel):
    """Input for the end-to-end IPv6 health check."""

    domain: str = Field(
        "baidu.com",
        description="用于测试 AAAA 解析的域名（默认 baidu.com）",
        min_length=1,
        max_length=253,
    )
    timeout: int = Field(6, ge=2, le=30, description="每层超时（秒）")

    @field_validator("domain")
    @classmethod
    def _v_domain(cls, v: str) -> str:
        v = _no_shell_meta(v)
        if not _is_valid_domain(v):
            raise ValueError("invalid domain name")
        return v


class Ipv6RaInspectInput(BaseModel):
    """Input for the Router Advertisement listener."""

    interface: Optional[str] = Field(
        None,
        description="监听网卡（如 eth0）；留空 = 自动探测默认路由网卡",
        max_length=32,
    )
    duration: int = Field(
        30,
        ge=3,
        le=300,
        description="监听时长（秒）。RA 发送周期通常 4-18 分钟，没抓到可适当延长",
    )
    max_packets: int = Field(
        20, ge=2, le=200, description="最多抓取的 RA 报文数"
    )

    @field_validator("interface")
    @classmethod
    def _v_iface(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v)
        if not re.match(r"^[A-Za-z0-9._-]{1,32}$", v):
            raise ValueError("invalid interface name")
        return v


class Ipv6RouteDebugInput(BaseModel):
    """Input for IPv6 source-address / route diagnosis."""

    target: Optional[str] = Field(
        None,
        description="目标 IPv6 地址或域名（默认 2400:3200::1 公共 DNS）",
        max_length=256,
    )

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v)
        if _is_valid_ipv6(v) or _is_valid_domain(v):
            return v
        raise ValueError("target must be a valid IPv6 address or domain name")


# ===================================================================
# 1. ipv6_status
# ===================================================================


async def ipv6_status() -> str:
    """查看本机 IPv6 全景状态（地址 / 路由 / 内核参数，只读）。

    一次性给出：
    - 每个网卡的 IPv6 地址（区分 global 公网 / ULA 内网 / 链路本地）
    - IPv6 默认网关
    - 关键内核参数：IPv6 是否启用、RA 接收、临时地址（隐私扩展）

    排查 IPv6 不通的第一步：先跑这个看本机有没有公网 IPv6 地址。

    Requires: iproute2, procps/sysctl（Kali 预装）
    """
    executor = get_executor(timeout=15)
    r_addr = await executor.run(["ip", "-6", "addr", "show"])
    r_route = await executor.run(["ip", "-6", "route", "show"])
    r_sys = await executor.run(
        [
            "sysctl",
            "net.ipv6.conf.all.disable_ipv6",
            "net.ipv6.conf.default.disable_ipv6",
            "net.ipv6.conf.all.accept_ra",
            "net.ipv6.conf.all.use_tempaddr",
        ]
    )

    lines = ["## IPv6 状态总览", ""]

    # --- parse addresses per interface (incl. scope + kernel flags) ---
    counts = {"global": 0, "ULA": 0, "link-local": 0, "loopback": 0}
    iface: str = ""
    addr_rows: list[dict] = []
    if r_addr.success:
        for line in r_addr.stdout.splitlines():
            m_if = re.match(r"^\d+:\s+([^:]+):", line)
            if m_if:
                iface = m_if.group(1)
                continue
            m_addr = re.match(r"\s+inet6\s+(\S+)\s+scope\s+(\w+)(.*)$", line)
            if m_addr and iface:
                raw = m_addr.group(1)
                cls = _classify_ipv6(raw)
                counts[cls] = counts.get(cls, 0) + 1
                try:
                    prefix = str(ipaddress.ip_interface(raw).network)
                except ValueError:
                    prefix = raw
                addr_rows.append(
                    {
                        "iface": iface,
                        "raw": raw,
                        "cls": cls,
                        "scope": m_addr.group(2),
                        "flags": m_addr.group(3).split(),
                        "prefix": prefix,
                    }
                )

    lines.append("### 地址清单")
    lines.append("")
    if addr_rows:
        lines.append("| 网卡 | 地址 | 类型 |")
        lines.append("|------|------|------|")
        label = {
            "global": "🌐 公网",
            "ULA": "🏠 ULA 内网",
            "link-local": "🔗 链路本地",
            "loopback": "🔄 回环",
        }
        for row in addr_rows:
            lines.append(f"| {row['iface']} | `{row['raw']}` | {label.get(row['cls'], row['cls'])} |")
        lines.append("")
        lines.append(
            f"**统计:** 公网 {counts['global']} 个 | ULA 内网 {counts['ULA']} 个 | "
            f"链路本地 {counts['link-local']} 个 | 回环 {counts['loopback']} 个"
        )
    else:
        lines.append("_(未发现任何 IPv6 地址 — IPv6 可能被禁用或未配置)_")
    lines.append("")

    # --- config-source analysis (SLAAC / DHCPv6 / static) ---
    config_rows = _analyze_addr_config(addr_rows)
    if config_rows:
        lines.append("### 地址配置来源分析")
        lines.append("")
        lines.append("| 网卡 | 地址 | 内核标志 | 配置来源推断 |")
        lines.append("|------|------|----------|--------------|")
        for row in config_rows:
            flags = " ".join(row["flags"]) or "-"
            lines.append(f"| {row['iface']} | `{row['raw']}` | {flags} | {row['verdict']} |")
        lines.append("")

    # --- default gateway ---
    default_v6 = ""
    if r_route.success:
        for line in r_route.stdout.splitlines():
            if line.startswith("default"):
                default_v6 = line.strip()
                break
    if default_v6:
        lines.append(f"**IPv6 默认路由:** `{default_v6}`")
    elif counts["global"] > 0:
        lines.append("⚠️ **有公网地址但无 IPv6 默认路由** — 出网 IPv6 不通（检查 RA / 手动路由）")
    elif counts["global"] == 0 and counts["ULA"] > 0:
        lines.append("ℹ️ 仅有 ULA 内网地址（fc00::/7），无公网 IPv6")
    lines.append("")

    # --- sysctl ---
    if r_sys.success:
        kv = dict(
            (l.split(" = ", 1)[0], l.split(" = ", 1)[1].strip())
            for l in r_sys.stdout.splitlines()
            if " = " in l
        )
        disabled = kv.get("net.ipv6.conf.all.disable_ipv6") == "1"
        lines.append("### 内核参数")
        lines.append("")
        lines.append("| 参数 | 值 | 说明 |")
        lines.append("|------|----|------|")
        lines.append(
            f"| disable_ipv6 (all) | `{kv.get('net.ipv6.conf.all.disable_ipv6', '?')}` "
            f"| {'❌ IPv6 已被内核禁用' if disabled else '✅ IPv6 已启用'} |"
        )
        lines.append(
            f"| accept_ra | `{kv.get('net.ipv6.conf.all.accept_ra', '?')}` "
            f"| 1=接收路由器通告(SLAAC 自动配置) |"
        )
        lines.append(
            f"| use_tempaddr | `{kv.get('net.ipv6.conf.all.use_tempaddr', '?')}` "
            f"| 1/2=启用隐私扩展临时地址 |"
        )
        lines.append("")

    # --- raw output ---
    lines.append("### 原始输出")
    lines.append("")
    raw = r_addr.stdout.strip()
    if r_route.stdout.strip():
        raw += "\n\n" + r_route.stdout.strip()
    lines.append("```")
    lines.append(raw[:_MAX_OUTPUT])
    lines.append("```")

    if r_addr.stderr or r_route.stderr:
        lines.append(f"\n**诊断:**\n```\n{(r_addr.stderr or r_route.stderr)[:500]}\n```")

    return "\n".join(lines)


# ===================================================================
# 2. ipv6_ping
# ===================================================================


async def ipv6_ping(params: Ipv6PingInput) -> str:
    """ICMPv6 ping 测试 IPv6 连通性与延迟。

    两种用法：
    - 指定 target：`ping -6` 测试给定 IPv6 地址
    - 不指定 target：自动 ping 三家公共 IPv6 DNS（Google 2001:4860:4860::8888 /
      阿里 2400:3200::1 / 腾讯 2402:4e00::），快速判断本机 IPv6 公网是否真正可用

    与 ping_host 的区别：本工具强制走 ICMPv6（ping -6），专门诊断 IPv6 链路。

    Requires: iputils-ping（Kali 预装）
    """
    executor = get_executor(timeout=60)

    if params.target:
        cmd = [
            "ping", "-6",
            "-c", str(params.count),
            "-W", str(params.timeout),  # iputils -W 单位是秒（毫秒会超上限报 bad linger time）
            params.target,
        ]
        result = await executor.run(cmd)
        return _fmt("IPv6 Ping (ICMPv6)", params.target, " ".join(cmd), result)

    # --- automatic multi-target check ---
    lines = ["## IPv6 连通性自检（公共 DNS）", ""]
    lines.append("| 服务 | 地址 | 可达 | 丢包率 | 平均延迟 | 原因 |")
    lines.append("|------|------|------|--------|----------|------|")
    reachable = 0
    raw_parts: list[str] = []
    for name, addr in PUBLIC_IPV6_DNS:
        cmd = [
            "ping", "-6",
            "-c", str(params.count),
            "-W", str(params.timeout),
            addr,
        ]
        r = await executor.run(cmd, timeout=params.count * params.timeout + 10)
        ok = r.success and " 0% packet loss" in r.stdout
        loss_m = _PING_LOSS_RE.search(r.stdout)
        loss = loss_m.group(1) + "%" if loss_m else "-"
        avg_m = _PING_AVG_RE.search(r.stdout)
        avg = avg_m.group(1) + " ms" if avg_m else "-"
        # 无路由时 ping 不输出汇总行，从输出/错误中提取原因
        combined = (r.stdout or "") + (r.stderr or "")
        if ok:
            reason = ""
            reachable += 1
        elif "network unreachable" in combined.lower() or "网络不可达" in combined:
            reason = "无 IPv6 路由（本机没有公网 IPv6）"
        elif "no route to host" in combined.lower() or "没有到主机的路由" in combined:
            reason = "No route to host"
        elif "connection refused" in combined.lower() or "连接被拒" in combined:
            reason = "Connection refused"
        elif loss_m:
            reason = "超时丢包"
        else:
            reason = "未知（见原始输出）"
        lines.append(f"| {name} | `{addr}` | {'✅' if ok else '❌'} | {loss} | {avg} | {reason} |")
        raw_parts.append(
            f"### {name} ({addr})\n```\n"
            f"{(r.stdout or r.stderr or '(无输出)').strip()}\n```"
        )

    lines.append("")
    if reachable == len(PUBLIC_IPV6_DNS):
        lines.append("🎉 **结论：三家全部可达，本机 IPv6 公网完全正常。**")
    elif reachable > 0:
        lines.append(f"⚠️ **结论：{reachable}/{len(PUBLIC_IPV6_DNS)} 可达 — IPv6 部分可用，可能存在运营商链路质量问题。**")
    else:
        lines.append("❌ **结论：全部不可达 — 本机很可能没有公网 IPv6 地址（或出口封禁 ICMPv6）。先跑 `ipv6_status` 看本机地址。**")
    lines.append("")
    lines.append("### 原始输出")
    lines.append("")
    lines.extend(raw_parts)
    return "\n".join(lines)


# ===================================================================
# 3. ipv6_traceroute
# ===================================================================


async def ipv6_traceroute(params: Ipv6TracerouteInput) -> str:
    """traceroute6 追踪到目标的路由路径（IPv6 版 traceroute）。

    逐跳显示路径，定位 IPv6 路由问题出在哪一跳。
    注意：首跳通常显示为链路本地地址（fe80::/10），这是 IPv6 的正常现象。

    与 traceroute_host 的区别：本工具强制走 IPv6（traceroute6）。

    Requires: traceroute（Kali 预装，提供 traceroute6）
    """
    # traceroute6 本身即 IPv6 专用，不接受 -6 选项（传入会报 "无效的选项 -- 6"）
    cmd = [
        "traceroute6",
        "-m", str(params.max_hops),
        "-w", str(params.timeout),
        params.target,
    ]

    executor = get_executor(timeout=params.max_hops * params.timeout + 15)
    result = await executor.run(cmd)
    return _fmt("IPv6 Traceroute", params.target, " ".join(cmd), result)


# ===================================================================
# 4. ipv6_dig
# ===================================================================


async def ipv6_dig(params: Ipv6DigInput) -> str:
    """查询域名 AAAA 记录，对照 A 记录判断是否部署了 IPv6。

    同时查 AAAA（IPv6）和 A（IPv4）记录并给出结论：
    - 有 AAAA 记录 → 该服务支持 IPv6 访问
    - 只有 A 记录 → 服务未部署 IPv6

    可选指定 DNS 服务器（支持 IPv6 地址，如 2400:3200::1）。

    与 dig_query 的区别：本工具专门做 AAAA 对照分析，输出直接给结论。

    Requires: dnsutils/dig（Kali 预装）
    """
    # 注意：dns_server 为空时不能传空字符串参数，否则 dig 会查询空域名
    srv = [f"@{params.dns_server}"] if params.dns_server else []
    executor = get_executor(timeout=20)

    cmd6 = ["dig"] + srv + [params.domain, "AAAA"]
    r6 = await executor.run(cmd6)
    cmd4 = ["dig"] + srv + [params.domain, "A"]
    r4 = await executor.run(cmd4)

    aaaa = _parse_dig_answers(r6.stdout) if r6.success else []
    a_rec = _parse_dig_answers(r4.stdout) if r4.success else []

    lines = ["## DNS IPv6 (AAAA) 查询", "", f"**域名:** `{params.domain}`"]
    if params.dns_server:
        lines.append(f"**DNS 服务器:** `{params.dns_server}`")
    lines.append("")

    lines.append("| 记录类型 | 结果 |")
    lines.append("|----------|------|")
    lines.append("| AAAA (IPv6) | " + ("、".join(f"`{r}`" for r in aaaa) if aaaa else "无记录") + " |")
    lines.append("| A (IPv4) | " + ("、".join(f"`{r}`" for r in a_rec) if a_rec else "无记录") + " |")
    lines.append("")

    if aaaa and a_rec:
        lines.append("✅ **结论：该域名同时支持 IPv4 和 IPv6（双栈）。**")
    elif aaaa:
        lines.append("✅ **结论：该域名只支持 IPv6（纯 v6 服务）。**")
    elif a_rec:
        lines.append("ℹ️ **结论：该域名未部署 IPv6，只有 IPv4 地址。**")
    else:
        lines.append("⚠️ **结论：AAAA 和 A 记录都没有 — 域名不存在或 DNS 解析失败。**")

    lines.append("")
    lines.append("### 原始输出")
    lines.append("")
    lines.append(f"#### AAAA (`{' '.join(cmd6)}`)")
    lines.append("```")
    lines.append(r6.stdout.strip()[:_MAX_OUTPUT])
    lines.append("```")
    lines.append("")
    lines.append(f"#### A (`{' '.join(cmd4)}`)")
    lines.append("```")
    lines.append(r4.stdout.strip()[:_MAX_OUTPUT])
    lines.append("```")

    if r6.stderr or r4.stderr:
        lines.append(f"\n**诊断:**\n```\n{(r6.stderr or r4.stderr)[:500]}\n```")

    return "\n".join(lines)


# ===================================================================
# 5. ipv6_neigh
# ===================================================================


async def ipv6_neigh() -> str:
    """查看 IPv6 邻居表（NDP，IPv6 版 ARP，只读）。

    列出本机已学到的 IPv6 邻居：地址、所在网卡、MAC（lladdr）、状态
    （REACHABLE=可达 / STALE=老化 / FAILED=不可达 等）。

    用途：
    - 排查 IPv6 二层邻居问题（对应 IPv4 的 arp_scan）
    - 查看网关/同网段设备的 IPv6 地址与 MAC

    注意：邻居表是被动缓存，只有通信过的设备才会出现；表为空属正常。

    Requires: iproute2（Kali 预装）
    """
    executor = get_executor(timeout=10)
    result = await executor.run(["ip", "-6", "neigh", "show"])

    lines = ["## IPv6 邻居表 (NDP)", ""]
    rows: list[tuple[str, str, str, str]] = []
    if result.success:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            addr = parts[0]
            ifname = parts[2] if parts[1] == "dev" else "-"
            mac = "-"
            for i, p in enumerate(parts):
                if p == "lladdr":
                    mac = parts[i + 1]
            state = parts[-1]
            rows.append((addr, ifname, mac, state))

    if rows:
        lines.append("| 地址 | 网卡 | MAC | 状态 |")
        lines.append("|------|------|-----|------|")
        for addr, ifn, mac, state in rows:
            lines.append(f"| `{addr}` | {ifn} | {mac} | {state} |")
        lines.append("")
        state_counts: dict[str, int] = {}
        for _, _, _, state in rows:
            state_counts[state] = state_counts.get(state, 0) + 1
        summary = " | ".join(f"{k}: {v}" for k, v in sorted(state_counts.items()))
        lines.append(f"**统计:** {len(rows)} 条邻居 | {summary}")
    else:
        lines.append("_(邻居表为空 — 尚未与任何 IPv6 设备通信，属正常现象)_")

    lines.append("")
    lines.append("### 原始输出")
    lines.append("```")
    lines.append(result.stdout.strip()[:_MAX_OUTPUT])
    lines.append("```")

    if result.stderr:
        lines.append(f"\n**诊断:**\n```\n{result.stderr[:500]}\n```")

    return "\n".join(lines)


# ===================================================================
# 6. ipv6_firewall
# ===================================================================


async def ipv6_firewall() -> str:
    """审计 IPv6 防火墙规则（ip6tables + nftables v6 族，只读）。

    典型问题：管理员只配了 IPv4 防火墙，IPv6 方向完全裸奔 —— 本工具专门
    检查 IPv6 的入站/出站规则，帮助发现未受控的 IPv6 暴露面。

    检查内容：
    - ip6tables filter / nat 表规则
    - nftables 的 ip6 族和 inet 族（双栈表）规则
    - 默认策略（accept/drop）
    - 零规则告警

    与 firewall_rules 的区别：firewall_rules 面向 IPv4/nft 全量，本工具
    聚焦 IPv6 方向并给出暴露面结论。

    Requires: ip6tables / nftables（Kali 预装）
    """
    executor = get_executor(timeout=15)
    sections: list[tuple[str, str, int]] = []  # (title, raw, rule count)

    # --- ip6tables (legacy / compat layer) ---
    for table in ("filter", "nat"):
        r = await executor.run(["ip6tables", "-t", table, "-S"])
        if r.success and r.stdout.strip():
            count = sum(1 for line in r.stdout.splitlines() if line.startswith("-A"))
            sections.append((f"ip6tables -t {table}", r.stdout, count))

    # --- nftables ip6 / inet families ---
    r_nft = await executor.run(["nft", "list", "ruleset"])
    v6_text = ""
    if r_nft.success and r_nft.stdout.strip():
        v6_text = _extract_v6_tables(r_nft.stdout)
        if v6_text:
            sections.append(
                ("nftables（ip6 / inet 族）", v6_text, _count_nft_rules(v6_text))
            )

    lines = ["## IPv6 防火墙审计", ""]

    if not sections:
        lines.append(
            "_无 IPv6 防火墙输出 — ip6tables/nftables 缺失或无 CAP_NET_ADMIN 权限。"
        )
        return "\n".join(lines)

    total = sum(c for _, _, c in sections)
    summary = " | ".join(f"{t.split('（')[0]}: {c} 条" for t, _, c in sections)
    lines.append(f"**汇总:** {summary}（共 {total} 条）")
    lines.append("")

    # default policy detection
    policy_lines = [
        l.strip()
        for l in (v6_text or "").splitlines()
        if re.search(r"\bpolicy\s+(accept|drop)\b", l)
    ]
    drop_policies = [l for l in policy_lines if "policy drop" in l]
    accept_policies = [l for l in policy_lines if "policy accept" in l]
    ipt_policies = [
        l.strip()
        for _, raw, _ in sections
        for l in raw.splitlines()
        if l.startswith("-P")
    ]

    if total == 0:
        lines.append(
            "🚨 **告警：IPv6 方向零规则。** 若默认策略为 accept，则所有 IPv6 "
            "入站流量不受限制（经典'只配 IPv4 防火墙'裸奔场景）。"
        )
        lines.append("")
    elif drop_policies:
        lines.append("✅ **默认策略为 drop（拒绝），且存在自定义规则 — IPv6 处于受控状态。**")
        lines.append("")
    elif accept_policies or any("ACCEPT" in l for l in ipt_policies):
        lines.append(
            "⚠️ **存在规则但默认策略为 accept** — 未匹配规则的 IPv6 流量仍会被放行，"
            "建议核对是否遗漏了拒绝规则。"
        )
        lines.append("")

    if policy_lines:
        lines.append("**链默认策略:**")
        lines.append("")
        for l in policy_lines:
            lines.append(f"- `{l}`")
        lines.append("")
    if ipt_policies:
        lines.append("**ip6tables 默认策略:**")
        lines.append("")
        for l in ipt_policies:
            lines.append(f"- `{l}`")
        lines.append("")

    for title, raw, count in sections:
        lines.append(f"### {title}")
        lines.append("")
        if count == 0:
            lines.append("_无规则（仅默认策略）。_")
            lines.append("")
        lines.append("```")
        lines.append(raw.strip()[:_MAX_OUTPUT])
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


# ===================================================================
# 7. ipv6_scan — LAN IPv6 device discovery
# ===================================================================


async def ipv6_scan(params: Ipv6ScanInput) -> str:
    """IPv6 设备发现：NDP 邻居表 + 有界主动扫描，与 IPv4 ARP 对照。

    /64 有 2^64 个地址无法全扫（与 IPv4 /24 的本质区别），本工具三层策略：
    1. **被动**：NDP 邻居表（ip -6 neigh）— 所有与本机通信过的 IPv6 设备
    2. **主动**（可选）：nmap -sn -6 扫指定小前缀（/80 或更小），或自动模式
       下扫本机每个 /64 前缀的前 16384 个地址（auto_sweep）
    3. **对照**：与 IPv4 arp-scan 结果按 MAC 对照 — 只出现在 v6 的设备
       标为 🔮 "仅 IPv6 可见"（IPv4 ARP 永远扫不到它们）

    Requires: nmap, iproute2, arp-scan（Kali 预装）
    """
    executor = get_executor(timeout=params.timeout + 30)
    lines = ["## IPv6 设备发现", ""]

    # --- layer 1: NDP neighbour table (passive) ---
    ndp = await ndp_devices(executor)

    # --- layer 2: active sweep ---
    sweep_hosts: list[dict] = []
    sweep_note = ""
    v4_by_mac: dict[str, str] = {}
    raw_parts: list[str] = []

    if params.subnet:
        raw_sub = params.subnet
        zone = ""
        bare = raw_sub
        if "%" in raw_sub:
            bare, zone = raw_sub.split("%", 1)
        iface = zone or params.interface or await detect_default_iface(executor)
        net = (
            ipaddress.IPv6Network(bare, strict=False)
            if "/" in bare
            else ipaddress.IPv6Network(bare + "/128", strict=False)
        )
        if net.is_link_local and not zone:
            zone = iface
        nmap_target = bare + (f"%{zone}" if zone else "")
        cmd = ["nmap", "-sn", "-6", "-T4", "--max-retries", "1", nmap_target]
        r = await executor.run(cmd, timeout=params.timeout)
        sweep_hosts = _parse_nmap6_hosts(r.stdout)
        sweep_note = f"主动扫描 `{nmap_target}` → {len(sweep_hosts)} 台在线"
        raw_parts.append(f"#### `{' '.join(cmd)}`\n```\n{r.stdout.strip()[:_MAX_OUTPUT]}\n```")
    else:
        # auto mode: v4 ARP cross-reference
        subnet4 = await detect_subnet(executor)
        if subnet4:
            _, v4_devices = await arp_scan_devices(executor, subnet4)
        else:
            v4_devices = []
            raw_parts.append("（无法自动探测本机 IPv4 网段，跳过 v4 ARP 对照）")
        v4_by_mac = {d["mac"]: d["ip"] for d in v4_devices}
        if params.auto_sweep:
            prefixes = await _own_v6_sweep_prefixes(executor)
            for p in prefixes:
                cmd = ["nmap", "-sn", "-6", "-T4", "--max-retries", "1", p]
                r = await executor.run(cmd, timeout=params.timeout)
                sweep_hosts.extend(_parse_nmap6_hosts(r.stdout))
                raw_parts.append(f"#### `{' '.join(cmd)}`\n```\n{r.stdout.strip()[:_MAX_OUTPUT]}\n```")
            sweep_note = (
                f"自动模式 + 主动 sweep {len(prefixes)} 个前缀"
                f"（各前 /80，共 {len(sweep_hosts)} 台在线）"
            )
        else:
            sweep_note = "自动模式（仅被动 NDP）。主动发现请用 auto_sweep=true 或指定 subnet"

    # --- merge NDP + sweep, dedupe by address ---
    merged: dict[str, dict] = {}
    for d in ndp:
        merged[d["ip"]] = {
            "ip": d["ip"],
            "mac": d["mac"],
            "cls": _classify_ipv6(d["ip"]),
            "src": "NDP 邻居表",
            "v4": "-",
        }
    for h in sweep_hosts:
        ip = h["ip"]
        if ip in merged:
            if h["mac"]:
                merged[ip]["mac"] = h["mac"]
            if "sweep" not in merged[ip]["src"] and "主动" not in merged[ip]["src"]:
                merged[ip]["src"] += " + 主动扫描"
        else:
            merged[ip] = {
                "ip": ip,
                "mac": h["mac"],
                "cls": _classify_ipv6(ip),
                "src": "主动扫描",
                "v4": "-",
            }

    # --- v4 cross-reference (auto mode) ---
    v6_only: list[dict] = []
    for row in merged.values():
        if not v4_by_mac:
            continue
        if row["mac"] in v4_by_mac:
            row["v4"] = v4_by_mac[row["mac"]]
        elif row["mac"]:
            row["v4"] = "🔮 仅 v6 可见"
            v6_only.append(row)

    # --- output ---
    cls_label = {"global": "🌐 公网", "ULA": "🏠 ULA", "link-local": "🔗 链路本地", "loopback": "🔄 回环"}
    lines.append(f"**策略:** {sweep_note}")
    lines.append("")
    rows = sorted(merged.values(), key=lambda x: (x["cls"], x["ip"]))
    if rows:
        lines.append("| 地址 | 类型 | MAC | IPv4 对照 | 来源 |")
        lines.append("|------|------|-----|-----------|------|")
        for row in rows:
            lines.append(
                f"| `{row['ip']}` | {cls_label.get(row['cls'], row['cls'])} "
                f"| {row['mac'] or '-'} | {row['v4']} | {row['src']} |"
            )
        lines.append("")
        lines.append(
            f"**统计:** 共 {len(rows)} 台 | NDP {len(ndp)} | 主动扫描 {len(sweep_hosts)}"
            + (f" | 🔮 仅 IPv6 可见 {len(v6_only)}" if v6_only else "")
        )
    else:
        lines.append("_(未发现任何 IPv6 设备 — NDP 表为空且无主动扫描结果)_")
    lines.append("")
    lines.append(
        "💡 NDP 是被动缓存（只有通信过的设备会出现）；/64 前缀有 2^64 个地址，"
        "全扫不可行 — 主动发现请指定 /80 或更小的 subnet，或开启 auto_sweep。"
    )
    if raw_parts:
        lines.append("")
        lines.append("### 原始输出")
        lines.append("")
        lines.extend(raw_parts)

    return "\n".join(lines)


# ===================================================================
# 8. ipv6_doctor — end-to-end health check
# ===================================================================

_DOCTOR_SUGGESTIONS = {
    "L1": "路由器/运营商未分配 IPv6 — 检查路由器 IPv6 设置，或用 ipv6_ra_inspect 看是否在通告",
    "L2": "有地址但无默认路由 — 路由器可能未在 RA 中通告默认路由，用 ipv6_ra_inspect 确认",
    "L3": "本机 IPv6 链路正常但 DNS 无 AAAA — 本机 DNS 解析器可能是纯 IPv4",
    "L4": "路由正常但 ping 不通 — 用 ipv6_traceroute 定位断点，或查 ipv6_firewall / 运营商封禁",
    "L5": "ICMP 正常但 v6 HTTP 不通 — 运营商可能限制 IPv6 的 TCP 流量",
}


async def ipv6_doctor(params: Ipv6DoctorInput) -> str:
    """一键 IPv6 全链路体检：地址 → 路由 → DNS → ping → v6 HTTP 出口。

    按依赖顺序跑 5 层检查，逐层给结论，直接指出"断在哪一层"，
    并建议下一步用哪个诊断工具：
    L1 本机地址 → L2 默认路由 → L3 AAAA 解析 → L4 公网 ping → L5 v6 HTTP 出口 IP。

    Requires: iproute2, iputils-ping, dnsutils, curl（Kali 预装）
    """
    executor = get_executor(timeout=params.timeout * 4 + 30)
    layers: list[dict] = []  # {id, name, status, detail, raw}

    # L1 本机地址
    r1 = await executor.run(["ip", "-6", "addr", "show"])
    n_global = n_ula = 0
    if r1.success:
        for line in r1.stdout.splitlines():
            m = re.match(r"\s+inet6\s+(\S+)", line)
            if m:
                cls = _classify_ipv6(m.group(1))
                if cls == "global":
                    n_global += 1
                elif cls == "ULA":
                    n_ula += 1
    if n_global:
        layers.append(
            {"id": "L1", "name": "本机地址", "status": "✅",
             "detail": f"{n_global} 个公网 + {n_ula} 个 ULA", "raw": ""}
        )
    elif n_ula:
        layers.append(
            {"id": "L1", "name": "本机地址", "status": "⚠️",
             "detail": f"只有 {n_ula} 个 ULA 内网地址，无公网 IPv6", "raw": ""}
        )
    else:
        layers.append(
            {"id": "L1", "name": "本机地址", "status": "❌",
             "detail": "没有任何 IPv6 地址（内核禁用或路由器未分配）", "raw": ""}
        )

    # L2 默认路由
    r2 = await executor.run(["ip", "-6", "route", "show", "default"])
    has_route = r2.success and bool(r2.stdout.strip())
    if has_route:
        layers.append(
            {"id": "L2", "name": "默认路由", "status": "✅",
             "detail": r2.stdout.strip().splitlines()[0][:80], "raw": r2.stdout.strip()}
        )
    else:
        layers.append(
            {"id": "L2", "name": "默认路由", "status": "❌",
             "detail": "无 IPv6 默认路由", "raw": (r2.stderr or "").strip()}
        )

    # L3 AAAA 解析（不依赖本机 v6 链路 — 解析器本身走 v4 也能查）
    # dig +short 会混入 CNAME 域名，只保留真实 IPv6 地址
    r3 = await executor.run(["dig", "+short", params.domain, "AAAA"], timeout=20)
    aaaa = [a for a in r3.stdout.split() if a and _is_valid_ipv6(a)]
    if aaaa:
        layers.append(
            {"id": "L3", "name": f"AAAA 解析 ({params.domain})", "status": "✅",
             "detail": "、".join(f"`{a}`" for a in aaaa[:3]), "raw": r3.stdout.strip()}
        )
    else:
        layers.append(
            {"id": "L3", "name": f"AAAA 解析 ({params.domain})", "status": "❌",
             "detail": "无 AAAA 记录", "raw": (r3.stdout or r3.stderr).strip()}
        )

    # L4 公网 ping（无公网地址则跳过）
    if not n_global:
        layers.append(
            {"id": "L4", "name": "公网 ping (2400:3200::1)", "status": "⏭️",
             "detail": "跳过 — 本机无公网地址", "raw": ""}
        )
    else:
        r4 = await executor.run(
            ["ping", "-6", "-c", "2", "-W", str(max(params.timeout, 2)), "2400:3200::1"],
            timeout=params.timeout * 3 + 10,
        )
        ok = r4.success and " 0% packet loss" in r4.stdout
        m_avg = re.search(r"min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", r4.stdout)
        layers.append(
            {"id": "L4", "name": "公网 ping (2400:3200::1)",
             "status": "✅" if ok else "❌",
             "detail": (f"平均延迟 {m_avg.group(1)} ms" if m_avg and ok else "不可达"),
             "raw": (r4.stdout or r4.stderr).strip()}
        )

    # L5 v6 HTTP 出口（L4 不通则跳过）
    l4 = next(l for l in layers if l["id"] == "L4")
    if l4["status"] != "✅":
        layers.append(
            {"id": "L5", "name": "v6 HTTP 出口", "status": "⏭️",
             "detail": "跳过 — 公网 ping 未通过", "raw": ""}
        )
    else:
        r5 = await executor.run(
            ["curl", "-6", "-s", "--max-time", str(params.timeout), "https://api6.ipify.org"],
            timeout=params.timeout + 10,
        )
        egress = r5.stdout.strip()
        ok = r5.success and bool(egress) and _is_valid_ipv6(egress)
        layers.append(
            {"id": "L5", "name": "v6 HTTP 出口", "status": "✅" if ok else "❌",
             "detail": f"出口 IPv6: `{egress}`" if ok else "v6 HTTP 失败",
             "raw": (r5.stdout or r5.stderr).strip()[:300]}
        )

    # --- verdict ---
    first_bad = next((l for l in layers if l["status"] in ("❌", "⚠️")), None)

    lines = ["## IPv6 全链路体检 (doctor)", ""]
    lines.append("| 层 | 检查项 | 结果 | 说明 |")
    lines.append("|----|--------|------|------|")
    for l in layers:
        lines.append(f"| {l['id']} | {l['name']} | {l['status']} | {l['detail']} |")
    lines.append("")

    if first_bad is None:
        egress = next((l["detail"] for l in layers if l["id"] == "L5"), "")
        lines.append("🎉 **结论：IPv6 全链路正常。** " + egress)
    else:
        lines.append(
            f"❌ **结论：断在 {first_bad['id']} — {first_bad['name']}。** {first_bad['detail']}"
        )
        lines.append("")
        lines.append(f"💡 **下一步:** {_DOCTOR_SUGGESTIONS.get(first_bad['id'], '检查网络配置')}")

    evidence = [l for l in layers if l["raw"]]
    if evidence:
        lines.append("")
        lines.append("### 证据（原始输出）")
        lines.append("")
        for l in evidence:
            lines.append(f"#### {l['id']} {l['name']}")
            lines.append("```")
            lines.append(l["raw"][:600])
            lines.append("```")
            lines.append("")

    return "\n".join(lines)


# ===================================================================
# 9. ipv6_ra_inspect — Router Advertisement listener
# ===================================================================


async def ipv6_ra_inspect(params: Ipv6RaInspectInput) -> str:
    """被动监听 Router Advertisement：路由器到底通告了什么？

    抓 ICMPv6 RA 报文并解析：通告的前缀（SLAAC 地址从哪来）、M/O 标志
    （是否用 DHCPv6）、MTU、路由器 lifetime。回答"我的 v6 地址是怎么来的"、
    "为什么设备拿不到 v6 地址"（常见：路由器发了 RA 但没通告前缀）。

    纯被动抓包，不产生任何主动流量。需要 root/CAP_NET_RAW。

    Requires: tcpdump（Kali 预装）
    """
    iface = params.interface or await detect_default_iface(get_executor(timeout=10))
    # `timeout -s INT {duration}` stops the listen at the requested duration:
    # SIGINT makes tcpdump flush + exit cleanly. Without it the executor's
    # backstop kill at duration+10 used to discard every captured RA.
    # `-l` line-buffers output so nothing is lost even if the kill does fire.
    cmd = ["timeout", "-s", "INT", str(params.duration),
           "tcpdump", "-i", iface, "-n", "-l", "-c", str(params.max_packets), "-vv",
           "icmp6[0] == 134"]
    executor = get_executor(timeout=params.duration + 10)
    result = await executor.run(cmd, timeout=params.duration + 10)

    ras = _parse_ra_output(result.stdout)
    lines = [
        "## IPv6 路由器通告 (RA) 监听",
        "",
        f"**接口:** `{iface}` | **监听:** {params.duration}s | **抓到:** {len(ras)} 个 RA",
        "",
    ]

    if not ras:
        lines.append("❌ **未抓到任何 Router Advertisement。**")
        lines.append("")
        lines.append("含义 / 下一步:")
        lines.append(
            f"- RA 发送周期（MaxRtrAdvInterval）通常 **4-18 分钟**，可先延长 `duration`"
            f"（最长 300s）再监听一次"
        )
        lines.append(
            "- 长监听仍为空：**路由器没有在该网段发送 RA** — 这是设备拿不到 IPv6 地址"
            "（SLAAC/DHCPv6 都依赖 RA 触发）的根本原因"
        )
        lines.append(
            "- 建议: 在路由器上启用 IPv6/RA，或先用 `ipv6_status` 确认 "
            "accept_ra 内核参数"
        )
        return "\n".join(lines)

    # group by source router
    by_src: dict[str, list[dict]] = {}
    for ra in ras:
        by_src.setdefault(ra["src"], []).append(ra)

    for src, group in by_src.items():
        # pick the most informative copy (most prefixes, then MTU)
        first = max(group, key=lambda x: (len(x["prefixes"]), x["mtu"] is not None))
        lines.append(f"### 路由器: `{src}`（{len(group)} 个 RA）")
        lines.append("")
        if first["lla"]:
            lines.append(f"- **MAC:** {first['lla']}")
        lines.append(f"- **Hop limit:** {first['hop_limit']} | **Router lifetime:** {first['router_lifetime']}s")
        lines.append(f"- **RA 标志:** `{first['flags']}`")
        if first["mtu"]:
            lines.append(f"- **MTU:** {first['mtu']}")
        if first["prefixes"]:
            lines.append("- **通告前缀 (SLAAC):**")
            for p in first["prefixes"]:
                lines.append(
                    f"  - `{p['prefix']}`（有效 {p['valid']}s / 首选 {p['preferred']}s，"
                    f"选项标志: {p['flags']}）"
                )
        else:
            lines.append("- **通告前缀:** 无")
        lines.append("")

    # --- conclusions ---
    all_flags = " ".join(r["flags"] for r in ras)
    has_prefix = any(r["prefixes"] for r in ras)
    lines.append("### 结论")
    lines.append("")
    if "managed" in all_flags:
        lines.append("- 📌 **M=1 (managed)**: 网络使用**有状态 DHCPv6** — 地址由 DHCPv6 分配，而非 SLAAC")
    if "other" in all_flags:
        lines.append("- 📌 **O=1 (other stateful)**: 启用**无状态 DHCPv6** — 地址仍走 SLAAC，但 DNS 等由 DHCPv6 提供")
    if has_prefix:
        prefixes = sorted({p["prefix"] for r in ras for p in r["prefixes"]})
        joined = "、".join(f"`{p}`" for p in prefixes)
        lines.append(f"- 📌 **SLAAC 自动配置**: 路由器通告前缀 {joined} — 设备用这些前缀自动生成全球地址")
    if not has_prefix and "managed" not in all_flags:
        lines.append(
            "- ⚠️ **RA 存在但未通告任何前缀，且无 M 标志** — 设备只能拿到链路本地 (fe80) 地址，"
            "拿不到全球/ULA IPv6。这是家用路由器 'IPv6 半开' 的典型表现："
            "需要在路由器上启用前缀通告 (SLAAC) 或 DHCPv6"
        )

    return "\n".join(lines)


# ===================================================================
# 10. ipv6_route_debug — source address selection
# ===================================================================


async def ipv6_route_debug(params: Ipv6RouteDebugInput) -> str:
    """诊断 IPv6 路由 / 源地址选择（ip -6 route get）。

    回答"到某目标会选哪个源地址、走哪个网卡、下一跳是谁"，
    定位'有公网地址但出不去网'这类问题。域名单先解析 AAAA，
    无 AAAA 记录直接给出结论。

    Requires: iproute2, dnsutils（Kali 预装）
    """
    executor = get_executor(timeout=30)
    target = params.target or "2400:3200::1"
    lines = ["## IPv6 路由 / 源地址诊断", "", f"**目标:** `{target}`", ""]

    if not _is_valid_ipv6(target):
        r = await executor.run(["dig", "+short", target, "AAAA"], timeout=20)
        aaaa = [a for a in r.stdout.split() if a]
        if not aaaa:
            lines.append(
                f"❌ **域名 `{target}` 无 AAAA 记录** — 该服务不支持 IPv6"
                "（用 ipv6_dig 可看 A/AAAA 对照详情）。"
            )
            return "\n".join(lines)
        lines.append(f"AAAA 解析 → `{aaaa[0]}`")
        lines.append("")
        target = aaaa[0]

    r = await executor.run(["ip", "-6", "route", "get", target])
    combined = (r.stdout or "") + (r.stderr or "")
    if not r.success and ("unreachable" in combined.lower() or "RTNETLINK" in combined):
        lines.append(f"❌ **到 `{target}` 无 IPv6 路由**")
        lines.append("")
        lines.append("```")
        lines.append(combined.strip())
        lines.append("```")
        lines.append("")
        lines.append("诊断:")
        lines.append("- 本机没有匹配前缀的 IPv6 地址，或根本没有默认路由 — 先用 `ipv6_status` 看地址和路由")
        lines.append("- 若有地址但无路由：路由器可能未在 RA 中通告默认路由 — 用 `ipv6_ra_inspect` 确认")
        return "\n".join(lines)

    info = _parse_route_get(r.stdout)
    src = info["src"] or info["from"]

    lines.append("| 项目 | 值 |")
    lines.append("|------|------|")
    if src:
        lines.append(f"| 源地址 | `{src}` ({_classify_ipv6(src)}) |")
    if info["via"]:
        lines.append(f"| 下一跳 | `{info['via']}` |")
    if info["dev"]:
        lines.append(f"| 出口网卡 | `{info['dev']}` |")
    if info["metric"] is not None:
        lines.append(f"| metric | {info['metric']} |")
    lines.append("")

    lines.append("### 原始输出")
    lines.append("```")
    lines.append(r.stdout.strip())
    lines.append("```")
    lines.append("")

    if info["dev"]:
        rdev = await executor.run(["ip", "-6", "addr", "show", "dev", info["dev"]])
        addrs = re.findall(r"inet6\s+(\S+)", rdev.stdout)
        if addrs:
            lines.append(
                f"**`{info['dev']}` 上的本机地址:** "
                + "、".join(f"`{a}`" for a in addrs)
            )
            lines.append("")

    if src:
        cls = _classify_ipv6(src)
        if cls == "link-local":
            lines.append(
                "⚠️ **选中的源地址是链路本地 (fe80)** — 只能与本网段通信；"
                "如果目标是网段外的，说明本机缺全球地址（看 ipv6_status）"
            )
        elif cls == "global":
            lines.append("✅ **选中全球地址作为源** — 路由选择正常；仍不通的话继续用 `ipv6_traceroute` 定位")
        elif cls == "ULA":
            lines.append("ℹ️ **选中 ULA 内网地址作为源** — 仅内网段可达")

    return "\n".join(lines)


# ===================================================================
# 11. ipv6_recon — 🟡 active IPv6 penetration recon (PENTEST_ENABLED)
# ===================================================================
#  A /64 holds 2^64 addresses, so "sweep everything" is infeasible;
#  active discovery has to lean on router discovery (rdisc6), passive
#  NDP, MAC→SLAAC EUI-64 guessing, and bounded small-prefix sweeps.


_RDISC_ROUTER_RE = re.compile(r"received from\s+([0-9A-Fa-f:]+)", re.I)


def _rdisc_int(line: str) -> Optional[int]:
    """First integer after the ':' in a rdisc6 label line."""
    m = re.search(r":\s*(\d+)", line)
    return int(m.group(1)) if m else None


def _rdisc_bool(line: str) -> Optional[bool]:
    """Yes/No (real rdisc6 1.0.8) or valid/invalid label value."""
    val = (
        line.split(":", 1)[1].strip().lower() if ":" in line else line.strip().lower()
    )
    if val in ("no", "invalid", "false", "0"):
        return False
    if val in ("yes", "valid", "true", "1"):
        return True
    return None


def _parse_rdisc_output(output: str) -> list[dict]:
    """Parse verbose ``rdisc6`` output → one dict per router advertisement.

    Field labels are taken from rdisc6 1.0.x (ndisc6 package). Each router:
    ``src, hop_limit, stateful_addr, stateful_other, mha, proxy, pref,
    lifetime (int | 'infinite' | None), reachable, retrans, lla, mtu,
    prefixes[{prefix, plen, onlink, autoconf, valid, pref}],
    routes[{prefix, plen, pref, lifetime}], rdns[{server, lifetime}],
    search_lists[{list, lifetime}], nat64[{prefix, plen, lifetime}]``.
    """
    routers: list[dict] = []
    cur: dict | None = None
    cur_prefix: dict | None = None
    cur_route: dict | None = None
    cur_rdns: dict | None = None
    cur_search: dict | None = None
    cur_nat64: dict | None = None

    def _new_router(src: str) -> None:
        nonlocal cur, cur_prefix, cur_route, cur_rdns, cur_search, cur_nat64
        if cur is not None:
            routers.append(cur)
        cur = {
            "src": src,
            "hop_limit": None,
            "stateful_addr": None,
            "stateful_other": None,
            "mha": None,
            "proxy": None,
            "pref": None,
            "lifetime": None,
            "reachable": None,
            "retrans": None,
            "lla": None,
            "mtu": None,
            "prefixes": [],
            "routes": [],
            "rdns": [],
            "search_lists": [],
            "nat64": [],
        }
        cur_prefix = cur_route = cur_rdns = cur_search = cur_nat64 = None

    # Label lines end their label with a letter/dot/hyphen/space before the
    # colon ("Hop limit :", "address:", "conf. :") — never with a digit, so
    # a v6 address's own colons can never be mistaken for a label colon.
    _field_re = re.compile(r"^[A-Za-z][A-Za-z0-9 .\-]*[A-Za-z .\-]\s*:")
    _from_re = re.compile(r"^from\s+([0-9A-Fa-f:]+)$", re.I)

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(
            ("Soliciting", "Timed out", "No response")
        ):
            continue
        m = _RDISC_ROUTER_RE.search(line)
        if m:
            _new_router(m.group(1))
            continue
        # Real rdisc6 1.0.8: the router source appears as an indented
        # " from <addr>" line closing each RA block.
        m_from = _from_re.match(stripped)
        if m_from:
            if cur is None:
                _new_router(m_from.group(1))
            else:
                cur["src"] = m_from.group(1)
                cur["_sealed"] = True
            continue
        # No current router (or the previous block already closed): a field
        # line opens the next RA block; an unindented line ending in an IPv6
        # address is an unrecognised router header.
        if cur is None or cur.get("_sealed"):
            if _field_re.match(stripped):
                _new_router(None)
            elif not line[:1].isspace():
                m2 = re.search(r"([0-9A-Fa-f:]+)$", stripped)
                if m2 and ":" in m2.group(1):
                    _new_router(m2.group(1))
                continue
            else:
                continue

        low = stripped.lower()

        def _cidr() -> Optional[re.Match]:
            return re.search(r"([0-9A-Fa-f:]+)/(\d+)", line)

        def _value() -> str:
            return stripped.split(":", 1)[1].strip() if ":" in stripped else ""

        if re.match(r"^prefix\b", low):
            mc = _cidr()
            if mc:
                cur_prefix = {
                    "prefix": mc.group(1),
                    "plen": int(mc.group(2)),
                    "onlink": None,
                    "autoconf": None,
                    "valid": None,
                    "pref": None,
                }
                cur["prefixes"].append(cur_prefix)
        elif re.match(r"^on-link\b", low) and cur_prefix is not None:
            cur_prefix["onlink"] = _rdisc_bool(line)
        elif re.match(r"^autonomous address conf", low) and cur_prefix is not None:
            cur_prefix["autoconf"] = _rdisc_bool(line)
        elif re.match(r"^valid time\b", low) and cur_prefix is not None:
            cur_prefix["valid"] = _rdisc_int(line)
        elif re.match(r"^pref\.?\s*time\b", low) and cur_prefix is not None:
            cur_prefix["pref"] = _rdisc_int(line)
        elif re.match(r"^route preference\b", low) and cur_route is not None:
            cur_route["pref"] = _value()
        elif re.match(r"^route lifetime\b", low) and cur_route is not None:
            cur_route["lifetime"] = _rdisc_int(line)
        elif re.match(r"^route\b", low):
            mc = _cidr()
            if mc:
                cur_route = {
                    "prefix": mc.group(1),
                    "plen": int(mc.group(2)),
                    "pref": None,
                    "lifetime": None,
                }
                cur["routes"].append(cur_route)
        elif re.match(r"^recursive dns server\b", low):
            cur_rdns = {"server": _value(), "lifetime": None}
            cur["rdns"].append(cur_rdns)
        elif re.match(r"^dns search list lifetime\b", low) and cur_search is not None:
            cur_search["lifetime"] = _rdisc_int(line)
        elif re.match(r"^dns search list\b", low):
            cur_search = {"list": _value(), "lifetime": None}
            cur["search_lists"].append(cur_search)
        elif re.match(r"^dns servers? lifetime\b", low) and cur_rdns is not None:
            cur_rdns["lifetime"] = _rdisc_int(line)
        elif re.match(r"^nat64 prefix lifetime\b", low) and cur_nat64 is not None:
            cur_nat64["lifetime"] = _rdisc_int(line)
        elif re.match(r"^nat64 prefix\b", low):
            mc = _cidr()
            if mc:
                cur_nat64 = {
                    "prefix": mc.group(1),
                    "plen": int(mc.group(2)),
                    "lifetime": None,
                }
                cur["nat64"].append(cur_nat64)
        elif re.match(r"^hop limit\b", low):
            cur["hop_limit"] = _rdisc_int(line)
        elif re.match(r"^stateful address conf", low):
            cur["stateful_addr"] = _rdisc_bool(line)
        elif re.match(r"^stateful other conf", low):
            cur["stateful_other"] = _rdisc_bool(line)
        elif re.match(r"^mobile home agent", low):
            cur["mha"] = _rdisc_bool(line)
        elif re.match(r"^neighbor discovery proxy", low):
            cur["proxy"] = _rdisc_bool(line)
        elif re.match(r"^router preference\b", low):
            cur["pref"] = _value()
        elif re.match(r"^router lifetime\b", low):
            cur["lifetime"] = "infinite" if "infinite" in low else _rdisc_int(line)
        elif re.match(r"^reachable time\b", low):
            cur["reachable"] = _rdisc_int(line)
        elif re.match(r"^retransmit time\b", low):
            cur["retrans"] = _rdisc_int(line)
        elif re.match(r"^source link-layer address\b", low):
            m2 = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
            cur["lla"] = m2.group(1).upper() if m2 else None
        elif re.match(r"^mtu\b", low):
            cur["mtu"] = _rdisc_int(line)
        else:
            # Fallback: an unindented line ending in an IPv6 address is a
            # router header we did not recognise.
            if not line[:1].isspace():
                m2 = re.search(r"([0-9A-Fa-f:]+)$", stripped)
                if m2 and ":" in m2.group(1):
                    _new_router(m2.group(1))
    if cur is not None:
        routers.append(cur)
    for r in routers:
        r.pop("_sealed", None)
    return routers


_NMAP6_HOST_RE = re.compile(r"^Nmap scan report for\s+(.+)$")
_NMAP6_PORT_RE = re.compile(r"^(\S+)\s+(open|filtered)\s+(\S+)\s*(.*)$")


def _parse_nmap6_service(output: str) -> list[dict]:
    """Parse ``nmap -6 -sV -sC`` output → host dicts.

    Each host: ``host, up, not_shown, ports[{port, proto, state, service,
    version, scripts[]}], service_info[], mac``.
    """
    hosts: list[dict] = []
    cur: dict | None = None
    cur_port: dict | None = None
    for line in output.splitlines():
        m = _NMAP6_HOST_RE.match(line)
        if m:
            if cur is not None:
                hosts.append(cur)
            cur = {
                "host": m.group(1).strip(),
                "up": None,
                "not_shown": "",
                "ports": [],
                "service_info": [],
                "mac": "",
            }
            cur_port = None
            continue
        if cur is None:
            continue
        if line.startswith("Host is up"):
            cur["up"] = True
            continue
        if line.startswith("Host does not appear to be up"):
            cur["up"] = False
            continue
        if line.startswith("Not shown:"):
            cur["not_shown"] = line[len("Not shown:"):].strip()
            continue
        if line.startswith("MAC Address:"):
            m2 = re.search(r"([0-9A-Fa-f:]{17})", line)
            if m2:
                cur["mac"] = m2.group(1).upper()
            continue
        if line.startswith("Service Info:"):
            cur["service_info"].append(line[len("Service Info:"):].strip())
            continue
        if line.lstrip().startswith("|"):
            if cur_port is not None:
                entry = line.strip().lstrip("|_").strip()
                cur_port["scripts"].append(entry or line.strip())
            continue
        m = _NMAP6_PORT_RE.match(line.strip())
        if m and "/" in m.group(1):
            port, proto = m.group(1).split("/", 1)
            cur_port = {
                "port": port,
                "proto": proto,
                "state": m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip(),
                "scripts": [],
            }
            cur["ports"].append(cur_port)
    if cur is not None:
        hosts.append(cur)
    return hosts


def _mac_to_eui64_iid(mac: str) -> Optional[str]:
    """MAC AA:BB:CC:DD:EE:FF → EUI-64 interface id (u/l bit flipped).

    ``00:1a:2b:3c:4d:5e`` → ``011a:2bff:fe3c:4d5e``. None if malformed.
    """
    if not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        return None
    b = bytes.fromhex(mac.replace(":", ""))
    b0 = b[0] ^ 0x01
    return f"{b0:02x}{b[1]:02x}:{b[2]:02x}ff:fe{b[3]:02x}:{b[4]:02x}{b[5]:02x}"


def _slaac_candidate(prefix: str, iid: str) -> str:
    """Combine a /64 network with an EUI-64 iid → candidate SLAAC address."""
    net = ipaddress.IPv6Network(prefix, strict=False)
    iid_int = int(iid.replace(":", ""), 16)
    return str(ipaddress.IPv6Address(int(net.network_address) | iid_int))


async def _local_v6_prefixes(executor) -> list[tuple[str, str]]:
    """``(prefix, iface)`` for this host's global/ULA subnets (prefixlen ≤ 64).

    A /64 is the SLAAC unit: interface prefixes smaller than /64 are
    collapsed to the /64 containing their address; link-local / loopback /
    point-to-point (/128) addresses are skipped.
    """
    r = await executor.run(["ip", "-6", "addr", "show"])
    out: list[tuple[str, str]] = []
    if not r.success:
        return out
    seen: set[str] = set()
    iface = ""
    for line in r.stdout.splitlines():
        m_if = re.match(r"^\d+:\s+([^:]+):", line)
        if m_if:
            iface = m_if.group(1)
            continue
        m_addr = re.match(r"\s+inet6\s+(\S+)", line)
        if not m_addr or iface in ("", "lo"):
            continue
        try:
            intf = ipaddress.ip_interface(m_addr.group(1))
        except ValueError:
            continue
        net = intf.network
        if net.prefixlen < 64:
            net = ipaddress.IPv6Network((intf.ip, 64))
        if (
            net.prefixlen > 64
            or net.is_link_local
            or net.is_loopback
        ):
            continue
        key = str(net)
        if key not in seen:
            seen.add(key)
            out.append((key, iface))
    return out


_V4_NEIGH_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9A-Fa-f:]{17})"
)


async def _v4_neigh_macs(executor) -> dict[str, str]:
    """Passive IPv4 neighbour table → {MAC(upper): v4-ip}."""
    r = await executor.run(["ip", "neigh", "show"])
    macs: dict[str, str] = {}
    if not r.success:
        return macs
    for line in r.stdout.splitlines():
        m = _V4_NEIGH_RE.match(line)
        if m:
            macs.setdefault(m.group(2).upper(), m.group(1))
    return macs


# ---------------------------------------------------------------------------
# Pydantic input models (🟡 tier)
# ---------------------------------------------------------------------------


class Ipv6ReconInput(BaseModel):
    """Input for active IPv6 penetration recon."""

    subnet: Optional[str] = Field(
        None,
        description=(
            "可选的额外有界扫描：/80 或更小的 IPv6 CIDR（如 fd00:beef::/80）或单个 "
            "IPv6 地址，对其跑 nmap -6 -sn；留空则跳过"
        ),
        max_length=64,
    )
    interface: Optional[str] = Field(
        None,
        description="rdisc6 路由器发现所用网卡（如 eth0）；留空 = 自动探测默认路由网卡",
        max_length=32,
    )
    slaac_guess: bool = Field(
        True,
        description="MAC→SLAAC 地址猜测：用 IPv4 ARP 表里的 MAC 推导 EUI-64 SLAAC 地址并并发 ping 验证（默认开）",
    )
    slaac_max: int = Field(
        32, ge=1, le=128, description="最多猜测多少个 MAC（默认 32）"
    )
    timeout: int = Field(
        300, ge=30, le=600, description="有界扫描超时（秒，默认 300）"
    )

    @field_validator("subnet")
    @classmethod
    def _v_subnet(cls, v: Optional[str]) -> Optional[str]:
        return _validate_v6_subnet(v)

    @field_validator("interface")
    @classmethod
    def _v_iface(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v)
        if not re.match(r"^[A-Za-z0-9._-]{1,32}$", v):
            raise ValueError("invalid interface name")
        return v


class Ipv6ServiceScanInput(BaseModel):
    """Input for IPv6 service scanning."""

    target: str = Field(
        ...,
        description=(
            "目标 IPv6 地址（如 2408:4000:1::1）或 /80 或更小的 CIDR（如 "
            "2408:4000:1::/90）；先用 ipv6_recon 发现地址"
        ),
        min_length=1,
        max_length=64,
    )
    ports: Optional[str] = Field(
        None,
        description='端口规格："80,443"、"1-1024"、"top-100"；留空 = nmap 默认（top 1000）',
        max_length=256,
    )
    service_version: bool = Field(
        True, description="服务/版本探测（-sV，默认开，较慢）"
    )
    scripts: bool = Field(
        True, description="跑默认 NSE 脚本（-sC，默认开）"
    )
    timing: str = Field("T4", description="Timing 模板 T1-T5（默认 T4）")
    timeout: int = Field(
        300, ge=30, le=900, description="扫描超时（秒，默认 300）"
    )

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: str) -> str:
        v = _no_shell_meta(v)
        bare = v.split("%", 1)[0]
        try:
            if "/" in bare:
                net = ipaddress.IPv6Network(bare, strict=False)
                if net.prefixlen < 80:
                    raise ValueError(
                        f"扫描前缀太大（/{net.prefixlen}）：/64 有 2^64 个地址无法全扫，"
                        "请指定 /80 或更小的前缀或单个地址"
                    )
            else:
                ipaddress.IPv6Address(bare)
        except ValueError as e:
            if "太大" in str(e):
                raise ValueError(str(e))
            raise ValueError(
                "target 必须是有效 IPv6 地址或 /80 或更小的 CIDR"
            ) from None
        return v

    @field_validator("ports")
    @classmethod
    def _v_ports(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = _no_shell_meta(v).strip()
        if not re.fullmatch(r"top-\d+|\d[\d,\-]*", v):
            raise ValueError('ports 形如 "80,443"、"1-1024" 或 "top-100"')
        return v

    @field_validator("timing")
    @classmethod
    def _v_timing(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in ("T1", "T2", "T3", "T4", "T5"):
            raise ValueError("timing 必须是 T1-T5")
        return v


# ---------------------------------------------------------------------------
# Tool implementations (🟡 tier)
# ---------------------------------------------------------------------------


async def ipv6_recon(params: Ipv6ReconInput) -> str:
    """IPv6 渗透侦察：路由发现 + NDP + MAC→SLAAC 地址猜测，一次摸清 v6 局域网。

    /64 有 2^64 个地址无法全扫，主动发现靠四路技巧：
    1. **rdisc6** — 主动 Router Solicitation，列出本网段所有 IPv6 路由器
       及其通告的前缀 / RDNSS（DNS 服务器）/ NAT64 前缀 — RDNSS 是 v6
       DNS 劫持攻击的核心目标
    2. **NDP 邻居表** — 被动收集所有与本机通信过的 v6 设备
    3. **SLAAC 猜测** — 取 IPv4 邻居表的 MAC → 推导 EUI-64 SLAAC 地址 →
       并发 ping 验证。这是找到"v4 设备的 v6 地址"的关键（EUI-64 地址在
       2^64 空间里按 MAC 分布，任何地址段扫描都扫不到；隐私扩展随机
       地址无法命中）
    4. **可选有界扫描** — 指定 /80 或更小前缀时额外跑 nmap -6 -sn

    需要 root。Requires: rdisc6 (ndisc6 包)、nmap、iproute2
    """
    executor = get_executor(timeout=params.timeout + 60)
    lines = ["## IPv6 渗透侦察", ""]

    iface = params.interface or await detect_default_iface(executor)

    # --- L1: rdisc6 active router discovery ---
    r = await executor.run(
        ["rdisc6", "-n", "-r", "2", "-w", "4000", iface], timeout=30
    )
    routers = _parse_rdisc_output(r.stdout)
    lines.append("### 1️⃣ 路由发现（rdisc6）")
    lines.append("")
    if "not found" in r.stderr:
        lines.append(
            "⚠️ rdisc6 未安装 — `sudo apt install ndisc6`（setup.sh 已包含）"
        )
    elif routers:
        for i, rt in enumerate(routers, 1):
            head = f"**路由器 {i}: `{rt['src']}`**"
            if rt["lla"]:
                head += f"（链路层 {rt['lla']}）"
            lines.append(head)
            meta = []
            if rt["lifetime"] is not None:
                meta.append(
                    f"lifetime {rt['lifetime']}s"
                    if isinstance(rt["lifetime"], int)
                    else "lifetime ∞"
                )
            if rt["mtu"]:
                meta.append(f"MTU {rt['mtu']}")
            flags = []
            if rt["stateful_addr"]:
                flags.append("managed（DHCPv6 地址）")
            if rt["stateful_other"]:
                flags.append("other-config（DHCPv6 其他配置）")
            if flags:
                meta.append("、".join(flags))
            if meta:
                lines.append("- " + " | ".join(meta))
            for p in rt["prefixes"]:
                pflags = []
                if p["onlink"]:
                    pflags.append("on-link")
                if p["autoconf"]:
                    pflags.append("自动配置（SLAAC）")
                if not p["onlink"] and not p["autoconf"]:
                    pflags.append("无 on-link/SLAAC（有状态分配）")
                life = (
                    f"valid {p['valid']}s / pref {p['pref']}s"
                    if p["valid"] is not None
                    else ""
                )
                lines.append(
                    f"- 前缀 `{p['prefix']}/{p['plen']}` — {'、'.join(pflags)}"
                    + (f"，{life}" if life else "")
                )
            for d in rt["rdns"]:
                lines.append(
                    f"- ⚠️ RDNSS 通告的 DNS 服务器：`{d['server']}`"
                    "（v6 DNS 劫持攻击的核心目标）"
                )
            for n in rt["nat64"]:
                lines.append(f"- NAT64 前缀：`{n['prefix']}/{n['plen']}`")
    elif r.returncode == 2:
        lines.append(
            "_(未收到任何路由器通告 — 本网段可能没有 IPv6 路由器，或路由器未发 RA；"
            "本机大概率没有 v6 默认路由，攻击类工具在此环境无从测起)_"
        )
    else:
        lines.append(
            f"⚠️ rdisc6 执行失败（exit {r.returncode}）："
            f"{(r.stderr or r.stdout).strip()[:200]}"
        )
    lines.append("")

    # --- passive data reused by both cross-reference and SLAAC guessing ---
    v4_by_mac = await _v4_neigh_macs(executor)

    # --- L2: NDP neighbour table (passive) ---
    ndp = await ndp_devices(executor)
    lines.append("### 2️⃣ NDP 邻居表（被动）")
    lines.append("")
    lines.append(f"共 {len(ndp)} 台与本机通信过的 v6 设备。")
    lines.append("")

    # --- L3: MAC → SLAAC EUI-64 guessing ---
    slaac_hits: list[dict] = []
    slaac_note = ""
    lines.append("### 3️⃣ SLAAC 地址猜测（MAC → EUI-64）")
    lines.append("")
    if not params.slaac_guess:
        slaac_note = "已关闭（slaac_guess=false）"
    else:
        prefixes = await _local_v6_prefixes(executor)
        if not prefixes:
            slaac_note = "跳过 — 本机没有 global/ULA /64 前缀（没有可推导的 SLAAC 网段）"
        elif not v4_by_mac:
            slaac_note = (
                "跳过 — IPv4 邻居表为空（先 ping 一下网段，或跑 ipv6_scan 做主动 arp-scan）"
            )
        else:
            cands: list[tuple[str, str, str]] = []  # (addr, mac, v4)
            for mac, v4 in list(v4_by_mac.items())[: params.slaac_max]:
                iid = _mac_to_eui64_iid(mac)
                if not iid:
                    continue
                for pref, _if in prefixes:
                    cands.append((_slaac_candidate(pref, iid), mac, v4))
            if cands:
                async def _ping_one(addr: str) -> tuple[str, bool]:
                    pr = await executor.run(
                        ["ping", "-6", "-c", "1", "-W", "2", addr], timeout=10
                    )
                    return addr, pr.success

                results = await asyncio.gather(
                    *[_ping_one(a) for a, _, _ in cands]
                )
                alive = {a for a, ok in results if ok}
                for addr, mac, v4 in cands:
                    if addr in alive:
                        slaac_hits.append({"ip": addr, "mac": mac, "v4": v4})
                slaac_note = (
                    f"用 {min(len(v4_by_mac), params.slaac_max)} 个 MAC × "
                    f"{len(prefixes)} 个前缀推导 {len(cands)} 个候选地址，"
                    f"并发 ping 验证 → **{len(alive)} 台命中**"
                )
    lines.append(slaac_note or "未执行。")
    lines.append("")

    # --- L4: optional bounded nmap sweep ---
    sweep_hosts: list[dict] = []
    raw_parts: list[str] = []
    if params.subnet:
        raw_sub = params.subnet
        zone = ""
        bare = raw_sub
        if "%" in raw_sub:
            bare, zone = raw_sub.split("%", 1)
        iface_s = zone or params.interface or await detect_default_iface(executor)
        net = (
            ipaddress.IPv6Network(bare, strict=False)
            if "/" in bare
            else ipaddress.IPv6Network(bare + "/128", strict=False)
        )
        if net.is_link_local and not zone:
            zone = iface_s
        nmap_target = bare + (f"%{zone}" if zone else "")
        cmd = ["nmap", "-sn", "-6", "-T4", "--max-retries", "1", nmap_target]
        lines.append("### 4️⃣ 有界扫描（nmap -6 -sn）")
        lines.append("")
        r2 = await executor.run(cmd, timeout=params.timeout)
        sweep_hosts = _parse_nmap6_hosts(r2.stdout)
        lines.append(
            f"主动扫描 `{nmap_target}` → {len(sweep_hosts)} 台在线"
        )
        raw_parts.append(
            f"#### `{' '.join(cmd)}`\n```\n{r2.stdout.strip()[:_MAX_OUTPUT]}\n```"
        )
        lines.append("")

    # --- merge NDP + SLAAC + sweep, dedupe by address ---
    merged: dict[str, dict] = {}
    for d in ndp:
        merged[d["ip"]] = {
            "ip": d["ip"],
            "mac": d["mac"],
            "cls": _classify_ipv6(d["ip"]),
            "src": "NDP 邻居表",
            "v4": "-",
        }
    for h in slaac_hits:
        if h["ip"] in merged:
            merged[h["ip"]]["src"] += " + SLAAC 猜测"
            if not merged[h["ip"]]["mac"]:
                merged[h["ip"]]["mac"] = h["mac"]
            if merged[h["ip"]]["v4"] == "-":
                merged[h["ip"]]["v4"] = h["v4"]
        else:
            merged[h["ip"]] = {
                "ip": h["ip"],
                "mac": h["mac"],
                "cls": _classify_ipv6(h["ip"]),
                "src": "SLAAC 猜测",
                "v4": h["v4"],
            }
    for h in sweep_hosts:
        ip = h["ip"]
        if ip in merged:
            if h["mac"]:
                merged[ip]["mac"] = h["mac"]
            if "扫描" not in merged[ip]["src"]:
                merged[ip]["src"] += " + 有界扫描"
        else:
            merged[ip] = {
                "ip": ip,
                "mac": h["mac"],
                "cls": _classify_ipv6(ip),
                "src": "有界扫描",
                "v4": "-",
            }

    # --- v4 cross-reference ---
    v6_only: list[dict] = []
    for row in merged.values():
        if not v4_by_mac or row["v4"] != "-":
            continue
        if row["mac"] in v4_by_mac:
            row["v4"] = v4_by_mac[row["mac"]]
        elif row["mac"]:
            row["v4"] = "🔮 仅 v6 可见"
            v6_only.append(row)

    # --- output ---
    cls_label = {
        "global": "🌐 公网",
        "ULA": "🏠 ULA",
        "link-local": "🔗 链路本地",
        "loopback": "🔄 回环",
    }
    lines.append("### 📋 发现汇总")
    lines.append("")
    rows = sorted(merged.values(), key=lambda x: (x["cls"], x["ip"]))
    if rows:
        lines.append("| 地址 | 类型 | MAC | IPv4 对照 | 来源 |")
        lines.append("|------|------|-----|-----------|------|")
        for row in rows:
            lines.append(
                f"| `{row['ip']}` | {cls_label.get(row['cls'], row['cls'])} "
                f"| {row['mac'] or '-'} | {row['v4']} | {row['src']} |"
            )
        lines.append("")
        lines.append(
            f"**统计:** 共 {len(rows)} 台 | NDP {len(ndp)} | "
            f"SLAAC 命中 {len(slaac_hits)} | 有界扫描 {len(sweep_hosts)}"
            + (f" | 🔮 仅 IPv6 可见 {len(v6_only)}" if v6_only else "")
        )
    else:
        lines.append("_(未发现任何 IPv6 设备)_")
    lines.append("")
    lines.append(
        "💡 SLAAC 猜测只命中 EUI-64 永久地址；设备若用隐私扩展随机地址则无法命中。"
        "/64 有 2^64 个地址，全扫不可行 — 确认地址后用 `ipv6_service_scan` "
        "做端口/服务扫描。"
    )
    if raw_parts:
        lines.append("")
        lines.append("### 原始输出")
        lines.append("")
        lines.extend(raw_parts)

    return "\n".join(lines)


# ===================================================================
# 12. ipv6_service_scan — 🟡 nmap -6 service scan (PENTEST_ENABLED)
# ===================================================================


async def ipv6_service_scan(params: Ipv6ServiceScanInput) -> str:
    """IPv6 服务扫描：nmap -6 -sV -sC 探测 v6 目标的开放端口/服务版本/NSE 脚本。

    target 可以是单个 IPv6 地址，或 /80 或更小的前缀（/64 有 2^64 个地址，
    全扫不可行；大前缀 -sV 会很慢，建议 /116 或更小）。先用 ipv6_recon
    发现目标地址。

    Requires: nmap（Kali 预装）
    """
    executor = get_executor(timeout=params.timeout + 60)
    raw = params.target
    zone = ""
    bare = raw
    if "%" in raw:
        bare, zone = raw.split("%", 1)
    has_cidr = "/" in bare
    try:
        net = (
            ipaddress.IPv6Network(bare, strict=False) if has_cidr else None
        )
    except ValueError:
        net = None
    if has_cidr:
        is_ll = net.is_link_local if net is not None else False
    else:
        is_ll = ipaddress.IPv6Address(bare).is_link_local
    if is_ll and not zone:
        zone = await detect_default_iface(executor)
    target = bare + (f"%{zone}" if zone else "")

    cmd = ["nmap", "-6"]
    if params.service_version:
        cmd.append("-sV")
    if params.scripts:
        cmd.append("-sC")
    cmd += ["-" + params.timing, "--max-retries", "1"]
    if params.ports:
        cmd += ["-p", params.ports]
    cmd.append(target)

    lines = [
        "## IPv6 服务扫描",
        "",
        f"目标: `{target}`  |  命令: `{' '.join(cmd)}`",
        "",
    ]
    if has_cidr and net is not None and net.prefixlen < 116:
        lines.append(
            f"⚠️ /{net.prefixlen} 前缀较大 — -sV 扫描很慢，可能被超时截断；"
            "建议 /116 或更小，或先缩小到单个地址"
        )
        lines.append("")

    r = await executor.run(cmd, timeout=params.timeout)
    hosts = _parse_nmap6_service(r.stdout)

    for h in hosts:
        head = f"### `{h['host']}`"
        if h["up"] is False:
            head += "（似乎离线）"
        lines.append(head)
        if h["not_shown"]:
            lines.append(f"_{h['not_shown']}_")
        open_ports = [p for p in h["ports"] if p["state"] == "open"]
        if h["ports"]:
            lines.append("")
            lines.append("| 端口 | 状态 | 服务 | 版本/信息 |")
            lines.append("|------|------|------|-----------|")
            for p in h["ports"]:
                lines.append(
                    f"| {p['port']}/{p['proto']} | {p['state']} "
                    f"| {p['service']} | {p['version'] or '-'} |"
                )
            for p in h["ports"]:
                if p["scripts"]:
                    lines.append("")
                    lines.append(
                        f"**端口 {p['port']}/{p['proto']} 脚本输出:**"
                    )
                    lines.append("")
                    for s in p["scripts"]:
                        lines.append(f"- {s}")
        else:
            lines.append("")
            lines.append("_(未发现开放端口)_")
        if h["mac"]:
            lines.append(f"\nMAC: {h['mac']}")
        for si in h["service_info"]:
            lines.append(f"Service Info: {si}")
        lines.append("")

    if not hosts:
        lines.append("_(无扫描结果 — 检查目标地址是否正确、是否在线)_")
        if r.stderr:
            lines.append("")
            lines.append(f"⚠️ nmap 输出: {r.stderr.strip()[:500]}")
        lines.append("")
    else:
        stats = ", ".join(
            f"{h['host']}: {sum(1 for p in h['ports'] if p['state'] == 'open')} 个开放端口"
            for h in hosts
        )
        lines.append(f"**统计:** {len(hosts)} 台主机 — {stats}")
        lines.append("")
        lines.append(
            "💡 快速查端口可关 -sV/-sC（service_version=false, scripts=false）"
        )
        lines.append("")
        lines.append("### 原始输出")
        lines.append("")
        lines.append(f"```\n{r.stdout.strip()[:_MAX_OUTPUT]}\n```")

    return "\n".join(lines)


# ===================================================================
# Registry
# ===================================================================

IPV6_TOOLS: dict[str, tuple[callable, type[BaseModel] | None]] = {
    "ipv6_status": (ipv6_status, None),
    "ipv6_ping": (ipv6_ping, Ipv6PingInput),
    "ipv6_traceroute": (ipv6_traceroute, Ipv6TracerouteInput),
    "ipv6_dig": (ipv6_dig, Ipv6DigInput),
    "ipv6_neigh": (ipv6_neigh, None),
    "ipv6_firewall": (ipv6_firewall, None),
    "ipv6_scan": (ipv6_scan, Ipv6ScanInput),
    "ipv6_doctor": (ipv6_doctor, Ipv6DoctorInput),
    "ipv6_ra_inspect": (ipv6_ra_inspect, Ipv6RaInspectInput),
    "ipv6_route_debug": (ipv6_route_debug, Ipv6RouteDebugInput),
}

# 🟡 Active IPv6 recon — gated by PENTEST_ENABLED (registered in server.py).
IPV6_PENTEST_TOOLS: dict[str, tuple[callable, type[BaseModel] | None]] = {
    "ipv6_recon": (ipv6_recon, Ipv6ReconInput),
    "ipv6_service_scan": (ipv6_service_scan, Ipv6ServiceScanInput),
}
