"""
Kali Linux IPv6 network maintenance tools.

Six read-only IPv6 diagnostics (all 🟢 network-maintenance level, always
enabled, no active traffic generation beyond the requested pings/traces):

  1. ipv6_status     — IPv6 overview: per-interface addresses, default
                       gateway, sysctl kernel parameters
  2. ipv6_ping       — ICMPv6 reachability (custom target, or automatic
                       test against public IPv6 DNS servers)
  3. ipv6_traceroute — IPv6 path tracing with traceroute6
  4. ipv6_dig        — DNS AAAA lookup, compared against the A record
  5. ipv6_neigh      — IPv6 neighbour table (NDP, the IPv6 equivalent of ARP)
  6. ipv6_firewall   — IPv6 firewall audit (ip6tables + nftables v6 families)

Requires: iproute2, iputils-ping, traceroute, dnsutils, ip6tables/nftables —
all pre-installed on a standard Kali install (no setup.sh changes needed).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import CommandResult, get_executor
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


# Public IPv6 DNS used by the automatic reachability check.
PUBLIC_IPV6_DNS: list[tuple[str, str]] = [
    ("Google", "2001:4860:4860::8888"),
    ("阿里", "2400:3200::1"),
    ("腾讯", "2402:4e00::"),
]

_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
_PING_RTT_RE = re.compile(r"time=[\d.]+ ms")
_PING_AVG_RE = re.compile(r"min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms")
_PING_RCVD_RE = re.compile(r"(\d+) packets received")

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

    # --- parse addresses per interface ---
    counts = {"global": 0, "ULA": 0, "link-local": 0}
    iface: str = ""
    addr_rows: list[tuple[str, str, str]] = []
    if r_addr.success:
        for line in r_addr.stdout.splitlines():
            m_if = re.match(r"^\d+:\s+([^:]+):", line)
            if m_if:
                iface = m_if.group(1)
                continue
            m_addr = re.match(r"\s+inet6\s+(\S+)", line)
            if m_addr and iface:
                raw = m_addr.group(1)
                cls = _classify_ipv6(raw)
                counts[cls] = counts.get(cls, 0) + 1
                addr_rows.append((iface, raw, cls))

    lines.append("### 地址清单")
    lines.append("")
    if addr_rows:
        lines.append("| 网卡 | 地址 | 类型 |")
        lines.append("|------|------|------|")
        label = {"global": "🌐 公网", "ULA": "🏠 ULA 内网", "link-local": "🔗 链路本地"}
        for ifn, addr, cls in addr_rows:
            lines.append(f"| {ifn} | `{addr}` | {label.get(cls, cls)} |")
        lines.append("")
        lines.append(
            f"**统计:** 公网 {counts['global']} 个 | ULA 内网 {counts['ULA']} 个 | "
            f"链路本地 {counts['link-local']} 个"
        )
    else:
        lines.append("_(未发现任何 IPv6 地址 — IPv6 可能被禁用或未配置)_")
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
            "-W", str(params.timeout * 1000),  # iputils -W 单位是毫秒
            params.target,
        ]
        result = await executor.run(cmd)
        return _fmt("IPv6 Ping (ICMPv6)", params.target, " ".join(cmd), result)

    # --- automatic multi-target check ---
    lines = ["## IPv6 连通性自检（公共 DNS）", ""]
    lines.append("| 服务 | 地址 | 可达 | 丢包率 | 平均延迟 |")
    lines.append("|------|------|------|--------|----------|")
    reachable = 0
    raw_parts: list[str] = []
    for name, addr in PUBLIC_IPV6_DNS:
        cmd = [
            "ping", "-6",
            "-c", str(params.count),
            "-W", str(params.timeout * 1000),
            addr,
        ]
        r = await executor.run(cmd, timeout=params.count * params.timeout + 10)
        ok = r.success and " 0% packet loss" in r.stdout
        loss_m = _PING_LOSS_RE.search(r.stdout)
        loss = loss_m.group(1) + "%" if loss_m else "-"
        avg_m = _PING_AVG_RE.search(r.stdout)
        avg = avg_m.group(1) + " ms" if avg_m else "-"
        if ok:
            reachable += 1
        lines.append(f"| {name} | `{addr}` | {'✅' if ok else '❌'} | {loss} | {avg} |")
        raw_parts.append(f"### {name} ({addr})\n```\n{r.stdout.strip()}\n```")

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
    cmd = [
        "traceroute6",
        "-6",
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
    at = f"@{params.dns_server}" if params.dns_server else ""
    executor = get_executor(timeout=20)

    cmd6 = ["dig", at, params.domain, "AAAA"]
    r6 = await executor.run(cmd6)
    cmd4 = ["dig", at, params.domain, "A"]
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
# Registry
# ===================================================================

IPV6_TOOLS: dict[str, tuple[callable, type[BaseModel] | None]] = {
    "ipv6_status": (ipv6_status, None),
    "ipv6_ping": (ipv6_ping, Ipv6PingInput),
    "ipv6_traceroute": (ipv6_traceroute, Ipv6TracerouteInput),
    "ipv6_dig": (ipv6_dig, Ipv6DigInput),
    "ipv6_neigh": (ipv6_neigh, None),
    "ipv6_firewall": (ipv6_firewall, None),
}
