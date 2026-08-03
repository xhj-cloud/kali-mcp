"""
Vulnerability discovery tools — automated scanners, fuzzers, recon.

🟡 Pentest level. Enable via PENTEST_ENABLED=true in .env.

Tools:
  1. nuclei_scan  — Template-based vulnerability scanning (3000+ CVEs)
  2. ffuf_fuzz    — Web fuzzer for hidden directories, params, vhosts
  3. dnsenum_scan — DNS reconnaissance (subdomains, zone transfer)
  4. snmpenum_scan — SNMP enumeration (users, processes, network info)

Requires: nuclei, ffuf, dnsrecon, snmp-check
Install:  sudo apt install nuclei ffuf dnsrecon snmp-check -y
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import get_executor
from kali_mcp.tools import _fmt, _no_shell_meta, _is_valid_target, _is_valid_domain


# ===================================================================
# 1. Nuclei — Template-based vulnerability scanner
# ===================================================================


class NucleiInput(BaseModel):
    """Input for Nuclei vulnerability scanning."""

    target: str = Field(
        ...,
        description="Target URL, IP, or hostname (e.g. 'https://example.com', '192.168.0.1')",
        min_length=1,
        max_length=512,
    )
    severity: str = Field(
        default="medium,high,critical",
        description="Minimum severity filter: info, low, medium, high, critical. Comma-separated.",
        pattern=r"^(info|low|medium|high|critical)(,(info|low|medium|high|critical))*$",
    )
    tags: str = Field(
        default="",
        description="Template tags filter (e.g. 'cve,oast,xss'). Leave empty for all.",
        max_length=256,
    )
    max_results: int = Field(
        default=30,
        description="Max findings to report",
        ge=5,
        le=200,
    )
    timeout_per_template: int = Field(
        default=10,
        description="Max seconds per template check",
        ge=3,
        le=60,
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


async def nuclei_scan(params: NucleiInput) -> str:
    """Run Nuclei template-based vulnerability scanner against a target.

    Nuclei uses 3000+ community-maintained YAML templates to detect
    CVEs, misconfigurations, exposed panels, default credentials,
    and more. Much faster and less noisy than full vulnerability scanners.

    Best for:
    - Quick vulnerability triage of a web app / API
    - Finding exposed admin panels, .git leaks, default credentials
    - CVE detection (Log4j, Spring4Shell, etc.)
    - Technology-specific checks (WordPress, Jira, GitLab, etc.)

    Requires: nuclei (sudo apt install nuclei -y)
    """
    executor = get_executor(timeout=300)
    cmd = [
        "nuclei",
        "-u", params.target,
        "-severity", params.severity,
        "-silent",
        "-no-color",
        "-timeout", str(params.timeout_per_template),
        "-stats-interval", "5",
        "-rl", "10",        # rate limit: 10 req/s
        "-bs", "5",         # bulk size
        "-c", "10",         # concurrency
    ]

    if params.tags:
        cmd.extend(["-tags", params.tags])

    # Limit results count
    # Nuclei doesn't have a built-in limit; we'll truncate after capture

    result = await executor.run(cmd, timeout=300)

    if not result.success:
        return _fmt("Nuclei Scan", params.target, " ".join(cmd), result)

    # Parse and deduplicate findings
    findings = []
    seen = set()
    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Format: [severity] [template] http://target/path [extra]
        key = line[:120]  # dedup by first 120 chars
        if key not in seen:
            seen.add(key)
            findings.append(line)
        if len(findings) >= params.max_results:
            break

    if not findings:
        severity_info = f"severity≥{params.severity}"
        if params.tags:
            severity_info += f", tags={params.tags}"
        return (
            f"## 🧬 Nuclei 漏洞扫描\n"
            f"**目标:** `{params.target}` | **过滤:** {severity_info}\n\n"
            f"> ✅ 未发现漏洞。目标在已加载的模板中无匹配项。\n\n"
            f"💡 提示：可尝试降低 severity 阈值或添加特定 tags。"
        )

    count_by_sev = {}
    for f in findings:
        for sev in ["critical", "high", "medium", "low", "info"]:
            if f.startswith(f"[{sev}]"):
                count_by_sev[sev] = count_by_sev.get(sev, 0) + 1
                break

    lines = [
        f"## 🧬 Nuclei 漏洞扫描",
        f"**目标:** `{params.target}`",
        f"**过滤器:** severity≥{params.severity}" + (f", tags={params.tags}" if params.tags else ""),
        f"**发现:** {len(findings)} 个漏洞",
        "",
    ]

    if count_by_sev:
        lines.append("### 严重程度分布")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in count_by_sev:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
                lines.append(f"- {icon} {sev}: {count_by_sev[sev]}")
        lines.append("")

    lines.append("### 漏洞详情")
    lines.append("| 严重 | 模板 | 目标 |")
    lines.append("|------|------|------|")
    for finding in findings[:params.max_results]:
        # Try to parse: [severity] [template-id] url [matcher-info]
        m = re.match(r"\[(\w+)\]\s+\[([^\]]+)\]\s+(.+)", finding)
        if m:
            sev, template, rest = m.group(1), m.group(2), m.group(3)
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "?")
            # Truncate long info
            rest_short = rest[:100] + ("..." if len(rest) > 100 else "")
            lines.append(f"| {icon} {sev} | `{template}` | {rest_short} |")
        else:
            lines.append(f"| ? | - | {finding[:120]} |")

    return "\n".join(lines)


# ===================================================================
# 2. FFUF — Fast web fuzzer
# ===================================================================


class FfufInput(BaseModel):
    """Input for ffuf web fuzzing."""

    url: str = Field(
        ...,
        description="Target URL with FUZZ keyword (e.g. 'https://example.com/FUZZ' or 'https://example.com/api?q=FUZZ')",
        min_length=1,
        max_length=1024,
    )
    wordlist: str = Field(
        default="/usr/share/wordlists/dirb/common.txt",
        description="Wordlist path on Kali. Default: dirb common (~4600 entries).",
        max_length=512,
    )
    mode: str = Field(
        default="dir",
        description="Fuzzing mode: dir (paths), param (GET params), vhost (virtual hosts), post (POST body)",
        pattern=r"^(dir|param|vhost|post)$",
    )
    match_codes: str = Field(
        default="200,204,301,302,307,401,403,405,500",
        description="HTTP status codes to show (comma-separated). Default: common interesting codes.",
        max_length=128,
    )
    filter_size: str = Field(
        default="",
        description="Filter out responses of this byte size (useful for false positives, e.g. '3849')",
        max_length=32,
    )
    threads: int = Field(default=20, description="Concurrent threads", ge=1, le=100)
    max_time: int = Field(default=120, description="Max runtime in seconds", ge=10, le=600)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        _no_shell_meta(v)
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        if "FUZZ" not in v:
            raise ValueError("URL must contain the FUZZ keyword (e.g. 'https://example.com/FUZZ')")
        return v

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, v: str) -> str:
        _no_shell_meta(v)
        return v


async def ffuf_fuzz(params: FfufInput) -> str:
    """Fast web fuzzing with ffuf — discover hidden directories, files, params.

    Uses wordlists to brute-force web paths, API endpoints, query parameters,
    and virtual hosts. Much faster than dirb/gobuster with auto-calibration.

    Use cases:
    - Discover hidden admin panels, backup files, config leaks
    - Fuzz API parameters for undocumented endpoints
    - Virtual host discovery on shared hosting
    - POST parameter fuzzing

    Modes:
    - dir:   FUZZ path segments   → https://target/FUZZ
    - param: FUZZ GET parameters  → https://target?FUZZ=test
    - vhost: FUZZ Host header     → virtual host brute-force
    - post:  FUZZ POST body       → {FUZZ: "test"}

    Requires: ffuf (sudo apt install ffuf -y)
    """
    executor = get_executor(timeout=params.max_time + 30)
    cmd = [
        "ffuf",
        "-u", params.url,
        "-w", params.wordlist,
        "-ac",                  # Auto-calibrate filter
        "-c",                   # Colorized (harmless in pipe)
        "-t", str(params.threads),
        "-maxtime", str(params.max_time),
        "-mc", params.match_codes,
        "-noninteractive",
    ]

    if params.mode == "vhost":
        cmd.extend(["-H", "Host: FUZZ"])
        # For vhost mode, use a subdomain wordlist as default
        if params.wordlist == "/usr/share/wordlists/dirb/common.txt":
            cmd[3] = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

    if params.mode == "post":
        cmd.extend(["-X", "POST", "-d", "FUZZ=test"])

    if params.mode == "param":
        # FUZZ is already in the URL as a query param
        pass

    if params.filter_size:
        cmd.extend(["-fs", params.filter_size])

    timeout = params.max_time + 15
    result = await executor.run(cmd, timeout=timeout)

    # ffuf outputs to stderr by default (progress) and stdout for JSON
    # Parse stderr for the summary table
    output = result.stderr if result.stderr else result.stdout

    # Count results
    findings = []
    for line in output.split("\n"):
        # ffuf stderr format: "GET /path [Status: 200, Size: 1234, ...]"
        if "Status:" in line and "Words:" not in line:
            findings.append(line.strip())

    if not findings:
        return (
            f"## 🎯 FFUF Web Fuzzing\n"
            f"**目标:** `{params.url}` | **模式:** {params.mode} | **词表:** {params.wordlist}\n\n"
            f"> ✅ 未发现匹配的路径/参数。\n\n"
            f"💡 可尝试换更大的词表：`/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`"
        )

    lines = [
        f"## 🎯 FFUF Web Fuzzing",
        f"**目标:** `{params.url}`",
        f"**模式:** {params.mode} | **线程:** {params.threads} | **词表:** {params.wordlist}",
        f"**发现:** {len(findings)} 条",
        "",
        "| 方法 | 路径 | 状态码 | 大小 |",
        "|------|------|------|------|",
    ]

    for finding in findings[:50]:
        m = re.search(
            r"(\w+)\s+(\S+).*?Status:\s*(\d+).*?Size:\s*(\d+)",
            finding,
        )
        if m:
            method, path, code, size = m.group(1), m.group(2), m.group(3), m.group(4)
            lines.append(f"| {method} | `{path}` | {code} | {size}B |")
        else:
            lines.append(f"| ? | {finding[:80]} | ? | ? |")

    return "\n".join(lines)


# ===================================================================
# 3. DNS Enumeration — subdomains, zone transfers
# ===================================================================


class DnsenumInput(BaseModel):
    """Input for DNS reconnaissance."""

    domain: str = Field(
        ...,
        description="Target domain (e.g. 'example.com')",
        min_length=1,
        max_length=256,
    )
    mode: str = Field(
        default="std",
        description="Scan type: std (standard: subdomains+SOA+NS+MX), axfr (zone transfer attempt), all (everything)",
        pattern=r"^(std|axfr|all)$",
    )
    dns_server: str = Field(
        default="",
        description="Specific DNS server to query. Empty = system default.",
        max_length=64,
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_domain(v):
            raise ValueError(f"Invalid domain: {v}")
        return v

    @field_validator("dns_server")
    @classmethod
    def validate_dns(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


async def dnsenum_scan(params: DnsenumInput) -> str:
    """DNS reconnaissance — discover subdomains, attempt zone transfers.

    Uses dnsrecon to enumerate DNS records, discover subdomains via
    brute-force and SRV records, and attempt AXFR zone transfers.

    Use cases:
    - Subdomain discovery for attack surface mapping
    - Zone transfer testing (misconfigured DNS servers)
    - Finding forgotten/development subdomains
    - DNS record enumeration (A, AAAA, MX, NS, SOA, TXT, SRV)

    Requires: dnsrecon (sudo apt install dnsrecon -y)
    """
    executor = get_executor(timeout=180)

    cmd = ["dnsrecon", "-d", params.domain]

    mode_map = {"std": "-t std", "axfr": "-t axfr", "all": "-a"}
    if params.mode == "all":
        cmd.append("-a")
    elif params.mode == "axfr":
        cmd.extend(["-t", "axfr"])
    else:
        cmd.extend(["-t", "std"])

    if params.dns_server:
        cmd.extend(["-n", params.dns_server])

    result = await executor.run(cmd, timeout=180)

    lines = [
        f"## 🌐 DNS 侦察 — {params.domain}",
        f"**模式:** {params.mode}" + (f" | **DNS:** {params.dns_server}" if params.dns_server else ""),
        "",
    ]

    # Parse dnsrecon output sections
    sections = {
        "A": [], "AAAA": [], "SOA": [], "NS": [], "MX": [],
        "TXT": [], "SRV": [], "CNAME": [], "PTR": [], "AXFR": [],
    }
    current_type = None

    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line:
            current_type = None
            continue

        # dnsrecon section headers
        for rtype in sections:
            if line.startswith(f"{rtype} ") or line.startswith(f"[*] {rtype} "):
                current_type = rtype
                break

        if current_type:
            sections[current_type].append(line)

    # Also try zone transfer manually with dig if axfr was attempted
    if params.mode in ("axfr", "all"):
        axfr_result = await executor.run(
            ["dig", f"@{params.dns_server or ''}", params.domain, "AXFR", "+short"],
            timeout=30,
        )
        if axfr_result.stdout.strip():
            sections["AXFR"].extend(axfr_result.stdout.strip().split("\n"))

    # Build output
    has_data = False
    for rtype in ["SOA", "NS", "MX", "A", "AAAA", "SRV", "TXT", "CNAME", "AXFR"]:
        if sections.get(rtype):
            has_data = True
            lines.append(f"### 📋 {rtype} 记录")
            lines.append("```")
            for entry in sections[rtype][:30]:
                lines.append(entry)
            lines.append("```")
            lines.append("")

    if not has_data:
        lines.append("> ⚠️ 未获取到 DNS 记录。目标域名可能不存在或 DNS 服务器无响应。")

    return "\n".join(lines)


# ===================================================================
# 4. SNMP Enumeration — users, processes, network
# ===================================================================


class SnmpenumInput(BaseModel):
    """Input for SNMP enumeration."""

    target: str = Field(
        ...,
        description="Target IP or hostname with SNMP enabled",
        min_length=1,
        max_length=256,
    )
    community: str = Field(
        default="public",
        description="SNMP community string. Common: public, private, internal, manager.",
        max_length=64,
    )
    mode: str = Field(
        default="full",
        description="Scan depth: quick (system info only), full (users+processes+network+routes), custom",
        pattern=r"^(quick|full|custom)$",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v

    @field_validator("community")
    @classmethod
    def validate_community(cls, v: str) -> str:
        _no_shell_meta(v)
        return v


async def snmpenum_scan(params: SnmpenumInput) -> str:
    """SNMP enumeration — extract system info, users, processes, network data.

    If a device has SNMP enabled with a guessable community string (public,
    private, etc.), this tool can extract extensive information:
    - System: hostname, OS, uptime, contact, location
    - Users: logged-in accounts
    - Processes: running software and versions
    - Network: interfaces, IP addresses, routing table
    - Storage: disk partitions and usage

    Common targets: routers, switches, printers, NAS devices, IP cameras.

    Requires: snmp-check (sudo apt install snmp-check -y)
    """
    executor = get_executor(timeout=120)

    # First, test SNMP reachability
    test_cmd = [
        "snmpwalk", "-v2c", "-c", params.community,
        "-t", "3", "-r", "1",
        params.target, "1.3.6.1.2.1.1.5.0",
    ]
    test_result = await executor.run(test_cmd, timeout=10)

    if not test_result.success or "No Such Object" in test_result.stdout or "Timeout" in test_result.stderr:
        return (
            f"## 📡 SNMP 枚举 — {params.target}\n"
            f"**社群字符串:** `{params.community}`\n\n"
            f"> ❌ SNMP 不可达。可能原因：\n"
            f"> - SNMP 服务未开启\n"
            f"> - 社群字符串 `{params.community}` 不正确\n"
            f"> - 防火墙拦截 UDP 161 端口\n\n"
            f"💡 尝试其他常见字符串: `private`, `internal`, `manager`, `admin`"
        )

    # Extract hostname
    hostname = params.target
    m = re.search(r'STRING:\s*"?(.+?)"?\s*$', test_result.stdout)
    if m:
        hostname = m.group(1)

    # Run snmp-check for comprehensive enumeration
    if params.mode == "quick":
        # Quick mode: just snmpwalk key OIDs
        oids = {
            "sysDescr": "1.3.6.1.2.1.1.1.0",
            "sysObjectID": "1.3.6.1.2.1.1.2.0",
            "sysUpTime": "1.3.6.1.2.1.1.3.0",
            "sysContact": "1.3.6.1.2.1.1.4.0",
            "sysName": "1.3.6.1.2.1.1.5.0",
            "sysLocation": "1.3.6.1.2.1.1.6.0",
            "sysServices": "1.3.6.1.2.1.1.7.0",
        }

        lines = [
            f"## 📡 SNMP 快速枚举 — {hostname}",
            f"**IP:** `{params.target}` | **社群:** `{params.community}`",
            "",
            "| 字段 | 值 |",
            "|------|------|",
        ]

        for label, oid in oids.items():
            r = await executor.run(
                ["snmpwalk", "-v2c", "-c", params.community, "-t", "3", "-r", "1",
                 params.target, oid],
                timeout=8,
            )
            m_val = re.search(r'=\s*(.+)$', r.stdout) if r.success else None
            value = m_val.group(1).strip() if m_val else "(no response)"
            if len(value) > 80:
                value = value[:77] + "..."
            lines.append(f"| {label} | {value} |")

        return "\n".join(lines)

    # Full mode: snmp-check
    cmd = ["snmp-check", "-c", params.community, "-t", params.target]
    result = await executor.run(cmd, timeout=120)

    if not result.success:
        # Fallback: try manual snmpwalk of important OIDs
        return await _snmp_manual_enum(params, hostname)

    lines = [
        f"## 📡 SNMP 枚举 — {hostname}",
        f"**IP:** `{params.target}` | **社群:** `{params.community}`",
        "",
    ]

    # Parse snmp-check output into sections
    current_section = ""
    section_lines: dict[str, list[str]] = {}

    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        # snmp-check section headers are like "System information" or "User accounts"
        if re.match(r"^[A-Z][a-z]", line) and not line.startswith(" "):
            current_section = line
            section_lines[current_section] = []
        elif current_section:
            section_lines[current_section].append(line)

    for section, entries in section_lines.items():
        if entries:
            lines.append(f"### {section}")
            # Limit each section
            for entry in entries[:25]:
                lines.append(f"- {entry}")
            if len(entries) > 25:
                lines.append(f"  ... ({len(entries) - 25} more)")
            lines.append("")

    # Also grab network interfaces
    iface_result = await executor.run(
        ["snmpwalk", "-v2c", "-c", params.community, "-t", "3", "-r", "1",
         params.target, "1.3.6.1.2.1.2.2.1.2"],
        timeout=15,
    )
    if iface_result.success and iface_result.stdout.strip():
        lines.append("### 网络接口")
        for line in iface_result.stdout.strip().split("\n")[:20]:
            m = re.search(r'=\s*STRING:\s*(.+)', line)
            if m:
                lines.append(f"- {m.group(1)}")
        lines.append("")

    return "\n".join(lines) if len(lines) > 2 else "\n".join(lines) + "\n_(snmp-check 输出无法解析，请检查 Kali 上是否安装 snmp-check)_"


async def _snmp_manual_enum(params: SnmpenumInput, hostname: str) -> str:
    """Fallback: manual snmpwalk of common OIDs when snmp-check fails."""
    executor = get_executor(timeout=60)
    oid_groups = {
        "系统信息": [
            ("1.3.6.1.2.1.1.1.0", "描述"),
            ("1.3.6.1.2.1.1.5.0", "主机名"),
            ("1.3.6.1.2.1.1.3.0", "运行时间"),
            ("1.3.6.1.2.1.1.4.0", "联系人"),
            ("1.3.6.1.2.1.1.6.0", "位置"),
        ],
        "网络接口": [
            ("1.3.6.1.2.1.2.2.1.2", "接口名称"),
            ("1.3.6.1.2.1.4.20.1.1", "IP地址"),
            ("1.3.6.1.2.1.2.2.1.6", "MAC地址"),
        ],
        "路由表": [
            ("1.3.6.1.2.1.4.21.1.1", "目标网络"),
            ("1.3.6.1.2.1.4.21.1.7", "下一跳"),
        ],
        "进程列表": [
            ("1.3.6.1.2.1.25.4.2.1.2", "进程名"),
        ],
    }

    lines = [
        f"## 📡 SNMP 手动枚举 — {hostname}",
        f"**IP:** `{params.target}` | **社群:** `{params.community}`",
        f"",
        "> ℹ️ snmp-check 不可用，使用 snmpwalk 回退模式。",
        "",
    ]

    for group_name, oids in oid_groups.items():
        lines.append(f"### {group_name}")
        for oid, label in oids:
            r = await executor.run(
                ["snmpwalk", "-v2c", "-c", params.community, "-t", "3", "-r", "1",
                 params.target, oid],
                timeout=8,
            )
            if r.success and r.stdout.strip():
                count = len(r.stdout.strip().split("\n"))
                lines.append(f"- **{label}:** {count} 条记录")
                if count <= 5:
                    for entry in r.stdout.strip().split("\n"):
                        m = re.search(r'=\s*(.+)$', entry)
                        if m:
                            val = m.group(1).strip()[:80]
                            lines.append(f"  - {val}")
        lines.append("")

    return "\n".join(lines)


# ===================================================================
# Registry
# ===================================================================

VULNSCAN_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "nuclei_scan": (nuclei_scan, NucleiInput),
    "ffuf_fuzz": (ffuf_fuzz, FfufInput),
    "dnsenum_scan": (dnsenum_scan, DnsenumInput),
    "snmpenum_scan": (snmpenum_scan, SnmpenumInput),
}
