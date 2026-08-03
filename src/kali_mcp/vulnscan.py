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
    template: str = Field(
        default="",
        description="Specific template or template dir (e.g. 'http/cves/'). Fast! Skips full library load.",
        max_length=512,
    )
    max_results: int = Field(
        default=30,
        description="Max findings to report",
        ge=5,
        le=200,
    )
    timeout_per_template: int = Field(
        default=5,
        description="Max seconds per template check",
        ge=3,
        le=60,
    )
    async_mode: bool = Field(
        default=False,
        description="Run in background and return immediately. Use nuclei_results to fetch later.",
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

    @field_validator("template")
    @classmethod
    def validate_template(cls, v: str) -> str:
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

    Requires: nuclei + templates (sudo apt install nuclei -y && nuclei -ut)
    """
    executor = get_executor(timeout=90)

    # Async mode: spawn background process, write to file, return immediately
    if params.async_mode:
        import asyncio, os
        outfile = os.path.expanduser("~/.kali-mcp/nuclei_results.txt")
        os.makedirs(os.path.dirname(outfile), exist_ok=True)
        # Build full cmd args for background
        bg_args = f"-u {params.target} -severity {params.severity}"
        if params.tags:
            bg_args += f" -tags {params.tags}"
        if params.template:
            bg_args += f" -t {params.template}"
        bg_cmd = (
            f"cd /root && nohup nuclei {bg_args} "
            f"-no-color -silent -stats-interval 5 "
            f"> {outfile} 2>&1 &"
        )
        await executor.run(["bash", "-l", "-c", bg_cmd], timeout=10)
        return (
            f"## 🧬 Nuclei 后台扫描\n"
            f"**目标:** `{params.target}` | **过滤:** severity≥{params.severity}\n\n"
            f"> 🔄 扫描已在后台启动。结果保存到 `{outfile}`。\n\n"
            f"使用 `nuclei_results` 工具查看进度和结果。"
        )

    cmd = [
        "nuclei",
        "-u", params.target,
        "-severity", params.severity,
        "-no-color",
        "-timeout", str(params.timeout_per_template),
        "-stats-interval", "5",
        "-rl", "10",        # rate limit: 10 req/s
        "-bs", "5",         # bulk size
        "-c", "10",         # concurrency
    ]

    if params.tags:
        cmd.extend(["-tags", params.tags])
    if params.template:
        cmd.extend(["-t", params.template])

    # Limit results count
    # Nuclei doesn't have a built-in limit; we'll truncate after capture

    result = await executor.run(cmd, timeout=60)

    # Auto-download templates on first run, then retry
    if not result.success and "no templates" in (result.stderr or "").lower():
        dl = await executor.run(["nuclei", "-ut", "-silent"], timeout=180)
        if dl.success:
            result = await executor.run(cmd, timeout=60)


    if not result.success:
        if "no templates" in (result.stderr or "").lower():
            return (
                f"## 🧬 Nuclei 漏洞扫描\n"
                f"**目标:** `{params.target}`\n\n"
                f"> ❌ 未找到 nuclei 模板。请在 Kali 上运行：\n"
                f"> ```bash\n> nuclei -ut\n> ```\n"
                f"> 这会从 GitHub 下载 3000+ 社区模板到 `~/nuclei-templates/`。"
            )
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

    # dnsrecon outputs to stderr (not stdout)
    raw_output = result.stdout.strip() or result.stderr.strip()

    lines = [
        f"## 🌐 DNS 侦察 — {params.domain}",
        f"**模式:** {params.mode}" + (f" | **DNS:** {params.dns_server}" if params.dns_server else ""),
        "",
    ]

    if not raw_output:
        lines.append("> ⚠️ 未获取到 DNS 记录。请检查 dnsrecon 是否正确安装：`sudo apt install dnsrecon -y`")
        return "\n".join(lines)

    # Strip INFO/ERROR prefixes for cleaner reading
    clean = re.sub(r"\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{4}\s*\w+\s*", "", raw_output)

    if len(clean) > 6000:
        clean = clean[:6000] + "\n\n... (truncated)"

    lines.append("```")
    lines.append(clean.strip())
    lines.append("```")

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
    private, etc.), this tool can extract extensive information using snmpwalk:
    - System: hostname, OS, uptime, contact, location
    - Network: interfaces, IP addresses, MACs, routing table
    - Storage: disk partitions and usage
    - Processes: running software and versions

    Common targets: routers, switches, printers, NAS devices, IP cameras.

    Requires: snmpwalk (sudo apt install snmp -y)
    """
    executor = get_executor(timeout=120)

    # 1. Test SNMP reachability
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

    # 2. Define OID groups for enumeration
    oid_groups: list[tuple[str, str, str]] = [
        # (section_name, oid, label)
        ("系统信息", "1.3.6.1.2.1.1.1.0", "描述"),
        ("系统信息", "1.3.6.1.2.1.1.5.0", "主机名"),
        ("系统信息", "1.3.6.1.2.1.1.3.0", "运行时间"),
        ("系统信息", "1.3.6.1.2.1.1.4.0", "联系人"),
        ("系统信息", "1.3.6.1.2.1.1.6.0", "位置"),
        ("系统信息", "1.3.6.1.2.1.1.7.0", "服务层"),
    ]

    if params.mode == "full":
        oid_groups.extend([
            ("网络接口", "1.3.6.1.2.1.2.2.1.2", "接口名称"),
            ("网络接口", "1.3.6.1.2.1.4.20.1.1", "IP地址"),
            ("网络接口", "1.3.6.1.2.1.2.2.1.6", "MAC地址"),
            ("路由表", "1.3.6.1.2.1.4.21.1.1", "目标网络"),
            ("路由表", "1.3.6.1.2.1.4.21.1.7", "下一跳"),
            ("ARP表", "1.3.6.1.2.1.4.22.1.2", "IP-MAC映射"),
            ("进程", "1.3.6.1.2.1.25.4.2.1.2", "进程名"),
            ("TCP连接", "1.3.6.1.2.1.6.13.1.3", "TCP端口"),
            ("UDP监听", "1.3.6.1.2.1.7.5.1.2", "UDP端口"),
            ("存储", "1.3.6.1.2.1.25.2.3.1.3", "存储设备"),
            ("存储", "1.3.6.1.2.1.25.2.3.1.5", "总大小"),
            ("存储", "1.3.6.1.2.1.25.2.3.1.6", "已用"),
        ])

    # 3. Walk each OID
    sections: dict[str, list[str]] = {}
    for section, oid, label in oid_groups:
        r = await executor.run(
            ["snmpwalk", "-v2c", "-c", params.community,
             "-t", "3", "-r", "1", params.target, oid],
            timeout=8,
        )
        if r.success and r.stdout.strip():
            if section not in sections:
                sections[section] = []
            count = len(r.stdout.strip().split("\n"))
            if count == 1:
                m_val = re.search(r'=\s*(.+)$', r.stdout.strip())
                val = m_val.group(1).strip()[:100] if m_val else r.stdout.strip()[:100]
                sections[section].append(f"**{label}:** {val}")
            else:
                header = f"**{label}** ({count} 条)"
                sections[section].append(header)
                for line in r.stdout.strip().split("\n")[:15]:
                    m_val = re.search(r'=\s*(.+)$', line.strip())
                    if m_val:
                        sections[section].append(f"  → {m_val.group(1).strip()[:80]}")

    # 4. Build output
    lines = [
        f"## 📡 SNMP 枚举 — {hostname}",
        f"**IP:** `{params.target}` | **社群:** `{params.community}` | **模式:** {params.mode}",
        f"",
    ]

    if not sections:
        lines.append("> ⚠️ 无法获取 SNMP 数据。设备可能限制了 OID 访问。")

    for section in ["系统信息", "网络接口", "路由表", "ARP表", "存储", "进程", "TCP连接", "UDP监听"]:
        if section in sections:
            lines.append(f"### {section}")
            for entry in sections[section][:30]:
                lines.append(f"- {entry}")
            if len(sections[section]) > 30:
                lines.append(f"  ... ({len(sections[section]) - 30} more)")
            lines.append("")

    return "\n".join(lines)


# ===================================================================
# 5. Nuclei Results — read background scan output
# ===================================================================


class NucleiResultsInput(BaseModel):
    """No-arg input for fetching nuclei background results."""

    pass


async def nuclei_results(_params: NucleiResultsInput = None) -> str:
    """Fetch results from a background nuclei scan.

    After starting a nuclei_scan with async_mode=True, use this tool
    to check if the scan is complete and retrieve findings.

    Reads from ~/.kali-mcp/nuclei_results.txt on the Kali host.
    """
    import os
    outfile = os.path.expanduser("~/.kali-mcp/nuclei_results.txt")

    if not os.path.exists(outfile):
        return "## Nuclei Results\n\nNo background scan found. Start one with nuclei_scan(async_mode=true)."

    with open(outfile, "r") as f:
        raw = f.read().strip()

    if not raw:
        return "## Nuclei Scan In Progress\n\nScan is running, no results yet. Check again later."

    findings = [l.strip() for l in raw.split("\n") if l.strip()
                and not l.strip().startswith("[INF]")
                and not l.strip().startswith("[WRN]")]

    result = f"## Nuclei Background Scan Results\n\n**Findings:** {len(findings)}\n\n"
    if findings:
        result += "```\n" + "\n".join(findings[:50]) + "\n```\n"
    else:
        result += "No vulnerabilities found, or scan still running.\n"

    return result




# ===================================================================
# Registry
# ===================================================================

VULNSCAN_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "nuclei_scan": (nuclei_scan, NucleiInput),
    "nuclei_results": (nuclei_results, NucleiResultsInput),
    "ffuf_fuzz": (ffuf_fuzz, FfufInput),
    "dnsenum_scan": (dnsenum_scan, DnsenumInput),
    "snmpenum_scan": (snmpenum_scan, SnmpenumInput),
}
