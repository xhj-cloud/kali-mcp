"""
Vulnerability discovery tools — automated scanners, fuzzers, recon.

🟡 Pentest level. Enable via PENTEST_ENABLED=true in .env.

Tools:
  1. nuclei_scan  — Template-based vulnerability scanning (3000+ CVEs)
  2. ffuf_fuzz    — Web fuzzer for hidden directories, params, vhosts
  3. dnsenum_scan — DNS reconnaissance (subdomains, zone transfer)
  4. snmpenum_scan — SNMP enumeration (users, processes, network info)
  5. ssl_cert_check — SSL/TLS certificate check (expiry/SAN/chain verify)

Requires: nuclei, ffuf, dnsrecon, snmp-check, openssl
Install:  sudo apt install nuclei ffuf dnsrecon snmp-check -y
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import get_executor
from kali_mcp.tools import _fmt, _no_shell_meta, _is_valid_target, _is_valid_domain

# ---------------------------------------------------------------------------
# Nuclei templates directory resolution
# ---------------------------------------------------------------------------

#: Env var that overrides automatic nuclei templates directory detection.
#: Set it in .env (or the systemd unit) when templates live somewhere
#: non-standard, e.g. NUCLEI_TEMPLATES_DIR=/home/xhj/.local/nuclei-templates
NUCLEI_TEMPLATES_DIR_ENV = "NUCLEI_TEMPLATES_DIR"

#: Candidate locations probed (in order) when $NUCLEI_TEMPLATES_DIR is unset.
#: Covers the legacy `nuclei -ut` location (~/nuclei-templates), the nuclei v3
#: XDG default (~/.local/share/nuclei/templates — where `nuclei -ut` actually
#: downloads on v3.x), and the equivalent paths under /root for servers
#: running as root (kali-mcp.service).
_DEFAULT_TEMPLATES_CANDIDATES = (
    "~/nuclei-templates",
    "~/.local/nuclei-templates",
    "~/.local/share/nuclei/templates",
    "/root/nuclei-templates",
    "/root/.local/nuclei-templates",
    "/root/.local/share/nuclei/templates",
)


def _resolve_templates_dir() -> str | None:
    """Locate the nuclei templates directory.

    Priority:
      1. ``$NUCLEI_TEMPLATES_DIR`` if set and the directory exists
         (explicit user override — authoritative)
      2. First candidate path that exists under the current HOME
      3. First candidate path under /root (root-run servers)

    Returns ``None`` when nothing can be located. Callers use this as an
    existence check to decide whether to bootstrap with ``nuclei -ut``;
    nuclei itself auto-detects its default template location at runtime
    (no directory flag is passed — nuclei v3 has none).
    """
    import os

    override = os.environ.get(NUCLEI_TEMPLATES_DIR_ENV, "").strip()
    if override:
        # Explicit override is authoritative: never silently fall back
        # to another path if the user set it but it is wrong/missing.
        return override if os.path.isdir(override) else None

    for cand in _DEFAULT_TEMPLATES_CANDIDATES:
        path = os.path.expanduser(cand)
        if os.path.isdir(path):
            return path
    return None


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

    # Async mode: spawn background nuclei via asyncio subprocess
    if params.async_mode:
        import asyncio, os
        outfile = os.path.expanduser("~/.kali-mcp/nuclei_results.txt")
        os.makedirs(os.path.dirname(outfile), exist_ok=True)

        # Bootstrap templates on first run if nothing is installed yet.
        # (No -templates-directory flag: not supported by nuclei v3 — it
        # auto-detects its default location after `nuclei -ut`.)
        tpl_dir = _resolve_templates_dir()
        if tpl_dir is None:
            await executor.run(["nuclei", "-ut"], timeout=180)

        # Build cmd as list (safe, no shell)
        bg_cmd = [
            "nuclei", "-u", params.target,
            "-severity", params.severity,
            "-no-color",
            "-stats-interval", "5",
        ]
        if params.tags:
            bg_cmd.extend(["-tags", params.tags])
        if params.template:
            bg_cmd.extend(["-t", params.template])

        # Spawn detached subprocess, redirect output to file
        with open(outfile, "w") as f_out:
            proc = await asyncio.create_subprocess_exec(
                *bg_cmd, stdout=f_out, stderr=f_out,
            )
        return (
            f"## 🧬 Nuclei 后台扫描\n"
            f"**目标:** `{params.target}` | **过滤:** severity≥{params.severity}\n\n"
            f"> 🔄 扫描已在后台启动 (PID {proc.pid})。结果保存到 `{outfile}`。\n\n"
            f"使用 `nuclei_results` 工具查看进度和结果。"
        )

    cmd = [
        "nuclei",
        "-u", params.target,
        "-severity", params.severity,
        "-no-color",
        "-timeout", str(params.timeout_per_template),
        "-stats-interval", "5",
        # Rate limit 50 req/s: a full severity-filtered run (e.g. ~1764
        # critical templates) at -rl 10 is rate-bound to >3 min and blows the
        # sync timeout; measured ~60s scan + startup at -rl 50.
        "-rl", "50",
        "-bs", "5",         # bulk size
        "-c", "10",         # concurrency
    ]

    if params.tags:
        cmd.extend(["-tags", params.tags])
    if params.template:
        cmd.extend(["-t", params.template])

    # Note: no -templates-directory flag (not supported by nuclei v3);
    # nuclei auto-detects its default location (~/.local/share/nuclei/templates).
    # The "no templates" retry below bootstraps `nuclei -ut` on first run.

    # 180s: a full severity-filtered scan (e.g. all ~1700 critical templates)
    # at -rl 10 legitimately takes minutes; cold starts also pay the cost of
    # building nuclei's template cache. Use async_mode=True for longer runs.
    result = await executor.run(cmd, timeout=180)

    # Auto-download templates on first run, then retry
    if not result.success and "no templates" in (result.stderr or "").lower():
        dl = await executor.run(["nuclei", "-ut", "-silent"], timeout=180)
        if dl.success:
            result = await executor.run(cmd, timeout=180)


    if not result.success:
        if "no templates" in (result.stderr or "").lower():
            return (
                f"## 🧬 Nuclei 漏洞扫描\n"
                f"**目标:** `{params.target}`\n\n"
                f"> ❌ 未找到 nuclei 模板。请先在 Kali 上运行：\n"
                f"> ```bash\n> nuclei -ut\n> ```\n"
                f"> 这会从 GitHub 下载 3000+ 社区模板。\n"
                f"> 若模板在非默认位置，可在 .env 里设置 "
                f"`NUCLEI_TEMPLATES_DIR=/path/to/nuclei-templates`。"
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

    findings = [l.strip() for l in raw.split("\n") if l.strip()
                and l.strip().startswith("[")
                and not l.strip().startswith("[INF]")
                and not l.strip().startswith("[WRN]")
                and not l.strip().startswith("[FTL]")]

    # Check if scan is still running (no output at all, or only stats)
    non_stats = [l for l in raw.split("\n") if l.strip() and not l.strip().startswith("[INF]")]
    done = not raw.endswith("[INF]") if raw else False

    if not raw or (not non_stats and not done):
        return "## Nuclei Scan In Progress\n\nScan still running. Check again later."

    if not findings:
        if "[FTL]" in raw:
            err_lines = [l for l in raw.split("\n") if "[FTL]" in l]
            return f"## Nuclei Error\n\n```\n{chr(10).join(err_lines[:3])}\n```"
        return "## Nuclei Scan Complete\n\n**Findings:** 0\n\nNo vulnerabilities found for this target/filter combination."

    result = f"## Nuclei Scan Complete\n\n**Findings:** {len(findings)}\n\n"
    result += "```\n" + "\n".join(findings[:50]) + "\n```\n"
    return result


# ===================================================================
# 6. SSL Certificate Check — openssl s_client + x509 parsing
# ===================================================================

#: First PEM block in `openssl s_client` output is the leaf certificate.
_CERT_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)
_VERIFY_CODE_RE = re.compile(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)")
_PROTOCOL_RE = re.compile(r"Protocol\s*:\s*(\S+)")


def _extract_cert_pem(sclient_output: str) -> str | None:
    """Extract the leaf certificate PEM from openssl s_client output."""
    m = _CERT_PEM_RE.search(sclient_output)
    if not m:
        return None
    body = m.group(1).strip()
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"


def _parse_openssl_date(value: str) -> datetime | None:
    """Parse an openssl date like 'May  1 00:00:00 2025 GMT' (UTC-aware)."""
    value = value.strip()
    if value.endswith(" GMT"):
        value = value[:-4].strip()
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def _cert_status(not_after: datetime | None, now: datetime) -> tuple[str, int | None]:
    """Return (status label, days remaining) for a certificate expiry."""
    if not_after is None:
        return ("❓ Unknown — could not parse notAfter", None)
    days = (not_after - now).days
    if days < 0:
        return f"🔴 EXPIRED {-days} day(s) ago", days
    if days < 7:
        return f"🟠 Expires in {days} day(s)", days
    if days < 30:
        return f"🟡 Expires in {days} day(s)", days
    return f"🟢 Valid — {days} day(s) remaining", days


def _parse_x509_summary(x509_out: str) -> dict[str, str]:
    """Parse `openssl x509 -noout -subject -issuer -dates -ext subjectAltName` output.

    Handles both openssl 3.x (`subject=C = CN`) and legacy (`subject=/C=CN`)
    formats; the SAN value sits on the line following its header.
    """
    info: dict[str, str] = {
        "subject": "", "issuer": "", "not_before": "", "not_after": "", "sans": ""
    }
    lines = x509_out.splitlines()
    for i, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith("subject="):
            info["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[1].strip()
        elif "Subject Alternative Name" in line:
            # Value is on the next non-empty line (indented)
            for nxt in lines[i + 1:]:
                if nxt.strip():
                    info["sans"] = nxt.strip()
                    break
    return info


class SslCertInput(BaseModel):
    """Input for SSL certificate checking."""

    host: str = Field(
        ...,
        description="Target hostname or IP (e.g. example.com, 192.168.0.1)",
        min_length=1,
        max_length=256,
    )
    port: int = Field(443, ge=1, le=65535, description="TLS port to connect to")

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_target(v):
            raise ValueError(f"Invalid host: {v}")
        return v


async def ssl_cert_check(params: SslCertInput) -> str:
    """Check the SSL/TLS certificate served by a target (read-only).

    Performs a TLS handshake with `openssl s_client`, then parses the leaf
    certificate to report subject, issuer, SANs, validity window and days
    remaining. Also reports the negotiated protocol and chain-verification
    result from OpenSSL itself.

    Useful for:
    - Expiry monitoring (warns at <30d / <7d, flags expired)
    - Verifying a domain is actually covered by the certificate (SAN check)
    - Spotting self-signed or broken chains during recon

    Requires: openssl (pre-installed on Kali). No extra packages.
    """
    executor = get_executor(timeout=20)
    target = f"{params.host}:{params.port}"
    cmd = [
        "openssl", "s_client", "-connect", target, "-servername", params.host,
    ]

    # Empty stdin → s_client exits right after the handshake.
    r1 = await executor.run(cmd, input_data="")
    pem = _extract_cert_pem(r1.stdout)
    if not pem:
        diag = (r1.stderr or r1.stdout)[:500]
        return (
            f"## SSL Certificate Check\n\n**Target:** `{target}`\n\n"
            f"✗ No certificate received.\n\n"
            f"**Diagnostics:**\n```\n{diag}\n```\n\n"
            "Hints: port closed / not a TLS service / connection timed out."
        )

    r2 = await executor.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates",
         "-ext", "subjectAltName"],
        input_data=pem,
    )
    info = _parse_x509_summary(r2.stdout)

    not_after = _parse_openssl_date(info["not_after"])
    now = datetime.now(timezone.utc)
    status_label, days = _cert_status(not_after, now)

    verify_m = _VERIFY_CODE_RE.search(r1.stdout)
    if verify_m:
        code, reason = verify_m.group(1), verify_m.group(2).strip()
        verify_txt = f"{code} ({reason})" + (" ✓" if code == "0" else " ⚠ chain not trusted")
    else:
        verify_txt = "n/a"

    proto_m = _PROTOCOL_RE.search(r1.stdout)
    protocol = proto_m.group(1) if proto_m else "n/a"

    # SAN coverage check for the requested host (only meaningful for domains)
    san_note = ""
    if info["sans"] and re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", params.host):
        sans_lower = [s.strip().lower() for s in info["sans"].split(",")]
        covered = any(
            s == params.host.lower() or s.lstrip("*.") == params.host.lower()
            for s in sans_lower if not s.startswith("ip address:")
        )
        san_note = (
            f"\n**SAN coverage:** `{params.host}` "
            + ("✓ is covered by this certificate" if covered else "⚠ NOT found in SANs")
        )

    lines = [
        "## SSL Certificate Check",
        "",
        f"**Target:** `{target}`",
        f"**Status:** {status_label}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Subject | {info['subject'] or 'n/a'} |",
        f"| Issuer | {info['issuer'] or 'n/a'} |",
        f"| SANs | {info['sans'] or 'none'} |",
        f"| Not Before | {info['not_before'] or 'n/a'} |",
        f"| Not After | {info['not_after'] or 'n/a'} |",
        f"| Days Remaining | {days if days is not None else 'n/a'} |",
        f"| TLS Protocol | {protocol} |",
        f"| Chain Verify | {verify_txt} |",
    ]
    if san_note:
        lines.append(san_note)
    lines += [
        "",
        "**Command:** `openssl s_client -connect " + target + "`",
    ]
    return "\n".join(lines)


# ===================================================================
# Registry
# ===================================================================

VULNSCAN_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "nuclei_scan": (nuclei_scan, NucleiInput),
    "nuclei_results": (nuclei_results, NucleiResultsInput),
    "ffuf_fuzz": (ffuf_fuzz, FfufInput),
    "dnsenum_scan": (dnsenum_scan, DnsenumInput),
    "snmpenum_scan": (snmpenum_scan, SnmpenumInput),
    "ssl_cert_check": (ssl_cert_check, SslCertInput),
}
