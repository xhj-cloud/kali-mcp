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

    # Freshness: the file outlives individual scans, so always say when it
    # was last written — an old file must not be mistaken for a current scan.
    mtime = datetime.fromtimestamp(
        os.path.getmtime(outfile)
    ).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    findings = [l.strip() for l in raw.split("\n") if l.strip()
                and l.strip().startswith("[")
                and not l.strip().startswith("[INF]")
                and not l.strip().startswith("[WRN]")
                and not l.strip().startswith("[FTL]")]

    # nuclei v3 writes a terminal "[INF] Scan finished ..." /
    # "[INF] Scan completed in ...s. N matches found." line — that (not the
    # presence of any non-INF line; the banner appears seconds after start)
    # is the reliable completion marker.
    finished = bool(re.search(r"\[INF\] Scan (?:finished|completed)", raw))

    if not raw or not finished:
        return (
            "## Nuclei Scan In Progress\n\n"
            f"**Results file last updated:** {mtime}\n\n"
            "Scan still running. Check again later."
        )

    if not findings:
        if "[FTL]" in raw:
            err_lines = [l for l in raw.split("\n") if "[FTL]" in l]
            return (
                f"## Nuclei Error\n\n"
                f"**Results file last updated:** {mtime}\n\n"
                f"```\n{chr(10).join(err_lines[:3])}\n```"
            )
        return (
            "## Nuclei Scan Complete\n\n"
            f"**Results file last updated:** {mtime}\n\n"
            "**Findings:** 0\n\n"
            "No vulnerabilities found for this target/filter combination."
        )

    result = (
        f"## Nuclei Scan Complete\n\n"
        f"**Results file last updated:** {mtime}\n\n"
        f"**Findings:** {len(findings)}\n\n"
    )
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
# System Patch Audit — compare installed patches against the vuls2
# CVE database (Vuls). Windows hotfixes/KB + OS build and Linux
# package versions are compared to find unpatched CVEs.
#
# Engine: vuls (github.com/future-architect/vuls) running over SSH.
#   - scan  : collect installed patches via SSH (PowerShell on Windows)
#   - report: correlate against the vuls2 DB (pulled from ghcr.io)
#
# SSH auth: key-based (keyPath) or password via an sshpass PATH shim
# (the password travels in an environment variable, never argv).
# The shim dir is configurable via $VULS_SSH_SHIM_DIR.
# ===================================================================

#: Env var overriding the vuls binary (default: resolved from PATH).
VULS_BIN_ENV = "VULS_BIN"

#: Env var overriding the ssh shim directory (default below).
VULS_SSH_SHIM_DIR_ENV = "VULS_SSH_SHIM_DIR"

#: Default location of the ssh shim directory (deployed by setup.sh).
_DEFAULT_SHIM_DIR = "/usr/local/lib/kali-mcp-vuls/bin"

#: Env var overriding the persistent vuls2 CVE database path.
VULS2_DB_PATH_ENV = "VULS2_DB_PATH"

#: Persistent location of the ~12GB vuls2 boltdb (survives per-run
#: temp workdirs; re-downloaded automatically when missing or stale).
_DEFAULT_VULS2_DB_PATH = "/var/lib/kali-mcp-vuls/vuls.db"

#: Pinned vuls2 nightly DB image + schema tag (schema 0, as of vuls
#: v0.39.3). Pinning the tag keeps the digest check against the exact
#: image the deployed DB was pulled from.
_DEFAULT_VULS2_REPO = "ghcr.io/vulsio/vuls-nightly-db:0"

#: Families whose CVE detection vuls supports (detector dispatch list).
_SUPPORTED_FAMILIES = {
    "windows", "debian", "ubuntu", "raspbian", "alpine",
    "redhat", "centos", "fedora", "alma", "rocky", "oracle",
    "amazon", "opensuse", "opensuseleap", "suseenterprise",
    "suseenterprisedesktop",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
_SEVERITY_LABEL = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🟢 Low",
    "unknown": "⚪ Unknown",
}


def _resolve_vuls_bin() -> str:
    """Locate the vuls binary: $VULS_BIN if set, else PATH lookup."""
    import os
    import shutil

    override = os.environ.get(VULS_BIN_ENV, "").strip()
    if override:
        return override
    found = shutil.which("vuls")
    return found or "vuls"


def _resolve_ssh_shim_dir() -> str | None:
    """Locate the ssh shim dir (containing the 'ssh' wrapper script).

    Priority: $VULS_SSH_SHIM_DIR (authoritative) then the default
    install location. Returns None when no shim is present — in that
    case only key-based auth is possible.
    """
    import os

    override = os.environ.get(VULS_SSH_SHIM_DIR_ENV, "").strip()
    cand = override if override else _DEFAULT_SHIM_DIR
    if os.path.isfile(os.path.join(cand, "ssh")):
        return cand
    return None


def _resolve_vuls2_db_path() -> str:
    """Persistent vuls2 DB path: $VULS2_DB_PATH if set, else default.

    The DB is ~12GB; pinning a fixed path means it is downloaded once
    and reused across runs (vuls re-checks the digest and refreshes
    only when the pinned nightly image actually changed).
    """
    import os

    override = os.environ.get(VULS2_DB_PATH_ENV, "").strip()
    return override or _DEFAULT_VULS2_DB_PATH


def _toml_escape(value: str) -> str:
    """Escape a string for inclusion in a TOML basic string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _pick(d: dict, *keys, default=None):
    """First present key wins (handles the PascalCase→lowercase JSON
    rename between vuls versions)."""
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _severity_from_score(score: float | None) -> str:
    """Map a CVSS score to a severity bucket."""
    if not score:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _find_latest_result_json(results_dir: str) -> str | None:
    """Newest <results>/<timestamp>/<server>.json under results_dir."""
    import glob
    import os

    pattern = os.path.join(results_dir, "*", "*.json")
    files = [
        p for p in glob.glob(pattern)
        if os.path.basename(os.path.dirname(p)) != "vuls"
    ]
    if not files:
        # Flat layout fallback (single result file directly in dir)
        files = glob.glob(os.path.join(results_dir, "*.json"))
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def _scan_error_from_result(data: dict) -> str | None:
    """Fatal per-server errors recorded in a scan result, if any."""
    for err in data.get("errors") or []:
        text = err if isinstance(err, str) else str(err)
        low = text.lower()
        if any(
            marker in low
            for marker in ("failed", "error", "timeout", "refused", "denied")
        ):
            return text.strip()
    return None


_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """Reduce an HTML fragment (e.g. Microsoft advisory descriptions)
    to plain text."""
    text = _HTML_TAG_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_cve_fields(c: dict) -> tuple[float | None, str, str, list[str]]:
    """Extract (score, title, description, links) from a vuls2 VulnInfo.

    vuls2 shape (v0.39.x): ``cveContents`` is a dict of
    ``{source: [content, ...]}`` where each content carries
    ``cvss3Score``/``cvss40Score``/``cvss2Score``, ``title``, ``summary``,
    ``sourceLink`` and ``references: [{link, source}, ...]``. The
    description is often empty in ``summary``; Microsoft advisory text
    lives (as HTML) in ``distroAdvisories[0].description``.
    """
    score = 0.0
    title = ""
    desc = ""
    links: list[str] = []

    contents = c.get("cveContents")
    if isinstance(contents, dict):
        for lst in contents.values():
            if not isinstance(lst, list):
                continue
            for item in lst:
                if not isinstance(item, dict):
                    continue
                for key in ("cvss3Score", "cvss40Score", "cvss2Score"):
                    raw = item.get(key)
                    try:
                        fv = float(raw) if raw is not None else 0.0
                    except (TypeError, ValueError):
                        fv = 0.0
                    if fv > score:
                        score = fv
                if not title and item.get("title"):
                    title = str(item["title"])
                if not desc and item.get("summary"):
                    desc = str(item["summary"]).strip()
                if item.get("sourceLink"):
                    links.append(str(item["sourceLink"]))
                for ref in item.get("references") or []:
                    if isinstance(ref, dict) and ref.get("link"):
                        links.append(str(ref["link"]))

    if not desc:
        for adv in c.get("distroAdvisories") or []:
            if isinstance(adv, dict) and adv.get("description"):
                desc = _strip_html(str(adv["description"]))
                break

    # Dedup links, keep order.
    seen: set[str] = set()
    uniq: list[str] = []
    for link in links:
        if link and link not in seen:
            seen.add(link)
            uniq.append(link)

    return (score if score > 0 else None), title, desc, uniq


class SystemPatchAuditInput(BaseModel):
    """Input for system patch audit (Vuls over SSH)."""

    host: str = Field(
        ...,
        description="Target host IP or hostname (Windows or Linux, e.g. '192.168.0.100')",
        min_length=1,
        max_length=256,
    )
    port: int = Field(default=22, ge=1, le=65535, description="SSH port")
    user: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="SSH username",
    )
    password: str = Field(
        default="",
        max_length=256,
        description=(
            "SSH password (passed to sshpass via environment, never on the "
            "command line). Leave empty for key-based auth."
        ),
    )
    key_path: str = Field(
        default="",
        max_length=512,
        description="Optional local path to an SSH private key",
    )
    severity: str = Field(
        default="all",
        pattern=r"^(all|critical|high|medium|low|unknown)$",
        description="Minimum severity to list: critical, high, medium, low, unknown, or all",
    )
    max_results: int = Field(
        default=100, ge=1, le=500, description="Max CVE entries to list in the report"
    )
    timeout: int = Field(
        default=600,
        ge=120,
        le=3600,
        description="Max seconds for the scan (first run also pulls the vuln DB)",
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        _no_shell_meta(v)
        return v

    @field_validator("user")
    @classmethod
    def validate_user(cls, v: str) -> str:
        _no_shell_meta(v)
        return v

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


async def system_patch_audit(params: SystemPatchAuditInput) -> str:
    """系统补丁审计 — 比对补丁寻找系统漏洞（Vuls over SSH）。

    Scans a target's installed patch level — Windows hotfixes (KB) + OS
    build, or Linux package versions — and compares it against the vuls2
    vulnerability database to find unpatched CVEs (with severity, CVSS and
    fixed versions).

    Works over SSH: Windows targets need OpenSSH (built into Win10/11);
    Linux targets need openssh. Auth via password (sshpass shim) or key.

    Requires: vuls binary ($VULS_BIN or PATH) and the ssh shim dir
    ($VULS_SSH_SHIM_DIR) for password auth.
    """
    import json
    import os
    import shutil
    import tempfile
    import time

    executor = get_executor(timeout=30)
    vuls_bin = _resolve_vuls_bin()
    shim_dir = _resolve_ssh_shim_dir()

    if params.password and shim_dir is None:
        return (
            "❌ 无法完成补丁审计：密码认证需要 sshpass 包装器（PATH shim），"
            f"但未找到 shim 目录（查找顺序：${VULS_SSH_SHIM_DIR_ENV} → "
            f"{_DEFAULT_SHIM_DIR}）。\n"
            "请改用 key_path 参数（密钥认证），或先完成 shim 部署。"
        )

    workdir = tempfile.mkdtemp(prefix="vuls-audit-")
    success = False
    try:
        # ------------------------------------------------------------------
        # 1. Per-run working files: config.toml + known_hosts
        # ------------------------------------------------------------------
        config_path = os.path.join(workdir, "config.toml")
        known_hosts = os.path.join(workdir, "known_hosts")
        results_dir = os.path.join(workdir, "results")
        os.makedirs(results_dir, exist_ok=True)

        toml_lines = [
            "[servers]",
            "  [servers.audit-target]",
            f'  host = "{_toml_escape(params.host)}"',
            f'  port = "{params.port}"',
            f'  user = "{_toml_escape(params.user)}"',
        ]
        if params.key_path:
            toml_lines.append(f'  keyPath = "{_toml_escape(params.key_path)}"')
        # Persistent vuls2 CVE database. Without a pinned path vuls
        # drops the ~12GB DB into the (temp) cwd and re-pulls it on
        # every run.
        toml_lines += [
            "",
            "[vuls2]",
            f'repository = "{_DEFAULT_VULS2_REPO}"',
            f'path = "{_toml_escape(_resolve_vuls2_db_path())}"',
        ]
        with open(config_path, "w", encoding="utf-8") as f:
            f.write("\n".join(toml_lines) + "\n")

        # Pre-populate the per-run known_hosts (vuls pre-checks it before
        # scanning and fails otherwise).
        rks = await executor.run(
            ["ssh-keyscan", "-H", "-T", "10", "-p", str(params.port), params.host],
            timeout=25,
        )
        if not rks.stdout.strip():
            raise _AuditError(
                f"无法获取 {params.host}:{params.port} 的 host key"
                "（SSH 不可达或端口未开放）。请确认目标可达且 SSH 服务已开启。"
            )
        with open(known_hosts, "w", encoding="utf-8") as f:
            f.write(rks.stdout.strip() + "\n")

        # ------------------------------------------------------------------
        # 2. Scan (collect installed patches via SSH)
        # ------------------------------------------------------------------
        env: dict[str, str] = {}
        if shim_dir:
            env["PATH"] = shim_dir + os.pathsep + os.environ.get("PATH", "")
        env["VULS_SSH_KNOWN_HOSTS"] = known_hosts
        if params.password:
            env["VULS_SSH_PASSWORD"] = params.password

        scan_cmd = [
            vuls_bin, "scan",
            "-config", config_path,
            "-results-dir", results_dir,
            "-timeout", "300",
            "-timeout-scan", str(params.timeout),
        ]
        rscan = await executor.run(
            scan_cmd, timeout=params.timeout + 600, env=env or None
        )
        scan_tail = (rscan.stderr or rscan.stdout or "").strip()

        result_path = _find_latest_result_json(results_dir)
        data: dict | None = None
        if result_path:
            try:
                with open(result_path, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                data = None

        fatal = _scan_error_from_result(data) if data else None
        if rscan.returncode != 0 or data is None or fatal:
            raise _AuditError(
                "扫描失败（vuls scan 未产出可用结果）。\n"
                f"vuls 输出（尾部）：\n```\n{scan_tail[-2000:]}\n```"
                + (f"\n结果中记录的错误：{fatal[:500]}" if fatal else "")
            )

        # ------------------------------------------------------------------
        # 3. Report (correlate against the vuls2 CVE database)
        # ------------------------------------------------------------------
        report_cmd = [
            vuls_bin, "report",
            "-config", config_path,
            "-results-dir", results_dir,
            "-format-json",
        ]
        rrep = await executor.run(report_cmd, timeout=900, env=env or None)
        rep_text = (rrep.stdout or "").strip()
        rep_err = (rrep.stderr or "").strip()
        unsupported = "unsupported detection methods" in rep_err.lower()

        # vuls report (v0.39.x) writes the correlation results BACK INTO
        # the scan result JSON in place — stdout carries nothing. Older
        # builds print the report JSON to stdout; accept both.
        reported: dict | None = None
        if result_path:
            try:
                with open(result_path, encoding="utf-8") as f:
                    reported = json.load(f)
            except (OSError, json.JSONDecodeError):
                reported = None
        if reported is None and rep_text[:1] in {"{", "["}:
            try:
                parsed = json.loads(rep_text)
                if isinstance(parsed, list):
                    parsed = parsed[0] if parsed else None
                if isinstance(parsed, dict):
                    reported = parsed
            except json.JSONDecodeError:
                reported = None

        if unsupported and data is not None:
            success = True
            return (
                _render_patch_inventory(data, params)
                + "\n\n⚠️ 漏洞比对：vuls 不支持 "
                f"`{str(_pick(data, 'family', 'Family', default='unknown')).lower()}` "
                "发行版的 CVE 检测（支持：Windows / Debian / "
                "Ubuntu / RHEL 系 / Alpine 等）。以上为已安装补丁清单与"
                "可更新项，可手动对照发行版安全公告。"
            )

        if rrep.returncode != 0 or reported is None:
            raise _AuditError(
                "报告生成失败（vuls report 未产出结果）。\n"
                f"vuls 输出（尾部）：\n```\n{rep_err[-2000:] or rep_text[-2000:]}\n```"
            )

        # ------------------------------------------------------------------
        # 4. Render the Markdown report
        # ------------------------------------------------------------------
        success = True
        return _render_vuln_report(reported, params, workdir=workdir)

    except _AuditError as e:
        return (
            f"❌ {e}\n\n（调试信息：工作目录已保留 → `{workdir}`，"
            "排查后可手动删除）"
        )
    finally:
        if success:
            shutil.rmtree(workdir, ignore_errors=True)


class _AuditError(Exception):
    """Fatal audit error carrying a user-facing message."""


def _render_patch_inventory(data: dict, params: SystemPatchAuditInput) -> str:
    """Fallback report: installed patch inventory without CVE detection."""
    family = _pick(data, "family", "Family", default="unknown")
    release = _pick(data, "release", "Release", default="")
    kernel = _pick(
        _pick(data, "runningKernel", "RunningKernel", default={}) or {},
        "release", "Release",
        default=_pick(data, "kernel", "Kernel", default=""),
    )
    packages = _pick(data, "packages", "Packages", default={}) or {}
    if isinstance(packages, list):
        packages = {p.get("name", "?"): p for p in packages if isinstance(p, dict)}

    updatable = {
        name: info
        for name, info in packages.items()
        if isinstance(info, dict)
        and (info.get("newVersion") or info.get("newRelease"))
    }

    wkb = _pick(data, "windowsKB", "WindowsKB", default=None)
    if not isinstance(wkb, dict):
        wkb = {}
    kb_applied = [k for k in wkb.get("applied") or [] if isinstance(k, str)]
    kb_unapplied = [
        k for k in wkb.get("unapplied") or [] if isinstance(k, str)
    ]
    is_windows = str(family).lower() == "windows"

    lines = [
        f"# 🩺 系统补丁清单 — {params.host}",
        "",
        "| 项目 | 值 |",
        "|---|---|",
        f"| 系统 | {family} {release} |",
        f"| 内核/Build | {kernel or 'n/a'} |",
    ]
    if is_windows:
        lines.append(
            f"| 热修复 (Hotfix/KB) | {len(kb_applied)} 个已应用"
            + (f"，{len(kb_unapplied)} 个缺失" if kb_unapplied else "") + " |"
        )
    else:
        lines.append(
            f"| 已装包/补丁 | {len(packages)} 个（其中 {len(updatable)} 个有可用更新） |"
        )
    lines.append(f"| 扫描时间 | {_pick(data, 'scannedAt', 'ScannedAt', default='n/a')} |")

    if is_windows and kb_unapplied:
        lines += [
            "",
            "## 🚨 未安装的关键补丁（unapplied KB）",
            "",
            f"共 {len(kb_unapplied)} 个（列出前 20）：",
            "",
        ]
        lines += [f"- `KB{k}`" for k in kb_unapplied[:20]]
    if updatable:
        lines += ["", "## 🔄 有可用更新的包（前 50）", "",
                  "| 包 | 已装 | 可更新到 |", "|---|---|---|"]
        for name, info in list(updatable.items())[:50]:
            lines.append(
                f"| {name} | {info.get('version', '?')} "
                f"→ {info.get('newVersion') or info.get('newRelease') or '?'} |"
            )
    return "\n".join(lines)


def _render_vuln_report(
    data: dict, params: SystemPatchAuditInput, workdir: str
) -> str:
    """Render the final patch-audit report from a vuls report JSON."""
    family = str(_pick(data, "family", "Family", default="unknown")).lower()
    release = _pick(data, "release", "Release", default="")
    kernel = _pick(
        _pick(data, "runningKernel", "RunningKernel", default={}) or {},
        "release", "Release",
        default=_pick(data, "kernel", "Kernel", default=""),
    )
    packages = _pick(data, "packages", "Packages", default={}) or {}
    if isinstance(packages, list):
        packages = {p.get("name", "?"): p for p in packages if isinstance(p, dict)}

    is_windows = family == "windows"
    pkg_label = "热修复 (Hotfix/KB)" if is_windows else "已安装包"
    updatable = {
        name: info
        for name, info in packages.items()
        if isinstance(info, dict)
        and (info.get("newVersion") or info.get("newRelease"))
    }

    # Windows: installed hotfixes live in windowsKB, not packages.
    # ``unapplied`` = KBs vuls' rollup rules expect but that are missing.
    wkb = _pick(data, "windowsKB", "WindowsKB", default=None)
    if not isinstance(wkb, dict):
        wkb = {}
    kb_applied = [k for k in wkb.get("applied") or [] if isinstance(k, str)]
    kb_unapplied = [
        k for k in wkb.get("unapplied") or [] if isinstance(k, str)
    ]

    # --- collect CVE entries (vuls2: dict; older: list) ---
    raw_cves = _pick(data, "scannedCves", "ScannedCves", "VulnDetails",
                     "VulnerabilityIDs", default={})
    if isinstance(raw_cves, dict):
        cve_items = list(raw_cves.values())
        # dict keyed by CVE id: rebuild pairs
        cve_items = [
            {**v, "__id": _pick(v, "cveID", "cveId", "CveID", "CVEID",
                                default=k)}
            for k, v in raw_cves.items()
        ]
    elif isinstance(raw_cves, list):
        cve_items = raw_cves
    else:
        cve_items = []
    cve_items = [c for c in cve_items if isinstance(c, dict)]

    # --- annotate severity + apply filter ---
    for c in cve_items:
        score_f, title, desc, links = _extract_cve_fields(c)
        c["__score"] = score_f
        c["__sev"] = _severity_from_score(score_f)
        c["__title"] = title
        c["__desc"] = desc
        c["__links"] = links

    min_sev = params.severity if params.severity != "all" else "unknown"
    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    sev_rank = order[min_sev] if min_sev in order else 5
    filtered = [c for c in cve_items if order[c["__sev"]] <= sev_rank]

    counts = {s: 0 for s in _SEVERITY_ORDER}
    for c in cve_items:
        counts[c["__sev"]] += 1
    filtered.sort(key=lambda c: (-(c["__score"] or 0)))
    shown = filtered[: params.max_results]

    # --- header ---
    if is_windows:
        pkg_count_txt = (
            f"{len(kb_applied)} 个已应用"
            + (f"，{len(kb_unapplied)} 个缺失" if kb_unapplied else "")
        )
    else:
        pkg_count_txt = f"{len(packages)} 个" + (
            f"（{len(updatable)} 个有可用更新）" if updatable else ""
        )

    lines = [
        f"# 🩺 系统补丁审计报告 — {params.host}",
        "",
        "| 项目 | 值 |",
        "|---|---|",
        f"| 系统 | {family} {release} |",
        f"| 内核/Build | {kernel or 'n/a'} |",
        f"| {pkg_label} | {pkg_count_txt} |",
        f"| 漏洞总数 | {len(cve_items)} 个（未修复 CVE） |",
        f"| 扫描时间 | {_pick(data, 'scannedAt', 'ScannedAt', 'reportedAt', default='n/a')} |",
        "",
    ]

    if is_windows and kb_unapplied:
        lines += [
            "## 🚨 未安装的关键补丁（unapplied KB）",
            "",
            f"vuls 依据累积更新（rollup）规则判定以下 KB 应当已安装但缺失，"
            f"共 {len(kb_unapplied)} 个（列出前 20）：",
            "",
        ]
        lines += [f"- `KB{k}`" for k in kb_unapplied[:20]]
        if len(kb_unapplied) > 20:
            lines.append(f"- … 其余 {len(kb_unapplied) - 20} 个见完整数据")
        lines.append("")

    if not cve_items:
        lines += [
            "## ✅ 未发现未修复的已知 CVE",
            "",
            "已装补丁级别在漏洞数据库中没有匹配的未修复漏洞。"
            "（数据库覆盖范围有限，不代表绝对安全。）",
        ]
        return "\n".join(lines)

    # --- summary table ---
    lines += ["## 📊 漏洞概览", "", "| 严重度 | 数量 |", "|---|---|"]
    for s in _SEVERITY_ORDER:
        if counts[s]:
            lines.append(f"| {_SEVERITY_LABEL[s]} | {counts[s]} |")
    if params.severity != "all":
        lines.append("")
        lines.append(f"（以下仅列出 ≥ {min_sev} 的漏洞，共 {len(filtered)} 个）")

    # --- per-severity detail ---
    for s in _SEVERITY_ORDER:
        bucket = [c for c in shown if c["__sev"] == s]
        if not bucket:
            continue
        lines += ["", f"## {_SEVERITY_LABEL[s]}（{counts[s]}）", ""]
        for c in bucket:
            cve_id = c.get("__id") or _pick(c, "cveID", "cveId", "CveID",
                                            "CVEID", default="?")
            title = c.get("__title") or _pick(c, "title", "Title", default="")
            score = c["__score"]
            lines.append(f"### {cve_id} — {title or '无标题'}")
            for pkg in (_pick(c, "affectedPackages", "AffectedPackages",
                              default=[]) or [])[:5]:
                if not isinstance(pkg, dict):
                    continue
                pname = _pick(pkg, "name", "pkgName", "PkgName", default="?")
                pver = _pick(pkg, "installedVersion", "InstalledVersion",
                             "version", default="")
                pfix = _pick(pkg, "fixedIn", "FixedIn", "fixedVersion",
                             "FixedVersion", "newVersion", default="")
                not_fixed = _pick(pkg, "notFixedYet", "NotFixedYet")
                fix_txt = f"{pver} → {pfix}" if pfix else (
                    f"{pver}（暂无修复版本）" if not_fixed
                    else ("暂无修复版本" if not pver else pver)
                )
                lines.append(f"- 组件: `{pname}` — {fix_txt}")
            if score:
                lines.append(f"- CVSS: {score:g}")
            desc = c.get("__desc") or _pick(c, "description", "Description",
                                            default="")
            if desc:
                desc = desc.replace("\n", " ")
                lines.append(f"- 描述: {desc[:300]}{'…' if len(desc) > 300 else ''}")
            links = c.get("__links") or [
                r.get("Link") or r.get("link") or ""
                for r in (_pick(c, "references", "References", default=[])
                          or [])[:3]
                if isinstance(r, dict)
            ]
            links = [l for l in links if l][:3]
            if links:
                lines.append("- 参考: " + " · ".join(f"[{l}]({l})" for l in links))
            lines.append("")

    if len(filtered) > len(shown):
        lines.append(
            f"（另有 {len(filtered) - len(shown)} 条同级别以上漏洞未列出，"
            f"完整数据见工作目录 `{workdir}`）"
        )
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
