"""
Web recon pipeline — the ProjectDiscovery trio (subfinder + httpx + dnsx)
plus dalfox v3 (XSS attack step of the same pipeline).

🟡 Pentest level. Enable via PENTEST_ENABLED=true in .env.

Tools:
  1. subfinder_scan — passive subdomain discovery (60+ OSINT sources, zero
                      active traffic toward the target)
  2. httpx_probe    — batch probe of live web services (status/title/tech/ports)
  3. dnsx_lookup    — batch DNS record discovery (A/AAAA/CNAME/NS/MX/TXT/...)
  4. dalfox_scan    — XSS scan with verified, reproducible POCs (reflection + DOM)

Design notes:
  - All four emit JSON (JSON-native) and are parsed into structured
    Markdown for LLM consumption — no raw-dump fallback.
  - Command lists only, never shell=True; every user string passes
    _no_shell_meta plus a tool-specific shape check.
  - Input bounds: ≤200 targets/domains per call, port ≤65535, wall-clock
    timeouts on every run (partial results kept by the executor on timeout).

CLI ground truth (verified against upstream Go sources, main branch, and
live binaries):
  - subfinder: -d/--all/-s/-es/--json/--silent/--no-color/--disable-update-check;
    JSONL line = {"host", "input", "source"}
  - httpx: stdin input, -p (nmap syntax), --json/-j, --silent, --no-color,
    -t, --timeout (int seconds), -rl, -fr, --http2, --tech-detect;
    JSONL line = {"url","input","title","status_code","content_length",
    "content_type","webserver","tech":[...],"failed",...}
  - dnsx: -l (comma list → plain resolution; -d is brute-force mode and
    requires -w in released 1.3.x), per-type flags
    --a/--aaaa/--cname/--ns/--txt/--srv/--ptr/--mx/--soa/--caa/--any, -all,
    --json/-j, --or (omit raw), --silent, --no-color, --disable-update-check,
    -t, --timeout (Go duration, e.g. "10s"), --auto-wildcard;
    JSONL line = retryabledns.DNSData {"host","a":[],"aaaa":[],"mx":[],
    "txt":[],"ns":[],"soa":[...],"status_code",...}
  - dalfox v3 (live-verified against 3.2.2 --help, 2026-09-07): subcommand
    `scan`, JSON via `-f json` (NO --json flag in v3), `-S`, `--no-color`,
    `--workers`, `--timeout` (per-request s), `--scan-timeout` (0 = off),
    `--rate-limit`, `-X`, `-d`, `-H` (repeatable), `--cookies`, `-b`,
    `-p` (repeatable, optional name:type), `-F`, `--only-discovery`;
    JSON = {"findings": [{type V/R/A/I, severity, confidence, param,
    location, payload, data (POC URL), detection_method, ...}],
    "meta": {findings_count, total_requests, scan_duration_ms, ...}};
    exit 0 = clean, exit 1 = vulnerable findings (NOT an error)

Requires: subfinder, httpx, dnsx, dalfox (v3)
Install:  sudo apt install subfinder httpx dnsx -y
          dalfox is NOT in Kali apt — install the .deb from
          github.com/hahwul/dalfox/releases (e.g. dalfox-v3.2.2-linux-aarch64.deb)
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import get_executor
from kali_mcp.tools import (
    _is_valid_domain,
    _is_valid_target,
    _no_shell_meta,
)

# ---------------------------------------------------------------------------
# Shared validation helpers
# ---------------------------------------------------------------------------

#: Max entries (targets/domains) accepted per call.
_MAX_ENTRIES = 200

#: subfinder source names are lowercase alphanumeric (see `subfinder -ls`).
_SUBFINDER_SOURCE_RE = re.compile(r"^[a-z0-9]+$")

#: One httpx -p part: optional http:/https: scheme prefix, then a port or range.
_HTTPX_PORT_PART_RE = re.compile(r"^(?:(?:http|https):)?\d+(?:-\d+)?$")

#: dnsx record type → CLI flag (no --a-style short form exists; all long).
_DNSX_TYPE_FLAGS: dict[str, str] = {
    "a": "--a",
    "aaaa": "--aaaa",
    "cname": "--cname",
    "ns": "--ns",
    "txt": "--txt",
    "srv": "--srv",
    "ptr": "--ptr",
    "mx": "--mx",
    "soa": "--soa",
    "caa": "--caa",
    "any": "--any",
}


def _split_entries(v: str) -> list[str]:
    """Split a comma/space/newline separated entry list, dedup, preserve order."""
    seen: set[str] = set()
    out: list[str] = []
    for part in re.split(r"[,\s]+", v):
        part = part.strip()
        if part and part not in seen:
            seen.add(part)
            out.append(part)
    return out


def _httpx_entry_host(entry: str) -> str:
    """Extract the bare host from one httpx target entry.

    Handles 'host', 'host:port', 'http(s)://host[:port][/path[?q#f]]' and
    bracketed IPv6 URLs like 'http://[::1]:8080/'.
    """
    e = entry
    if "://" in e:
        e = e.split("://", 1)[1]
    e = e.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if e.startswith("["):
        end = e.find("]")
        return e[1:end] if end > 0 else e[1:]
    if e.count(":") == 1:
        host, _, port = e.rpartition(":")
        if port.isdigit():
            return host
    return e


def _validate_httpx_ports(v: str) -> str:
    """Validate an httpx -p spec (nmap syntax subset)."""
    v = v.strip()
    if not v:
        raise ValueError("ports must not be empty")
    _no_shell_meta(v)
    for part in v.split(","):
        part = part.strip()
        if not _HTTPX_PORT_PART_RE.match(part):
            raise ValueError(
                f"Invalid port part: {part!r} "
                "(use '80', '8000-8100', or 'http:8080,https:8443')"
            )
        num = part.split(":", 1)[1] if ":" in part else part
        lo_s, _, hi_s = num.partition("-")
        lo, hi = int(lo_s), int(hi_s or lo_s)
        if lo > 65535 or hi > 65535 or lo > hi:
            raise ValueError(f"Port range out of bounds: {part!r}")
    return ",".join(p.strip() for p in v.split(","))


def _parse_jsonl(stdout: str) -> list[dict]:
    """Parse a JSONL stream into a list of dicts, skipping non-JSON lines."""
    rows: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


# ===================================================================
# 1. subfinder — passive subdomain discovery
# ===================================================================


class SubfinderInput(BaseModel):
    """Input for subfinder passive subdomain discovery."""

    domain: str = Field(
        ...,
        description="Target root domain (e.g. 'example.com')",
        min_length=1,
        max_length=256,
    )
    all_sources: bool = Field(
        False,
        description="Use all sources including slow ones (default: fast curated set)",
    )
    sources: str = Field(
        "",
        max_length=256,
        description=(
            "Only these sources, comma-separated lowercase names "
            "(e.g. 'crtsh,wayback'). Empty = default set. List with `subfinder -ls`."
        ),
    )
    exclude_sources: str = Field(
        "",
        max_length=256,
        description="Exclude these sources, comma-separated (e.g. 'alienvault')",
    )
    timeout: int = Field(
        180,
        ge=10,
        le=600,
        description="Max wall-clock seconds for the run (partial results kept on timeout)",
    )
    max_results: int = Field(
        300, ge=1, le=2000, description="Max subdomains to list in the report"
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        _no_shell_meta(v)
        if not _is_valid_domain(v):
            raise ValueError(f"Invalid domain: {v}")
        return v

    @field_validator("sources", "exclude_sources")
    @classmethod
    def validate_sources(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
            for tok in v.split(","):
                tok = tok.strip()
                if not _SUBFINDER_SOURCE_RE.match(tok):
                    raise ValueError(
                        f"Invalid source name: {tok!r} (lowercase a-z0-9 only)"
                    )
            return ",".join(t.strip() for t in v.split(",") if t.strip())
        return ""


def _subfinder_cmd(params: SubfinderInput) -> list[str]:
    cmd = [
        "subfinder",
        "-d", params.domain,
        "--json",
        "--silent",
        "--no-color",
        "--disable-update-check",
    ]
    if params.all_sources:
        cmd.append("--all")
    if params.sources:
        cmd.extend(["-s", params.sources])
    if params.exclude_sources:
        cmd.extend(["-es", params.exclude_sources])
    return cmd


def _parse_subfinder(stdout: str) -> list[str]:
    """Collect unique subdomains from subfinder JSONL output."""
    subs: set[str] = set()
    for obj in _parse_jsonl(stdout):
        host = obj.get("host") or obj.get("domain")
        if isinstance(host, str) and host:
            subs.add(host.lower().rstrip("."))
    return sorted(subs)


def _subfinder_parent_counts(subs: list[str]) -> list[tuple[str, int]]:
    """Count subdomains grouped by their immediate parent domain."""
    counts: dict[str, int] = {}
    for s in subs:
        parts = s.split(".")
        if len(parts) < 3:
            continue  # root domain itself or direct label
        parent = ".".join(parts[1:])
        counts[parent] = counts.get(parent, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _subfinder_report(
    params: SubfinderInput, subs: list[str]
) -> str:
    mode = "全部源（含慢源）" if params.all_sources else "默认快速源集"
    if params.sources:
        mode += f"（限定: {params.sources}）"
    lines = [
        f"## 🔭 Subfinder 被动子域发现 — {params.domain}",
        f"**源模式:** {mode}",
        f"**发现:** {len(subs)} 个子域（去重后）",
        "",
    ]
    if not subs:
        lines.append(
            "> ✅ 未发现子域。被动源无结果不代表目标不存在，"
            "可尝试 all_sources=true 扩大源范围。"
        )
        return "\n".join(lines)

    parents = _subfinder_parent_counts(subs)
    if parents:
        lines.append("### 📊 父域分布（Top 10）")
        for parent, count in parents[:10]:
            lines.append(f"- `{parent}`: {count}")
        lines.append("")

    lines.append(f"### 📋 子域列表（前 {min(len(subs), params.max_results)} 个）")
    lines.append("```")
    lines.extend(subs[: params.max_results])
    lines.append("```")
    if len(subs) > params.max_results:
        lines.append(f"… 其余 {len(subs) - params.max_results} 个未列出")

    lines.append("")
    lines.append(
        "> 后续建议：把子域清单交给 httpx_probe 探测存活 web 服务，"
        "再对存活目标跑 nuclei_scan。"
    )
    return "\n".join(lines)


async def subfinder_scan(params: SubfinderInput) -> str:
    """Passive subdomain discovery with subfinder (zero active traffic).

    Aggregates 60+ public OSINT sources (crt.sh, Wayback, DNSDumpster,
    Threatminer, ...) to enumerate subdomains WITHOUT sending any active
    traffic to the target — safe first step of a web recon pipeline.

    Output: deduplicated subdomain list + parent-domain distribution,
    ready to feed into httpx_probe.

    Requires: subfinder (sudo apt install subfinder -y)
    """
    executor = get_executor(timeout=params.timeout)
    cmd = _subfinder_cmd(params)
    result = await executor.run(cmd, timeout=params.timeout)

    if not result.success:
        diag = (result.stderr or result.stdout or "")[:500]
        return (
            f"## 🔭 Subfinder 被动子域发现 — {params.domain}\n"
            f"**命令:** `{' '.join(cmd)}`\n\n"
            f"❌ subfinder 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 若未安装：`sudo apt install subfinder -y`"
        )

    subs = _parse_subfinder(result.stdout)
    return _subfinder_report(params, subs)


# ===================================================================
# 2. httpx — batch probe of live web services
# ===================================================================


class HttpxInput(BaseModel):
    """Input for httpx live web service probing."""

    targets: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description=(
            "Comma/space separated targets: IPs, hostnames, host:port, or full "
            "URLs (e.g. 'example.com, 192.168.0.1:8080, http://10.0.0.5'). "
            "Max 200 entries."
        ),
    )
    ports: str = Field(
        "80,443",
        max_length=256,
        description=(
            "Ports to probe, nmap syntax: '80,443', '8000-8100', "
            "'http:8080,https:8443' (scheme prefix forces the protocol)"
        ),
    )
    threads: int = Field(50, ge=1, le=200, description="Concurrent probe threads")
    timeout: int = Field(10, ge=1, le=60, description="Per-request timeout in seconds")
    wall_timeout: int = Field(
        300, ge=10, le=3600,
        description="Max wall-clock seconds for the whole probe",
    )
    follow_redirects: bool = Field(False, description="Follow HTTP redirects")
    http2: bool = Field(False, description="Probe for HTTP/2 support")
    tech_detect: bool = Field(
        True, description="Detect technologies via the wappalyzer dataset"
    )
    rate_limit: int = Field(150, ge=1, le=1000, description="Max requests per second")
    max_results: int = Field(
        100, ge=1, le=500, description="Max live-service rows to list in the report"
    )

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: str) -> str:
        _no_shell_meta(v)
        entries = _split_entries(v)
        if not entries:
            raise ValueError("No targets given")
        if len(entries) > _MAX_ENTRIES:
            raise ValueError(f"At most {_MAX_ENTRIES} targets per call")
        for entry in entries:
            host = _httpx_entry_host(entry)
            if not host or not _is_valid_target(host):
                raise ValueError(f"Invalid target host: {host!r}")
        return v

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        return _validate_httpx_ports(v)


def _httpx_cmd(params: HttpxInput) -> list[str]:
    cmd = [
        "httpx",
        "--json",
        "--silent",
        "--no-color",
        "-p", params.ports,
        "-t", str(params.threads),
        "--timeout", str(params.timeout),
        "-rl", str(params.rate_limit),
        # Display flags: keep the JSON payload complete (title/tech only
        # appear in output when extraction is enabled).
        "--status-code",
        "--title",
        "--content-length",
        "--content-type",
        "--web-server",
    ]
    if params.tech_detect:
        cmd.append("--tech-detect")
    if params.follow_redirects:
        cmd.extend(["-fr"])
    if params.http2:
        cmd.append("--http2")
    return cmd


def _httpx_input_text(params: HttpxInput) -> str:
    return "\n".join(_split_entries(params.targets))


def _httpx_live_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if isinstance(r.get("status_code"), int) and r.get("status_code")]


def _httpx_report(
    params: HttpxInput, rows: list[dict], total_targets: int
) -> str:
    live = _httpx_live_rows(rows)
    live_inputs = {
        str(r.get("input", "")).lower() for r in live
    }
    status_counts: dict[int, int] = {}
    for r in live:
        status_counts[r["status_code"]] = status_counts.get(r["status_code"], 0) + 1

    lines = [
        "## 🌐 httpx Web 服务探测",
        f"**目标:** {total_targets} 个 | **存活服务:** {len(live)} 条 | "
        f"**无响应目标:** {max(0, total_targets - len(live_inputs))} 个",
        "",
    ]

    if not live:
        lines.append(
            "> ✅ 未发现存活的 web 服务。端口/协议可能不匹配，"
            "可调整 ports（如 '80,443,8080'）或 follow_redirects 重试。"
        )
        return "\n".join(lines)

    lines.append("### 📊 状态码分布")
    for code in sorted(status_counts):
        lines.append(f"- `{code}`: {status_counts[code]}")
    lines.append("")

    lines.append("### 📋 存活服务（前 {} 条）".format(min(len(live), params.max_results)))
    lines.append("| URL | 状态 | 标题 | 技术栈 | 服务器 | 大小 |")
    lines.append("|---|---|---|---|---|---|")
    for r in live[: params.max_results]:
        url = r.get("url") or r.get("input", "?")
        status = r.get("status_code", "?")
        title = (r.get("title") or "").strip()
        title = title.replace("|", "\\|")[:60]
        tech = r.get("tech") or []
        if isinstance(tech, list):
            tech_txt = ", ".join(str(t) for t in tech[:4])
            if len(tech) > 4:
                tech_txt += f" (+{len(tech) - 4})"
        else:
            tech_txt = str(tech)
        server = (
            r.get("webserver")
            or r.get("web_server")
            or r.get("server")
            or ""
        )
        server = str(server).replace("|", "\\|")[:40]
        cl = r.get("content_length")
        size = f"{cl / 1024:.1f}KB" if isinstance(cl, int) and cl > 0 else (
            f"{cl}B" if isinstance(cl, int) else "?"
        )
        lines.append(
            f"| `{url}` | {status} | {title or '-'} | {tech_txt or '-'} | "
            f"{server or '-'} | {size} |"
        )
    if len(live) > params.max_results:
        lines.append(f"… 其余 {len(live) - params.max_results} 条未列出")

    lines.append("")
    lines.append(
        "> 后续建议：对高价值目标跑 nuclei_scan 漏洞扫描，或用 ffuf_fuzz 挖隐藏路径。"
    )
    return "\n".join(lines)


async def httpx_probe(params: HttpxInput) -> str:
    """Batch-probe live web services with httpx (status/title/tech/ports).

    Sends one HTTP(S) request per target×port and reports which services
    are alive, their status codes, page titles, detected technology
    stack (wappalyzer), server header and content size. The middle step
    of the web recon pipeline: subfinder (find hosts) → httpx (find live
    web) → nuclei/ffuf (attack surface).

    Input is piped via stdin; targets are IPs, hostnames, host:port or
    full URLs. Port spec uses nmap syntax ('http:8080' forces HTTP on 8080).

    Requires: httpx (sudo apt install httpx -y)
    """
    executor = get_executor(timeout=params.wall_timeout)
    cmd = _httpx_cmd(params)
    entries = _split_entries(params.targets)
    result = await executor.run(
        cmd, timeout=params.wall_timeout, input_data="\n".join(entries)
    )

    if not result.success and not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            f"## 🌐 httpx Web 服务探测\n"
            f"**目标:** {len(entries)} 个 | **端口:** {params.ports}\n\n"
            f"❌ httpx 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 若未安装：`sudo apt install httpx -y`"
        )

    rows = _parse_jsonl(result.stdout)
    return _httpx_report(params, rows, len(entries))


# ===================================================================
# 3. dnsx — batch DNS record discovery
# ===================================================================


class DnsxInput(BaseModel):
    """Input for dnsx batch DNS record discovery."""

    domains: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description=(
            "Comma/newline separated domains (e.g. 'example.com, sub.example.com'). "
            "Max 200 entries."
        ),
    )
    record_types: str = Field(
        "a,aaaa,cname,ns,txt,mx",
        max_length=128,
        description=(
            "Record types to query, comma-separated from: "
            "a,aaaa,cname,ns,txt,srv,ptr,mx,soa,caa,any"
        ),
    )
    all_records: bool = Field(
        False, description="Query ALL record types (overrides record_types)"
    )
    auto_wildcard: bool = Field(
        True, description="Auto-detect and filter wildcard domains"
    )
    timeout: int = Field(
        10, ge=1, le=60, description="Per-DNS-query timeout in seconds"
    )
    threads: int = Field(100, ge=1, le=500, description="Concurrent resolution threads")
    wall_timeout: int = Field(
        180, ge=10, le=1800, description="Max wall-clock seconds for the run"
    )
    max_results: int = Field(
        200, ge=1, le=1000, description="Max hosts to list in the report"
    )

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v: str) -> str:
        _no_shell_meta(v)
        entries = _split_entries(v)
        if not entries:
            raise ValueError("No domains given")
        if len(entries) > _MAX_ENTRIES:
            raise ValueError(f"At most {_MAX_ENTRIES} domains per call")
        for d in entries:
            if not _is_valid_domain(d):
                raise ValueError(f"Invalid domain: {d!r}")
        return v

    @field_validator("record_types")
    @classmethod
    def validate_record_types(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("record_types must not be empty (or use all_records=true)")
        for tok in v.split(","):
            tok = tok.strip()
            if tok not in _DNSX_TYPE_FLAGS:
                raise ValueError(
                    f"Unknown record type: {tok!r} "
                    f"(valid: {', '.join(sorted(_DNSX_TYPE_FLAGS))})"
                )
        return ",".join(t.strip() for t in v.split(",") if t.strip())


def _dnsx_cmd(params: DnsxInput) -> list[str]:
    domains = _split_entries(params.domains)
    cmd = [
        "dnsx",
        # -l (list) = plain resolution of the given hosts.
        # -d (domain) is BRUTE-FORCE mode and REQUIRES a wordlist in the
        # released 1.3.x builds ("[FTL] missing wordlist(w) flag required
        # with domain(d) input") — only the main-branch build falls back
        # to resolution, so -d must not be used here.
        "-l", ",".join(domains),
        "--json",
        "--or",  # omit raw DNS response from JSONL (keep payload small)
        "--silent",
        "--no-color",
        "--disable-update-check",
    ]
    if params.all_records:
        cmd.append("-all")
    else:
        for tok in params.record_types.split(","):
            cmd.append(_DNSX_TYPE_FLAGS[tok])
    if params.auto_wildcard:
        cmd.append("--auto-wildcard")
    cmd.extend([
        "-t", str(params.threads),
        "--timeout", f"{params.timeout}s",
    ])
    return cmd


def _dnsx_report(params: DnsxInput, rows: list[dict]) -> str:
    rows = [r for r in rows if r.get("host")]
    internal: list[tuple[str, list[str]]] = []
    for r in rows:
        if r.get("internal_ips"):
            internal.append((r["host"], list(r["internal_ips"])))

    lines = [
        "## 🧬 dnsx 批量 DNS 记录发现",
        f"**域:** {len(_split_entries(params.domains))} 个 | "
        f"**有记录主机:** {len(rows)} 个",
        f"**查询类型:** {'全部' if params.all_records else params.record_types}",
        "",
    ]
    if not rows:
        lines.append(
            "> ✅ 未发现 DNS 记录。检查域名拼写，或换 resolver/放宽 "
            "record_types（如 soa,ns）重试。"
        )
        return "\n".join(lines)

    lines.append("| 主机 | A | AAAA | MX | NS | TXT |")
    lines.append("|---|---|---|---|---|---|")
    for r in rows[: params.max_results]:
        def _cell(key: str, limit: int = 3, maxlen: int = 40) -> str:
            vals = r.get(key) or []
            if isinstance(vals, str):
                vals = [vals]
            txt = ", ".join(str(v) for v in vals[:limit])
            if len(vals) > limit:
                txt += f" (+{len(vals) - limit})"
            if len(txt) > maxlen:
                txt = txt[:maxlen] + "…"
            return txt.replace("|", "\\|") or "-"

        host = str(r.get("host", "?"))
        soa = r.get("soa") or []
        soa_txt = ""
        if isinstance(soa, list) and soa and isinstance(soa[0], dict):
            soa_txt = str(soa[0].get("name") or soa[0].get("ns") or "")
        if soa_txt:
            host += f"  (SOA: {soa_txt})"

        lines.append(
            f"| `{host}` | {_cell('a', 3, 32)} | {_cell('aaaa', 2, 36)} | "
            f"{_cell('mx', 2, 32)} | {_cell('ns', 2, 32)} | {_cell('txt', 2, 48)} |"
        )
    if len(rows) > params.max_results:
        lines.append(f"… 其余 {len(rows) - params.max_results} 个主机未列出")

    if internal:
        lines.append("")
        lines.append("### 🏠 内网 IP 提示")
        for host, ips in internal[:20]:
            lines.append(f"- `{host}` → {', '.join(ips)}")

    lines.append("")
    lines.append(
        "> 后续建议：把 subfinder_scan 发现的子域喂给本工具补全记录，"
        "再用 httpx_probe 确认哪些主机开着 web 服务。"
    )
    return "\n".join(lines)


async def dnsx_lookup(params: DnsxInput) -> str:
    """Batch DNS record discovery with dnsx (A/AAAA/CNAME/NS/MX/TXT/...).

    Resolves the requested record types for a list of domains and renders
    a per-host table. Flags hosts whose answers contain internal (RFC1918
    / ULA) IPs — useful when mapping a target's shadow infrastructure.

    The DNS step of the web recon pipeline: subfinder (names) → dnsx
    (records) → httpx (live web).

    Requires: dnsx (sudo apt install dnsx -y)
    """
    executor = get_executor(timeout=params.wall_timeout)
    cmd = _dnsx_cmd(params)
    result = await executor.run(cmd, timeout=params.wall_timeout)

    if not result.success and not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🧬 dnsx 批量 DNS 记录发现\n"
            f"**域:** {params.domains}\n\n"
            f"❌ dnsx 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 若未安装：`sudo apt install dnsx -y`"
        )

    rows = _parse_jsonl(result.stdout)
    return _dnsx_report(params, rows)


# ===================================================================
# 4. dalfox — XSS scanning (verified POCs: reflection + DOM)
# ===================================================================

#: dalfox v3 finding type legend (ground truth from live v3.2.2 output).
_DALFOX_TYPE_LEGEND: dict[str, str] = {
    "V": "vulnerable",
    "R": "reflected",
    "A": "ast-dom",
    "I": "info",
}

_DALFOX_METHOD_RE = re.compile(r"^[A-Z]{2,10}$")
_DALFOX_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_DALFOX_PARAM_RE = re.compile(
    r"^[A-Za-z0-9_.\-\[\]]{1,64}(?::(?:query|body|json|cookie|header))?$"
)


def _validate_dalfox_url(v: str) -> str:
    v = v.strip()
    if not v.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    # Query strings legitimately contain shell metachars (& ; = + % ...).
    # The command runs as an argv list (no shell), so only the host part
    # gets the shell-meta scrutiny plus a control-char check on the whole.
    if any(c in v for c in "\r\n\x00"):
        raise ValueError("url must not contain control characters")
    _no_shell_meta(_httpx_entry_host(v))
    return v


def _split_header_pairs(v: str) -> list[str]:
    """Split a comma-separated 'Name: value' list into dalfox -H values.

    Values may contain colons (e.g. 'Referer: http://x/') — each pair is
    split on its FIRST colon only.
    """
    out: list[str] = []
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition(":")
        if not sep or not _DALFOX_HEADER_NAME_RE.match(name.strip()):
            raise ValueError(
                f"invalid header pair: {part!r} (expected 'Name: value')"
            )
        out.append(f"{name.strip()}:{value.strip()}")
    return out


class DalfoxInput(BaseModel):
    """Input for dalfox v3 XSS scan."""

    url: str = Field(
        ...,
        description=(
            "Target URL to scan (http/https), e.g. "
            "http://192.168.0.1:80/login.php?id=1"
        ),
        min_length=10,
        max_length=2048,
    )
    params: str = Field(
        default="",
        description=(
            "Optional parameter names to analyze, comma-separated; an "
            "optional type suffix after ':' (query, body, json, cookie, "
            "header), e.g. 'id,q:body'"
        ),
        max_length=512,
    )
    method: str = Field(
        default="GET",
        description="HTTP method override (GET, POST, PUT, DELETE, ...)",
        max_length=10,
    )
    data: str = Field(
        default="",
        description="Optional HTTP request body (for POST etc.)",
        max_length=4096,
    )
    headers: str = Field(
        default="",
        description=(
            "Optional extra HTTP headers, comma-separated 'Name: value' "
            "pairs, e.g. 'X-Api-Token: abc,Referer: http://x.example/'"
        ),
        max_length=1024,
    )
    cookies: str = Field(
        default="",
        description="Optional raw Cookie header value, e.g. 'session=abc123'",
        max_length=2048,
    )
    blind: str = Field(
        default="",
        description="Optional blind-XSS callback URL (dalfox -b)",
        max_length=512,
    )
    workers: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Concurrent workers (dalfox default 50)",
    )
    timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Per-request timeout in seconds (network only)",
    )
    scan_timeout: int = Field(
        default=120,
        ge=0,
        le=3600,
        description=(
            "Wall-clock cap in seconds for the payload-injection stage per "
            "target (dalfox --scan-timeout; 0 = off)"
        ),
    )
    rate_limit: int = Field(
        default=0,
        ge=0,
        le=500,
        description="Global request-rate cap in req/s across all workers (0 = unlimited)",
    )
    follow_redirects: bool = Field(
        default=False,
        description="Follow HTTP redirects (dalfox -F)",
    )
    discovery_only: bool = Field(
        default=False,
        description="Only discover parameters, do not send XSS payloads",
    )
    wall_timeout: int = Field(
        default=300,
        ge=30,
        le=1800,
        description="Overall wall-clock timeout in seconds (partial results kept)",
    )
    max_results: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Max findings rendered in the report",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_dalfox_url(v)

    @field_validator("params")
    @classmethod
    def validate_params(cls, v: str) -> str:
        for token in _split_entries(v):
            if not _DALFOX_PARAM_RE.match(token):
                raise ValueError(f"invalid param spec: {token!r}")
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        v = v.strip().upper()
        if not _DALFOX_METHOD_RE.match(v):
            raise ValueError(f"invalid HTTP method: {v!r}")
        return v

    @field_validator("data")
    @classmethod
    def validate_data(cls, v: str) -> str:
        if v:
            # Bodies legitimately contain & ; = $ { } (form data, JSON).
            # Execution is an argv list — no shell — so only control
            # characters are rejected.
            if any(c in v for c in "\r\n\x00"):
                raise ValueError("data must not contain control characters")
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: str) -> str:
        if v:
            _split_header_pairs(v)  # validates pair shape and header names
            # Values may contain & ; = (query strings, cookie lists); the
            # argv-list execution makes shell chars inert. Control chars
            # are the real danger (HTTP header injection).
            if any(c in v for c in "\r\n\x00"):
                raise ValueError("headers must not contain control characters")
        return v

    @field_validator("cookies")
    @classmethod
    def validate_cookies(cls, v: str) -> str:
        if v:
            if any(c in v for c in "\r\n\x00"):
                raise ValueError("cookies must not contain control characters")
        return v

    @field_validator("blind")
    @classmethod
    def validate_blind(cls, v: str) -> str:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("blind callback must be an http(s) URL")
        return v


def _dalfox_cmd(params: DalfoxInput) -> list[str]:
    """Build the dalfox v3 command.

    Ground truth (dalfox v3.2.2 --help, live-verified 2026-09-07):
      - subcommand `scan`, positional TARGET
      - JSON via `-f json` (there is NO --json flag in v3)
      - `-S` silence, `--no-color`, `--workers`, `--timeout` (per-request s),
        `--scan-timeout` (injection-stage cap, 0 = off), `--rate-limit`,
        `-X` method, `-d` body, `-H` header (repeatable), `--cookies`,
        `-b` blind callback, `-p` param (repeatable), `-F` follow redirects,
        `--only-discovery`
    """
    cmd = ["dalfox", "scan"]
    cmd.extend(["-f", "json", "-S", "--no-color"])
    cmd.extend(["--workers", str(params.workers)])
    cmd.extend(["--timeout", str(params.timeout)])
    if params.scan_timeout > 0:
        cmd.extend(["--scan-timeout", str(params.scan_timeout)])
    if params.rate_limit > 0:
        cmd.extend(["--rate-limit", str(params.rate_limit)])
    if params.follow_redirects:
        cmd.append("-F")
    if params.discovery_only:
        cmd.append("--only-discovery")
    if params.method != "GET":
        cmd.extend(["-X", params.method])
    if params.data:
        cmd.extend(["-d", params.data])
    for h in _split_header_pairs(params.headers):
        cmd.extend(["-H", h])
    if params.cookies:
        cmd.extend(["--cookies", params.cookies])
    if params.blind:
        cmd.extend(["-b", params.blind])
    for p in _split_entries(params.params):
        cmd.extend(["-p", p])
    cmd.append(params.url)
    return cmd


def _parse_dalfox(stdout: str) -> tuple[list[dict], dict]:
    """Extract (findings, meta) from dalfox `-f json` output.

    Ground-truth shape (dalfox 3.2.2, live-verified 2026-09-07):
        {"findings": [{type, severity, confidence, confidence_reason,
                       param, location, payload, data, method,
                       detection_method, cwe, ...}],
         "meta": {dalfox_version, findings_count, scan_duration_ms,
                  total_requests, target_summary, ...}}
    Note: exit code is 0 when clean and 1 when vulnerable findings exist —
    the presence of findings is authoritative, not the exit code.
    """
    try:
        start = stdout.index("{")
        doc = json.loads(stdout[start : stdout.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return [], {}
    if not isinstance(doc, dict):
        return [], {}
    findings = doc.get("findings")
    meta = doc.get("meta")
    return (
        findings if isinstance(findings, list) else [],
        meta if isinstance(meta, dict) else {},
    )


def _dalfox_report(params: DalfoxInput, findings: list[dict], meta: dict) -> str:
    mode = (
        "parameter discovery only"
        if params.discovery_only
        else "XSS scan (reflection + DOM)"
    )
    lines = [
        "## 🦊 dalfox XSS 扫描",
        f"**目标:** {params.url}",
        f"**模式:** {mode}",
        "",
    ]
    if meta:
        lines.append(
            f"**统计:** {meta.get('findings_count', 0)} findings · "
            f"{meta.get('total_requests', '?')} requests · "
            f"{meta.get('scan_duration_ms', 0)} ms"
        )
        lines.append("")
    if not findings:
        lines.append("✅ 未发现 XSS（扫描干净）。")
        return "\n".join(lines)

    vuln = [f for f in findings if f.get("type") == "V"]
    if vuln:
        lines.append(
            f"🔴 **{len(vuln)} 个已验证可利用的 XSS** "
            f"（dalfox 退出码 1 = 发现漏洞，非执行失败）"
        )
        lines.append("")

    shown = findings[: params.max_results]
    lines.extend(
        [
            "| 严重度 | 类型 | 参数 | 位置 | Payload |",
            "|--------|------|------|------|---------|",
        ]
    )
    for f in shown:
        ftype = f.get("type", "?")
        legend = _DALFOX_TYPE_LEGEND.get(ftype, f.get("type_description", ""))
        payload = (f.get("payload") or "").replace("|", "\\|")[:120]
        lines.append(
            f"| {f.get('severity', '?')} | {ftype} ({legend}) "
            f"| `{f.get('param', '?')}` | {f.get('location', '?')} "
            f"| `{payload}` |"
        )
    if len(findings) > len(shown):
        lines.append(
            f"\n… 另有 {len(findings) - len(shown)} 条未显示 "
            f"(max_results={params.max_results})"
        )

    poc = [f for f in shown if f.get("data")]
    if poc:
        lines.extend(["", "### 🧪 可复现 POC", ""])
        for f in poc:
            lines.append(
                f"- `{f.get('data')}` "
                f"(参数 `{f.get('param', '?')}`，{f.get('detection_method', '?')})"
            )

    other = [f for f in findings if f.get("type") != "V"]
    if other:
        lines.append(
            f"\nℹ️ 另有 {len(other)} 条仅反射/信息类发现（未验证可利用）。"
        )
    lines.extend(
        [
            "",
            "> 后续建议：浏览器手动验证 POC URL；同一主机可跑 `nuclei_scan` "
            "查已知 CVE，`ffuf_fuzz` 补目录/参数面。",
        ]
    )
    return "\n".join(lines)


async def dalfox_scan(params: DalfoxInput) -> str:
    """Scan a web endpoint for XSS with dalfox v3 (verified, reproducible POCs).

    dalfox runs parameter discovery, then injects its XSS payload catalog
    with DOM verification. A 'V' finding means dalfox proved the payload
    reached an executable position in the response — the report includes
    the reproducible POC URL. 'R' = reflected but not verified,
    'A' = static DOM-analysis candidate, 'I' = informational.

    ACTIVE scanning: sends many crafted requests to the target. Only scan
    applications you own or are authorized to test.

    The attack step of the web pipeline: subfinder (hosts) → httpx (live
    web) → dalfox (XSS) / nuclei (CVEs).

    Requires: dalfox v3 (NOT in Kali apt; install the .deb from
    github.com/hahwul/dalfox/releases)
    """
    executor = get_executor(timeout=params.wall_timeout)
    cmd = _dalfox_cmd(params)
    result = await executor.run(cmd, timeout=params.wall_timeout)

    if not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🦊 dalfox XSS 扫描\n"
            f"**目标:** {params.url}\n\n"
            f"❌ dalfox 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 若未安装（Kali apt 无此包）：从 github.com/hahwul/dalfox/"
            "releases 下载 `dalfox-v3.*-linux-<arch>.deb` 后 "
            "`sudo dpkg -i`"
        )

    findings, meta = _parse_dalfox(result.stdout)
    return _dalfox_report(params, findings, meta)


# ===================================================================
# Registry
# ===================================================================

RECON_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "subfinder_scan": (subfinder_scan, SubfinderInput),
    "httpx_probe": (httpx_probe, HttpxInput),
    "dnsx_lookup": (dnsx_lookup, DnsxInput),
    "dalfox_scan": (dalfox_scan, DalfoxInput),
}
