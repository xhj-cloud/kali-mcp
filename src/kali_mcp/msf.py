"""
Metasploit RPC bridge — exploit execution + session management over msfrpcd.

Closes the "find vulnerability → exploit → get shell → command" loop:
  msf_search → msf_show_opts → msf_run_exploit (🔴, runs as an msf job)
  → msf_jobs / msf_sessions → msf_session_exec (meterpreter/shell commands)

Gating:
  🟡 PENTEST_ENABLED=true  — msf_search, msf_show_opts, msf_job_info,
                             msf_log (read-only)
  🔴 ATTACK_ENABLED=true   — msf_run_exploit, msf_jobs, msf_stop_job,
                             msf_sessions, msf_kill_session,
                             msf_session_exec

Implementation: pymetasploit3 (Kali apt: python3-pymetasploit3, the
DanMcInerney fork maintained by the Kali team). The client is synchronous
(requests-based msgpack JSON-RPC), so every call runs in a worker thread
with a wall-clock timeout; msfrpcd-side jobs keep running after a timeout
and can be stopped with msf_stop_job.

msfrpcd daemon (systemd, one-time setup — see setup.sh _msfrpcd_setup):
  - binds 127.0.0.1:55553 only (never exposed on the network)
  - `-S` (no SSL — loopback only), `-n` (no DB), `-f` (foreground)
  - password from .env (MSF_RPC_PASSWORD), never committed
  - WorkingDirectory=/usr/share/metasploit-framework — REQUIRED: with
    CWD=/, Rails config.root=/ makes bootsnap recursively scan /lib
    (→ /usr/lib) and crash with ELOOP on Kali's llvm-21/build/Release
    symlink loop (verified 2026-09-07 on Kali arm64).

pymetasploit3 ground truth (live-verified against Kali 6.5.0 msfrpcd,
python3-pymetasploit3 1.0.3+git20250715, 2026-09-07):
  - MsfRpcClient(password, username=, server=, port=, ssl=False) logs in
    immediately and adds a persistent API token; set
    client.persistentlogin=False + client.logout() to remove it again.
  - modules.search(q) → LIST of {type, name, fullname, rank,
    disclosuredate} (no 'desc' field; broad keyword match).
  - modules.use(mtype, mname) → module object; .info dict uses key
    'description' (NOT 'desc'); .optioninfo(name) → {type, required,
    advanced, evasion, default, enums?, desc}; unknown module raises an
    internal TypeError ('bool' object is not subscriptable).
  - modules.execute(mtype, mname, **opts) → {'job_id': int|None,
    'uuid': str|None}. Unknown option names are SILENTLY ignored
    server-side → validate client-side against module options + globals.
    Missing required option → job_id is None (NO exception).
  - jobs.list / sessions.list are PROPERTIES (not methods);
    sessions.list keys are native INTS ({6: {...}}), job list keys too.
  - sessions.session(sid) is BROKEN in this package version
    (_create_session passes the whole list as the session description →
    int key hits re.match → TypeError). Bypassed by constructing
    MeterpreterSession/ShellSession(sid, client, description) directly.
  - meterpreter: 'session.meterpreter_run_single' then poll
    'session.meterpreter_read' — a bare immediate read() races the
    output arriving in the session ring (verified: returns '').
  - shell: 'session.shell_write' + poll 'session.shell_read'.
  - Payload naming is linux/aarch64/* (NOT arm64); msfvenom -f elf for a
    directly executable binary (raw shellcode cannot be exec'd).

Job-table & log ground truth (live-verified against Kali 6.5.0 msfrpcd
+ framework source, 2026-09-10):
  - jobs.info(jid) returns METADATA ONLY (jid/name/start_time/datastore)
    — there is no module-output field, ever. The job table is in-memory
    and a finished job is deleted the instant it ends (Rex::Job#start
    ensure block → JobContainer#remove_job, lib/rex/job.rb), so finished
    and never-existed ids both return {"error_message": "Invalid Job"}.
    msfconsole behaves the same (jobs shows running only).
  - Module print_* output (login lines, scan results, exploit banners)
    goes to the daemon's stdout. Our systemd unit appends stdout+stderr
    to /var/log/metasploit-framework/msfrpcd.log — the journald stdout
    stream for the daemon has been observed DEAD on Kali (writes to fd 1
    vanish; only the stderr stream survives), so the file is the
    reliable sink. _msf_log reads the file first, falls back to
    journalctl -u msfrpcd. The MSF Logger file
    (~/.msf4/logs/framework.log) only carries framework-level
    [d(0)]/[e(0)] entries — NOT module output.
  - modules.execute payload key: the server checks ONLY the ALL-CAPS
    'PAYLOAD' option (lib/msf/core/rpc/v10/rpc_module.rb _run_exploit);
    a mixed-case 'Payload=...' slips past that check and the handler
    silently receives the framework default payload (verified:
    Payload=linux/x64/shell_reverse_tcp → datastore PAYLOAD=
    windows/meterpreter/reverse_tcp). _execute normalizes both
    spellings to PAYLOAD and rejects conflicting pairs.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from kali_mcp.tools import _is_valid_target, _no_nul_or_newline, _no_shell_meta

# Optional dependency: import at module level so the tool can report a
# clean "not installed" message at call time instead of crashing import.
try:
    from pymetasploit3.msfrpc import MeterpreterSession, ShellSession
except ImportError:  # non-Kali host / tests
    MeterpreterSession = None  # type: ignore[assignment]
    ShellSession = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# msfrpcd connection config (all via environment / .env — never committed)
# ---------------------------------------------------------------------------

_MSFRPCD_DEFAULT_HOST = "127.0.0.1"
_MSFRPCD_DEFAULT_PORT = 55553
_MSFRPCD_DEFAULT_USER = "msf"

#: Option names msfrpcd accepts even when a module does not declare them
#: (framework globals + payload slot). Everything else must be a declared
#: module option — the server silently ignores unknown names.
#:
#: PAYLOAD is a framework global, NOT a module option (live-verified
#: 2026-09-10: exploit/multi/handler's option list is
#: ContextInformationFile/DisablePayloadHandler/EnableContextEncoding/
#: ExitOnSession/ListenerTimeout/VERBOSE/WORKSPACE/WfsDelay — no
#: PAYLOAD, no LHOST/LPORT either). rpc_module.rb _run_exploit reads
#: ONLY the ALL-CAPS 'PAYLOAD' key from the datastore; a mixed-case
#: 'Payload' lands in the datastore under a different key, leaves
#: 'PAYLOAD' blank and silently falls back to the default payload.
#: Both spellings are whitelisted here; _execute normalizes to PAYLOAD.
_GLOBAL_OPTION_WHITELIST = frozenset({
    "RHOST", "RPORT", "LHOST", "LPORT", "LPORT2",
    "Payload", "PAYLOAD", "AutoRunScript", "Session",
})

_MODULE_TYPE_RE = re.compile(r"^(exploit|auxiliary|post|payload|encoder|nop)$")
_OPTION_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_UUID_RE = re.compile(r"^[0-9A-Za-z]{8,64}$")


class MsfConfigError(Exception):
    """msfrpcd / client library not configured on this host."""


class MsfConnectionError(Exception):
    """msfrpcd daemon unreachable."""


def _msf_env() -> dict:
    """Read msfrpcd connection settings from the environment."""
    host = os.getenv("MSF_RPC_HOST", _MSFRPCD_DEFAULT_HOST)
    try:
        port = int(os.getenv("MSF_RPC_PORT", str(_MSFRPCD_DEFAULT_PORT)))
    except ValueError as e:
        raise MsfConfigError("MSF_RPC_PORT must be an integer") from e
    user = os.getenv("MSF_RPC_USER", _MSFRPCD_DEFAULT_USER)
    password = os.getenv("MSF_RPC_PASSWORD", "")
    if not password:
        raise MsfConfigError(
            "MSF_RPC_PASSWORD 未在 .env 中配置——"
            "运行 setup.sh（--tool-level full）或手动设置 MSF_RPC_PASSWORD "
            "并确保 msfrpcd systemd 服务已启动（systemctl status msfrpcd）"
        )
    return {"host": host, "port": port, "user": user, "password": password}


def _make_client():
    """Create an authenticated msfrpc client. BLOCKING — run in a thread."""
    cfg = _msf_env()  # config check first (most common setup problem)
    if MeterpreterSession is None:
        raise MsfConfigError(
            "pymetasploit3 未安装——sudo apt install python3-pymetasploit3"
        )
    from pymetasploit3 import msfrpc

    try:
        client = msfrpc.MsfRpcClient(
            cfg["password"],
            username=cfg["user"],
            server=cfg["host"],
            port=cfg["port"],
            ssl=False,
        )
    except Exception as e:
        raise MsfConnectionError(
            f"无法连接 msfrpcd {cfg['host']}:{cfg['port']}（{type(e).__name__}: {e}）"
        ) from e
    # Remove the API token on logout so repeated tool calls do not pile up
    # permanent tokens inside msfrpcd.
    client.persistentlogin = False
    return client


def _close_client(client) -> None:
    try:
        client.logout()
    except Exception:
        pass


async def _rpc(blocking_fn, *args, timeout: int = 30):
    """Create a client, run a blocking msfrpc call in a worker thread, close.

    On wall-clock timeout the worker thread is abandoned (Python threads
    are not killable); msfrpcd-side state (jobs/sessions) is unaffected
    and remains manageable via msf_jobs / msf_stop_job.
    """
    client = await asyncio.to_thread(_make_client)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(blocking_fn, client, *args), timeout=timeout
        )
    finally:
        await asyncio.to_thread(_close_client, client)


# ---------------------------------------------------------------------------
# Blocking worker functions (run in threads against a live client)
# ---------------------------------------------------------------------------


def _split_fullname(fullname: str) -> tuple[str, str]:
    """Split 'exploit/multi/handler' → ('exploit', 'exploit/multi/handler')."""
    head, _, rest = fullname.partition("/")
    if not rest or not _MODULE_TYPE_RE.match(head):
        raise ValueError(
            f"无效的模块名 {fullname!r}——需要 类型/路径 形式，"
            "如 exploit/multi/handler（类型: exploit/auxiliary/post/"
            "payload/encoder/nop）"
        )
    return head, fullname


def _search(client, query: str, module_type: str) -> list[dict]:
    rows = client.modules.search(query)
    if not isinstance(rows, list):
        return []
    if module_type != "any":
        rows = [r for r in rows if r.get("type") == module_type]
    return [
        {
            "type": r.get("type", "?"),
            "name": r.get("name", ""),
            "fullname": r.get("fullname", ""),
            "rank": r.get("rank", ""),
        }
        for r in rows
        if isinstance(r, dict) and r.get("fullname")
    ]


def _resolve_fullnames(client, module: str) -> list[str]:
    """Resolve a module name (with or without type prefix) to fullnames."""
    if "/" in module:
        head = module.split("/", 1)[0]
        if _MODULE_TYPE_RE.match(head):
            return [module]
    rows = client.modules.search(module)
    matches: list[str] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        full = r.get("fullname", "")
        if "/" in full and full.split("/", 1)[1] == module:
            if full not in matches:
                matches.append(full)
    return matches


def _show_opts(client, fullname: str) -> dict:
    mtype, _ = _split_fullname(fullname)
    mod = client.modules.use(mtype, fullname)
    info = mod.info or {}
    opts = {}
    for key in mod.options:
        try:
            meta = mod.optioninfo(key)
        except Exception:
            meta = {}
        opts[key] = {
            "type": (meta or {}).get("type", "?"),
            "required": bool((meta or {}).get("required")),
            "advanced": bool((meta or {}).get("advanced")),
            "default": (meta or {}).get("default"),
            "enums": (meta or {}).get("enums") or [],
            "desc": str((meta or {}).get("desc") or ""),
        }
    return {"info": info, "options": opts, "required": list(mod.required)}


def _execute(client, fullname: str, target: str, opts: dict) -> dict:
    mtype, _ = _split_fullname(fullname)
    kwargs = dict(opts)
    # msfrpcd's _run_exploit checks ONLY the ALL-CAPS 'PAYLOAD' key
    # (lib/msf/core/rpc/v10/rpc_module.rb) — a mixed-case 'Payload' slips
    # past that check and the handler silently falls back to the framework
    # default payload (live-verified 2026-09-10: Payload=
    # linux/x64/shell_reverse_tcp was replaced by
    # windows/meterpreter/reverse_tcp in the handler datastore). Normalize
    # both spellings to PAYLOAD; reject conflicting pairs loudly.
    if "Payload" in kwargs:
        if "PAYLOAD" in kwargs and kwargs["PAYLOAD"] != kwargs["Payload"]:
            raise ValueError(
                f"选项里同时有 Payload 和 PAYLOAD 且取值不同"
                f"（{kwargs['Payload']!r} vs {kwargs['PAYLOAD']!r}）——只传一个"
            )
        kwargs["PAYLOAD"] = kwargs.pop("Payload")
    # target → RHOST (framework global; harmless for listener modules).
    kwargs.setdefault("RHOST", target)
    result = client.modules.execute(mtype, fullname, **kwargs)
    if not isinstance(result, dict):
        result = {"job_id": None, "uuid": None}
    return result


def _jobs(client) -> dict:
    jobs = client.jobs.list
    return {int(k): str(v) for k, v in (jobs or {}).items()}


def _stop_job(client, job_id: int) -> None:
    client.jobs.stop(job_id)


def _kill_session(client, sid: str) -> tuple:
    """Kill a session by numeric ID or uuid. Returns (resolved_id, type).

    Calls the raw `session.stop` RPC directly (what MsfSession.stop() does
    under the hood) — works for meterpreter AND shell sessions. Bypasses
    SessionManager.session() for the same reason _session_exec does.
    """
    sl = client.sessions.list or {}
    key = None
    if sid.isdigit():
        n = int(sid)
        if n in sl:
            key = n
    if key is None:
        for k, v in sl.items():
            if isinstance(v, dict) and v.get("uuid") == sid:
                key = k
                break
    if key is None:
        known = ", ".join(
            f"{k}({v.get('uuid', '?') if isinstance(v, dict) else '?'})"
            for k, v in sl.items()
        ) or "（无）"
        raise LookupError(f"会话 {sid} 不存在——当前会话: {known}")
    data = sl[key]
    stype = data.get("type", "?") if isinstance(data, dict) else "?"
    client.call("session.stop", [key])
    return key, stype


def _job_info(client, job_id: int) -> dict:
    """Fetch the msfrpcd job record of a *currently running* job (job.info).

    The job table is in-memory and holds ONLY jobs still running: the
    instant a job ends (success OR failure) Rex::Job#start's ensure block
    removes it (lib/rex/job.rb — source-verified 2026-09-10). For any
    absent id — finished or never existed — the RPC returns the same
    error dict ({"error": true, "error_message": "Invalid Job",
    "error_code": 500}).

    Even for a running job the record is metadata only:
    jid/name/start_time/datastore. Module stdout never appears in the
    job record — it flows to the msfrpcd log (see _msf_log / msf_log).
    """
    raw = client.jobs.info(job_id) or {}
    if isinstance(raw, dict) and raw.get("error"):
        msg = raw.get("error_message") or raw.get("error_string") or "未知错误"
        raise LookupError(
            f"job {job_id} 不在 job 表中：msfrpcd 的 job 表只保留*正在运行*的 job——"
            f"作业结束（无论成功失败）的瞬间就被移除，"
            f"所以已完成的 job 与从未存在过的 job 表现相同（服务端: {msg}）。"
            f"已完成 job 的模块输出只存在于 msfrpcd 日志，用 `msf_log` 读取。"
        )
    inner = raw.get("result") if isinstance(raw, dict) else None
    if not isinstance(inner, dict):
        inner = raw if isinstance(raw, dict) else {}
    return {
        "job_id": inner.get("jid", inner.get("job_id", job_id)),
        "name": inner.get("name", "?"),
        "start_time": inner.get("start_time"),
        "datastore": inner.get("datastore") or {},
    }


#: Log file the msfrpcd systemd unit appends stdout+stderr to
#: (StandardOutput=append:/var/log/metasploit-framework/msfrpcd.log).
#: ALL module print_* output (login lines, scan results, exploit banners)
#: ends up here. Override via env for custom deployments.
_MSFRPCD_LOG_FILE = os.getenv(
    "MSF_RPC_LOG_FILE", "/var/log/metasploit-framework/msfrpcd.log"
)

#: journald unit fallback (hosts whose unit still streams to the journal).
_MSFRPCD_LOG_UNIT = os.getenv("MSF_RPC_LOG_UNIT", "msfrpcd")

# short-iso journal line: "2026-09-10T00:54:33+0800 kali msfrpcd[956]: [*] …"
_JOURNAL_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<unit>[^\s\[]+)\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)


def _read_log_tail(path: str, max_bytes: int = 2 * 1024 * 1024) -> str:
    """Read the last max_bytes of a log file (never loads the whole file)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return ""
    if size == 0:
        return ""
    with open(path, "rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    text = data.decode("utf-8", errors="replace")
    if size > max_bytes and "\n" in text:
        text = text.split("\n", 1)[1]  # drop the partial first line
    return text


def _msf_log(client, filter_text: str, lines: int, minutes: int) -> tuple:
    """Read module output from the msfrpcd log — file first, journal fallback.

    Our systemd unit appends msfrpcd's stdout+stderr to
    /var/log/metasploit-framework/msfrpcd.log — that is the only place
    module print_* output reliably lands: the journald stdout stream for
    the daemon has been observed DEAD on Kali (verified 2026-09-10:
    writes to the process's fd 1 vanish; only the stderr stream and
    Logger-file entries survive). The file lines carry no timestamps, so
    `minutes` only constrains the journal fallback.

    Returns (rows, source) with source in {"file", "journal"}.
    """
    if os.path.isfile(_MSFRPCD_LOG_FILE):
        text = _read_log_tail(_MSFRPCD_LOG_FILE)
        if text:
            needle = filter_text.lower()
            out = [
                ln
                for ln in (raw.strip() for raw in text.splitlines())
                if ln and (not needle or needle in ln.lower())
            ]
            return out[-lines:], "file"
    # fallback: journald (requires root or `adm` group membership)
    if shutil.which("journalctl") is None:
        raise MsfConfigError(
            "找不到 msfrpcd 日志：日志文件不存在且 journalctl 不可用"
        )
    fetch = min(max(lines * 5, 200), 5000)
    cmd = [
        "journalctl", "-u", _MSFRPCD_LOG_UNIT, "--no-pager",
        "-o", "short-iso", "--since", f"-{minutes} minutes", "-n", str(fetch),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as e:
        raise MsfConfigError("journalctl 不可用（未安装 systemd/journal）") from e
    except subprocess.TimeoutExpired as e:
        raise MsfConnectionError(
            f"journalctl 读取最近 {minutes} 分钟日志超时"
        ) from e
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if "No entries" in stderr:
            return [], "journal"
        raise MsfConnectionError(f"journalctl 失败 (rc={proc.returncode}): {stderr[:200]}")
    needle = filter_text.lower()
    out: list[str] = []
    for raw in (proc.stdout or "").splitlines():
        # newer systemd prints the sentinel to stdout with rc=0
        # (live-verified 2026-09-10: rc=0, stdout="-- No entries --")
        if raw.strip() == "-- No entries --":
            return [], "journal"
        m = _JOURNAL_LINE_RE.match(raw)
        ts = m.group("ts") if m else ""
        msg = m.group("msg") if m else raw
        if needle and needle not in msg.lower():
            continue
        out.append(f"{ts}  {msg}" if ts else msg)
    return out[-lines:], "journal"


def _sessions(client) -> dict:
    sl = client.sessions.list or {}
    out = {}
    for k, v in sl.items():
        try:
            key = int(k)
        except (TypeError, ValueError):
            key = k
        if isinstance(v, dict):
            out[key] = {
                "type": v.get("type", "?"),
                "tunnel": f"{v.get('tunnel_local', '?')} → {v.get('tunnel_peer', '?')}",
                "via_exploit": str(v.get("via_exploit") or ""),
                "via_payload": str(v.get("via_payload") or ""),
                "payload_note": _payload_note(
                    str(v.get("via_payload") or ""),
                    str(v.get("platform") or ""),
                    str(v.get("arch") or ""),
                ),
                "info": v.get("info", ""),
                "username": v.get("username", ""),
                "platform": v.get("platform", ""),
                "arch": v.get("arch", ""),
                "uuid": v.get("uuid", ""),
            }
    return out


def _payload_note(via_payload: str, platform: str, arch: str) -> str:
    """Display form of via_payload + a mismatch warning when the payload's
    platform token contradicts the session's actual platform.

    via_payload is the handler module's *configured* PAYLOAD option
    (msfrpcd Session#set_from_exploit), not necessarily what was actually
    delivered — a multi/handler configured with one payload can still
    accept another, so a linux session may report a windows payload.
    """
    if not via_payload:
        return ""
    disp = via_payload
    if disp.startswith("payload/"):
        disp = disp[len("payload/") :]
    note = ""
    if platform and disp:
        tok = disp.split("/", 1)[0]
        if tok not in (platform, "multi") and tok != "generic":
            note = f"⚠️ 与平台 {platform}/{arch or '?'} 不符（handler 配置值）"
    return f"{disp} {note}".strip()


def _poll_read(read_fn, seconds: float, interval: float = 0.5) -> str:
    """Poll a session ring read until non-empty (meterpreter output arrives
    a beat after run_single returns — a bare read() races it)."""
    import time

    deadline = time.time() + seconds
    while True:
        try:
            chunk = read_fn() or ""
        except Exception:
            chunk = ""
        if chunk:
            return str(chunk)
        if time.time() >= deadline:
            return ""
        time.sleep(interval)


def _session_exec(client, sid: str, command: str) -> tuple[str, str]:
    """Run one command in a live session. Returns (type, output)."""
    sl = client.sessions.list or {}

    def _find() -> object | None:
        if sid.isdigit():
            n = int(sid)
            if n in sl:
                return n
        for k, v in sl.items():
            if isinstance(v, dict) and v.get("uuid") == sid:
                return k
        return None

    key = _find()
    if key is None:
        known = ", ".join(
            f"{k}({v.get('uuid', '?') if isinstance(v, dict) else '?'})"
            for k, v in sl.items()
        ) or "（无）"
        raise LookupError(f"会话 {sid} 不存在——当前会话: {known}")

    data = sl[key]
    stype = data.get("type")
    # NOTE: bypass the package's SessionManager.session() — its
    # _create_session() swaps the session description / whole list
    # arguments, so int session keys crash re.match() (verified 2026-09-07).
    if stype == "meterpreter":
        s = MeterpreterSession(key, client, data)
        s.rpc.call("session.meterpreter_run_single", [key, command])
        out = _poll_read(
            lambda: (s.rpc.call("session.meterpreter_read", [key]) or {}).get("data"),
            seconds=15,
        )
    elif stype == "shell":
        s = ShellSession(key, client, data)
        s.write(command + "\n")
        out = _poll_read(s.read, seconds=8)
    else:
        raise ValueError(f"不支持的会话类型: {stype}")
    return stype, out


# ---------------------------------------------------------------------------
# Option parsing / validation / coercion
# ---------------------------------------------------------------------------


def _parse_options(s: str) -> dict[str, str]:
    """Parse 'KEY=VALUE,KEY2=VALUE2' into an ordered dict of strings."""
    s = s.strip()
    if not s:
        return {}
    out: dict[str, str] = {}
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        key, eq, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if not eq or not key:
            raise ValueError(f"无效的选项 {part!r}——需要 KEY=VALUE 形式")
        if not _OPTION_KEY_RE.match(key):
            raise ValueError(f"无效的选项名: {key!r}")
        _no_shell_meta(value)
        if key in out:
            raise ValueError(f"重复的选项: {key}")
        out[key] = value
    return out


def _coerce_option(name: str, value: str, meta: dict | None) -> object:
    """Coerce a string option value to the module-declared type."""
    if meta is None:
        return value
    t = meta.get("type")
    if t == "integer":
        try:
            return int(value)
        except ValueError as e:
            raise ValueError(f"选项 {name} 需要整数，得到 {value!r}") from e
    if t == "float":
        try:
            return float(value)
        except ValueError as e:
            raise ValueError(f"选项 {name} 需要数字，得到 {value!r}") from e
    if t == "bool":
        if value.lower() in ("1", "true", "yes"):
            return True
        if value.lower() in ("0", "false", "no"):
            return False
        raise ValueError(f"选项 {name} 需要布尔值 (true/false)，得到 {value!r}")
    if meta.get("enums") and value not in meta["enums"]:
        raise ValueError(f"选项 {name} 的值 {value!r} 不在允许范围: {meta['enums']}")
    return value


# ---------------------------------------------------------------------------
# Reports (Chinese markdown)
# ---------------------------------------------------------------------------


def _error_report(title: str, e: Exception) -> str:
    if isinstance(e, MsfConfigError):
        body = (
            f"❌ {e}\n\n"
            "💡 环境准备（一次性）：\n"
            "1. `sudo apt install metasploit-framework python3-pymetasploit3`\n"
            "2. 运行 `setup.sh --tool-level full`（自动建 msfrpcd systemd 服务"
            "并在 .env 生成 MSF_RPC_PASSWORD），或手动 `systemctl start msfrpcd`"
        )
    elif isinstance(e, MsfConnectionError):
        body = (
            f"❌ {e}\n\n"
            "💡 检查 msfrpcd 服务：`sudo systemctl status msfrpcd`，"
            "日志 `journalctl -u msfrpcd -n 30`。"
            "注意 msfrpcd 只绑定 127.0.0.1，MCP 服务必须与它在同一台机器上。"
        )
    else:
        body = f"❌ {type(e).__name__}: {e}"
    return f"## 🎯 Metasploit {title}\n\n{body}"


def _search_report(params: "MsfSearchInput", rows: list[dict]) -> str:
    lines = [
        f"## 🎯 Metasploit 模块搜索 — {params.query}",
        f"**类型过滤:** {params.module_type}",
        f"**命中:** {len(rows)} 个模块",
        "",
    ]
    if not rows:
        lines.append(
            "> ✅ 无匹配模块。试试更短的关键词（如 `smb`、`http`），"
            "或 module_type=any 扩大范围。"
        )
        return "\n".join(lines)

    by_type: dict[str, list[dict]] = {}
    for r in rows:
        by_type.setdefault(r["type"], []).append(r)
    lines.append("### 📊 类型分布")
    for t in ("exploit", "auxiliary", "post", "payload", "encoder", "nop"):
        if t in by_type:
            lines.append(f"- `{t}`: {len(by_type[t])}")
    lines.append("")
    lines.append(f"### 📋 模块列表（前 {min(len(rows), params.max_results)} 个）")
    lines.append("| 类型 | 模块 | rank |")
    lines.append("|------|------|------|")
    for r in rows[: params.max_results]:
        lines.append(f"| {r['type']} | `{r['fullname']}` | {r['rank']} |")
    if len(rows) > params.max_results:
        lines.append(f"… 其余 {len(rows) - params.max_results} 个未列出")
    lines.append("")
    lines.append(
        "> 后续步骤：`msf_show_opts` 查看目标模块的选项 → `msf_run_exploit` 执行。"
    )
    return "\n".join(lines)


def _fmt_list_value(v, limit: int = 6) -> str:
    """Render msf info values that may be lists (platform/arch) compactly."""
    if isinstance(v, (list, tuple)):
        items = [str(x) for x in v]
        if not items:
            return "?"
        head = ", ".join(items[:limit])
        return head + (f"… (+{len(items) - limit})" if len(items) > limit else "")
    return str(v)


def _show_opts_report(fullname: str, data: dict) -> str:
    info = data["info"]
    opts = data["options"]
    lines = [
        f"## 🎯 Metasploit 模块选项 — `{fullname}`",
        f"**名称:** {info.get('name', '')}",
    ]
    desc = str(info.get("description") or "")
    if desc:
        lines.append(f"**描述:** {desc[:300]}{'…' if len(desc) > 300 else ''}")
    meta_bits = [f"平台: {_fmt_list_value(info.get('platform', '?'))}"]
    if info.get("arch"):
        meta_bits.append(f"架构: {_fmt_list_value(info.get('arch'))}")
    meta_bits.append(f"rank: {info.get('rank', '?')}")
    if info.get("references"):
        refs = info["references"]
        if isinstance(refs, list):
            meta_bits.append(f"参考: {', '.join(str(x) for x in refs[:4])}")
        else:
            meta_bits.append(f"参考: {refs}")
    lines.append("**" + " ｜ ".join(meta_bits) + "**")
    lines.append("")
    lines.append(f"### ⚙️ 选项（{len(opts)} 个）")
    lines.append("| 选项 | 类型 | 必需 | 默认 | 说明 |")
    lines.append("|------|------|:----:|------|------|")
    for key, meta in opts.items():
        req = "⚠️" if meta["required"] else ""
        dflt = repr(meta["default"]) if meta["default"] is not None else "—"
        d = meta["desc"][:80] + ("…" if len(meta["desc"]) > 80 else "")
        adv = "（高级）" if meta["advanced"] else ""
        lines.append(f"| `{key}` | {meta['type']}{adv} | {req} | {dflt} | {d} |")
    lines.append("")
    required = [k for k in opts if opts[k]["required"]]
    if required:
        lines.append(f"**必填选项:** {', '.join('`%s`' % k for k in required)}")
    if "Payload" in opts or (info.get("type") == "exploit"):
        lines.append("")
        lines.append(
            "> 后续步骤：`msf_run_exploit(module, target, options)`——"
            "target 自动写入 RHOST，其余选项用 `KEY=VALUE` 传入；"
            "exploit 类模块通常还需 `Payload=...`（见模块 compatible payloads）。"
        )
    else:
        lines.append("")
        lines.append("> 后续步骤：`msf_run_exploit(module, target, options)` 执行该模块。")
    return "\n".join(lines)


def _run_exploit_report(params: "MsfRunExploitInput", result: dict) -> str:
    job_id = result.get("job_id")
    if job_id is None:
        return (
            f"## 🎯 Metasploit 执行 — `{params.module}`\n\n"
            f"❌ msf 拒绝启动该模块（job_id=None）。\n\n"
            "常见原因：**缺少必填选项**（如 RHOST/Payload）或模块名不存在。\n\n"
            "💡 用 `msf_show_opts` 查看该模块的必填选项（⚠️ 标记），补齐后重试。"
        )
    lines = [
        f"## 🎯 Metasploit 执行 — `{params.module}`",
        f"**目标:** {params.target}（→ RHOST）",
    ]
    if params.options:
        lines.append(f"**选项:** `{params.options}`")
    lines += [
        f"**Job ID:** {job_id}",
        "",
        "模块已作为 msf 后台作业启动（exploit 运行不阻塞 RPC）。",
        "",
        "> 后续步骤：`msf_jobs` 查看作业状态 → 出现会话后用 "
        "`msf_sessions` / `msf_session_exec` 交互；结束用 `msf_stop_job`。"
    ]
    return "\n".join(lines)


def _jobs_report(jobs: dict) -> str:
    lines = ["## 🎯 Metasploit 作业", f"**运行中:** {len(jobs)} 个", ""]
    if not jobs:
        lines.append("> ✅ 当前没有运行中的 msf 作业。")
        return "\n".join(lines)
    lines.append("| Job | 模块 |")
    lines.append("|-----|------|")
    for jid, desc in sorted(jobs.items()):
        lines.append(f"| {jid} | {desc} |")
    lines.append("")
    lines.append("> 停止作业：`msf_stop_job(job_id)`。")
    return "\n".join(lines)


def _job_info_report(info: dict) -> str:
    ds = info.get("datastore") or {}
    if ds:
        ds_lines = []
        for k in sorted(ds)[:40]:
            v = ds[k]
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            ds_lines.append(f"- `{k}`: {v}")
        if len(ds) > 40:
            ds_lines.append(f"… 其余 {len(ds) - 40} 项未列出")
        ds_txt = "\n".join(ds_lines)
    else:
        ds_txt = "（无选项快照）"
    try:
        start_txt = datetime.fromtimestamp(int(info.get("start_time"))).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (TypeError, ValueError, OSError):
        start_txt = "?"
    lines = [
        f"## 🎯 Metasploit 作业详情 — job {info['job_id']}（运行中）",
        f"**模块:** `{info['name']}`  |  **启动时间:** {start_txt}",
        "",
        "**选项快照 (datastore):**",
        ds_txt,
        "",
        "> ⚠️ 作业记录只有元数据——模块自身的输出（如 ssh_login 成功/失败行、"
        "扫描结果）从不进入作业记录，用 `msf_log` 从 msfrpcd 日志读取。",
    ]
    return "\n".join(lines)


def _log_report(params: "MsfLogInput", rows: list[str], source: str = "journal") -> str:
    filt = f"`{params.filter}`" if params.filter else "（无）"
    if source == "file":
        window = f"日志文件 `{_MSFRPCD_LOG_FILE}` 尾部"
    else:
        window = f"journal 最近 {params.minutes} 分钟"
    lines = [
        "## 📜 Metasploit msfrpcd 日志",
        f"**来源:** {window}  |  **过滤:** {filt}  |  **命中:** {len(rows)} 行",
        "",
    ]
    if not rows:
        if params.filter:
            why = f"没有匹配 `{params.filter}` 的行"
        elif source == "file":
            why = "日志文件为空或无匹配——msfrpcd 可能刚重启，或尚未运行过任何作业"
        else:
            why = "窗口内没有日志——msfrpcd 可能刚重启，或尚未运行过任何作业"
        lines.append(f"> ✅ {why}。")
        return "\n".join(lines)
    lines.append("```")
    lines.extend(rows)
    lines.append("```")
    lines.append("")
    lines.append(
        "> 💡 模块自身的输出只在这里：作业记录只有元数据，且 job 完成即从 job 表移除。"
        "过滤建议用模块名（如 `ssh_login`）或目标 IP。"
    )
    return "\n".join(lines)


def _sessions_report(sessions: dict) -> str:
    lines = ["## 🎯 Metasploit 会话", f"**活跃:** {len(sessions)} 个", ""]
    if not sessions:
        lines.append(
            "> ✅ 当前没有活跃会话。exploit 执行后需等待目标回连"
            "（handler 类模块会一直等待，直到超时或收到连接）。"
        )
        return "\n".join(lines)
    lines.append("| ID | 类型 | 隧道 | 用户 | 平台/架构 | 来源 exploit | 来源 payload |")
    lines.append("|----|------|------|------|-----------|--------------|--------------|")
    for sid, s in sorted(sessions.items(), key=lambda kv: kv[0]):
        via_exploit = s.get("via_exploit") or "?"
        payload = s.get("payload_note") or (s.get("via_payload") or "—")
        lines.append(
            f"| {sid} | {s['type']} | {s['tunnel']} | {s['username']} "
            f"| {s['platform']}/{s['arch']} | {via_exploit} | {payload} |"
        )
    lines.append("")
    lines.append(
        "> 后续步骤：`msf_session_exec(session_id, command)` 在会话内执行命令"
        "（如 `sysinfo`、`getuid`、`shell -i`）；结束会话用 `msf_kill_session(session_id)`。"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pydantic inputs
# ---------------------------------------------------------------------------


class MsfSearchInput(BaseModel):
    """Input for msf_search."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Keyword to match against module names/descriptions/refs (e.g. 'smb', 'apache', 'ms17_010')",
    )
    module_type: str = Field(
        "any",
        pattern="^(any|exploit|auxiliary|post|payload|encoder|nop)$",
        description="Restrict to one module type (default: any)",
    )
    max_results: int = Field(
        30, ge=1, le=200, description="Max modules to list in the report"
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        _no_shell_meta(v)
        return v.strip()


class MsfShowOptsInput(BaseModel):
    """Input for msf_show_opts."""

    module: str = Field(
        ...,
        min_length=3,
        max_length=256,
        description=(
            "Module full name, e.g. 'exploit/multi/handler' "
            "(type prefix may be omitted: 'multi/handler')"
        ),
    )

    @field_validator("module")
    @classmethod
    def validate_module(cls, v: str) -> str:
        _no_shell_meta(v)
        v = v.strip()
        if not re.match(r"^[A-Za-z0-9_\-./]+$", v):
            raise ValueError(f"Invalid module name: {v}")
        return v


class MsfRunExploitInput(BaseModel):
    """Input for msf_run_exploit."""

    module: str = Field(
        ...,
        min_length=3,
        max_length=256,
        description="Module full name, e.g. 'exploit/multi/handler' or 'multi/handler'",
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Target host (IP or hostname); written to the RHOST option",
    )
    options: str = Field(
        "",
        max_length=1024,
        description=(
            "Additional module options 'KEY=VALUE,KEY2=VALUE2' "
            "(see msf_show_opts for available keys, e.g. 'Payload=windows/x64/meterpreter/reverse_tcp,LPORT=4444'; "
            "the payload key accepts both spellings 'Payload' and 'PAYLOAD' — normalized server-side)"
        ),
    )
    timeout: int = Field(
        60,
        ge=5,
        le=600,
        description="Wall-clock seconds for the RPC call itself (the exploit runs as a background msf job afterwards)",
    )

    @field_validator("module")
    @classmethod
    def validate_module(cls, v: str) -> str:
        _no_shell_meta(v)
        v = v.strip()
        if not re.match(r"^[A-Za-z0-9_\-./]+$", v):
            raise ValueError(f"Invalid module name: {v}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        v = v.strip()
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v

    @field_validator("options")
    @classmethod
    def validate_options(cls, v: str) -> str:
        if v:
            _parse_options(v)  # fail early on malformed input
        return v.strip()


class MsfStopJobInput(BaseModel):
    """Input for msf_stop_job."""

    job_id: int = Field(..., ge=0, description="Job ID from msf_jobs / msf_run_exploit")


class MsfSessionExecInput(BaseModel):
    """Input for msf_session_exec."""

    session_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Session ID (numeric, from msf_sessions) or its uuid",
    )
    command: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description=(
            "One meterpreter/shell command (e.g. 'sysinfo', 'getuid', "
            "'hashdump', 'shell -i'). Sent via the msf RPC, not a shell."
        ),
    )
    timeout: int = Field(
        60, ge=5, le=300, description="Wall-clock seconds to wait for the command output"
    )

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        v = v.strip()
        if not (v.isdigit() or _UUID_RE.match(v)):
            raise ValueError(
                f"Invalid session id: {v!r} (use the numeric ID or uuid from msf_sessions)"
            )
        return v

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: str) -> str:
        if "\n" in v or "\r" in v:
            raise ValueError("command must be a single line")
        return v.strip()


class MsfKillSessionInput(BaseModel):
    """Input for msf_kill_session."""

    session_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Session ID (numeric, from msf_sessions) or its uuid",
    )

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        v = v.strip()
        if not (v.isdigit() or _UUID_RE.match(v)):
            raise ValueError(
                f"Invalid session id: {v!r} (use the numeric ID or uuid from msf_sessions)"
            )
        return v


class MsfJobInfoInput(BaseModel):
    """Input for msf_job_info."""

    job_id: int = Field(..., ge=0, description="Job ID from msf_jobs / msf_run_exploit")


class MsfLogInput(BaseModel):
    """Input for msf_log."""

    filter: str = Field(
        "",
        max_length=200,
        description=(
            "Case-insensitive substring to keep, e.g. 'ssh_login' or a target IP; "
            "empty = raw tail of the msfrpcd log"
        ),
    )
    lines: int = Field(
        100, ge=1, le=1000, description="Max lines to return (last N after filtering)"
    )
    minutes: int = Field(
        60, ge=1, le=1440, description="How far back in the msfrpcd log to search"
    )

    @field_validator("filter")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        return _no_nul_or_newline(v.strip())


# ---------------------------------------------------------------------------
# Async tools
# ---------------------------------------------------------------------------


async def msf_search(params: MsfSearchInput) -> str:
    """Search the Metasploit module database (exploits/auxiliary/post/payloads).

    Broad keyword search over module names, descriptions and references —
    the first step of the exploit loop: find → show opts → run → session.

    Requires: msfrpcd systemd service (setup.sh --tool-level full),
    MSF_RPC_PASSWORD in .env. Read-only.
    """
    try:
        rows = await _rpc(_search, params.query, params.module_type, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("模块搜索", e)
    return _search_report(params, rows)


async def msf_show_opts(params: MsfShowOptsInput) -> str:
    """Show all options (name/type/required/default/description) of an msf module.

    Read-only. Resolves the type prefix automatically ('multi/handler' is
    accepted); ambiguous bare names are resolved against the module DB.

    Requires: msfrpcd systemd service, MSF_RPC_PASSWORD in .env.
    """
    try:
        client_rows = await _rpc(_resolve_fullnames, params.module, timeout=30)
        if not client_rows:
            return (
                f"## 🎯 Metasploit 模块选项 — `{params.module}`\n\n"
                f"❌ 未找到模块 `{params.module}`。用 `msf_search` 确认模块名。"
            )
        if len(client_rows) > 1:
            return (
                f"## 🎯 Metasploit 模块选项 — `{params.module}`\n\n"
                "❌ 模块名有歧义，请带类型前缀重试：\n\n"
                + "\n".join(f"- `{f}`" for f in client_rows[:10])
            )
        fullname = client_rows[0]
        data = await _rpc(_show_opts, fullname, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("模块选项", e)
    except (ValueError, TypeError) as e:
        # 'bool' object is not subscriptable — pymetasploit3's internal
        # error when the module does not exist (module.info returns False).
        return (
            f"## 🎯 Metasploit 模块选项 — `{params.module}`\n\n"
            f"❌ 加载模块失败: {e}\n\n💡 用 `msf_search` 确认模块名是否存在。"
        )
    return _show_opts_report(fullname, data)


async def msf_run_exploit(params: MsfRunExploitInput) -> str:
    """Launch an msf module (exploit/auxiliary) against a target as a background job.

    🔴 ACTIVE EXPLOITATION. The module runs server-side inside msfrpcd and
    keeps running after this call returns — poll msf_jobs / msf_sessions.
    `target` is written to RHOST; pass everything else (e.g. Payload, LPORT)
    via `options` after checking msf_show_opts.

    Only use against targets you own or are explicitly authorized to test.

    Requires: msfrpcd systemd service, MSF_RPC_PASSWORD in .env.
    """
    try:
        fullnames = await _rpc(_resolve_fullnames, params.module, timeout=30)
        if not fullnames:
            return (
                f"## 🎯 Metasploit 执行 — `{params.module}`\n\n"
                f"❌ 未找到模块 `{params.module}`。用 `msf_search` 确认模块名。"
            )
        if len(fullnames) > 1:
            return (
                f"## 🎯 Metasploit 执行 — `{params.module}`\n\n"
                "❌ 模块名有歧义，请带类型前缀重试：\n\n"
                + "\n".join(f"- `{f}`" for f in fullnames[:10])
            )
        fullname = fullnames[0]
        _split_fullname(fullname)  # validate the type prefix
        opts_meta = await _rpc(_show_opts, fullname, timeout=30)

        parsed = _parse_options(params.options)
        unknown = [
            k
            for k in parsed
            if k not in opts_meta["options"] and k not in _GLOBAL_OPTION_WHITELIST
        ]
        if unknown:
            return (
                f"## 🎯 Metasploit 执行 — `{fullname}`\n\n"
                f"❌ 未知选项: {', '.join('`%s`' % k for k in unknown)}\n\n"
                "💡 该模块的可用选项见 `msf_show_opts`（服务端会静默忽略未知选项，"
                "所以这里先拒绝）。"
            )
        coerced = {
            k: _coerce_option(k, v, opts_meta["options"].get(k))
            for k, v in parsed.items()
        }
        result = await _rpc(_execute, fullname, params.target, coerced,
                            timeout=params.timeout)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("执行", e)
    except ValueError as e:
        return (
            f"## 🎯 Metasploit 执行 — `{params.module}`\n\n"
            f"❌ 参数错误: {e}"
        )
    return _run_exploit_report(params, result)


async def msf_jobs() -> str:
    """List all currently running msf jobs (id + module)."""
    try:
        jobs = await _rpc(_jobs, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("作业列表", e)
    return _jobs_report(jobs)


async def msf_stop_job(params: MsfStopJobInput) -> str:
    """Stop a running msf job (e.g. a handler that is no longer needed)."""
    try:
        await _rpc(_stop_job, params.job_id, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("停止作业", e)
    except Exception as e:
        return (
            f"## 🎯 Metasploit 停止作业\n\n"
            f"❌ 停止 job {params.job_id} 失败: {type(e).__name__}: {e}"
        )
    return (
        f"## 🎯 Metasploit 停止作业\n\n"
        f"✅ 已请求停止 job {params.job_id}。\n\n"
        "> 用 `msf_jobs` 确认它已消失。"
    )


async def msf_sessions() -> str:
    """List active meterpreter/shell sessions (id, type, tunnel, user)."""
    try:
        sessions = await _rpc(_sessions, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("会话列表", e)
    return _sessions_report(sessions)


async def msf_session_exec(params: MsfSessionExecInput) -> str:
    """Execute one command inside a live meterpreter/shell session.

    🔴 Post-exploitation: the command runs on the compromised host via the
    msf RPC (meterpreter run_single / shell write+read) — NOT through a
    local shell. Single line, ≤512 chars.

    Requires: msfrpcd systemd service, MSF_RPC_PASSWORD in .env.
    """
    try:
        stype, out = await _rpc(
            _session_exec, params.session_id, params.command, timeout=params.timeout
        )
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("会话命令", e)
    except LookupError as e:
        return (
            f"## 🎯 Metasploit 会话命令\n\n❌ {e}\n\n"
            "💡 用 `msf_sessions` 查看当前会话及其 ID/uuid。"
        )
    lines = [
        f"## 🎯 Metasploit 会话命令 — session {params.session_id} ({stype})",
        f"**命令:** `{params.command}`",
        "",
        "```",
        out.strip() if out else "（无输出）",
        "```",
        "",
        "> 更多命令：`sysinfo` / `getuid` / `shell -i` / `hashdump`（meterpreter）。"
    ]
    return "\n".join(lines)


async def msf_kill_session(params: MsfKillSessionInput) -> str:
    """Kill a live meterpreter/shell session (cleanup after post-exploitation).

    Calls the msfrpcd `session.stop` RPC — the session is closed on the
    target side (the reverse connection drops). Use it as part of full
    cleanup together with `msf_stop_job` (handlers) so no foothold lingers.
    """
    try:
        key, stype = await _rpc(_kill_session, params.session_id, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("结束会话", e)
    except LookupError as e:
        return (
            f"## 🎯 Metasploit 结束会话\n\n❌ {e}\n\n"
            "💡 用 `msf_sessions` 查看当前会话及其 ID/uuid。"
        )
    except Exception as e:
        return (
            f"## 🎯 Metasploit 结束会话\n\n"
            f"❌ 结束 session {params.session_id} 失败: {type(e).__name__}: {e}"
        )
    return (
        f"## 🎯 Metasploit 结束会话\n\n"
        f"✅ 已终止 session {key}（{stype}）。\n\n"
        "> 用 `msf_sessions` 确认它已消失；handler 还在跑的话用 `msf_stop_job` 停掉。"
    )


async def msf_job_info(params: MsfJobInfoInput) -> str:
    """Read a *running* msf job's metadata (module, start time, options snapshot).

    The msfrpcd job table holds only jobs still running: the instant a job
    ends (success OR failure) it is removed (Rex::Job#start), so a finished
    job returns 'Invalid Job' — identical to a job that never existed.
    Even for running jobs the record is metadata only; module output (an
    ssh_login line, a scan report) flows exclusively to the msfrpcd log —
    read it with `msf_log`.
    """
    try:
        info = await _rpc(_job_info, params.job_id, timeout=30)
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("作业详情", e)
    except LookupError as e:
        return (
            f"## 🎯 Metasploit 作业详情\n\n❌ {e}\n\n"
            "💡 已完成 job 的模块输出用 `msf_log(filter=\"模块名或目标IP\")` 读取；"
            "用 `msf_jobs` 查看当前运行中的 job。"
        )
    except Exception as e:
        return (
            f"## 🎯 Metasploit 作业详情\n\n"
            f"❌ 读取 job {params.job_id} 失败: {type(e).__name__}: {e}"
        )
    return _job_info_report(info)


async def msf_log(params: MsfLogInput) -> str:
    """Tail the msfrpcd log — the only place finished jobs' module output can be read.

    msf job records are metadata-only and finished jobs are deleted from
    the job table, so module stdout (ssh_login success lines, scan
    reports, exploit banners) flows exclusively to the msfrpcd log
    (file /var/log/metasploit-framework/msfrpcd.log; journald unit
    `msfrpcd` as fallback). Use filter to keep lines matching a module
    name, target IP, or keyword.

    Read-only. Requires: msfrpcd systemd service (setup.sh writes the
    log-capturing unit); the MCP service runs as root on our deployment.
    """
    try:
        rows, source = await _rpc(
            _msf_log, params.filter, params.lines, params.minutes, timeout=45
        )
    except (MsfConfigError, MsfConnectionError) as e:
        return _error_report("msfrpcd 日志", e)
    except Exception as e:
        return (
            f"## 📜 Metasploit msfrpcd 日志\n\n"
            f"❌ 读取日志失败: {type(e).__name__}: {e}"
        )
    return _log_report(params, rows, source)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

MSF_PENTEST_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "msf_search": (msf_search, MsfSearchInput),
    "msf_show_opts": (msf_show_opts, MsfShowOptsInput),
    "msf_job_info": (msf_job_info, MsfJobInfoInput),
    "msf_log": (msf_log, MsfLogInput),
}

MSF_ATTACK_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "msf_run_exploit": (msf_run_exploit, MsfRunExploitInput),
    "msf_jobs": (msf_jobs, None),
    "msf_stop_job": (msf_stop_job, MsfStopJobInput),
    "msf_sessions": (msf_sessions, None),
    "msf_kill_session": (msf_kill_session, MsfKillSessionInput),
    "msf_session_exec": (msf_session_exec, MsfSessionExecInput),
}
