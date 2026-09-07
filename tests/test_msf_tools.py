"""Tests for the Metasploit RPC bridge (msf.py).

Covers per the project baseline:
  - gating/registration (🟡 MSF_PENTEST_TOOLS / 🔴 MSF_ATTACK_TOOLS)
  - msfrpcd connection config (password required, clear error reports)
  - module-name resolution (type prefix vs bare name, ambiguity, not-found)
  - option parsing / coercion / unknown-option rejection (the server
    silently ignores unknown options → validated client-side)
  - report rendering (Chinese markdown, tables, hint lines)
  - async tools with a stubbed msfrpc client (no network, no daemon)

pymetasploit3 ground truth baked in here (live-verified 2026-09-07 on
Kali 6.5.0 / python3-pymetasploit3 1.0.3+git20250715):
  - sessions.list keys are native INTS; module.execute returns
    {'job_id': int|None, 'uuid': str|None} (job_id None = refused, e.g.
    missing required option); unknown modules raise TypeError internally.
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from kali_mcp import msf
from kali_mcp.msf import (
    MSF_ATTACK_TOOLS,
    MSF_PENTEST_TOOLS,
    MsfConnectionError,
    MsfConfigError,
    MsfJobInfoInput,
    MsfKillSessionInput,
    MsfRunExploitInput,
    MsfSearchInput,
    MsfSessionExecInput,
    MsfShowOptsInput,
    MsfStopJobInput,
    _coerce_option,
    _jobs_report,
    _job_info,
    _kill_session,
    _parse_options,
    _payload_note,
    _run_exploit_report,
    _search_report,
    _sessions_report,
    _show_opts_report,
    _split_fullname,
    msf_job_info,
    msf_jobs,
    msf_kill_session,
    msf_search,
    msf_session_exec,
    msf_sessions,
    msf_show_opts,
    msf_stop_job,
    msf_run_exploit,
)
from kali_mcp.tools import TOOL_REGISTRY


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Stub client (mimics the live-verified pymetasploit3 API surface)
# ---------------------------------------------------------------------------


class FakeModule:
    def __init__(self, info: dict, options: dict):
        self._info = info
        self._moptions = options

    @property
    def info(self):
        return self._info

    @property
    def options(self):
        return list(self._moptions)

    @property
    def required(self):
        return [k for k, v in self._moptions.items() if v.get("required")]

    def optioninfo(self, option):
        return self._moptions[option]


class _FakeManager:
    def __init__(self, client):
        self.client = client

    def search(self, query):
        return list(self.client.search_rows)

    def use(self, mtype, mname):
        return self.client._module_for(mname)

    def execute(self, mtype, mname, **kwargs):
        self.client.executed.append((mtype, mname, kwargs))
        return dict(self.client.execute_result)


class _FakeJobs:
    def __init__(self, client):
        self.client = client

    @property
    def list(self):
        return dict(self.client._jobs_data)

    def stop(self, jobid):
        self.client.stopped.append(jobid)

    def info(self, jobid):
        # mimics the job.info RPC: for unknown jobs the live RPC RETURNS
        # an error dict (does not raise) — verified 2026-09-07:
        # {"error": true, "error_message": "Invalid Job", "error_code": 500}
        if jobid not in self.client._job_info_data:
            return {
                "error": True,
                "error_class": "Msf::RPC::Exception",
                "error_string": "Msf::RPC::Exception",
                "error_message": "Invalid Job",
                "error_code": 500,
            }
        return dict(self.client._job_info_data[jobid])


class _FakeSessions:
    def __init__(self, client):
        self.client = client

    @property
    def list(self):
        return dict(self.client._sessions_data)


class FakeClient:
    def __init__(
        self,
        search_rows=None,
        modules=None,
        jobs=None,
        sessions=None,
        execute_result=None,
        job_info=None,
    ):
        self.search_rows = search_rows or []
        self.modules_db = modules or {}
        self._jobs_data = jobs or {}
        self._sessions_data = sessions or {}
        self._job_info_data = job_info or {}
        self.execute_result = execute_result or {"job_id": 1, "uuid": "abcd"}
        self.executed = []
        self.stopped = []
        self.killed = []
        self.logged_out = 0

    def call(self, method, params):
        # raw RPC entry point (what MsfSession.stop() uses under the hood)
        self.killed.append((method, list(params)))
        return {"result": "success"}

    def _module_for(self, mname):
        if mname not in self.modules_db:
            # mimics pymetasploit3's internal error for unknown modules
            raise TypeError("'bool' object is not subscriptable")
        info, options = self.modules_db[mname]
        return FakeModule(info, options)

    @property
    def modules(self):
        return _FakeManager(self)

    @property
    def jobs(self):
        return _FakeJobs(self)

    @property
    def sessions(self):
        return _FakeSessions(self)

    def logout(self):
        self.logged_out += 1


HANDLER_OPTS = {
    "LHOST": {"type": "string", "required": False, "default": None, "desc": "Local host"},
    "LPORT": {"type": "integer", "required": False, "default": 4444, "desc": "Local port"},
    "ExitOnSession": {"type": "bool", "required": True, "default": True, "desc": "Exit on session"},
    "VERBOSE": {"type": "bool", "required": False, "default": False, "desc": "Verbose output"},
}

HANDLER_INFO = {
    "name": "Generic Payload Handler",
    "fullname": "exploit/multi/handler",
    "description": "This module receives a payload",
    "platform": "multi",
    "arch": None,
    "rank": "manual",
    "references": ["URL:https://attack.mitre.org"],
    "type": "exploit",
}

SESSION_ROW = {
    "type": "meterpreter",
    "tunnel_local": "127.0.0.1:4444",
    "tunnel_peer": "127.0.0.1:49999",
    "via_exploit": "exploit/multi/handler",
    "via_payload": "payload/linux/aarch64/meterpreter_reverse_tcp",
    "info": "xhj @ kali",
    "username": "xhj",
    "platform": "linux",
    "arch": "aarch64",
    "uuid": "atv8tnyh",
}


@pytest.fixture
def stub(monkeypatch):
    """Route msf._make_client / _close_client to a configurable FakeClient."""
    holder: dict = {"client": None, "raise": None}

    def _factory():
        if holder["raise"] is not None:
            raise holder["raise"]
        return holder["client"]

    monkeypatch.setattr(msf, "_make_client", _factory)
    monkeypatch.setattr(
        msf, "_close_client", lambda c: c.logout() if c is not None else None
    )
    return holder


def _client(stub, **kw):
    stub["client"] = FakeClient(**kw)
    return stub["client"]


# ===================================================================
# Gating / registration
# ===================================================================


class TestMsfGating:
    def test_pentest_set(self):
        assert set(MSF_PENTEST_TOOLS) == {
            "msf_search",
            "msf_show_opts",
            "msf_job_info",
        }
        for name, (func, model) in MSF_PENTEST_TOOLS.items():
            assert callable(func)
            assert model.__name__.endswith("Input")

    def test_attack_set(self):
        assert set(MSF_ATTACK_TOOLS) == {
            "msf_run_exploit",
            "msf_jobs",
            "msf_stop_job",
            "msf_sessions",
            "msf_kill_session",
            "msf_session_exec",
        }
        for name, (func, model) in MSF_ATTACK_TOOLS.items():
            assert callable(func)
            if model is not None:
                assert model.__name__.endswith("Input")

    def test_no_overlap_with_green(self):
        for registry in (MSF_PENTEST_TOOLS, MSF_ATTACK_TOOLS):
            assert not set(registry) & set(TOOL_REGISTRY)

    def test_no_overlap_between_registries(self):
        assert not set(MSF_PENTEST_TOOLS) & set(MSF_ATTACK_TOOLS)


# ===================================================================
# Connection config
# ===================================================================


class TestMsfConfig:
    def test_missing_password(self, monkeypatch):
        monkeypatch.delenv("MSF_RPC_PASSWORD", raising=False)
        with pytest.raises(MsfConfigError, match="MSF_RPC_PASSWORD"):
            msf._msf_env()

    def test_bad_port(self, monkeypatch):
        monkeypatch.setenv("MSF_RPC_PASSWORD", "x")
        monkeypatch.setenv("MSF_RPC_PORT", "not-a-port")
        with pytest.raises(MsfConfigError):
            msf._msf_env()

    def test_defaults(self, monkeypatch):
        monkeypatch.setenv("MSF_RPC_PASSWORD", "secret")
        for var in ("MSF_RPC_HOST", "MSF_RPC_PORT", "MSF_RPC_USER"):
            monkeypatch.delenv(var, raising=False)
        cfg = msf._msf_env()
        assert cfg == {
            "host": "127.0.0.1",
            "port": 55553,
            "user": "msf",
            "password": "secret",
        }

    def test_search_reports_config_error(self, monkeypatch):
        # real _make_client path: config check runs before the library import
        monkeypatch.delenv("MSF_RPC_PASSWORD", raising=False)
        out = _run(msf_search(MsfSearchInput(query="smb")))
        assert "MSF_RPC_PASSWORD" in out
        assert "msfrpcd" in out

    def test_search_reports_connection_error(self, stub):
        stub["raise"] = MsfConnectionError("refused")
        out = _run(msf_search(MsfSearchInput(query="smb")))
        assert "msfrpcd" in out
        assert "systemctl" in out


# ===================================================================
# Option parsing / coercion
# ===================================================================


class TestParseOptions:
    def test_empty(self):
        assert _parse_options("") == {}
        assert _parse_options("   ") == {}

    def test_simple(self):
        opts = _parse_options("LPORT=4444,Payload=windows/x64/meterpreter/reverse_tcp")
        assert opts == {
            "LPORT": "4444",
            "Payload": "windows/x64/meterpreter/reverse_tcp",
        }

    def test_spaces(self):
        assert _parse_options(" LPORT = 4444 , VERBOSE = true ") == {
            "LPORT": "4444",
            "VERBOSE": "true",
        }

    def test_missing_equals(self):
        with pytest.raises(ValueError, match="KEY=VALUE"):
            _parse_options("LPORT")

    def test_bad_key(self):
        with pytest.raises(ValueError, match="选项名"):
            _parse_options("9LPORT=1")

    def test_shell_meta_in_value(self):
        with pytest.raises(ValueError):
            _parse_options("A=foo|bar")
        with pytest.raises(ValueError):
            _parse_options("A=$(reboot)")

    def test_duplicate(self):
        with pytest.raises(ValueError, match="重复"):
            _parse_options("A=1,A=2")


class TestCoerceOption:
    def test_integer(self):
        assert _coerce_option("LPORT", "4444", {"type": "integer"}) == 4444
        with pytest.raises(ValueError):
            _coerce_option("LPORT", "abc", {"type": "integer"})

    def test_bool(self):
        assert _coerce_option("V", "true", {"type": "bool"}) is True
        assert _coerce_option("V", "False", {"type": "bool"}) is False
        assert _coerce_option("V", "1", {"type": "bool"}) is True
        with pytest.raises(ValueError):
            _coerce_option("V", "maybe", {"type": "bool"})

    def test_enum(self):
        meta = {"type": "string", "enums": ["a", "b"]}
        assert _coerce_option("O", "a", meta) == "a"
        with pytest.raises(ValueError, match="允许范围"):
            _coerce_option("O", "c", meta)

    def test_passthrough_without_meta(self):
        assert _coerce_option("RHOST", "1.2.3.4", None) == "1.2.3.4"


# ===================================================================
# Module name handling
# ===================================================================


class TestSplitFullname:
    def test_valid(self):
        assert _split_fullname("exploit/multi/handler") == (
            "exploit",
            "exploit/multi/handler",
        )

    def test_no_slash(self):
        with pytest.raises(ValueError):
            _split_fullname("handler")

    def test_bad_prefix(self):
        with pytest.raises(ValueError):
            _split_fullname("foo/bar/baz")


class TestResolve:
    def test_with_prefix_no_search(self, stub):
        c = _client(stub)
        assert msf._resolve_fullnames(c, "exploit/multi/handler") == [
            "exploit/multi/handler"
        ]
        assert c.search_rows == []

    def test_bare_name_resolved(self, stub):
        _client(
            stub,
            search_rows=[
                {"type": "exploit", "fullname": "exploit/multi/handler", "name": "x"},
                {"type": "auxiliary", "fullname": "auxiliary/scan/other", "name": "y"},
            ],
        )
        c = stub["client"]
        assert msf._resolve_fullnames(c, "multi/handler") == ["exploit/multi/handler"]

    def test_bare_name_no_match(self, stub):
        c = _client(stub)
        assert msf._resolve_fullnames(c, "does/not/exist") == []


# ===================================================================
# Report rendering
# ===================================================================


class TestSearchReport:
    def test_rows(self):
        p = MsfSearchInput(query="smb")
        rows = [
            {"type": "exploit", "name": "MS17-010", "fullname": "exploit/windows/smb/ms17_010_eternalblue", "rank": "excellent"},
            {"type": "auxiliary", "name": "SMB enum", "fullname": "auxiliary/scanner/smb/smb_version", "rank": "normal"},
        ]
        out = _search_report(p, rows)
        assert "2 个模块" in out
        assert "`exploit/windows/smb/ms17_010_eternalblue`" in out
        assert "`auxiliary/scanner/smb/smb_version`" in out
        assert "`exploit`: 1" in out
        assert "`auxiliary`: 1" in out
        assert "msf_show_opts" in out

    def test_empty(self):
        out = _search_report(MsfSearchInput(query="zzz"), [])
        assert "无匹配模块" in out

    def test_truncation(self):
        p = MsfSearchInput(query="x", max_results=2)
        rows = [
            {"type": "exploit", "name": f"m{i}", "fullname": f"exploit/a/{i}", "rank": "n"}
            for i in range(5)
        ]
        out = _search_report(p, rows)
        assert "5 个模块" in out
        assert "其余 3 个未列出" in out
        assert "exploit/a/3" not in out


class TestShowOptsReport:
    def _data(self):
        return {
            "info": dict(HANDLER_INFO),
            "options": {
                k: {
                    "type": v["type"],
                    "required": v["required"],
                    "advanced": False,
                    "default": v.get("default"),
                    "enums": [],
                    "desc": v["desc"],
                }
                for k, v in HANDLER_OPTS.items()
            },
            "required": ["ExitOnSession"],
        }

    def test_render(self):
        out = _show_opts_report("exploit/multi/handler", self._data())
        assert "`exploit/multi/handler`" in out
        assert "Generic Payload Handler" in out
        assert "平台: multi" in out
        assert "`LPORT`" in out
        assert "⚠️" in out  # required marker
        assert "ExitOnSession" in out
        assert "msf_run_exploit" in out

    def test_truncates_long_desc(self):
        data = self._data()
        data["info"]["description"] = "x" * 500
        out = _show_opts_report("exploit/multi/handler", data)
        assert "…" in out

    def test_list_platform_compact(self):
        data = self._data()
        data["info"]["platform"] = ["Linux", "Windows", "BSD", "OSX", "Solaris", "Java", "Ruby"]
        data["info"]["arch"] = ["x86", "x64", "aarch64"]
        out = _show_opts_report("exploit/multi/handler", data)
        assert "平台: Linux, Windows, BSD, OSX, Solaris, Java" in out
        assert "(+1)" in out
        assert "架构: x86, x64, aarch64" in out


class TestRunExploitReport:
    def test_success(self):
        p = MsfRunExploitInput(module="exploit/multi/handler", target="127.0.0.1")
        out = _run_exploit_report(p, {"job_id": 5, "uuid": "zz"})
        assert "Job ID:** 5" in out
        assert "127.0.0.1" in out
        assert "msf_jobs" in out

    def test_refused(self):
        p = MsfRunExploitInput(module="exploit/multi/handler", target="127.0.0.1")
        out = _run_exploit_report(p, {"job_id": None, "uuid": None})
        assert "必填选项" in out
        assert "msf_show_opts" in out


class TestJobsReport:
    def test_empty(self):
        out = _jobs_report({})
        assert "没有运行中的" in out

    def test_rows(self):
        out = _jobs_report({2: "Exploit: multi/handler"})
        assert "| 2 | Exploit: multi/handler |" in out
        assert "msf_stop_job" in out


class TestSessionsReport:
    def test_empty(self):
        out = _sessions_report({})
        assert "没有活跃会话" in out

    def test_rows(self):
        out = _sessions_report(
            {6: {"type": "meterpreter", "tunnel": "127.0.0.1:4444 → 127.0.0.1:49999",
                 "via_exploit": "exploit/multi/handler",
                 "via_payload": "payload/linux/aarch64/meterpreter_reverse_tcp",
                 "payload_note": "linux/aarch64/meterpreter_reverse_tcp",
                 "username": "xhj",
                 "platform": "linux", "arch": "aarch64", "uuid": "atv8tnyh"}}
        )
        assert "| 6 | meterpreter" in out
        assert "msf_session_exec" in out
        assert "msf_kill_session" in out
        # via_payload prefix stripped in the payload column
        assert "payload/linux/" not in out

    def test_rows_shell_no_platform(self):
        out = _sessions_report(
            {10: {"type": "shell", "tunnel": "192.168.0.225:44839 → 192.168.0.77:22",
                  "via_exploit": "auxiliary/scanner/ssh/ssh_login",
                  "via_payload": "", "payload_note": "",
                  "username": "xhj", "platform": "", "arch": "", "uuid": "u1"}}
        )
        assert "auxiliary/scanner/ssh/ssh_login" in out
        # empty payload renders as the dash placeholder
        assert "| — |" in out


class TestPayloadNote:
    def test_strips_payload_prefix(self):
        assert _payload_note(
            "payload/linux/x64/meterpreter_reverse_tcp", "linux", "x64"
        ) == "linux/x64/meterpreter_reverse_tcp"

    def test_no_note_when_platform_matches(self):
        note = _payload_note("payload/windows/x64/meterpreter/reverse_tcp",
                             "windows", "x64")
        assert "⚠️" not in note

    def test_mismatch_warns(self):
        note = _payload_note("payload/windows/meterpreter/reverse_tcp",
                             "linux", "x64")
        assert "windows/meterpreter/reverse_tcp" in note
        assert "⚠️" in note
        assert "linux/x64" in note

    def test_multi_and_generic_payloads_no_note(self):
        assert "⚠️" not in _payload_note("payload/multi/reverse_tcp", "linux", "x64")
        assert "⚠️" not in _payload_note("payload/generic/shell_reverse_tcp", "windows", "x64")

    def test_empty_via_payload(self):
        assert _payload_note("", "linux", "x64") == ""

    def test_shell_session_no_platform_skips_check(self):
        # shell sessions carry no platform in session.list → no false alarm
        assert "⚠️" not in _payload_note("payload/x", "", "")


# ===================================================================
# Input validation
# ===================================================================


class TestInputValidation:
    def test_search_query_shell_meta(self):
        with pytest.raises(ValidationError):
            MsfSearchInput(query="smb; rm -rf /")

    def test_search_bad_type(self):
        with pytest.raises(ValidationError):
            MsfSearchInput(query="smb", module_type="weapon")

    def test_search_max_results_bounds(self):
        with pytest.raises(ValidationError):
            MsfSearchInput(query="smb", max_results=0)
        with pytest.raises(ValidationError):
            MsfSearchInput(query="smb", max_results=1000)

    def test_run_bad_target(self):
        with pytest.raises(ValidationError):
            MsfRunExploitInput(module="exploit/multi/handler", target="bad host;")

    def test_run_bad_module_chars(self):
        with pytest.raises(ValidationError):
            MsfRunExploitInput(module="exploit/multi/handler`id`", target="127.0.0.1")

    def test_run_bad_options(self):
        with pytest.raises(ValidationError):
            MsfRunExploitInput(
                module="exploit/multi/handler", target="127.0.0.1", options="LPORT"
            )

    def test_session_bad_id(self):
        with pytest.raises(ValidationError):
            MsfSessionExecInput(session_id="six;", command="sysinfo")

    def test_session_multiline_command(self):
        with pytest.raises(ValidationError):
            MsfSessionExecInput(session_id="1", command="sysinfo\ngetuid")

    def test_show_opts_bad_module_chars(self):
        with pytest.raises(ValidationError):
            MsfShowOptsInput(module="exploit/multi/handler | id")


# ===================================================================
# Async tools with stubbed client
# ===================================================================


class TestMsfSearchTool:
    def test_happy_path(self, stub):
        _client(
            stub,
            search_rows=[
                {"type": "exploit", "name": "MS17-010", "fullname": "exploit/windows/smb/ms17_010_eternalblue", "rank": "excellent", "disclosuredate": "2017-05-12"},
            ],
        )
        out = _run(msf_search(MsfSearchInput(query="ms17_010")))
        assert "`exploit/windows/smb/ms17_010_eternalblue`" in out

    def test_type_filter(self, stub):
        _client(
            stub,
            search_rows=[
                {"type": "exploit", "fullname": "exploit/a/x", "name": "x"},
                {"type": "auxiliary", "fullname": "auxiliary/a/y", "name": "y"},
            ],
        )
        out = _run(msf_search(MsfSearchInput(query="x", module_type="exploit")))
        assert "exploit/a/x" in out
        assert "auxiliary/a/y" not in out


class TestMsfShowOptsTool:
    def _db(self):
        return {"exploit/multi/handler": (dict(HANDLER_INFO), dict(HANDLER_OPTS))}

    def test_happy_path(self, stub):
        _client(stub, modules=self._db())
        out = _run(msf_show_opts(MsfShowOptsInput(module="exploit/multi/handler")))
        assert "`LPORT`" in out
        assert "Generic Payload Handler" in out
        assert stub["client"].logged_out >= 1  # one logout per _rpc round trip

    def test_bare_name(self, stub):
        _client(
            stub,
            modules=self._db(),
            search_rows=[
                {"type": "exploit", "fullname": "exploit/multi/handler", "name": "x"},
            ],
        )
        out = _run(msf_show_opts(MsfShowOptsInput(module="multi/handler")))
        assert "Generic Payload Handler" in out

    def test_not_found(self, stub):
        _client(stub)
        out = _run(msf_show_opts(MsfShowOptsInput(module="does/not/exist")))
        assert "未找到模块" in out

    def test_ambiguous(self, stub):
        _client(
            stub,
            modules=self._db(),
            search_rows=[
                {"type": "exploit", "fullname": "exploit/a/x", "name": "x"},
                {"type": "auxiliary", "fullname": "auxiliary/a/x", "name": "x"},
            ],
        )
        out = _run(msf_show_opts(MsfShowOptsInput(module="a/x")))
        assert "歧义" in out
        assert "exploit/a/x" in out
        assert "auxiliary/a/x" in out

    def test_unknown_module_internal_error(self, stub):
        # bare name with no search hits but a type prefix that passes the
        # regex goes straight to use() → library TypeError
        _client(stub, modules={})
        out = _run(msf_show_opts(MsfShowOptsInput(module="exploit/no/such/mod")))
        assert "加载模块失败" in out


class TestMsfRunExploitTool:
    def _db(self):
        return {"exploit/multi/handler": (dict(HANDLER_INFO), dict(HANDLER_OPTS))}

    def test_happy_path(self, stub):
        _client(stub, modules=self._db())
        out = _run(
            msf_run_exploit(
                MsfRunExploitInput(
                    module="exploit/multi/handler",
                    target="127.0.0.1",
                    options="LPORT=4444,ExitOnSession=false",
                )
            )
        )
        assert "Job ID:** 1" in out
        mtype, mname, kwargs = stub["client"].executed[0]
        assert mtype == "exploit"
        assert mname == "exploit/multi/handler"
        assert kwargs["RHOST"] == "127.0.0.1"
        assert kwargs["LPORT"] == 4444  # coerced to int
        assert kwargs["ExitOnSession"] is False  # coerced to bool

    def test_unknown_option_rejected(self, stub):
        _client(stub, modules=self._db())
        out = _run(
            msf_run_exploit(
                MsfRunExploitInput(
                    module="exploit/multi/handler",
                    target="127.0.0.1",
                    options="BOGUS=1",
                )
            )
        )
        assert "未知选项" in out
        assert "BOGUS" in out
        assert stub["client"].executed == []  # never launched

    def test_global_whitelist_ok(self, stub):
        _client(stub, modules=self._db())
        out = _run(
            msf_run_exploit(
                MsfRunExploitInput(
                    module="exploit/multi/handler",
                    target="127.0.0.1",
                    options="Payload=linux/aarch64/meterpreter_reverse_tcp,LHOST=127.0.0.1",
                )
            )
        )
        assert "Job ID" in out
        kwargs = stub["client"].executed[0][2]
        assert kwargs["Payload"] == "linux/aarch64/meterpreter_reverse_tcp"
        assert kwargs["LHOST"] == "127.0.0.1"

    def test_refused_job(self, stub):
        _client(
            stub,
            modules=self._db(),
            execute_result={"job_id": None, "uuid": None},
        )
        out = _run(
            msf_run_exploit(
                MsfRunExploitInput(module="exploit/multi/handler", target="127.0.0.1")
            )
        )
        assert "必填选项" in out

    def test_not_found(self, stub):
        _client(stub)
        out = _run(
            msf_run_exploit(
                MsfRunExploitInput(module="no/such/mod", target="127.0.0.1")
            )
        )
        assert "未找到模块" in out


class TestMsfJobsTool:
    def test_happy_path(self, stub):
        _client(stub, jobs={2: "Exploit: multi/handler"})
        out = _run(msf_jobs())
        assert "| 2 | Exploit: multi/handler |" in out

    def test_empty(self, stub):
        _client(stub)
        out = _run(msf_jobs())
        assert "没有运行中的" in out


class TestMsfStopJobTool:
    def test_happy_path(self, stub):
        _client(stub, jobs={2: "Exploit: multi/handler"})
        out = _run(msf_stop_job(MsfStopJobInput(job_id=2)))
        assert "已请求停止" in out
        assert stub["client"].stopped == [2]

    def test_error(self, stub):
        class _FailingJobs:
            @property
            def list(self):
                return {}

            def stop(self, jid):
                raise RuntimeError("job not found")

        class _FailingClient(FakeClient):
            @property
            def jobs(self):
                return _FailingJobs()

        stub["client"] = _FailingClient()
        out = _run(msf_stop_job(MsfStopJobInput(job_id=9)))
        assert "停止 job 9 失败" in out
        assert "RuntimeError" in out


class TestMsfSessionsTool:
    def test_happy_path(self, stub):
        _client(stub, sessions={6: dict(SESSION_ROW)})
        out = _run(msf_sessions())
        assert "| 6 | meterpreter" in out
        assert "xhj" in out

    def test_empty(self, stub):
        _client(stub)
        out = _run(msf_sessions())
        assert "没有活跃会话" in out


class TestMsfSessionExecTool:
    class FakeMeterpreter:
        def __init__(self, sid, client, data):
            self.sid = sid
            self.cmds = []
            self.rpc = self

        def call(self, method, args):
            if method == "session.meterpreter_run_single":
                self.cmds.append(args[1])
                return {"result": "success"}
            if method == "session.meterpreter_read":
                return {"data": f"OK ran {self.cmds[-1]}" if self.cmds else ""}
            return {}

    class FakeShell:
        def __init__(self, sid, client, data):
            self.sid = sid
            self.written = []

        def write(self, data):
            self.written.append(data)

        def read(self):
            return "shell output line"

    def test_meterpreter(self, stub, monkeypatch):
        monkeypatch.setattr(msf, "MeterpreterSession", self.FakeMeterpreter)
        _client(stub, sessions={6: dict(SESSION_ROW)})
        out = _run(
            msf_session_exec(MsfSessionExecInput(session_id="6", command="sysinfo"))
        )
        assert "OK ran sysinfo" in out
        assert "(meterpreter)" in out

    def test_by_uuid(self, stub, monkeypatch):
        monkeypatch.setattr(msf, "MeterpreterSession", self.FakeMeterpreter)
        _client(stub, sessions={6: dict(SESSION_ROW)})
        out = _run(
            msf_session_exec(
                MsfSessionExecInput(session_id="atv8tnyh", command="getuid")
            )
        )
        assert "OK ran getuid" in out

    def test_shell_session(self, stub, monkeypatch):
        monkeypatch.setattr(msf, "ShellSession", self.FakeShell)
        row = dict(SESSION_ROW, type="shell")
        _client(stub, sessions={7: row})
        out = _run(
            msf_session_exec(MsfSessionExecInput(session_id="7", command="id"))
        )
        assert "shell output line" in out
        assert "(shell)" in out

    def test_not_found(self, stub, monkeypatch):
        monkeypatch.setattr(msf, "MeterpreterSession", self.FakeMeterpreter)
        _client(stub, sessions={6: dict(SESSION_ROW)})
        out = _run(
            msf_session_exec(MsfSessionExecInput(session_id="99", command="sysinfo"))
        )
        assert "会话 99 不存在" in out
        assert "msf_sessions" in out


# ===================================================================
# msf_kill_session (bug 4: missing session-kill tool)
# ===================================================================


class TestKillSessionWorker:
    def test_by_int_id(self, stub):
        _client(stub, sessions={9: dict(SESSION_ROW)})
        key, stype = _run(msf._rpc(_kill_session, "9"))
        assert key == 9 and stype == "meterpreter"

    def test_by_uuid(self, stub):
        _client(stub, sessions={9: dict(SESSION_ROW)})
        key, stype = _run(msf._rpc(_kill_session, "atv8tnyh"))
        assert key == 9

    def test_not_found(self, stub):
        _client(stub, sessions={9: dict(SESSION_ROW)})
        with pytest.raises(LookupError) as ei:
            _run(msf._rpc(_kill_session, "99"))
        assert "99" in str(ei.value)

    def test_uses_session_stop_rpc(self, stub):
        c = _client(stub, sessions={9: dict(SESSION_ROW)})
        _run(msf._rpc(_kill_session, "9"))
        assert c.killed == [("session.stop", [9])]


class TestMsfKillSessionTool:
    def test_happy_path(self, stub):
        _client(stub, sessions={9: dict(SESSION_ROW)})
        out = _run(msf_kill_session(MsfKillSessionInput(session_id="9")))
        assert "✅ 已终止 session 9" in out
        assert "meterpreter" in out
        assert "msf_stop_job" in out  # cleanup hint

    def test_not_found(self, stub):
        _client(stub, sessions={9: dict(SESSION_ROW)})
        out = _run(msf_kill_session(MsfKillSessionInput(session_id="99")))
        assert "❌" in out and "msf_sessions" in out

    def test_bad_session_id_rejected(self):
        with pytest.raises(ValidationError):
            MsfKillSessionInput(session_id="9; rm -rf /")


# ===================================================================
# msf_job_info (③-b: read completed job output)
# ===================================================================

JOB_INFO_SSH_LOGIN = {
    "result": {
        "job_id": 12,
        "type": "auxiliary",
        "command": "auxiliary/scanner/ssh/ssh_login",
        "name": "SSH Login",
        "result": "[*] 192.168.0.77:22  xhj:xhj200814 - Login Succeeded",
    }
}


class TestJobInfoWorker:
    def test_wraped_result_shape(self, stub):
        _client(stub, job_info={12: JOB_INFO_SSH_LOGIN})
        info = _run(msf._rpc(_job_info, 12))
        assert info["job_id"] == 12
        assert info["command"] == "auxiliary/scanner/ssh/ssh_login"
        assert "Login Succeeded" in info["result"]

    def test_unwrapped_shape(self, stub):
        _client(stub, job_info={11: {
            "job_id": 11, "type": "handler",
            "command": "exploit/multi/handler", "name": "Handler",
            "result": None,
        }})
        info = _run(msf._rpc(_job_info, 11))
        assert info["command"] == "exploit/multi/handler"
        assert info["result"] is None

    def test_unknown_job_error_dict_raises(self, stub):
        # live-verified: the RPC returns {"error": True, "error_message":
        # "Invalid Job"} instead of raising
        _client(stub)
        with pytest.raises(LookupError) as ei:
            _run(msf._rpc(_job_info, 99))
        assert "Invalid Job" in str(ei.value)
        assert "99" in str(ei.value)


class TestMsfJobInfoTool:
    def test_happy_path_str_result(self, stub):
        _client(stub, job_info={12: JOB_INFO_SSH_LOGIN})
        out = _run(msf_job_info(MsfJobInfoInput(job_id=12)))
        assert "job 12" in out
        assert "auxiliary/scanner/ssh/ssh_login" in out
        assert "Login Succeeded" in out

    def test_dict_result_json_dumped(self, stub):
        _client(stub, job_info={13: {
            "result": {"job_id": 13, "type": "exploit",
                       "command": "exploit/multi/handler", "name": "Handler",
                       "result": {"ok": True, "count": 2}},
        }})
        out = _run(msf_job_info(MsfJobInfoInput(job_id=13)))
        assert '"count": 2' in out

    def test_missing_result_field(self, stub):
        _client(stub, job_info={11: {
            "result": {"job_id": 11, "type": "handler",
                       "command": "exploit/multi/handler", "name": "Handler"},
        }})
        out = _run(msf_job_info(MsfJobInfoInput(job_id=11)))
        assert "无结果字段" in out

    def test_unknown_job(self, stub):
        _client(stub)
        out = _run(msf_job_info(MsfJobInfoInput(job_id=99)))
        assert "❌" in out and "99" in out
        assert "不存在或记录已被清除" in out
        assert "msf_jobs" in out
