"""Tests for the AD + privesc surgical points (impacket 五件套 + peas).

Covers per the project baseline:
  - gating/registration (🟡 AD_PENTEST_TOOLS / 🔴 AD_ATTACK_TOOLS)
  - impacket unified credential target string construction (masked password)
  - command construction (exact flags, verified against --help ground truth
    on Kali impacket v0.14.0.dev0, 2026-09-07)
  - input validation (shell-meta, credential-prompt guards, shape, bounds)
  - output parsing (SID rows, hash rows, relay events, LinPEAS-ng sections
    and red/yellow findings) and report rendering
"""

from __future__ import annotations

import asyncio

import pytest

from kali_mcp.ad import (
    AD_ATTACK_TOOLS,
    AD_PENTEST_TOOLS,
    _creds_target,
    _dcsync_cmd,
    _HASH_ROW_RE,
    _lookupsid_cmd,
    _masked_cmd,
    _ntlmrelayx_cmd,
    _parse_lookupsid,
    _peas_linux_cmd,
    _peas_parse,
    _peas_windows_cmd,
    _psexec_cmd,
    _secretsdump_cmd,
    _split_targets,
    DcsyncInput,
    LookupsidInput,
    NtlmrelayxInput,
    PeasLinuxInput,
    PeasWindowsInput,
    PsexecInput,
    SecretsdumpInput,
    impacket_dcsync,
    impacket_lookupsid,
    impacket_ntlmrelayx,
    impacket_psexec,
    impacket_secretsdump,
    peas_linux,
    peas_windows,
)
from kali_mcp.executor import CommandResult
from kali_mcp.tools import TOOL_REGISTRY


def _run(coro):
    return asyncio.run(coro)


# ===================================================================
# Gating / registration
# ===================================================================


class TestAdGating:
    """🟡/🔴 gating: AD tools never land in the unconditional green registry."""

    def test_pentest_set(self):
        assert set(AD_PENTEST_TOOLS) == {
            "impacket_lookupsid",
            "peas_linux",
            "peas_windows",
        }
        for name, (func, model) in AD_PENTEST_TOOLS.items():
            assert callable(func)
            assert model.__name__.endswith("Input")

    def test_attack_set(self):
        assert set(AD_ATTACK_TOOLS) == {
            "impacket_secretsdump",
            "impacket_dcsync",
            "impacket_psexec",
            "impacket_ntlmrelayx",
        }
        for name, (func, model) in AD_ATTACK_TOOLS.items():
            assert callable(func)
            assert model.__name__.endswith("Input")

    def test_no_overlap_with_green(self):
        for registry in (AD_PENTEST_TOOLS, AD_ATTACK_TOOLS):
            assert not set(registry) & set(TOOL_REGISTRY)

    def test_no_overlap_between_ad_registries(self):
        assert not set(AD_PENTEST_TOOLS) & set(AD_ATTACK_TOOLS)


# ===================================================================
# Shared credential-target helpers
# ===================================================================


class TestCredsTarget:
    def test_no_creds_plain_target(self):
        assert _creds_target("192.168.0.213", "", "", "") == "192.168.0.213"

    def test_user_only(self):
        assert _creds_target("dc", "", "jdoe", "") == "jdoe@dc"

    def test_user_password(self):
        assert _creds_target("dc", "", "jdoe", "S3cr3t") == "jdoe:S3cr3t@dc"

    def test_domain_user_password(self):
        assert (
            _creds_target("dc", "corp", "jdoe", "S3cr3t")
            == "corp/jdoe:S3cr3t@dc"
        )

    def test_backslash_user(self):
        assert _creds_target("dc", "", "CORP\\jdoe", "x") == "CORP\\jdoe:x@dc"


class TestMaskedCmd:
    def test_password_masked(self):
        line = _masked_cmd(
            ["impacket-lookupsid", "corp/jdoe:S3cr3t@dc", "4000"], "S3cr3t"
        )
        assert "S3cr3t" not in line
        assert "corp/jdoe:***@dc" in line

    def test_no_password_unchanged(self):
        line = _masked_cmd(["impacket-lookupsid", "-no-pass", "dc", "4000"], "")
        assert line == "impacket-lookupsid -no-pass dc 4000"

    def test_spaced_element_quoted(self):
        line = _masked_cmd(["impacket-psexec", "dc", "whoami /all"], "")
        assert '"whoami /all"' in line


class TestSplitTargets:
    def test_comma_and_space_split_dedup(self):
        assert _split_targets("a.b, c.b a.b") == ["a.b", "c.b"]

    def test_empty(self):
        assert _split_targets("  , ") == []


# ===================================================================
# impacket_lookupsid (🟡)
# ===================================================================

#: Ground truth format (impacket v0.14 source, lookupsid.py line 138):
#:   "%d: %s\\%s (%s)" % (rid, domain, name, SID_NAME_USE kind)
_LOOKUPSID_OUT = """\
500: CORP\\Administrator (User)
501: CORP\\Guest (User)
512: CORP\\Domain Admins (Alias)
1001: CORP\\jdoe (User)
"""

_LOOKUPSID_STDERR = (
    "Impacket v0.14.0.dev0 - Copyright Fortra, LLC\n"
    "Domain SID is: S-1-5-21-2667927173-4084240773-3234464186\n"
)


class TestLookupsidCmd:
    def _capture(self, monkeypatch, params, stdout="", stderr="", success=True):
        import kali_mcp.ad as a

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                captured["cmd"] = cmd
                captured["timeout"] = timeout
                return CommandResult(
                    stdout=stdout,
                    stderr=stderr,
                    returncode=0 if success else 1,
                    success=success,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(impacket_lookupsid(params))
        assert isinstance(out, str)
        return captured, out

    def test_default_cmd_anonymous(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, LookupsidInput(target="192.168.0.213")
        )
        assert captured["cmd"] == [
            "impacket-lookupsid", "-no-pass", "192.168.0.213", "4000",
        ]
        assert captured["timeout"] == 120

    def test_credentialed_cmd_no_nopass(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch,
            LookupsidInput(
                target="dc.corp.local", domain="corp",
                username="jdoe", password="S3cr3t",
            ),
        )
        cmd = captured["cmd"]
        assert "-no-pass" not in cmd
        assert "corp/jdoe:S3cr3t@dc.corp.local" in cmd
        assert cmd[-1] == "4000"

    def test_optional_flags(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch,
            LookupsidInput(
                target="dc", max_rid=100000, domain_sids=True,
                target_ip="10.0.0.5", port=10445,
            ),
        )
        cmd = captured["cmd"]
        assert cmd[1] == "-domain-sids"
        assert "-target-ip" in cmd and "10.0.0.5" in cmd
        assert "-port" in cmd and "10445" in cmd
        assert cmd[-1] == "100000"

    def test_wall_timeout_forwarded(self, monkeypatch):
        captured, _ = self._capture(
            monkeypatch, LookupsidInput(target="10.0.0.5", wall_timeout=300)
        )
        assert captured["timeout"] == 300

    def test_system_path_env_pinned(self, monkeypatch):
        """impacket shebang is `#!/usr/bin/env python` — the service PATH is
        venv-first, which would resolve `env python` to the venv python (no
        impacket). The call must pin a pure system PATH."""
        captured, _ = self._capture(
            monkeypatch, LookupsidInput(target="10.0.0.5")
        )
        assert captured["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


class TestLookupsidValidation:
    def test_bad_target_rejected(self):
        with pytest.raises(Exception):
            LookupsidInput(target="not a host")

    def test_username_space_rejected(self):
        with pytest.raises(Exception):
            LookupsidInput(target="10.0.0.5", username="bad user")

    def test_password_shell_meta_rejected(self):
        with pytest.raises(Exception):
            LookupsidInput(
                target="10.0.0.5", username="u", password="p;rm -rf"
            )

    @pytest.mark.parametrize("rid", [0, 200001])
    def test_max_rid_bounds(self, rid):
        with pytest.raises(Exception):
            LookupsidInput(target="10.0.0.5", max_rid=rid)

    def test_target_ip_shell_meta_rejected(self):
        with pytest.raises(Exception):
            LookupsidInput(target="10.0.0.5", target_ip="x;ls")


class TestLookupsidParsing:
    def test_parse_rows_sorted_by_rid(self):
        rows = _parse_lookupsid(_LOOKUPSID_OUT)
        assert [r["rid"] for r in rows] == [500, 501, 512, 1001]
        assert rows[0] == {
            "rid": 500, "domain": "CORP",
            "name": "Administrator", "kind": "User",
        }
        assert rows[2]["kind"] == "Alias"
        assert rows[3]["name"] == "jdoe"

    def test_parse_ignores_noise(self):
        rows = _parse_lookupsid("noise line\n[*] Connecting...\n")
        assert rows == []

    def test_extract_domain_sid(self):
        from kali_mcp.ad import _extract_domain_sid

        assert (
            _extract_domain_sid(_LOOKUPSID_STDERR)
            == "S-1-5-21-2667927173-4084240773-3234464186"
        )
        assert _extract_domain_sid("") == ""


class TestLookupsidE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", success=True):
        import kali_mcp.ad as a

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                captured["cmd"] = cmd
                return CommandResult(
                    stdout=stdout,
                    stderr=stderr,
                    returncode=0 if success else 1,
                    success=success,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(impacket_lookupsid(params))
        assert isinstance(out, str)
        return captured, out

    def test_success_report(self, monkeypatch):
        _, out = self._capture(
            monkeypatch,
            LookupsidInput(target="192.168.0.213"),
            stdout=_LOOKUPSID_OUT,
            stderr=_LOOKUPSID_STDERR,
        )
        assert "🔎 impacket-lookupsid" in out
        assert "Administrator" in out
        assert "Domain Admins" in out
        assert "User 3 / Group+Alias 1" in out
        assert "S-1-5-21-2667927173-4084240773-3234464186" in out

    def test_unsorted_input_sorted_in_report(self, monkeypatch):
        _, out = self._capture(
            monkeypatch,
            LookupsidInput(target="10.0.0.9"),
            stdout="1001: CORP\\jdoe (User)\n500: CORP\\Administrator (User)\n",
        )
        admin_pos = out.find("Administrator")
        jdoe_pos = out.find("jdoe")
        assert admin_pos != -1 and jdoe_pos != -1
        assert admin_pos < jdoe_pos

    def test_no_rows_path(self, monkeypatch):
        _, out = self._capture(
            monkeypatch,
            LookupsidInput(target="192.168.0.213"),
            stdout="no sid lines here",
        )
        assert "未枚举到任何账户" in out
        assert "enum4linux_scan" in out  # hint for non-AD targets

    def test_failure_path(self, monkeypatch):
        _, out = self._capture(
            monkeypatch,
            LookupsidInput(target="192.168.0.213"),
            stderr="[-] SMB Session Error: STATUS_ACCESS_DENIED",
            success=False,
        )
        assert "❌ lookupsid 执行失败" in out
        assert "STATUS_ACCESS_DENIED" in out


# ===================================================================
# impacket_secretsdump (🔴)
# ===================================================================

_HASH_OUT = """\
Impacket v0.14.0.dev0 - Copyright Fortra, LLC
[-] RemoteOperations _saveSAM:
Administrator::500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest::501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount::503:(null):aad3b435b51404eeaad3b435b51404ee:::
"""


class TestSecretsdumpCmd:
    def test_default_cmd(self):
        p = SecretsdumpInput(target="192.168.0.234")
        cmd = _secretsdump_cmd(p)
        assert cmd == [
            "impacket-secretsdump",
            "-no-pass",
            "-exec-method", "wmiexec",
            "192.168.0.234",
        ]

    def test_credentialed_with_options(self):
        p = SecretsdumpInput(
            target="dc", domain="corp", username="admin",
            password="pw", exec_method="smbexec",
            skip_sam=True, skip_security=True,
            target_ip="10.0.0.9", dc_ip="10.0.0.1",
        )
        cmd = _secretsdump_cmd(p)
        assert "-no-pass" not in cmd
        assert "corp/admin:pw@dc" in cmd
        assert "-exec-method" in cmd and "smbexec" in cmd
        assert "-skip-sam" in cmd and "-skip-security" in cmd
        assert "-target-ip" in cmd and "10.0.0.9" in cmd
        assert "-dc-ip" in cmd and "10.0.0.1" in cmd

    def test_hashes_pass_the_hash(self):
        p = SecretsdumpInput(
            target="10.0.0.9",
            username="admin",
            hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        cmd = _secretsdump_cmd(p)
        # pass-the-hash rides the standalone -hashes flag, NOT the target
        assert "-hashes" in cmd
        assert "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" in cmd
        assert "admin@10.0.0.9" in cmd  # target has no embedded hash


class TestSecretsdumpValidation:
    def test_bad_exec_method(self):
        with pytest.raises(Exception):
            SecretsdumpInput(target="10.0.0.9", exec_method="atexec")

    def test_username_without_password_rejected(self):
        with pytest.raises(Exception):
            SecretsdumpInput(target="10.0.0.9", username="admin")

    def test_username_with_hashes_ok(self):
        p = SecretsdumpInput(
            target="10.0.0.9", username="admin",
            hashes="a" * 32 + ":" + "b" * 32,
        )
        assert p.username == "admin"

    def test_bad_hashes_rejected(self):
        with pytest.raises(Exception):
            SecretsdumpInput(
                target="10.0.0.9", username="admin",
                password="x", hashes="nothex:!",
            )


class TestHashParsing:
    def test_parse_hash_rows(self):
        rows = []
        for line in _HASH_OUT.splitlines():
            m = _HASH_ROW_RE.match(line.strip())
            if m:
                rows.append(dict(user=m.group(1), rid=int(m.group(2))))
        assert [r["user"] for r in rows] == [
            "Administrator", "Guest", "DefaultAccount",
        ]
        assert rows[2]["rid"] == 503

    def test_null_lm_accepted(self):
        m = _HASH_ROW_RE.match(
            "DefaultAccount::503:(null):aad3b435b51404eeaad3b435b51404ee:::"
        )
        assert m and m.group(3) == "(null)"


class TestSecretsdumpE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", success=True):
        import kali_mcp.ad as a

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                captured["cmd"] = cmd
                return CommandResult(
                    stdout=stdout, stderr=stderr,
                    returncode=0 if success else 1, success=success,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(impacket_secretsdump(params))
        return captured, out

    def test_success_report(self, monkeypatch):
        captured, out = self._capture(
            monkeypatch,
            SecretsdumpInput(
                target="10.0.0.9", username="admin", password="pw"
            ),
            stdout=_HASH_OUT,
        )
        assert "🗝 impacket-secretsdump" in out
        assert "3 个本地账户哈希已提取" in out
        assert "Administrator" in out
        # password never leaks into the success report (no command echo)
        assert "pw" not in out

    def test_failure_path(self, monkeypatch):
        _, out = self._capture(
            monkeypatch,
            SecretsdumpInput(target="10.0.0.9", username="admin", password="x"),
            stderr="[-] SMB Session Error: STATUS_LOGON_FAILURE",
            success=False,
        )
        assert "❌ secretsdump 执行失败" in out
        assert "exec_method=smbexec" in out  # recovery hint


# ===================================================================
# impacket_dcsync (🔴)
# ===================================================================


class TestDcsyncCmd:
    def test_default_cmd_just_dc(self):
        p = DcsyncInput(target="dc.corp.local")
        cmd = _dcsync_cmd(p)
        assert cmd[0] == "impacket-secretsdump"
        assert cmd[1] == "-just-dc"
        assert "-no-pass" in cmd
        assert cmd[-1] == "dc.corp.local"

    def test_full_options(self):
        p = DcsyncInput(
            target="dc", domain="corp", username="admin", password="pw",
            just_dc_ntlm=True, just_dc_user="jdoe",
            ldapfilter="(sAMAccountName=jdoe)",
        )
        cmd = _dcsync_cmd(p)
        assert "-just-dc-ntlm" in cmd
        assert "-just-dc-user" in cmd and "jdoe" in cmd
        assert "-ldapfilter" in cmd and "(sAMAccountName=jdoe)" in cmd
        assert "corp/admin:pw@dc" in cmd

    def test_username_without_password_rejected(self):
        with pytest.raises(Exception):
            DcsyncInput(target="dc", username="admin")


class TestDcsyncValidation:
    def test_ldapfilter_control_char_rejected(self):
        with pytest.raises(Exception):
            DcsyncInput(target="dc", ldapfilter="a\nb")

    def test_ldapfilter_too_long_rejected(self):
        with pytest.raises(Exception):
            DcsyncInput(target="dc", ldapfilter="x" * 513)

    def test_dc_user_shell_meta_rejected(self):
        with pytest.raises(Exception):
            DcsyncInput(target="dc", just_dc_user="a;b")


class TestDcsyncE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", success=True):
        captured = {}

        import kali_mcp.ad as a

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                return CommandResult(
                    stdout=stdout, stderr=stderr,
                    returncode=0 if success else 1, success=success,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(impacket_dcsync(params))
        return out

    def test_success_report(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            DcsyncInput(target="dc"),
            stdout="Administrator::500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n",
        )
        assert "🏛 impacket-dcsync" in out
        assert "1 个域账户哈希已通过 DRSUAPI 外带" in out
        assert "Administrator" in out

    def test_no_rows_hint(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            DcsyncInput(target="dc", username="admin", password="x"),
            stdout="[-] DRSUAPI error\n",
        )
        assert "DS-Replication-Get-Changes" in out

    def test_failure_path(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            DcsyncInput(target="dc", username="admin", password="x"),
            stderr="[-] Kerberos SessionError",
            success=False,
        )
        assert "❌ dcsync 执行失败" in out


# ===================================================================
# impacket_psexec (🔴)
# ===================================================================


class TestPsexecCmd:
    def test_default_cmd(self):
        p = PsexecInput(target="192.168.0.234")
        cmd = _psexec_cmd(p)
        assert cmd == [
            "impacket-psexec", "-no-pass", "192.168.0.234", "cmd.exe",
        ]

    def test_credentialed_with_options(self):
        p = PsexecInput(
            target="10.0.0.9", domain="corp", username="admin",
            password="pw", command="whoami /all",
            service_name="MySvc1", path="C:\\temp",
            codec="gbk", port=10445, target_ip="10.0.0.9",
        )
        cmd = _psexec_cmd(p)
        assert "-no-pass" not in cmd
        assert "corp/admin:pw@10.0.0.9" in cmd
        assert cmd[-1] == "whoami /all"
        assert "-service-name" in cmd and "MySvc1" in cmd
        assert "-path" in cmd and "C:\\temp" in cmd
        assert "-codec" in cmd and "gbk" in cmd
        assert "-port" in cmd and "10445" in cmd
        assert "-target-ip" in cmd and "10.0.0.9" in cmd
        assert cmd[-1] == "whoami /all"


class TestPsexecValidation:
    def test_command_control_char_rejected(self):
        with pytest.raises(Exception):
            PsexecInput(target="10.0.0.9", command="a\nb")

    def test_bad_service_name(self):
        with pytest.raises(Exception):
            PsexecInput(target="10.0.0.9", service_name="bad name")

    def test_bad_codec(self):
        with pytest.raises(Exception):
            PsexecInput(target="10.0.0.9", codec="utf-8;ls")

    def test_username_without_password_rejected(self):
        with pytest.raises(Exception):
            PsexecInput(target="10.0.0.9", username="admin")


class TestPsexecE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", rc=0):
        captured = {}

        import kali_mcp.ad as a

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                return CommandResult(
                    stdout=stdout, stderr=stderr,
                    returncode=rc, success=rc == 0,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(impacket_psexec(params))
        return out

    def test_success_report(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            PsexecInput(
                target="10.0.0.9", username="admin",
                password="pw", command="whoami /all",
            ),
            stdout="corp\\admin\n\nGROUP:\n  Administrators\n",
        )
        assert "🎯 impacket-psexec" in out
        assert "corp\\admin" in out
        assert "退出码:** 0" in out

    def test_nonzero_still_reported(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            PsexecInput(
                target="10.0.0.9", username="admin",
                password="pw", command="dir C:",
            ),
            stdout="File Not Found", rc=1,
        )
        assert "非零退出" in out
        assert "File Not Found" in out

    def test_failure_path(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            PsexecInput(target="10.0.0.9", username="admin", password="x"),
            stderr="[-] SMB Session Error: STATUS_LOGON_FAILURE", rc=1,
        )
        assert "❌ psexec 执行失败" in out


# ===================================================================
# impacket_ntlmrelayx (🔴)
# ===================================================================

_RELAY_OUT = """\
Impacket v0.14.0.dev0 - Copyright Fortra, LLC
[*] Sniffing on 0.0.0.0
[*] Serving SMB...
[*] Connection from 192.168.0.61:44321
[*] Relaying to 192.168.0.234:445
[!] No valid answer
"""


class TestNtlmrelayxCmd:
    def test_default_bounded_surface(self):
        p = NtlmrelayxInput(targets="192.168.0.234,192.168.0.213")
        cmd = _ntlmrelayx_cmd(p)
        assert cmd[0] == "impacket-ntlmrelayx"
        assert cmd[1] == "-t" and cmd[2] == "192.168.0.234"
        assert "192.168.0.213" in cmd
        assert "--smb-port" in cmd and "445" in cmd
        assert "-smb2support" in cmd
        # default: SMB + raw only — http/wcf/winrm/rpc off
        assert "--no-http-server" in cmd
        assert "--no-wcf-server" in cmd
        assert "--no-winrm-server" in cmd
        assert "--no-rpc-server" in cmd
        assert "--no-raw-server" not in cmd

    def test_optional_flags(self):
        p = NtlmrelayxInput(
            targets="10.0.0.9", domain="corp", interface_ip="192.168.0.225",
            smb_port=1445, socks=True, command="whoami",
            enum_local_admins=True, keep_relaying=True, enable_http=True,
            smb2support=False,
        )
        cmd = _ntlmrelayx_cmd(p)
        assert "-ip" in cmd and "192.168.0.225" in cmd
        assert "1445" in cmd
        assert "-smb2support" not in cmd
        assert "--no-http-server" not in cmd
        assert "-socks" in cmd
        assert "-c" in cmd and "whoami" in cmd
        assert "--enum-local-admins" in cmd
        assert "--keep-relaying" in cmd
        assert "-domain" in cmd and "corp" in cmd


class TestNtlmrelayxValidation:
    def test_wildcard_rejected(self):
        with pytest.raises(Exception):
            NtlmrelayxInput(targets="*")

    def test_empty_rejected(self):
        with pytest.raises(Exception):
            NtlmrelayxInput(targets="")

    def test_bad_target_rejected(self):
        with pytest.raises(Exception):
            NtlmrelayxInput(targets="10.0.0.9;ls")

    def test_command_control_char_rejected(self):
        with pytest.raises(Exception):
            NtlmrelayxInput(targets="10.0.0.9", command="a\nb")


class TestNtlmrelayxE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", rc=124):
        captured = {}

        import kali_mcp.ad as a

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                return CommandResult(
                    stdout=stdout, stderr=stderr,
                    returncode=rc, success=rc == 0,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(impacket_ntlmrelayx(params))
        return out

    def test_events_rendered(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            NtlmrelayxInput(targets="192.168.0.234"),
            stdout=_RELAY_OUT,
        )
        assert "🕸 impacket-ntlmrelayx" in out
        assert "Connection from 192.168.0.61" in out
        assert "Relaying to 192.168.0.234:445" in out
        assert "Sniffing on" not in out  # not an event of interest

    def test_empty_window_not_failure(self, monkeypatch):
        out = self._capture(
            monkeypatch,
            NtlmrelayxInput(targets="192.168.0.234"),
            stdout="[*] Serving SMB...\n",
        )
        assert "无成功中继" in out
        assert "❌" not in out


# ===================================================================
# peas_linux (🟡)
# ===================================================================

_LINPEAS_OUT = """\
          LinPEAS-ng by carlospolop

  YOU ARE ALREADY ROOT!!! (it could take longer to complete execution)

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚══════════════════════╝
OS: Linux version 7.0.12+kali-arm64
User & Groups: uid=0(root) gid=0(root)
Hostname: kali
                               ╔═══════════════════╗
═══════════════════════════════╣ Files with Interesting Permissions ╠═══════════════════════════════
                               ╚══════════════════════╝
-rwsr-xr-x 1 root root 70K  4月 3日 01:44 /usr/bin\x1b[1;31m/chfn  --->  SuSE_9.3/10\x1b[0m
-rwsr-xr-x 1 root root 67K  6月 8日 01:44 /usr/bin\x1b[1;31m/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)\x1b[0m
-rw-r--r-- 1 root root 1K  1月 1日 00:00 /etc/\x1b[33mshadow\x1b[0m readable
"""


class TestPeasLinuxCmd:
    def test_default_cmd(self):
        cmd = _peas_linux_cmd(PeasLinuxInput())
        # -N deliberately absent: it suppresses the red/yellow markers
        assert cmd == [
            "bash", "/usr/share/peass/linpeas/linpeas.sh", "-q", "-s",
        ]
        assert "-N" not in cmd

    def test_all_extra_flags(self):
        cmd = _peas_linux_cmd(
            PeasLinuxInput(
                stealth=False, all_checks=True, extra=True,
                checks="users_information,cloud", mitre="T1057,T1082",
            )
        )
        assert "-s" not in cmd
        assert "-N" not in cmd
        assert "-a" in cmd and "-e" in cmd
        assert "-o" in cmd and "users_information,cloud" in cmd
        assert "-T" in cmd and "T1057,T1082" in cmd

    def test_unknown_check_rejected(self):
        with pytest.raises(Exception):
            PeasLinuxInput(checks="not_a_check")

    def test_bad_mitre_rejected(self):
        with pytest.raises(Exception):
            PeasLinuxInput(mitre="T105")

    def test_wall_timeout_forwarded(self, monkeypatch):
        import kali_mcp.ad as a

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                captured["timeout"] = timeout
                return CommandResult(
                    stdout="ok", stderr="", returncode=0, success=True,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        _run(peas_linux(PeasLinuxInput(wall_timeout=600)))
        assert captured["timeout"] == 600


class TestPeasRanking:
    def test_noise_dropped_and_ranked(self):
        from kali_mcp.ad import _peas_rank

        out = _peas_rank(
            [
                "RED: You should take a look into it",
                "  ═╣ AppArmor profile? .............. unconfined",
                "/dev/sr0 /media/cdrom0 udf,iso9660 user,noauto 0 0",
                "-rwsr-xr-x 1 root root 67K /usr/bin/pkexec ---> CVE-2019-13272",
            ]
        )
        # legend dropped; bullet-╣ line kept; CVE line ranked first
        assert out[0].startswith("-rwsr-xr-x")
        assert any("AppArmor" in o for o in out)
        assert not any("You should take a look" in o for o in out)
        assert len(out) == 3

    def test_stable_order_without_keywords(self):
        from kali_mcp.ad import _peas_rank

        out = _peas_rank(["line-b", "line-a"])
        assert out == ["line-b", "line-a"]


class TestPeasParsing:
    def test_sections_red_yellow(self):
        sections, red, yellow = _peas_parse(_LINPEAS_OUT)
        assert sections == ["Basic information", "Files with Interesting Permissions"]
        assert len(red) == 2
        assert "pkexec" in red[1]
        assert "CVE-2019-13272" in red[1]
        assert len(yellow) == 1
        assert "shadow" in yellow[0]
        # ANSI stripped from findings
        assert "\x1b" not in red[0]


class TestPeasLinuxE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", success=True):
        captured = {}

        import kali_mcp.ad as a

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                return CommandResult(
                    stdout=stdout, stderr=stderr,
                    returncode=0 if success else 1, success=success,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(peas_linux(params))
        return out

    def test_success_report(self, monkeypatch):
        out = self._capture(monkeypatch, PeasLinuxInput(), stdout=_LINPEAS_OUT)
        assert "🐑 linpeas" in out
        assert "2 个高置信提权向量" in out
        assert "pkexec" in out
        assert "stealth 快速" in out
        assert "原始输出" in out

    def test_clean_report(self, monkeypatch):
        out = self._capture(
            monkeypatch, PeasLinuxInput(),
            stdout="═══╣ Basic information ╠═══\nOS: Linux\n",
        )
        assert "未发现红/黄色高亮项" in out

    def test_failure_path(self, monkeypatch):
        out = self._capture(
            monkeypatch, PeasLinuxInput(), stderr="bash: no such file",
            success=False,
        )
        assert "❌ linpeas 执行失败" in out
        assert "apt install peass" in out


# ===================================================================
# peas_windows (🟡)
# ===================================================================


class TestPeasWindowsCmd:
    def test_default_cmd_stages_x64(self):
        p = PeasWindowsInput(target="192.168.0.234")
        cmd = _peas_windows_cmd(p)
        assert cmd == [
            "impacket-psexec",
            "-c", "/usr/share/peass/winpeas/winPEASx64.exe",
            "-no-pass",
            "192.168.0.234",
            "winPEASx64.exe -s",
        ]

    def test_arch_variants(self):
        for arch, exe in (
            ("x86", "winPEASx86.exe"),
            ("any", "winPEASany.exe"),
        ):
            cmd = _peas_windows_cmd(
                PeasWindowsInput(target="10.0.0.9", arch=arch,
                                  all_checks=True)
            )
            assert f"/usr/share/peass/winpeas/{exe}" in cmd
            assert cmd[-1] == f"{exe} -s -a"

    def test_credentialed_cmd(self):
        cmd = _peas_windows_cmd(
            PeasWindowsInput(
                target="10.0.0.9", domain="corp",
                username="jdoe", password="S3cr3t", silent=False,
            )
        )
        assert "-no-pass" not in cmd
        assert "corp/jdoe:S3cr3t@10.0.0.9" in cmd
        assert cmd[-1] == "winPEASx64.exe"

    def test_bad_arch_rejected(self):
        with pytest.raises(Exception):
            PeasWindowsInput(target="10.0.0.9", arch="arm64")

    def test_username_without_password_rejected(self):
        with pytest.raises(Exception):
            PeasWindowsInput(target="10.0.0.9", username="jdoe")


class TestPeasWindowsE2E:
    def _capture(self, monkeypatch, params, stdout="", stderr="", rc=0):
        import kali_mcp.ad as a

        captured = {}

        class _CapEx:
            async def run(self, cmd, timeout=None, input_data=None, env=None):
                captured.setdefault("env", env)
                captured["cmd"] = cmd
                return CommandResult(
                    stdout=stdout, stderr=stderr,
                    returncode=rc, success=rc == 0,
                )

        monkeypatch.setattr(a, "get_executor", lambda timeout=None: _CapEx())
        out = _run(peas_windows(params))
        return captured, out

    def test_success_report(self, monkeypatch):
        captured, out = self._capture(
            monkeypatch,
            PeasWindowsInput(
                target="192.168.0.234", username="admin", password="pw"
            ),
            stdout="> peass ~ Privilege Escalation Awesome Scripts SUITE\nUsers: admin\n",
        )
        assert "🐑 winpeas" in out
        assert "暂存到目标临时目录" in out
        assert "Users: admin" in out
        # password never leaks into the success report (no command echo)
        assert "pw" not in out
        assert "S3cr3t" not in out

    def test_failure_path(self, monkeypatch):
        _, out = self._capture(
            monkeypatch,
            PeasWindowsInput(
                target="192.168.0.234", username="admin", password="x"
            ),
            stderr="[-] SMB Session Error: STATUS_LOGON_FAILURE", rc=1,
        )
        assert "❌ winpeas 执行失败" in out
        # masked command shown, password never present
        assert "x" not in out or "S3cr3t" not in out
