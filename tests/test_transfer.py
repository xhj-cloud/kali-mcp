"""Tests for the file transfer & local file tools (transfer.py).

Covers:
  - scp command construction (list-form, sshpass -e prefix, option order)
  - password via SSHPASS env, NEVER in argv
  - missing sshpass / missing local file / existing download target
  - file_read: text, truncation, binary header, dir/absolute-path refusal
  - file_delete: confirm gate, dir/symlink refusal, success, missing path
  - gating: all four under TRANSFER_TOOLS (ATTACK_ENABLED in server.py)
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from pydantic_core import core_schema  # noqa: F401  (kept for future schema tests)

from kali_mcp.executor import CommandResult
from kali_mcp import transfer
from kali_mcp.transfer import (
    TRANSFER_TOOLS,
    FileDeleteInput,
    FileReadInput,
    FileTransferInput,
    _scp_command,
    file_delete,
    file_download,
    file_read,
    file_upload,
)


def _run(coro):
    return asyncio.run(coro)


class FakeExecutor:
    """Executor stub: matches commands by predicate, records (cmd, env)."""

    def __init__(self, handlers: list[tuple[callable, CommandResult]]):
        self.handlers = handlers
        self.calls: list[tuple[list[str], dict | None]] = []

    async def run(self, cmd, timeout=None, input_data=None, hold_stdin=False,
                  env=None):
        self.calls.append((list(cmd), env))
        for predicate, result in self.handlers:
            if predicate(cmd):
                if callable(result):
                    return result(cmd)
                return result
        return CommandResult(
            stdout="",
            stderr="no fake handler for: " + " ".join(cmd),
            returncode=1,
            success=False,
        )


def _ok(stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(stdout=stdout, stderr=stderr, returncode=0, success=True)


def _err(stderr: str, rc: int = 1) -> CommandResult:
    return CommandResult(stdout="", stderr=stderr, returncode=rc, success=False)


def _params(**kw) -> FileTransferInput:
    base = dict(
        target="192.168.0.77",
        username="xhj",
        password="xhj200814",
        port=22,
        local_path="/tmp/mcp_only_test.elf",
        remote_path="/tmp/mcp_only_test.elf",
    )
    base.update(kw)
    return FileTransferInput(**base)


# ===================================================================
# Gating
# ===================================================================


class TestTransferGating:
    def test_registry_members(self):
        assert set(TRANSFER_TOOLS) == {
            "file_upload",
            "file_download",
            "file_read",
            "file_delete",
        }
        for name, (func, model) in TRANSFER_TOOLS.items():
            assert callable(func)
            if name in ("file_read", "file_delete"):
                assert model in (FileReadInput, FileDeleteInput)

    def test_no_overlap_with_msf(self):
        from kali_mcp.msf import MSF_PENTEST_TOOLS, MSF_ATTACK_TOOLS
        msf_names = set(MSF_PENTEST_TOOLS) | set(MSF_ATTACK_TOOLS)
        assert msf_names.isdisjoint(set(TRANSFER_TOOLS))


# ===================================================================
# scp command construction
# ===================================================================


class TestScpCommand:
    def test_upload_layout(self):
        cmd = _scp_command("upload", _params())
        assert cmd[0] == "scp"
        assert cmd[-1] == "xhj@192.168.0.77:/tmp/mcp_only_test.elf"
        assert cmd[-2] == "/tmp/mcp_only_test.elf"
        # port flag
        assert "-P" in cmd and cmd[cmd.index("-P") + 1] == "22"
        # host-key paranoia options
        joined = " ".join(cmd)
        assert "StrictHostKeyChecking=no" in joined
        assert "UserKnownHostsFile=/dev/null" in joined

    def test_download_layout(self):
        cmd = _scp_command("download", _params(remote_path="/etc/hostname"))
        assert cmd[-2] == "xhj@192.168.0.77:/etc/hostname"
        assert cmd[-1] == "/tmp/mcp_only_test.elf"

    def test_port_roundtrip(self):
        cmd = _scp_command("upload", _params(port=2222))
        assert cmd[cmd.index("-P") + 1] == "2222"

    def test_password_never_in_argv(self):
        # The password must never appear in the scp argv — it rides in env.
        cmd = _scp_command("upload", _params(password="hunter2"))
        assert "hunter2" not in " ".join(cmd)


class TestFileUpload:
    def test_password_via_env_not_argv(self, tmp_path, monkeypatch):
        src = tmp_path / "payload.elf"
        src.write_bytes(b"\x7fELF-fake")
        exec_ = FakeExecutor([(lambda c: c[0] == "sshpass", _ok())])
        monkeypatch.setattr(transfer, "get_executor", lambda timeout=600: exec_)
        with patch.object(transfer, "shutil") as sh:
            sh.which.side_effect = lambda b: "/usr/bin/" + b
            out = _run(file_upload(_params(
                local_path=str(src), remote_path="/tmp/payload.elf")))
        assert "✅ 传输成功" in out
        (cmd, env), = exec_.calls
        assert cmd[0] == "sshpass" and cmd[1] == "-e" and cmd[2] == "scp"
        assert env == {"SSHPASS": "xhj200814"}
        assert "xhj200814" not in " ".join(cmd)

    def test_key_auth_no_sshpass_prefix(self, tmp_path, monkeypatch):
        src = tmp_path / "payload.elf"
        src.write_bytes(b"x")
        exec_ = FakeExecutor([(lambda c: c[0] == "scp", _ok())])
        monkeypatch.setattr(transfer, "get_executor", lambda timeout=600: exec_)
        with patch.object(transfer, "shutil") as sh:
            sh.which.side_effect = lambda b: "/usr/bin/" + b

        _run(file_upload(_params(
            password="", local_path=str(src))))
        (cmd, env), = exec_.calls
        assert cmd[0] == "scp"
        assert env is None

    def test_missing_local_file_fails_fast(self):
        out = _run(file_upload(_params(local_path="/tmp/nope-definitely-missing")))
        assert "❌" in out and "不存在" in out

    def test_missing_sshpass_reports(self, tmp_path, monkeypatch):
        src = tmp_path / "p"
        src.write_bytes(b"x")
        exec_ = FakeExecutor([])
        monkeypatch.setattr(transfer, "get_executor", lambda timeout=600: exec_)
        with patch.object(transfer, "shutil") as sh:
            sh.which.side_effect = lambda b: None if b == "sshpass" else "/usr/bin/" + b
        out = _run(file_upload(_params(local_path=str(src))))
        assert "sshpass" in out and "❌" in out

    def test_permission_denied_hint(self, tmp_path, monkeypatch):
        src = tmp_path / "p"
        src.write_bytes(b"x")
        exec_ = FakeExecutor([(
            lambda c: c[0] == "sshpass",
            _err("xhj@192.168.0.77: Permission denied (publickey,password)."),
        )])
        monkeypatch.setattr(transfer, "get_executor", lambda timeout=600: exec_)
        with patch.object(transfer, "shutil") as sh:
            sh.which.side_effect = lambda b: "/usr/bin/" + b
            out = _run(file_upload(_params(local_path=str(src))))
        assert "❌ 传输失败" in out and "凭证被拒" in out


class TestFileDownload:
    def test_success_and_hint(self, tmp_path, monkeypatch):
        dest = tmp_path / "out.txt"
        exec_ = FakeExecutor([(lambda c: c[0] == "sshpass", _ok())])
        monkeypatch.setattr(transfer, "get_executor", lambda timeout=600: exec_)
        with patch.object(transfer, "shutil") as sh:
            sh.which.side_effect = lambda b: "/usr/bin/" + b
            out = _run(file_download(_params(
                local_path=str(dest), remote_path="/etc/hostname")))
        assert "✅ 传输成功" in out and "file_read" in out
        (cmd, env), = exec_.calls
        assert cmd[-2] == "xhj@192.168.0.77:/etc/hostname"
        assert cmd[-1] == str(dest)

    def test_existing_local_refused(self, tmp_path, monkeypatch):
        dest = tmp_path / "exists.txt"
        dest.write_text("old")
        exec_ = FakeExecutor([(lambda c: True, _ok())])
        monkeypatch.setattr(transfer, "get_executor", lambda timeout=600: exec_)
        with patch.object(transfer, "shutil") as sh:
            sh.which.side_effect = lambda b: "/usr/bin/" + b
        out = _run(file_download(_params(local_path=str(dest))))
        assert "❌" in out and "已存在" in out
        assert exec_.calls == []  # no scp attempt


# ===================================================================
# file_read (Kali local)
# ===================================================================


class TestFileRead:
    def test_text_file(self, tmp_path):
        f = tmp_path / "note.txt"
        f.write_text("hello world\nline2\n", encoding="utf-8")
        out = _run(file_read(FileReadInput(path=str(f))))
        assert "hello world" in out and "line2" in out
        assert "65536" not in out  # no truncation notice

    def test_truncation_notice(self, tmp_path):
        f = tmp_path / "big.txt"
        f.write_text("A" * 200, encoding="utf-8")
        out = _run(file_read(FileReadInput(path=str(f), max_bytes=50)))
        assert "已截断" in out

    def test_binary_header_only(self, tmp_path):
        f = tmp_path / "x.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        out = _run(file_read(FileReadInput(path=str(f))))
        assert "二进制" in out
        assert "7f 45 4c 46" in out  # hexdump head
        assert "A" * 100 not in out  # no bulk dump

    def test_missing(self):
        out = _run(file_read(FileReadInput(path="/no/such/file")))
        assert "不存在" in out

    def test_directory_refused(self, tmp_path):
        out = _run(file_read(FileReadInput(path=str(tmp_path))))
        assert "目录" in out

    def test_relative_path_rejected(self):
        with pytest.raises(ValidationError):
            FileReadInput(path="relative/path")


# ===================================================================
# file_delete (Kali local)
# ===================================================================


class TestFileDelete:
    def test_success(self, tmp_path):
        f = tmp_path / "payload.elf"
        f.write_bytes(b"x")
        out = _run(file_delete(FileDeleteInput(path=str(f), confirm="yes")))
        assert "✅ 已删除" in out
        assert not f.exists()
        assert "msf_kill_session" in out  # cleanup checklist hint

    def test_missing_confirm_rejected(self):
        with pytest.raises(ValidationError):
            FileDeleteInput(path="/tmp/x", confirm="sure")

    def test_directory_refused(self, tmp_path):
        out = _run(file_delete(FileDeleteInput(path=str(tmp_path), confirm="yes")))
        assert "❌ 拒绝删除" in out

    def test_symlink_refused(self, tmp_path):
        target = tmp_path / "t"
        target.write_text("x")
        link = tmp_path / "l"
        os.symlink(target, link)
        out = _run(file_delete(FileDeleteInput(path=str(link), confirm="yes")))
        assert "❌ 拒绝删除" in out
        assert target.exists()  # target untouched

    def test_missing_path_noop(self):
        out = _run(file_delete(FileDeleteInput(path="/no/such", confirm="yes")))
        assert "无需删除" in out

    def test_relative_path_rejected(self):
        with pytest.raises(ValidationError):
            FileDeleteInput(path="rel/file", confirm="yes")


# ===================================================================
# Input validation
# ===================================================================


class TestTransferInputValidation:
    def test_shell_meta_in_username_rejected(self):
        with pytest.raises(ValidationError):
            FileTransferInput(**{
                "target": "192.168.0.77", "username": "xhj; rm -rf /",
                "local_path": "/tmp/a", "remote_path": "/tmp/b",
            })

    def test_bad_target_rejected(self):
        with pytest.raises(ValidationError):
            FileTransferInput(**{
                "target": "192.168.0.77; id", "username": "x",
                "local_path": "/tmp/a", "remote_path": "/tmp/b",
            })
