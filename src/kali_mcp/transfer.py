"""File transfer & local file tools.

Closes the meterpreter-delivery gap in a pure-MCP attack chain:
  - file_upload   : scp Kali → target (payload delivery)
  - file_download : scp target → Kali (evidence / file retrieval)
  - file_read     : read a file ON KALI (wordlists, payload contents, logs)
  - file_delete   : delete a file ON KALI (payload cleanup)

Auth: sshpass -e with the password in the SSHPASS environment variable
(never on the command line, so it does not leak into `ps` output).
Commands are list-form (no shell) — the only metacharacter that matters
in a subprocess argument is NUL, which subprocess rejects anyway.

Gating: all four are registered under ATTACK_ENABLED (they are part of
the offensive workflow; file_read/file_delete operate on the Kali host).
"""

from __future__ import annotations

import os
import shutil

from pydantic import BaseModel, Field, field_validator

from kali_mcp.executor import get_executor
from kali_mcp.tools import _no_nul, _no_shell_meta, _is_valid_target


# ---------------------------------------------------------------------------
# SSH transfer (scp over sshpass)
# ---------------------------------------------------------------------------


class FileTransferInput(BaseModel):
    """Input for file_upload / file_download (scp over SSH)."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Target host (IP or hostname) reachable from Kali",
    )
    username: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="SSH username on the target",
    )
    password: str = Field(
        default="",
        max_length=256,
        description=(
            "SSH password. Passed to sshpass via the SSHPASS environment "
            "variable — never on the command line. Leave empty to use the "
            "Kali default key."
        ),
    )
    port: int = Field(default=22, ge=1, le=65535, description="SSH port")
    local_path: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description=(
            "File on the Kali host. For upload: the source file. For "
            "download: where the remote file is saved (parent dir must exist)."
        ),
    )
    remote_path: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description=(
            "Path on the target. For upload: the destination (absolute or "
            "relative to the remote user's home). For download: the file to fetch."
        ),
    )
    timeout: int = Field(
        default=600, ge=10, le=3600, description="Max seconds for the transfer"
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        _no_shell_meta(v)
        v = v.strip()
        if not _is_valid_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        _no_shell_meta(v)
        return v.strip()

    @field_validator("local_path", "remote_path")
    @classmethod
    def validate_paths(cls, v: str) -> str:
        # List-form argument; shell meta is inert. Keep the standard filter
        # for consistency, and forbid NUL explicitly.
        _no_shell_meta(v)
        return v.strip()


def _scp_command(direction: str, params: FileTransferInput) -> list[str]:
    """Build the list-form scp command (no shell involved)."""
    remote = f"{params.username}@{params.target}:{params.remote_path}"
    base = [
        "scp",
        "-P",
        str(params.port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "BatchMode=no",
    ]
    if direction == "upload":
        return base + [params.local_path, remote]
    return base + [remote, params.local_path]


async def _scp_transfer(direction: str, params: FileTransferInput) -> "tuple":
    """Run scp (with sshpass -e when a password is given). Returns (rc, out, err)."""
    if not shutil.which("scp"):
        raise RuntimeError("Kali 上未找到 scp 二进制")
    if params.password and not shutil.which("sshpass"):
        raise RuntimeError(
            "Kali 上未找到 sshpass——无法使用密码认证（请安装 sshpass 或改用密钥）"
        )
    cmd = _scp_command(direction, params)
    if params.password:
        cmd = ["sshpass", "-e"] + cmd
    env = {"SSHPASS": params.password} if params.password else None
    executor = get_executor(timeout=params.timeout)
    return await executor.run(cmd, timeout=params.timeout, env=env)


def _transfer_report(direction: str, params: FileTransferInput, result) -> str:
    verb = "上传" if direction == "upload" else "下载"
    path_txt = (
        f"`{params.local_path}` → `{params.username}@{params.target}:{params.remote_path}`"
        if direction == "upload"
        else f"`{params.username}@{params.target}:{params.remote_path}` → `{params.local_path}`"
    )
    lines = [
        f"## 📦 文件{verb}（scp over SSH）",
        f"**路径:** {path_txt}",
        "",
    ]
    if result.returncode == 0:
        lines.append("✅ 传输成功。")
        if result.stderr.strip():
            # scp writes progress/warnings to stderr even on success.
            lines.append("")
            lines.append("```")
            lines.append(result.stderr.strip()[-2000:])
            lines.append("```")
        lines.append(
            ""
            if direction == "upload"
            else "\n> 用 `file_read` 查看下载到的文件内容。"
        )
    else:
        lines.append(f"❌ 传输失败（exit {result.returncode}）。")
        err = (result.stderr or result.stdout or "").strip()
        lines.append("")
        lines.append("```")
        lines.append(err[-3000:] if err else "（无错误输出）")
        lines.append("```")
        if "Permission denied" in err:
            lines.append(
                "\n💡 凭证被拒：确认 username/password；目标可能只接受密钥认证。"
            )
        elif "No such file or directory" in err:
            lines.append("\n💡 路径不存在：检查 local_path（Kali 端）/ remote_path（目标端）。")
    return "\n".join(lines)


async def file_upload(params: FileTransferInput) -> str:
    """Upload a file from Kali to a target host over scp (password or key auth).

    🔴 Offensive use: delivers payloads/tools to the compromised host
    (e.g. a msfvenom-generated ELF for meterpreter). The password is passed
    via the SSHPASS environment variable (sshpass -e), never on the command
    line. List-form scp — no shell, so payload paths stay intact.

    Requires: scp + sshpass on Kali (preinstalled).
    """
    if not os.path.isfile(params.local_path):
        return (
            "## 📦 文件上传（scp over SSH）\n\n"
            f"❌ Kali 本地文件不存在: `{params.local_path}`\n\n"
            "> 先确认源文件路径（生成产物一般在 /tmp 下）。"
        )
    try:
        result = await _scp_transfer("upload", params)
    except RuntimeError as e:
        return f"## 📦 文件上传（scp over SSH）\n\n❌ {e}"
    return _transfer_report("upload", params, result)


async def file_download(params: FileTransferInput) -> str:
    """Download a file from a target host to Kali over scp (password or key auth).

    Evidence / file retrieval after access (configs, hashes, documents).
    The remote file is saved to local_path on Kali; afterwards use
    `file_read` to inspect it via MCP.

    Requires: scp + sshpass on Kali (preinstalled).
    """
    if os.path.exists(params.local_path):
        return (
            "## 📦 文件下载（scp over SSH）\n\n"
            f"❌ 目标路径已存在: `{params.local_path}`（拒绝覆盖，换一个本地路径）"
        )
    try:
        result = await _scp_transfer("download", params)
    except RuntimeError as e:
        return f"## 📦 文件下载（scp over SSH）\n\n❌ {e}"
    return _transfer_report("download", params, result)


# ---------------------------------------------------------------------------
# Local file tools (Kali host)
# ---------------------------------------------------------------------------


class FileReadInput(BaseModel):
    """Input for file_read (Kali-local)."""

    path: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Absolute path of the file on the KALI host (e.g. /tmp/x.elf)",
    )
    max_bytes: int = Field(
        default=65536,
        ge=1,
        le=1048576,
        description="Max bytes to return (default 64 KiB, cap 1 MiB); larger files are truncated",
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("/"):
            raise ValueError("path must be absolute on the Kali host")
        _no_shell_meta(v)
        return v


async def file_read(params: FileReadInput) -> str:
    """Read a file on the Kali host (size-capped) — wordlists, payloads, logs.

    Closes the MCP read gap: after file_download (or msfvenom_gen), inspect
    the content without touching a shell. Binary files are shown as a
    header + hexdump head. Text is returned in a code block, truncated to
    max_bytes with a notice.
    """
    path = params.path
    if not os.path.exists(path):
        return f"## 📄 文件读取\n\n❌ 文件不存在: `{path}`"
    if os.path.isdir(path):
        return f"## 📄 文件读取\n\n❌ 是目录而非文件: `{path}`（列出目录请用 file_read 不支持——改用 ls 类工具）"
    size = os.path.getsize(path)
    cap = params.max_bytes
    try:
        with open(path, "rb") as f:
            raw = f.read(cap)
        head = raw[:4]
        is_binary = b"\x00" in raw[:4096]
        lines = [
            "## 📄 文件读取",
            f"**路径:** `{path}`  |  **大小:** {size} 字节  "
            f"{'|  ⚠️ 已截断（仅显示前 ' + str(len(raw)) + ' 字节）' if size > cap else ''}",
            "",
        ]
        if is_binary:
            lines.append("**类型:** 二进制文件（十六进制头部）")
            lines.append("")
            lines.append("```")
            lines.append(" ".join(f"{b:02x}" for b in head))
            lines.append("```")
            lines.append("")
            lines.append(
                "> 需要内容请用 `file_download` 类流程或 hexdump（本工具不对二进制做全文转储）。"
            )
        else:
            text = raw.decode("utf-8", errors="replace")
            lines.append("```")
            lines.append(text.rstrip("\n"))
            lines.append("```")
        return "\n".join(lines)
    except OSError as e:
        return f"## 📄 文件读取\n\n❌ 读取失败: {type(e).__name__}: {e}"


class FileDeleteInput(BaseModel):
    """Input for file_delete (Kali-local)."""

    path: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Absolute path of the file on the KALI host to delete",
    )
    confirm: str = Field(
        ...,
        pattern=r"^yes$",
        description='Literal "yes" — required to prevent accidental deletion',
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("/"):
            raise ValueError("path must be absolute on the Kali host")
        _no_shell_meta(v)
        return v


async def file_delete(params: FileDeleteInput) -> str:
    """Delete a file on the Kali host (regular files only) — payload cleanup.

    The final step of a clean-room loop: remove /tmp/*.elf payloads after
    verification so no artifacts linger on the attack box. Refuses
    directories and symlinks; requires confirm="yes".
    """
    path = params.path
    if not os.path.lexists(path):
        return f"## 🗑️ 文件删除\n\n✅ 路径不存在（无需删除）: `{path}`"
    if os.path.islink(path) or os.path.isdir(path):
        return (
            "## 🗑️ 文件删除\n\n"
            f"❌ 拒绝删除: `{path}` 是目录或符号链接（只允许删除普通文件）"
        )
    try:
        os.remove(path)
    except OSError as e:
        return f"## 🗑️ 文件删除\n\n❌ 删除失败: {type(e).__name__}: {e}"
    return (
        f"## 🗑️ 文件删除\n\n✅ 已删除: `{path}`\n\n"
        "> 清理检查单：payload 文件（本工具）→ 目标端文件（会话内 rm）→ "
        "session（msf_kill_session）→ job（msf_stop_job）。"
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TRANSFER_TOOLS: dict[str, tuple[callable, type[BaseModel]]] = {
    "file_upload": (file_upload, FileTransferInput),
    "file_download": (file_download, FileTransferInput),
    "file_read": (file_read, FileReadInput),
    "file_delete": (file_delete, FileDeleteInput),
}
