"""Generic long-running task manager for tools that can run for minutes.

The first consumer is hydra_brute. The manager keeps task state in the
MCP process, gives each task a log file under /tmp/kali-mcp-long-tasks,
and exposes status/stop tools so an agent can poll progress instead of
blocking on a single long tool call.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, Field

TaskFn = Callable[[], Awaitable[str]]


@dataclass
class CommandResult:
    """Minimal command result shape compatible with kali_mcp.executor.CommandResult."""

    stdout: str
    stderr: str
    returncode: int
    success: bool


@dataclass
class LongTask:
    job_id: str
    tool: str
    target: str
    log_path: str
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    state: str = "pending"
    exit_code: int | None = None
    result_path: str | None = None
    error: str | None = None
    _task: asyncio.Task | None = field(default=None, repr=False)

    def metadata(self) -> dict[str, Any]:
        now = time.time()
        return {
            "job_id": self.job_id,
            "tool": self.tool,
            "target": self.target,
            "state": self.state,
            "exit_code": self.exit_code,
            "error": self.error,
            "log_path": self.log_path,
            "result_path": self.result_path,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "age_seconds": round((now - self.created_at), 1),
            "duration_seconds": (
                round((self.finished_at or now) - (self.started_at or self.created_at), 1)
            ),
        }


class LongTaskManager:
    """Track background tasks and write progress to local log files."""

    def __init__(self, root: str | None = None):
        self.root = Path(root or os.getenv("KALI_MCP_LONG_TASK_DIR", "/tmp/kali-mcp-long-tasks"))
        self.tasks: dict[str, LongTask] = {}
        self.root.mkdir(parents=True, exist_ok=True)

    def new_log_path(self, tool: str, job_id: str | None = None) -> str:
        job_id = job_id or secrets.token_hex(6)
        safe_tool = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in tool)
        return str(self.root / f"{job_id}-{safe_tool}.log")

    def register_task(self, task: LongTask) -> str:
        self.tasks[task.job_id] = task
        return task.job_id

    async def start(self, tool: str, target: str, work: TaskFn) -> str:
        job_id = secrets.token_hex(6)
        path = Path(self.new_log_path(tool, job_id))
        task = LongTask(
            job_id=job_id,
            tool=tool,
            target=target,
            log_path=str(path),
            created_at=time.time(),
            state="pending",
        )
        self.register_task(task)
        task._task = asyncio.create_task(self._run(task, work))
        return job_id

    async def _run(self, task: LongTask, work: TaskFn) -> None:
        task.state = "running"
        task.started_at = time.time()
        try:
            result = await work()
            task.result_path = task.log_path
            task.state = "completed"
            task.exit_code = 0
        except asyncio.CancelledError:
            task.state = "stopped"
            task.exit_code = None
            self._append(task, "[long-task] stopped\n")
            raise
        except Exception as e:  # noqa: BLE001
            task.state = "failed"
            task.exit_code = -1
            task.error = f"{type(e).__name__}: {e}"
        finally:
            task.finished_at = time.time()
            self._append(task, f"[long-task] finished state={task.state}\n")

    def _append(self, task: LongTask, text: str) -> None:
        try:
            with open(task.log_path, "a", encoding="utf-8") as f:
                f.write(text)
        except OSError:
            pass

    async def status(self, job_id: str) -> dict[str, Any]:
        task = self.tasks.get(job_id)
        if task is None:
            return {"job_id": job_id, "error": "not_found"}
        data = dict(task.metadata())
        data["tail"] = self._tail(task.log_path, 2000)
        data["size_bytes"] = self._size(task.log_path)
        return data

    async def stop(self, job_id: str) -> dict[str, Any]:
        task = self.tasks.get(job_id)
        if task is None:
            return {"job_id": job_id, "error": "not_found"}
        if task.state in {"completed", "failed", "stopped"}:
            return {"job_id": job_id, "status": "already_" + task.state, "metadata": task.metadata()}
        if task._task is not None and not task._task.done():
            task._task.cancel()
            try:
                await task._task
            except asyncio.CancelledError:
                pass
        task.state = "stopped"
        return {"job_id": job_id, "status": "stopped", "metadata": task.metadata()}

    async def list_tasks(self, limit: int = 50) -> list[dict[str, Any]]:
        ordered = sorted(self.tasks.values(), key=lambda t: t.created_at, reverse=True)
        return [t.metadata() for t in ordered[:limit]]

    def _tail(self, path: str, limit: int) -> str:
        try:
            with open(path, "rb") as f:
                data = f.read()
            return data[-limit:].decode("utf-8", "replace")
        except OSError:
            return ""

    def _size(self, path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0


_default_manager = LongTaskManager()


def get_long_task_manager() -> LongTaskManager:
    return _default_manager


class LongTaskStatusInput(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=64, description="Job ID from long-running tool output")


class LongTaskStopInput(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=64, description="Job ID to stop")


def append_log(path: str, text: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass


def _tail(path: str, limit: int) -> str:
    return _default_manager._tail(path, limit)


async def long_task_status(params: LongTaskStatusInput) -> str:
    """Read status and recent output tail for a long-running background task."""
    data = await _default_manager.status(params.job_id)
    if data.get("error") == "not_found":
        return (
            f"❌ 找不到任务 `{params.job_id}`。\n\n"
            "任务列表只保存在当前 kali-mcp 进程内；MCP 服务重启后旧 job_id 会失效。\n"
            "请重新发起长任务，并在返回后立即使用新的 job_id。"
        )
    meta = data
    state_icon = {"running": "🟡", "completed": "🟢", "failed": "🔴", "stopped": "⚪"}.get(meta.get("state"), "⚪")
    lines = [
        "## 长任务状态",
        f"**Job ID:** `{meta.get('job_id')}`",
        f"**状态:** {state_icon} `{meta.get('state')}`",
        f"**工具:** `{meta.get('tool')}`",
        f"**目标:** `{meta.get('target')}`",
        f"**已运行:** {meta.get('duration_seconds')}s",
        f"**日志文件:** `{meta.get('log_path')}`",
        f"**日志大小:** {data.get('size_bytes', 0)} bytes",
    ]
    if meta.get("exit_code") is not None:
        lines.append(f"**退出码:** {meta.get('exit_code')}")
    if meta.get("error"):
        lines.append(f"**错误:** {meta.get('error')}")
    tail = data.get("tail", "")
    lines += ["", "### 最近输出", "```", tail or "(empty)", "```"]
    return "\n".join(lines)


async def long_task_stop(params: LongTaskStopInput) -> str:
    """Stop a running long-running background task by job ID."""
    data = await _default_manager.stop(params.job_id)
    if data.get("error") == "not_found":
        return f"❌ 找不到任务 `{params.job_id}`。"
    return f"✅ 已处理任务 `{params.job_id}`：状态 `{data.get('status')}`。"


LONG_TASK_TOOLS: dict[str, tuple[Callable, type[BaseModel]]] = {
    "long_task_status": (long_task_status, LongTaskStatusInput),
    "long_task_stop": (long_task_stop, LongTaskStopInput),
}
