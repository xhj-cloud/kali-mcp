"""Tests for generic long-running task management (hydra_brute first)."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from kali_mcp import long_tasks
from kali_mcp.long_tasks import (
    LongTask,
    LongTaskManager,
    LongTaskStopInput,
    LongTaskStatusInput,
    long_task_stop,
    long_task_status,
)
from kali_mcp.pentest import HydraInput, hydra_brute


def _run(coro):
    return asyncio.run(coro)


class TestLongTaskManager:
    def test_starts_background_task_and_tracks_status(self):
        manager = LongTaskManager()
        started_at = 0.0

        async def work() -> str:
            nonlocal started_at
            started_at = asyncio.get_event_loop().time()
            await asyncio.sleep(0.02)
            return "done"

        async def scenario():
            job_id = await manager.start("hydra_brute", "192.168.0.10 (ssh)", work)
            await asyncio.sleep(0.03)
            return await manager.status(job_id)

        status = _run(scenario())
        assert status["job_id"]
        assert status["tool"] == "hydra_brute"
        assert status["state"] == "completed"
        assert status["exit_code"] == 0

    def test_stop_running_task(self):
        manager = LongTaskManager()

        async def work() -> str:
            await asyncio.sleep(5)
            return "should not finish"

        async def scenario():
            job_id = await manager.start("hydra_brute", "192.168.0.10 (ssh)", work)
            await asyncio.sleep(0.01)
            return await manager.stop(job_id)

        stopped = _run(scenario())
        assert stopped["status"] == "stopped"
        status = _run(manager.status(stopped["job_id"]))
        assert status["state"] == "stopped"

    def test_missing_job_reports_not_found(self):
        manager = LongTaskManager()
        status = _run(manager.status("nope"))
        assert status["error"] == "not_found"


class TestLongTaskTools:
    def test_default_manager_tracks_tasks(self):
        async def work() -> str:
            await asyncio.sleep(0.01)
            return "done"

        async def scenario():
            job_id = await long_tasks._default_manager.start("hydra_brute", "target", work)
            await asyncio.sleep(0.02)
            status = await long_task_status(LongTaskStatusInput(job_id=job_id))
            stop = await long_task_stop(LongTaskStopInput(job_id=job_id))
            return status, stop

        status, stop = _run(scenario())
        assert "**Job ID:**" in status
        assert "已处理任务" in stop

    def test_stop_requires_job_id(self):
        with pytest.raises(ValidationError):
            LongTaskStopInput()

    def test_status_requires_job_id(self):
        with pytest.raises(ValidationError):
            LongTaskStatusInput()


class TestHydraBrute:
    def test_input_supports_timeout_and_mode(self):
        m = HydraInput(target="192.168.0.10", service="ssh", username="root", timeout=90, mode="background")
        assert m.timeout == 90
        assert m.mode == "background"

    def test_timeout_bounds(self):
        assert HydraInput(target="192.168.0.10", service="ssh", username="root", timeout=1).timeout == 1
        with pytest.raises(ValidationError):
            HydraInput(target="192.168.0.10", service="ssh", username="root", timeout=0)
        with pytest.raises(ValidationError):
            HydraInput(target="192.168.0.10", service="ssh", username="root", timeout=3601)

    def test_sync_timeout_is_passed_to_hydra_command(self, monkeypatch):
        calls = {}

        class FakeExecutor:
            async def run(self, cmd, timeout=None, **kwargs):
                calls["cmd"] = cmd
                calls["timeout"] = timeout
                return long_tasks.CommandResult(stdout="ok", stderr="", returncode=0, success=True)

        monkeypatch.setattr("kali_mcp.pentest.get_executor", lambda timeout=None: FakeExecutor())
        out = _run(hydra_brute(HydraInput(target="192.168.0.10", service="ssh", username="root", timeout=90)))
        assert calls["cmd"][0] == "timeout"
        assert calls["cmd"][1] == "90"
        assert calls["cmd"][2] == "hydra"
        assert calls["timeout"] == 95
        assert "Command:" in out
        assert "timeout 90 hydra" in out

    def test_background_returns_job_id(self, monkeypatch):
        class FakeExecutor:
            async def run(self, cmd, timeout=None, **kwargs):
                raise AssertionError("sync executor should not run in background mode")

        monkeypatch.setattr("kali_mcp.pentest.get_executor", lambda timeout=None: FakeExecutor())

        monkeypatch.setattr(
            "kali_mcp.pentest._start_background_hydra",
            lambda params, cmd: (
                "**Job ID:** `job-abc`\nlong_task_status\nlong_task_stop\nPassword File"
            ),
        )
        out = _run(hydra_brute(HydraInput(target="192.168.0.10", service="ssh", username="root", mode="background")))
        assert "job-abc" in out
        assert "long_task_status" in out
        assert "long_task_stop" in out
        assert "Password File" in out

    def test_background_command_keeps_full_wordlist_and_reports_path(self, monkeypatch):
        captured = {}

        class FakeManager:
            async def start(self, tool, target, work, **kwargs):
                captured["kwargs"] = kwargs
                return "job-123"

        async def fake_work() -> str:
            return "done"

        monkeypatch.setattr(
            "kali_mcp.pentest._start_background_hydra",
            lambda params, cmd: (
                "**Job ID:** `job-123`\nPassword File: `/usr/share/wordlists/rockyou.txt.gz`\nThreads: `8`"
            ),
        )
        out = _run(hydra_brute(HydraInput(
            target="192.168.0.10",
            service="ssh",
            username="root",
            mode="background",
            password_file="/usr/share/wordlists/rockyou.txt.gz",
            threads=8,
        )))
        assert "job-123" in out
        assert "/usr/share/wordlists/rockyou.txt.gz" in out
        assert "threads" in out.lower()
