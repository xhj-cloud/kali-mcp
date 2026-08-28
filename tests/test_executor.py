"""Tests for CommandExecutor — especially partial-output survival on timeout."""

import asyncio

from kali_mcp.executor import CommandExecutor


def _run(coro):
    return asyncio.run(coro)


class TestNormalExecution:
    def test_simple_command(self):
        ex = CommandExecutor(default_timeout=10)
        r = _run(ex.run(["echo", "hello"]))
        assert r.success is True
        assert r.returncode == 0
        assert r.stdout == "hello"

    def test_stdout_and_stderr_separated(self):
        ex = CommandExecutor(default_timeout=10)
        r = _run(ex.run(["sh", "-c", "echo out; echo err 1>&2"]))
        assert r.success is True
        assert r.stdout == "out"
        assert r.stderr == "err"

    def test_input_data_piped(self):
        ex = CommandExecutor(default_timeout=10)
        r = _run(ex.run(["sh", "-c", "cat"], input_data="piped text"))
        assert r.success is True
        assert r.stdout == "piped text"

    def test_missing_command(self):
        ex = CommandExecutor(default_timeout=10)
        r = _run(ex.run(["definitely-not-a-real-binary-xyz"]))
        assert r.success is False
        assert "not found" in r.stderr.lower()

    def test_fast_command_under_timeout(self):
        ex = CommandExecutor(default_timeout=5)
        r = _run(ex.run(["sh", "-c", "echo quick"], timeout=5))
        assert r.success is True
        assert r.stdout == "quick"
        assert "timed out" not in r.stderr


class TestTimeout:
    def test_partial_output_preserved(self):
        """Regression: the old wait_for(communicate()) pattern cancelled the
        pipe reader on timeout, so everything tcpdump had already flushed was
        lost (live-verified: 'partial: 0 chars' while packets were captured).
        The streaming pump must keep every line written before the kill."""
        ex = CommandExecutor(default_timeout=5)
        r = _run(
            ex.run(
                ["sh", "-c", "for i in 1 2 3; do echo line_$i; sleep 1; done"],
                timeout=2,
            )
        )
        assert r.success is False
        assert r.returncode == -1
        assert "timed out" in r.stderr
        assert "line_1" in r.stdout
        assert "line_2" in r.stdout

    def test_timeout_marker_in_stderr(self):
        ex = CommandExecutor(default_timeout=5)
        r = _run(ex.run(["sh", "-c", "sleep 5"], timeout=1))
        assert r.success is False
        assert "[timed out after 1s" in r.stderr
