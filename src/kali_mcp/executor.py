"""
Safe asynchronous command executor for Kali Linux tools.

Uses asyncio.create_subprocess_exec (never shell=True) to prevent
command injection. All commands are constructed as lists and executed
with configurable timeouts.
"""

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of executing a shell command."""

    stdout: str
    stderr: str
    returncode: int
    success: bool


class CommandExecutor:
    """Execute shell commands safely with timeout and input validation.

    Never uses shell=True. All commands are passed as lists to
    asyncio.create_subprocess_exec for maximum safety.
    """

    def __init__(self, default_timeout: int = 120):
        self.default_timeout = default_timeout

    async def run(
        self,
        cmd: list[str],
        timeout: int | None = None,
        input_data: str | None = None,
        hold_stdin: bool = False,
    ) -> CommandResult:
        """Execute a command and return its output.

        Args:
            cmd: Command as list, e.g. ['nmap', '-sP', '192.168.1.0/24']
            timeout: Override default timeout in seconds
            input_data: Optional data to pipe to process stdin
            hold_stdin: Keep the stdin pipe open (and unread) for the whole
                run. For interactive tools that block on a "press any key to
                stop" read (e.g. yersinia dhcp flood) — closing stdin would
                deliver EOF and make them exit immediately without doing
                anything. The command then runs until it exits on its own or
                the timeout kills it.

        Returns:
            CommandResult with captured stdout, stderr, and exit code
        """
        timeout = timeout or self.default_timeout
        cmd_str = " ".join(cmd)
        logger.info("Executing: %s (timeout=%ds)", cmd_str, timeout)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE,
            )

            # Stream both pipes into chunk lists as data arrives. Unlike
            # wait_for(proc.communicate()) — whose cancellation discards
            # everything buffered in the pipes — this keeps partial output
            # intact when the command is killed for exceeding the timeout.
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []

            async def _pump(stream, sink: list[bytes]) -> None:
                while True:
                    chunk = await stream.read(65536)
                    if not chunk:
                        break
                    sink.append(chunk)

            pump_tasks = []
            if proc.stdout is not None:
                pump_tasks.append(asyncio.ensure_future(_pump(proc.stdout, stdout_chunks)))
            if proc.stderr is not None:
                pump_tasks.append(asyncio.ensure_future(_pump(proc.stderr, stderr_chunks)))

            async def _wait_completion() -> None:
                if input_data is not None:
                    proc.stdin.write(input_data.encode("utf-8"))
                    await proc.stdin.drain()
                if not hold_stdin:
                    proc.stdin.close()
                    await proc.stdin.wait_closed()
                await proc.wait()
                if pump_tasks:
                    await asyncio.gather(*pump_tasks)

            timed_out = False
            try:
                await asyncio.wait_for(_wait_completion(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass  # already exited (e.g. a grandchild holds the pipe)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=10)
                except asyncio.TimeoutError:
                    logger.warning("Process did not exit after kill: %s", cmd_str)

            # Drain whatever the pumps have buffered (after the kill the pipes
            # reach EOF). Bounded, so a surviving grandchild holding a pipe
            # open cannot hang us — we then use the partial output as-is.
            if pump_tasks:
                try:
                    await asyncio.wait_for(asyncio.gather(*pump_tasks), timeout=5)
                except asyncio.TimeoutError:
                    for t in pump_tasks:
                        t.cancel()
                    logger.warning(
                        "Pipes did not close after timeout; using partial output: %s",
                        cmd_str,
                    )

            stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace").strip()
            stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace").strip()

            if timed_out:
                stderr = (
                    stderr + f"\n[timed out after {timeout}s, showing partial output]"
                ).strip()
                logger.warning(
                    "Command timed out after %ds (partial: %d chars): %s",
                    timeout, len(stdout), cmd_str,
                )
                return CommandResult(
                    stdout=stdout,
                    stderr=stderr,
                    returncode=-1,
                    success=False,
                )

            result = CommandResult(
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode or 0,
                success=proc.returncode == 0,
            )
            logger.info(
                "Command completed: returncode=%d, stdout=%d chars",
                result.returncode,
                len(result.stdout),
            )
            return result

        except FileNotFoundError:
            logger.error("Command not found: %s", cmd[0])
            return CommandResult(
                stdout="",
                stderr=(
                    f"Tool '{cmd[0]}' not found. "
                    f"Install it with: sudo apt install {cmd[0]}"
                ),
                returncode=-1,
                success=False,
            )

        except Exception as e:
            logger.exception("Unexpected error executing: %s", cmd_str)
            return CommandResult(
                stdout="",
                stderr=f"Error: {type(e).__name__}: {e}",
                returncode=-1,
                success=False,
            )


# Module-level singleton for convenience
_default_executor: CommandExecutor | None = None


def get_executor(timeout: int | None = None) -> CommandExecutor:
    """Get or create the default executor instance."""
    global _default_executor
    if _default_executor is None:
        _default_executor = CommandExecutor(default_timeout=timeout or 120)
    return _default_executor
