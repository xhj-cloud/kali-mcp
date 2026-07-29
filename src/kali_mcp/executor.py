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
    ) -> CommandResult:
        """Execute a command and return its output.

        Args:
            cmd: Command as list, e.g. ['nmap', '-sP', '192.168.1.0/24']
            timeout: Override default timeout in seconds
            input_data: Optional data to pipe to process stdin

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
                stdin=asyncio.subprocess.PIPE if input_data else None,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(
                    input=input_data.encode("utf-8") if input_data else None
                ),
                timeout=timeout,
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

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

        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            logger.warning("Command timed out after %ds: %s", timeout, cmd_str)
            return CommandResult(
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                returncode=-1,
                success=False,
            )

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
