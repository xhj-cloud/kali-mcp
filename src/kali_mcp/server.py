"""
Kali MCP Server — Main entry point.

Exposes Kali Linux network tools as MCP tools for AI assistants.
Supports two transports:

  stdio  — For local use (Cherry Studio spawns this process)
  http   — For LAN deployment (clients connect via HTTP/SSE)

Usage:
  python -m kali_mcp.server                        # stdio (default)
  python -m kali_mcp.server --transport http       # HTTP on 0.0.0.0:8000
  python -m kali_mcp.server --transport http --port 9000 --host 127.0.0.1
"""

from __future__ import annotations

import argparse
import inspect
import logging
import os
import sys
from pathlib import Path

# -- Load .env before other imports -------------------------------------------
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass

# -- FastMCP ------------------------------------------------------------------
from fastmcp import FastMCP

# -- Tools --------------------------------------------------------------------
from kali_mcp.tools import TOOL_REGISTRY
from kali_mcp.monitor import MONITOR_TOOLS

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,  # stderr so stdout stays clean for stdio transport
)
logger = logging.getLogger("kali_mcp")

# ---------------------------------------------------------------------------
# FastMCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Kali Tools",
    instructions=(
        "Kali Linux network tools for AI assistants. "
        "Provides device change detection (network_diff), live traffic analysis (traffic_stats), "
        "port uptime monitoring (port_monitor), port scanning (nmap), "
        "network discovery (arp-scan), topology mapping with Mermaid diagrams, "
        "diagnostics (ping, traceroute, mtr), DNS queries (dig), "
        "WHOIS lookups, packet capture (tcpdump), HTTP testing (curl), "
        "and system network information (ss, ip route, ip addr). "
        "All tools run with safe parameter validation and timeouts."
    ),
)

# ---------------------------------------------------------------------------
# Dynamic tool registration using Pydantic model signatures
# ---------------------------------------------------------------------------


def _register_tool_with_model(
    tool_name: str,
    func: callable,
    model_cls: type | None,
) -> None:
    """Register a tool, building its FastMCP signature from a Pydantic model.

    For tools with a Pydantic input model, we introspect the model fields
    to construct an inspect.Signature so FastMCP can auto-generate the
    correct JSON inputSchema (types, defaults, descriptions).

    For no-arg tools (model_cls=None), register directly.
    """
    if model_cls is None:
        # No-argument tool
        async def _wrapper() -> str:
            return await func()

        _wrapper.__name__ = tool_name
        _wrapper.__doc__ = func.__doc__
        mcp.tool(name=tool_name, description=func.__doc__ or "")(_wrapper)
        return

    # Build signature from Pydantic model fields
    sig_params: list[inspect.Parameter] = []
    annotations: dict = {}

    for field_name, field_info in model_cls.model_fields.items():
        default = (
            field_info.default
            if not field_info.is_required()
            else inspect.Parameter.empty
        )
        sig_params.append(
            inspect.Parameter(
                field_name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=field_info.annotation,
            )
        )
        annotations[field_name] = field_info.annotation

    async def _wrapper(**kwargs) -> str:
        validated = model_cls(**kwargs)
        return await func(validated)

    _wrapper.__signature__ = inspect.Signature(sig_params)
    _wrapper.__annotations__ = {**annotations, "return": str}
    _wrapper.__name__ = tool_name
    _wrapper.__doc__ = func.__doc__

    mcp.tool(name=tool_name, description=func.__doc__ or "")(_wrapper)


# Register base tools (network maintenance)
for _name, (_func, _model) in TOOL_REGISTRY.items():
    _register_tool_with_model(_name, _func, _model)
    logger.info("Registered tool: %s", _name)

logger.info("Network tools: %d registered", len(TOOL_REGISTRY))

# Register monitoring tools (always enabled — 🟢 network maintenance)
for _name, (_func, _model) in MONITOR_TOOLS.items():
    _register_tool_with_model(_name, _func, _model)
    logger.info("Registered monitor tool: %s", _name)

logger.info("Monitor tools: %d registered", len(MONITOR_TOOLS))

# Conditionally register pentest tools
_pentest_enabled = os.getenv("PENTEST_ENABLED", "").lower() in ("true", "1", "yes")
if _pentest_enabled:
    try:
        from kali_mcp.pentest import PENTEST_TOOLS  # noqa: F811

        for _name, (_func, _model) in PENTEST_TOOLS.items():
            _register_tool_with_model(_name, _func, _model)
            logger.info("Registered pentest tool: %s", _name)

        logger.info("Pentest tools: %d registered (PENTEST_ENABLED=%s)",
                     len(PENTEST_TOOLS), os.getenv("PENTEST_ENABLED"))
    except ImportError as e:
        logger.warning("Pentest module import failed: %s", e)
else:
    logger.info(
        "Pentest tools: disabled (set PENTEST_ENABLED=true in .env to enable)"
    )

# Conditionally register attack tools
_attack_enabled = os.getenv("ATTACK_ENABLED", "").lower() in ("true", "1", "yes")
if _attack_enabled:
    try:
        from kali_mcp.pentest import ATTACK_TOOLS

        for _name, (_func, _model) in ATTACK_TOOLS.items():
            _register_tool_with_model(_name, _func, _model)
            logger.info("Registered attack tool: %s", _name)

        logger.info("Attack tools: %d registered (ATTACK_ENABLED=%s)",
                     len(ATTACK_TOOLS), os.getenv("ATTACK_ENABLED"))
    except ImportError as e:
        logger.warning("Attack module import failed: %s", e)
else:
    logger.info(
        "Attack tools: disabled (set ATTACK_ENABLED=true in .env to enable)"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Kali MCP Server — AI-powered Kali Linux network tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kali-mcp                                          # stdio transport
  kali-mcp --transport http                         # HTTP on 0.0.0.0:8000
  kali-mcp --transport http --port 9000             # HTTP on port 9000
  kali-mcp --transport http --host 127.0.0.1        # localhost only
        """,
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default=os.getenv("TRANSPORT", "sse"),
        help="Transport: stdio (local), sse (Cherry Studio), http/streamable-http (Claude Desktop). Env: TRANSPORT. Default: sse.",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("HTTP_HOST", "0.0.0.0"),
        help="HTTP bind address (env: HTTP_HOST, default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("HTTP_PORT", "8000")),
        help="HTTP port (env: HTTP_PORT, default: 8000)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("DEFAULT_TIMEOUT", "120")),
        help="Default command timeout in seconds (env: DEFAULT_TIMEOUT, default: 120)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Start the Kali MCP server."""
    args = parse_args(argv)

    os.environ["DEFAULT_TIMEOUT"] = str(args.timeout)

    if args.transport == "stdio":
        _run_stdio()
    elif args.transport == "sse":
        _run_sse(args)
    else:
        _run_streamable_http(args)


def _run_stdio() -> None:
    """Run with stdio transport (for Cherry Studio / Claude Desktop local mode)."""
    logger.info("Starting Kali MCP server [transport=stdio]")
    mcp.run(transport="stdio")


def _run_sse(args: argparse.Namespace) -> None:
    """Run with old SSE transport — compatible with Cherry Studio SSE type."""
    logger.info(
        "Starting Kali MCP server [transport=sse, %s:%d]", args.host, args.port
    )
    _warn_auth()

    # FastMCP built-in SSE server (separate /sse + /messages endpoints)
    mcp.run(
        transport="sse",
        host=args.host,
        port=args.port,
    )


def _run_streamable_http(args: argparse.Namespace) -> None:
    """Run with Streamable HTTP transport (single /mcp endpoint)."""
    logger.info(
        "Starting Kali MCP server [transport=streamable-http, %s:%d]",
        args.host, args.port,
    )
    _warn_auth()

    app = mcp.http_app()
    _apply_auth_middleware(app)
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


def _warn_auth() -> None:
    """Warn if no auth token is configured."""
    auth_token = os.getenv("AUTH_TOKEN", "")
    if not auth_token:
        logger.warning(
            "No AUTH_TOKEN set — endpoint is OPEN. "
            "Set AUTH_TOKEN in .env for LAN security."
        )


def _apply_auth_middleware(app) -> None:
    """Apply bearer-token middleware if AUTH_TOKEN is configured."""
    auth_token = os.getenv("AUTH_TOKEN", "")
    if not auth_token:
        return

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class BearerAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/mcp"):
                auth = request.headers.get("Authorization", "")
                if not auth or auth != f"Bearer {auth_token}":
                    return JSONResponse(
                        {"error": "Unauthorized — valid Bearer token required"},
                        status_code=401,
                    )
            return await call_next(request)

    app.add_middleware(BearerAuthMiddleware)
    logger.info("Bearer token authentication ENABLED")


if __name__ == "__main__":
    main()
