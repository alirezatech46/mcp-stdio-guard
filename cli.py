"""
CLI stdio proxy wrapper for mcp-stdio-guard.
Wraps any upstream MCP server command, sanitizes bidirectional JSON-RPC 2.0 traffic,
returns standard JSON-RPC error frames on policy blocks, and cleanly propagates EOF.
"""

from __future__ import annotations
import argparse
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional, TextIO, Tuple
from mcp_guard import GuardPolicy, MCPStdioGuard

_STDOUT_LOCK = threading.Lock()


def _extract_request_id(raw_line: str) -> Tuple[bool, Any]:
    """Return (has_id, id_value) if the JSON-RPC frame is a request expecting a response."""
    try:
        data = json.loads(raw_line)
        if isinstance(data, dict) and "id" in data and "method" in data:
            return True, data["id"]
    except Exception:
        pass
    return False, None


def _write_line_threadsafe(stream: TextIO, line: str) -> None:
    with _STDOUT_LOCK:
        stream.write(line + "\n")
        stream.flush()


def _pump_inbound(
    client_in: TextIO,
    server_in: TextIO,
    client_out: TextIO,
    guard: MCPStdioGuard,
) -> None:
    """Pump client -> server frames; emit JSON-RPC error back to client on policy violation and close server_in on EOF."""
    try:
        for raw_line in client_in:
            line = raw_line.strip()
            if not line:
                continue
            try:
                safe_line = guard.process_jsonrpc_line(line, inbound=True)
                server_in.write(safe_line + "\n")
                server_in.flush()
            except Exception as exc:
                sys.stderr.write(f"[mcp-stdio-guard] blocked inbound frame: {exc}\n")
                sys.stderr.flush()
                has_id, req_id = _extract_request_id(line)
                if has_id:
                    err_frame = MCPStdioGuard.build_error_response(req_id, str(exc))
                    _write_line_threadsafe(client_out, err_frame)
    except (BrokenPipeError, ValueError, OSError):
        pass
    finally:
        try:
            server_in.close()
        except Exception:
            pass


def _pump_outbound(
    server_out: TextIO,
    client_out: TextIO,
    guard: MCPStdioGuard,
) -> None:
    """Pump server -> client frames with secret scrubbing."""
    try:
        for raw_line in server_out:
            line = raw_line.strip()
            if not line:
                continue
            try:
                safe_line = guard.process_jsonrpc_line(line, inbound=False)
                _write_line_threadsafe(client_out, safe_line)
            except Exception as exc:
                sys.stderr.write(f"[mcp-stdio-guard] blocked outbound frame: {exc}\n")
                sys.stderr.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Zero-dependency stdio security proxy for MCP servers.")
    parser.add_argument("--root", action="append", default=[], help="Allowed filesystem root directory")
    parser.add_argument("--entropy", type=float, default=4.35, help="Shannon entropy threshold (bits/char)")
    parser.add_argument(
        "--shell-mode",
        choices=("tool_scoped", "strict", "off"),
        default="tool_scoped",
        help="Shell command inspection mode (default: tool_scoped)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Upstream MCP server command and args")
    args = parser.parse_args(argv)

    cmd = [c for c in args.command if c != "--"]
    if not cmd:
        parser.error("An upstream MCP server command is required after '--'")

    roots = tuple(Path(r).resolve() for r in args.root) or (Path.cwd().resolve(),)
    policy = GuardPolicy(
        allowed_roots=roots,
        entropy_threshold=args.entropy,
        shell_guard_mode=args.shell_mode,
    )
    guard = MCPStdioGuard(policy=policy)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None

    t_in = threading.Thread(
        target=_pump_inbound,
        args=(sys.stdin, proc.stdin, sys.stdout, guard),
        daemon=True,
    )
    t_out = threading.Thread(
        target=_pump_outbound,
        args=(proc.stdout, sys.stdout, guard),
        daemon=True,
    )
    t_in.start()
    t_out.start()

    t_in.join()
    t_out.join()
    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
