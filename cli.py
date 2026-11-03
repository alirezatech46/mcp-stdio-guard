"""
CLI stdio proxy wrapper for mcp-stdio-guard.
Wraps any upstream MCP server command and sanitizes bidirectional JSON-RPC 2.0 traffic.
"""

from __future__ import annotations
import argparse
import subprocess
import sys
import threading
from pathlib import Path
from typing import TextIO
from mcp_guard import GuardPolicy, MCPStdioGuard


def _pump_stream(src: TextIO, dst: TextIO, guard: MCPStdioGuard, inbound: bool) -> None:
    for raw_line in src:
        line = raw_line.strip()
        if not line:
            continue
        try:
            safe_line = guard.process_jsonrpc_line(line, inbound=inbound)
            dst.write(safe_line + "\n")
            dst.flush()
        except Exception as exc:
            sys.stderr.write(f"[mcp-stdio-guard] blocked frame ({'in' if inbound else 'out'}): {exc}\n")
            sys.stderr.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="Zero-dependency stdio security proxy for MCP servers.")
    parser.add_argument("--root", action="append", default=[], help="Allowed filesystem root directory")
    parser.add_argument("--entropy", type=float, default=4.35, help="Shannon entropy threshold (bits/char)")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Upstream MCP server command and args")
    args = parser.parse_args()

    cmd = [c for c in args.command if c != "--"]
    if not cmd:
        parser.error("An upstream MCP server command is required after '--'")

    roots = tuple(Path(r).resolve() for r in args.root) or (Path.cwd().resolve(),)
    guard = MCPStdioGuard(policy=GuardPolicy(allowed_roots=roots, entropy_threshold=args.entropy))

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None

    t_in = threading.Thread(target=_pump_stream, args=(sys.stdin, proc.stdin, guard, True), daemon=True)
    t_out = threading.Thread(target=_pump_stream, args=(proc.stdout, sys.stdout, guard, False), daemon=True)
    t_in.start()
    t_out.start()
    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
