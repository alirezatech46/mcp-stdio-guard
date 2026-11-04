# mcp-stdio-guard

<p>
  <img src="https://img.shields.io/badge/version-v0.2.0-0969da?style=flat-square" alt="Version v0.2.0" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square" alt="Python 3.9+" />
  <img src="https://img.shields.io/badge/dependencies-zero-2da44e?style=flat-square" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" alt="MIT License" />
</p>

`mcp-stdio-guard` is a lightweight, zero-dependency Python security interceptor and secret-redaction proxy for **Model Context Protocol (MCP)** `JSON-RPC 2.0` stdio streams. It sits between an MCP client (such as Claude Code or Claude Desktop) and an upstream MCP server to prevent accidental credential exfiltration, symlink/path traversal outside allowed workspace roots, and destructive shell commands.

> **Ecosystem & Naming Note:** This Python security proxy (`pip install .` / `mcp_guard`) is unrelated to the npm stdout-formatting test package of the same name. Unlike heavier policy gateways (`mcpwall`, `agentsec-gateway`), `mcp-stdio-guard` focuses on being an auditable, zero-dependency Python stdlib wrapper for per-server stdio sandboxing with ~0.6ms per-frame inspection overhead.

## Architecture & Data Flow

    +---------------------------------------+
    |       Claude Code / MCP Client        |
    +-------------------+-------------------+
                        |
         JSON-RPC 2.0   |   Sanitized Output or
         Inbound        v   -32001 Error Frame
    +---------------------------------------+
    |             MCPStdioGuard             |
    |  1. Universal Path.resolve() Sandbox  |
    |  2. Tool-Scoped Shell Command Guard   |
    |  3. Dual Base64/Hex Entropy Scrubber  |
    +-------------------+-------------------+
                        |
           stdio pipe   |   raw output (EOF-safe)
                        v
    +---------------------------------------+
    |          Upstream MCP Server          |
    |       (Filesystem / Git / Shell)      |
    +---------------------------------------+

## Threat Mitigation Matrix

| Layer | Mechanism | Threat Mitigated |
| :--- | :--- | :--- |
| **Dual Entropy Scrubber** | Base64 (`>= 4.35 bits/char`) & Hex (`>= 3.50 bits/char`, where $\log_2(16)=4.0$) | Leaks of unindexed API keys, hex tokens, and session secrets into LLM context |
| **22+ Secret Signatures & Dict Keys** | Pre-compiled rules for Anthropic, OpenAI, AWS, GitHub, JWT, PEM, DB URIs, `password=...`, and sensitive JSON keys | Accidental credential exposure in config files, `.env` reads, or logs |
| **Binary-Safe Exemption** | Preserves MCP `image`/`audio`/`data` fields, Data URIs, and binary magic headers (`PNG`, `JPEG`, `PDF`, `ZIP`) | Prevents false-positive corruption of base64 binary payloads |
| **Universal Path Sandbox** | `Path.resolve()` canonicalization across 24 path keys, `file://` URIs, arrays, and path-like string values | `../` path traversal and unauthorized reads (e.g. `/etc/passwd`) |
| **Tool-Scoped Shell Guard** | Inspects shell tools/arguments (`rm -rf`/`-fr`, newline injection, `curl/wget \| python/sh`, reverse shells) | Destructive shell execution while allowing Markdown backticks in `write_file` |
| **Protocol-Compliant Proxy** | Returns standard JSON-RPC `-32001` error frames on blocked requests and propagates `stdin` EOF cleanly | Prevents client hangs on blocked tool calls or orphaned server processes |

## Installation & CLI Proxy Usage

    pip install .
    mcp-stdio-guard --root /workspace --entropy 4.35 -- npx -y @modelcontextprotocol/server-filesystem /workspace

Or run directly without installation:

    python3 cli.py --root /workspace -- npx -y @modelcontextprotocol/server-filesystem /workspace

## Library Usage (`mcp_guard.py`)

    from pathlib import Path
    from mcp_guard import GuardPolicy, MCPStdioGuard

    guard = MCPStdioGuard(
        policy=GuardPolicy(allowed_roots=(Path("/workspace").resolve(),), entropy_threshold=4.35)
    )
    safe_frame = guard.process_jsonrpc_line(raw_stdio_line, inbound=False)

## Running Tests

    python3 -m unittest test_mcp_guard.py -v

## License
MIT License.
