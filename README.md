# mcp-stdio-guard

> Note: Extracted and migrated from our internal self-hosted GitLab security tooling to GitHub as a standalone, zero-dependency MIT-licensed package.

mcp-stdio-guard is a single-file, zero-dependency security interceptor and secret-redaction firewall for Model Context Protocol (MCP) JSON-RPC 2.0 stdio streams. It protects local AI coding agents and MCP servers against accidental credential exfiltration, symlink/path traversal outside workspace roots, and shell metacharacter injection.

## Why Single-File & Zero-Dependency?
Security middleware sitting directly in the stdio pipe between an LLM agent and local tools must have a zero external dependency tree to prevent supply-chain poisoning and keep startup latency under 2ms.

## Threat Mitigation Matrix

| Layer | Mechanism | Threat Mitigated |
| :--- | :--- | :--- |
| **Shannon Entropy Scrubber** | Computes entropy (>= 4.35 bits/char) on candidate tokens | Leaks of unindexed API keys, session secrets, and credentials into LLM context |
| **Signature Redaction** | Pre-compiled rules for Anthropic (sk-ant-api03), OpenAI, AWS IAM, GitHub PAT, JWT, and PEM | Accidental secret exposure during file-read or log-inspection tool calls |
| **Path Canonicalization** | Path.resolve() boundary enforcement against allowed_roots | ../ path traversal and symlink escapes in MCP filesystem tools |
| **Command Guard** | Pattern inspection on inbound tools/call arguments | Destructive shell chaining (rm -rf, pipe-to-shell) from prompt injection |

## Quick Usage

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
