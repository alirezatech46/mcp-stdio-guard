import json
import unittest
from pathlib import Path
from mcp_guard import GuardPolicy, MCPStdioGuard, shannon_entropy


class TestMCPStdioGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("/tmp/mcp_safe_root").resolve()
        self.policy = GuardPolicy(allowed_roots=(self.root,), entropy_threshold=4.2)
        self.guard = MCPStdioGuard(policy=self.policy)

    def test_shannon_entropy_calculation(self) -> None:
        self.assertLess(shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 1.0)
        self.assertGreater(shannon_entropy("aB3$xP9!qW2#zL8@mN5%vR7^kT4&yU1*"), 4.5)

    def test_redacts_anthropic_api_key(self) -> None:
        fake_key = "sk-ant-api03-" + ("A1b2C3d4E5" * 9)
        frame = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"text": f"token={fake_key}"}})
        sanitized = json.loads(self.guard.process_jsonrpc_line(frame, inbound=False))
        self.assertIn("[REDACTED:ANTHROPIC_KEY]", sanitized["result"]["text"])

    def test_blocks_path_traversal(self) -> None:
        frame = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"path": "/etc/passwd"},
        })
        with self.assertRaises(PermissionError):
            self.guard.process_jsonrpc_line(frame, inbound=True)

    def test_blocks_shell_injection(self) -> None:
        frame = json.dumps({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"cmd": "ls -la; rm -rf /"},
        })
        with self.assertRaises(PermissionError):
            self.guard.process_jsonrpc_line(frame, inbound=True)


if __name__ == "__main__":
    unittest.main()
