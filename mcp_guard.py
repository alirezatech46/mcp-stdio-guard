"""
mcp-stdio-guard: Zero-dependency JSON-RPC 2.0 stdio security interceptor for MCP servers.
Provides Shannon-entropy secret scrubbing, POSIX path canonicalization, and payload inspection.
License: MIT
"""

from __future__ import annotations
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-api03-[A-Za-z0-9\-_]{80,120}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{32,64}")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("PRIVATE_KEY_PEM", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("BEARER_JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)

TOKEN_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{24,128}\b")
DANGEROUS_SHELL_RE = re.compile(
    r"(?:;\s*rm\s+-rf|&&\s*curl\s+|\|\s*(?:bash|sh|zsh)\b|`[^`]+`|\$\([^)]+\))",
    re.IGNORECASE,
)


def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy H(X) in bits per symbol for high-entropy secret detection."""
    length = len(token)
    if length <= 1:
        return 0.0
    counts = Counter(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


@dataclass(frozen=True)
class GuardPolicy:
    allowed_roots: Tuple[Path, ...] = field(default_factory=lambda: (Path.cwd().resolve(),))
    entropy_threshold: float = 4.35
    min_entropy_token_len: int = 28
    max_payload_bytes: int = 2_097_152
    block_shell_metachars: bool = True
    blocked_methods: Set[str] = field(default_factory=set)


@dataclass
class AuditFinding:
    rule_id: str
    severity: str
    json_path: str
    detail: str


class MCPStdioGuard:
    """Intercepts and sanitizes bidirectional JSON-RPC 2.0 frames over stdio."""

    def __init__(self, policy: Optional[GuardPolicy] = None) -> None:
        self.policy = policy or GuardPolicy()
        self.findings: List[AuditFinding] = []

    def _record(self, rule_id: str, severity: str, json_path: str, detail: str) -> None:
        self.findings.append(AuditFinding(rule_id=rule_id, severity=severity, json_path=json_path, detail=detail))

    def validate_filesystem_path(self, raw_path: str, json_path: str) -> bool:
        try:
            candidate = Path(os.path.expandvars(os.path.expanduser(raw_path))).resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            self._record("PATH_RESOLUTION_ERR", "HIGH", json_path, f"Malformed path: {exc}")
            return False

        for root in self.policy.allowed_roots:
            try:
                candidate.relative_to(root.resolve(strict=False))
                return True
            except ValueError:
                continue

        self._record("PATH_TRAVERSAL", "CRITICAL", json_path, f"Path escapes allowed roots: {raw_path}")
        return False

    def scrub_string(self, value: str, json_path: str) -> str:
        scrubbed = value
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(scrubbed):
                self._record(f"SECRET_{label}", "CRITICAL", json_path, f"Redacted {label} signature")
                scrubbed = pattern.sub(f"[REDACTED:{label}]", scrubbed)

        def _replace_high_entropy(match: re.Match[str]) -> str:
            tok = match.group(0)
            if len(tok) >= self.policy.min_entropy_token_len and not tok.isalpha() and not tok.isdigit():
                ent = shannon_entropy(tok)
                if ent >= self.policy.entropy_threshold:
                    self._record("HIGH_ENTROPY_TOKEN", "HIGH", json_path, f"Entropy={ent:.2f} bits/char")
                    return "[REDACTED:HIGH_ENTROPY_SECRET]"
            return tok

        return TOKEN_CANDIDATE_RE.sub(_replace_high_entropy, scrubbed)

    def inspect_node(self, node: Any, json_path: str = "$", inbound: bool = True) -> Any:
        if isinstance(node, dict):
            sanitized_dict: Dict[str, Any] = {}
            for k, v in node.items():
                child_path = f"{json_path}.{k}"
                if inbound and k.lower() in {"path", "filepath", "file_path", "cwd", "directory"} and isinstance(v, str):
                    if not self.validate_filesystem_path(v, child_path):
                        raise PermissionError(f"MCPStdioGuard blocked path traversal at {child_path}")
                sanitized_dict[k] = self.inspect_node(v, child_path, inbound=inbound)
            return sanitized_dict

        if isinstance(node, list):
            return [self.inspect_node(item, f"{json_path}[{idx}]", inbound=inbound) for idx, item in enumerate(node)]

        if isinstance(node, str):
            if inbound and self.policy.block_shell_metachars and DANGEROUS_SHELL_RE.search(node):
                self._record("SHELL_INJECTION_PATTERN", "CRITICAL", json_path, "Blocked dangerous shell metacharacters")
                raise PermissionError(f"MCPStdioGuard blocked suspicious command pattern at {json_path}")
            return self.scrub_string(node, json_path)

        return node

    def process_jsonrpc_line(self, raw_line: str, inbound: bool = True) -> str:
        if len(raw_line.encode("utf-8", errors="replace")) > self.policy.max_payload_bytes:
            raise ValueError("JSON-RPC frame exceeds maximum permitted byte size")

        payload = json.loads(raw_line)
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            raise ValueError("Invalid JSON-RPC 2.0 envelope")

        method = payload.get("method")
        if inbound and isinstance(method, str) and method in self.policy.blocked_methods:
            raise PermissionError(f"Blocked restricted MCP method: {method}")

        sanitized = self.inspect_node(payload, inbound=inbound)
        return json.dumps(sanitized, separators=(",", ":"), ensure_ascii=False)
