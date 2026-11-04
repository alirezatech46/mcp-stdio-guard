"""
mcp-stdio-guard: Zero-dependency JSON-RPC 2.0 stdio security interceptor for MCP servers.
Provides multi-pattern secret scrubbing, dual-alphabet Shannon-entropy inspection (Base64 & Hex),
universal path canonicalization, and tool-scoped shell command guards.
License: MIT
"""

from __future__ import annotations
import base64
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9\-_]{20,140}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,120}")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b")),
    ("GITHUB_FINE_GRAINED", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,255}\b")),
    ("GITLAB_TOKEN", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,100}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{16,120}\b")),
    ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("GOOGLE_OAUTH", re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,200}\b")),
    ("HF_TOKEN", re.compile(r"\bhf_[A-Za-z0-9]{30,100}\b")),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{30,100}\b")),
    ("PYPI_TOKEN", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{30,200}\b")),
    ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64}\b")),
    ("TWILIO_KEY", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("PRIVATE_KEY_PEM", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("BEARER_JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("DB_CONN_URI", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/@]+:[^@\s/]+@[^\s\"']+")),
    ("AUTH_HEADER", re.compile(r"(?i)\b(?:Authorization|X-API-Key)\s*:\s*(?:Bearer\s+|Basic\s+|Token\s+)?[A-Za-z0-9\-._~+/]+=*")),
    ("INLINE_KV_SECRET", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key)"
        r"\s*([=:])\s*(['\"]?)([^\s'\",;]{4,128})\3"
    )),
    ("HEX_SECRET_ASSIGN", re.compile(
        r"(?i)\b(key|token|secret|hash|hmac|signature|seed)\s*([=:])\s*(['\"]?)\b([0-9a-fA-F]{32,128})\b\3"
    )),
)

SENSITIVE_DICT_KEYS: Set[str] = {
    "password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "auth_token", "credentials",
    "authorization", "cookie", "set-cookie", "session_id", "session_token",
    "secret_key", "aws_secret_access_key", "x-api-key", "bearer", "token", "key",
}

BINARY_EXEMPT_KEYS: Set[str] = {
    "data", "blob", "base64", "image", "audio", "bytes", "raw_bytes", "thumbnail",
}

PATH_KEY_NAMES: Set[str] = {
    "path", "paths", "filepath", "file_path", "file", "files", "filename",
    "source", "src", "destination", "dest", "dst", "cwd", "dir", "directory",
    "root", "repo_path", "uri", "url", "target", "location", "workdir", "folder",
}

SHELL_TOOL_NAMES: Set[str] = {
    "bash", "sh", "zsh", "shell", "exec", "execute", "run_command", "run_shell",
    "execute_command", "terminal", "run_terminal_cmd", "system", "subprocess",
}

SHELL_ARG_KEYS: Set[str] = {
    "cmd", "command", "commands", "shell_cmd", "script", "command_line",
}

SYSTEM_SENSITIVE_PREFIXES: Tuple[str, ...] = (
    "/etc/", "/proc/", "/sys/", "/dev/", "/root/", "/var/run/docker.sock",
    "/var/log/", "/boot/", "/private/etc/",
)

HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{32,128}\b")
TOKEN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/=_\-]{28,256}(?![A-Za-z0-9+/=_\-])")

DANGEROUS_SHELL_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("RM_RECURSIVE", re.compile(
        r"(?:^|[;&|\n\r`()]|\b(?:sudo|env)\s+)rm\s+"
        r"(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+-[a-zA-Z]*[rf][a-zA-Z]*|-[a-zA-Z]*(?:rf|fr)[a-zA-Z]*|--recursive|--no-preserve-root)\b",
        re.IGNORECASE,
    )),
    ("PIPE_TO_INTERPRETER", re.compile(
        r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|"
        r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python[23]?|perl|ruby|node|php)\b",
        re.IGNORECASE,
    )),
    ("DISK_DESTRUCT", re.compile(
        r"\b(?:mkfs(?:\.[a-z0-9]+)?|dd\s+if=|wipefs|shred)\b|>\s*/dev/(?:sd[a-z]|nvme\d|disk\d)",
        re.IGNORECASE,
    )),
    ("REVERSE_SHELL", re.compile(
        r"/dev/(?:tcp|udp)/[^\s/]+/\d+|\bnc(?:at)?\s+[^\n]*-e\s+(?:/bin/)?(?:ba)?sh|\bbash\s+-i\s+>&",
        re.IGNORECASE,
    )),
    ("PRIVILEGE_ESCALATION", re.compile(
        r"\bchmod\s+(?:-[Rvf]+\s+)*(?:[0-7]*777|[ugoa]*\+s)\b|\bchown\s+-R\s+root\b",
        re.IGNORECASE,
    )),
)


def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy H(X) in bits per character."""
    length = len(token)
    if length <= 1:
        return 0.0
    counts = Counter(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_pure_base64_blob(value: str) -> bool:
    """Return True if value is a binary base64 payload (e.g. PNG/JPEG/PDF/ZIP) or data URI."""
    compact = re.sub(r"\s+", "", value)
    if compact.startswith("data:") and ";base64," in compact:
        return True
    if compact.startswith(("iVBORw0KGgo", "/9j/", "R0lGOD", "UklGR", "JVBERi0", "UEsDB", "H4sIA")):
        return True
    if len(compact) >= 120 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            decoded = base64.b64decode(compact, validate=True)
            try:
                decoded.decode("utf-8")
                return False
            except UnicodeDecodeError:
                return True
        except Exception:
            return False
    return False


def _looks_like_filesystem_path(value: str) -> bool:
    """Heuristic check for whether an arbitrary string argument represents a path."""
    s = value.strip()
    if not s or len(s) > 4096 or "\n" in s:
        return False
    if " " in s and not s.startswith(("/", "~/", "./", "../", "file://")):
        return False
    if s.startswith(("http://", "https://", "mailto:", "data:")):
        return False
    if s.startswith(("file://", "/", "~/", "../", "./")) or "/../" in s or s.endswith("/.."):
        return True
    if any(s.startswith(prefix) for prefix in SYSTEM_SENSITIVE_PREFIXES):
        return True
    return False


@dataclass(frozen=True)
class GuardPolicy:
    allowed_roots: Tuple[Path, ...] = field(default_factory=lambda: (Path.cwd().resolve(),))
    entropy_threshold: float = 4.35
    hex_entropy_threshold: float = 3.50  # Max theoretical hex entropy is log2(16) = 4.0 bits/char
    min_entropy_token_len: int = 28
    max_payload_bytes: int = 2_097_152
    inspect_all_string_paths: bool = True
    shell_guard_mode: str = "tool_scoped"  # "tool_scoped", "strict", or "off"
    exempt_binary_fields: bool = True
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

    def _normalize_path_input(self, raw_path: str) -> str:
        s = raw_path.strip()
        if s.startswith("file://"):
            parsed = urlparse(s)
            return unquote(parsed.path or "")
        return s

    def validate_filesystem_path(self, raw_path: str, json_path: str) -> bool:
        cleaned = self._normalize_path_input(raw_path)
        if not cleaned or "\x00" in cleaned:
            self._record("PATH_NULL_BYTE", "CRITICAL", json_path, "Null byte or empty path")
            return False

        try:
            expanded = os.path.expandvars(os.path.expanduser(cleaned))
            candidate = Path(expanded).resolve(strict=False)
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

    def inspect_shell_command(self, value: str, json_path: str) -> None:
        for rule_name, pattern in DANGEROUS_SHELL_PATTERNS:
            if pattern.search(value):
                self._record(f"SHELL_{rule_name}", "CRITICAL", json_path, f"Blocked dangerous shell pattern ({rule_name})")
                raise PermissionError(f"MCPStdioGuard blocked dangerous shell command ({rule_name}) at {json_path}")

    def scrub_string(self, value: str, json_path: str, is_binary_field: bool = False) -> str:
        if not value:
            return value
        if self.policy.exempt_binary_fields and (is_binary_field or _looks_like_pure_base64_blob(value)):
            return value

        scrubbed = value
        for label, pattern in SECRET_PATTERNS:
            if label == "INLINE_KV_SECRET":
                if pattern.search(scrubbed):
                    self._record("SECRET_INLINE_KV", "CRITICAL", json_path, "Redacted inline key-value secret")
                    scrubbed = pattern.sub(r"\1\2\3[REDACTED:SECRET]\3", scrubbed)
            elif label == "HEX_SECRET_ASSIGN":
                if pattern.search(scrubbed):
                    self._record("SECRET_HEX_ASSIGN", "HIGH", json_path, "Redacted hex-encoded secret")
                    scrubbed = pattern.sub(r"\1\2\3[REDACTED:HEX_SECRET]\3", scrubbed)
            elif pattern.search(scrubbed):
                self._record(f"SECRET_{label}", "CRITICAL", json_path, f"Redacted {label} signature")
                scrubbed = pattern.sub(f"[REDACTED:{label}]", scrubbed)

        def _replace_hex_secret(match: re.Match[str]) -> str:
            tok = match.group(0)
            if not tok.isdigit() and not tok.isalpha():
                ent = shannon_entropy(tok)
                if ent >= self.policy.hex_entropy_threshold:
                    self._record("HIGH_ENTROPY_HEX", "HIGH", json_path, f"Hex entropy={ent:.2f} bits/char")
                    return "[REDACTED:HEX_SECRET]"
            return tok

        scrubbed = HEX_TOKEN_RE.sub(_replace_hex_secret, scrubbed)

        def _replace_high_entropy(match: re.Match[str]) -> str:
            tok = match.group(0)
            if "REDACTED" in tok or "/" in tok:
                return tok
            if len(tok) >= self.policy.min_entropy_token_len and not tok.isalpha() and not tok.isdigit():
                ent = shannon_entropy(tok)
                if ent >= self.policy.entropy_threshold:
                    self._record("HIGH_ENTROPY_TOKEN", "HIGH", json_path, f"Entropy={ent:.2f} bits/char")
                    return "[REDACTED:HIGH_ENTROPY_SECRET]"
            return tok

        return TOKEN_CANDIDATE_RE.sub(_replace_high_entropy, scrubbed)

    def _is_binary_container(self, node: Dict[str, Any]) -> bool:
        mime = str(node.get("mimeType") or node.get("mime_type") or "").lower()
        node_type = str(node.get("type") or "").lower()
        if node_type in {"image", "audio", "resource_blob"}:
            return True
        if mime.startswith(("image/", "audio/", "video/", "application/octet-stream", "application/pdf", "application/zip")):
            return True
        return False

    def inspect_node(
        self,
        node: Any,
        json_path: str = "$",
        inbound: bool = True,
        active_tool_name: Optional[str] = None,
        parent_key: Optional[str] = None,
        in_binary_context: bool = False,
    ) -> Any:
        if isinstance(node, dict):
            binary_ctx = in_binary_context or self._is_binary_container(node)
            tool_name = active_tool_name
            if inbound and isinstance(node.get("name"), str) and json_path in {"$.params", "$"}:
                tool_name = node["name"].lower()

            sanitized_dict: Dict[str, Any] = {}
            for k, v in node.items():
                child_path = f"{json_path}.{k}"
                k_lower = k.lower()

                if isinstance(v, str) and k_lower in SENSITIVE_DICT_KEYS and v and not v.startswith("[REDACTED"):
                    if k_lower != "key" or len(v) >= 12 or re.fullmatch(r"[0-9a-fA-F]{16,128}", v) or shannon_entropy(v) >= 3.2:
                        self._record("SENSITIVE_DICT_FIELD", "CRITICAL", child_path, f"Redacted sensitive field '{k}'")
                        sanitized_dict[k] = f"[REDACTED:{k_lower.upper()}]"
                        continue

                if inbound and k_lower in PATH_KEY_NAMES:
                    if isinstance(v, str):
                        if not self.validate_filesystem_path(v, child_path):
                            raise PermissionError(f"MCPStdioGuard blocked path traversal at {child_path}")
                    elif isinstance(v, list):
                        for idx, item in enumerate(v):
                            if isinstance(item, str) and not self.validate_filesystem_path(item, f"{child_path}[{idx}]"):
                                raise PermissionError(f"MCPStdioGuard blocked path traversal at {child_path}[{idx}]")

                sanitized_dict[k] = self.inspect_node(
                    v,
                    child_path,
                    inbound=inbound,
                    active_tool_name=tool_name,
                    parent_key=k_lower,
                    in_binary_context=binary_ctx or (k_lower in BINARY_EXEMPT_KEYS),
                )
            return sanitized_dict

        if isinstance(node, list):
            return [
                self.inspect_node(
                    item,
                    f"{json_path}[{idx}]",
                    inbound=inbound,
                    active_tool_name=active_tool_name,
                    parent_key=parent_key,
                    in_binary_context=in_binary_context,
                )
                for idx, item in enumerate(node)
            ]

        if isinstance(node, str):
            is_bin = in_binary_context or (parent_key in BINARY_EXEMPT_KEYS)

            if inbound and not is_bin:
                if self.policy.inspect_all_string_paths and _looks_like_filesystem_path(node):
                    if not self.validate_filesystem_path(node, json_path):
                        raise PermissionError(f"MCPStdioGuard blocked unauthorized path value at {json_path}")

                mode = self.policy.shell_guard_mode
                is_shell_context = (
                    mode == "strict"
                    or (
                        mode == "tool_scoped"
                        and (
                            (active_tool_name and any(t in active_tool_name for t in SHELL_TOOL_NAMES))
                            or (parent_key in SHELL_ARG_KEYS)
                        )
                    )
                )
                if is_shell_context:
                    self.inspect_shell_command(node, json_path)

            return self.scrub_string(node, json_path, is_binary_field=is_bin)

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

    @staticmethod
    def build_error_response(req_id: Any, message: str, code: int = -32001) -> str:
        """Build a standard JSON-RPC 2.0 error response so clients never hang on blocked requests."""
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": code,
                    "message": message,
                },
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )
