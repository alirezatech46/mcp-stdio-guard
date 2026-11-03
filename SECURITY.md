# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| 0.1.x | Yes |

## Threat Model & Scope
`mcp-stdio-guard` operates as an inline `stdio` interceptor for Model Context Protocol (MCP) JSON-RPC 2.0 streams. Any bypass of the Shannon-entropy redaction threshold, regex token scrubbers, or `Path.resolve()` canonicalization checks is treated as a high-severity vulnerability.

## Reporting a Vulnerability
Please do not report security bypasses or regex evasion vectors in public GitHub issues. Open a draft security advisory directly in this repository so fixes can be shipped before disclosure.
