# Examples

These files are **intentionally vulnerable** (except `safe_server.py`).
They exist so you can watch MCP-Scanner work. Do not deploy them, do not
connect a real MCP client to them, and do not copy patterns from the
vulnerable files into a real server.

| File | What it shows |
| --- | --- |
| `vulnerable_server.py` | A FastMCP server that hits most rules at once: shell execution, an exfiltration path, unscoped file access, secret exposure, dynamic code execution, self-modification, and an unauthenticated SSE transport. |
| `vulnerable_config.json` | A client config with a shell-wrapped server, a typosquatted package name, an unpinned auto-install, a headerless HTTP server, and a plaintext database password in `env`. |
| `safe_server.py` | The boring version: pinned file root, path validation, typed parameters, stdio transport. Scans completely clean. |

Try it:

```bash
mcp-scan examples/vulnerable_server.py
mcp-scan examples/vulnerable_config.json
mcp-scan examples/safe_server.py
```
