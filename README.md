# MCP-Scanner

[![PyPI version](https://img.shields.io/pypi/v/runtime-mcp-scanner.svg)](https://pypi.org/project/runtime-mcp-scanner/)
[![Python versions](https://img.shields.io/pypi/pyversions/runtime-mcp-scanner.svg)](https://pypi.org/project/runtime-mcp-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/AdamDiStefanoAI/mcp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AdamDiStefanoAI/mcp-scanner/actions/workflows/ci.yml)

**Scan MCP server configs and source code for risky exposures before your agent connects to them.**

This week, researchers documented MONST3R-AI: a criminal toolkit built on stolen API keys and more than 800 fake AI-skill and MCP repositories. Malicious MCP servers are not a theory anymore. They are a distribution channel.

You would not install a random npm package without looking at it. Your agent connects to MCP servers with far less scrutiny, and an MCP server runs on your machine, with your credentials, able to offer your agent any tool it likes. A tool that runs shell commands. A tool that reads any file. A server that exfiltrates through tools that look boring on their own.

MCP-Scanner is a fast, dependency-light static check you run before you trust a server, and in CI after you do.

## Quickstart (30 seconds)

```bash
# No install (uv)
uvx --from runtime-mcp-scanner mcp-scan path/to/config.json

# Or with pipx
pipx install runtime-mcp-scanner
mcp-scan path/to/server.py

# Or plain pip
pip install runtime-mcp-scanner
```

Point it at client configs (Claude Desktop, Cursor, VS Code, Claude Code), Python servers (FastMCP and the low-level SDK), or TypeScript servers (`@modelcontextprotocol/sdk`). Directories are scanned recursively. The exit code is nonzero when any CRITICAL finding exists, so it drops straight into CI.

Try it on the intentionally vulnerable examples in this repo:

```bash
git clone https://github.com/AdamDiStefanoAI/mcp-scanner
cd mcp-scanner
mcp-scan examples/vulnerable_server.py    # 15 findings, exit 1
mcp-scan examples/vulnerable_config.json  # 6 findings, exit 1
mcp-scan examples/safe_server.py          # clean, exit 0
```

## Sample output

<details>
<summary>Full output of <code>mcp-scan examples/vulnerable_server.py</code></summary>

```text
MCP-Scanner v0.1.0

CRITICAL (3)
  [MCP-001] examples/vulnerable_server.py:20
  Shell execution exposed
  Evidence: subprocess.run(command, shell=True, capture_output=True, text=True)
  Why it matters: A tool that runs shell commands gives anyone who can steer the agent, including
  content injected into its context, arbitrary code execution on the host machine.
  Fix: Remove shell execution from the tool surface. Replace it with a fixed allowlist of specific
  operations that take validated, typed arguments.

  [MCP-002] examples/vulnerable_server.py:26
  Exfiltration path (network fetch plus file write)
  Evidence: server combines network fetch with local file writes
  Why it matters: One server that can both read local files or fetch network resources and write or
  send data out is a complete exfiltration channel. Prompt injection only has to convince the agent
  to use tools that already exist.
  Fix: Split network access and file writes into separate servers with least privilege, and put an
  egress allowlist in front of any fetch tool.

  [MCP-001] examples/vulnerable_server.py:63
  Shell execution exposed
  Evidence: subprocess.run(f"pip install {package}", shell=True, capture_output=True)
  Why it matters: A tool that runs shell commands gives anyone who can steer the agent, including
  content injected into its context, arbitrary code execution on the host machine.
  Fix: Remove shell execution from the tool surface. Replace it with a fixed allowlist of specific
  operations that take validated, typed arguments.

HIGH (7)
  [MCP-003] examples/vulnerable_server.py:27
  Unscoped filesystem access
  Evidence: open(dest, "w")
  Why it matters: A file tool that takes a raw path from tool input can read or overwrite anything
  the server process can reach: home directories, SSH keys, cloud credentials, other projects.
  Fix: Pin file tools to an explicit root directory and reject any resolved path that escapes it
  (resolve the path, then check the prefix).

  [MCP-003] examples/vulnerable_server.py:34
  Unscoped filesystem access
  Evidence: open(file_path)
  Why it matters: A file tool that takes a raw path from tool input can read or overwrite anything
  the server process can reach: home directories, SSH keys, cloud credentials, other projects.
  Fix: Pin file tools to an explicit root directory and reject any resolved path that escapes it
  (resolve the path, then check the prefix).

  [MCP-004] examples/vulnerable_server.py:40
  Secret access
  Evidence: os.environ[var_name]
  Why it matters: Tools or configs that expose environment variables, credential files, or the cloud
  metadata endpoint hand live secrets to the model context, where they can be logged, leaked, or
  exfiltrated.
  Fix: Never expose raw environment or credential stores as tool output. Scope credentials per
  server, inject only what that server needs, and block the link-local metadata address at the
  network layer.

  [MCP-004] examples/vulnerable_server.py:45
  Secret access
  Evidence: ~/.ssh/id_rsa
  Why it matters: Tools or configs that expose environment variables, credential files, or the cloud
  metadata endpoint hand live secrets to the model context, where they can be logged, leaked, or
  exfiltrated.
  Fix: Never expose raw environment or credential stores as tool output. Scope credentials per
  server, inject only what that server needs, and block the link-local metadata address at the
  network layer.

  [MCP-010] examples/vulnerable_server.py:58
  Dynamic code execution
  Evidence: eval(code)
  Why it matters: eval, exec, and dynamic imports inside a tool handler turn any string the model
  produces into running code, bypassing every other control in the server.
  Fix: Remove dynamic evaluation from tool handlers. Replace it with a dispatch table of named,
  audited operations.

  [MCP-003] examples/vulnerable_server.py:70
  Unscoped filesystem access
  Evidence: open(config_path)
  Why it matters: A file tool that takes a raw path from tool input can read or overwrite anything
  the server process can reach: home directories, SSH keys, cloud credentials, other projects.
  Fix: Pin file tools to an explicit root directory and reject any resolved path that escapes it
  (resolve the path, then check the prefix).

  [MCP-005] examples/vulnerable_server.py:75
  Network transport without authentication
  Evidence: network transport started with no authentication check in file
  Why it matters: An MCP server listening on HTTP or SSE with no authentication lets anyone who can
  reach the port call its tools directly, no agent required.
  Fix: Require an Authorization header or token check on every request, bind to localhost when
  remote access is not needed, and put the server behind a gateway that authenticates callers.

MEDIUM (5)
  [MCP-007] examples/vulnerable_server.py:18
  Overbroad tool description
  Evidence: description of exec_shell: "anything"
  Why it matters: Tool descriptions are instructions to the model. Descriptions that advertise
  unrestricted capability ("run any command", "access all files") teach the agent to use the tool as
  a general escape hatch and are a hallmark of malicious MCP packages.
  Fix: Describe exactly what the tool does, what it may touch, and what it must never do. Treat
  description text as part of your attack surface.

  [MCP-007] examples/vulnerable_server.py:33
  Overbroad tool description
  Evidence: description of read_file: "any file"
  Why it matters: Tool descriptions are instructions to the model. Descriptions that advertise
  unrestricted capability ("run any command", "access all files") teach the agent to use the tool as
  a general escape hatch and are a hallmark of malicious MCP packages.
  Fix: Describe exactly what the tool does, what it may touch, and what it must never do. Treat
  description text as part of your attack surface.

  [MCP-006] examples/vulnerable_server.py:50
  Mutating tool with no input schema
  Evidence: tool delete_data mutates state but its parameters have no type/schema annotations
  Why it matters: A write, delete, or execute tool with an empty input schema accepts arbitrary
  arguments with no validation layer between the model and the action.
  Fix: Give every mutating tool a strict input schema with typed, bounded fields, and validate
  arguments server-side before acting on them.

  [MCP-008] examples/vulnerable_server.py:63
  Self-modifying server
  Evidence: pip install
  Why it matters: A tool that can rewrite MCP client configs or install new packages can persist
  itself, add new malicious servers, and survive removal of the original package.
  Fix: MCP servers must never write to client configuration files or invoke package managers. Keep
  config changes manual and reviewable.

  [MCP-008] examples/vulnerable_server.py:69
  Self-modifying server
  Evidence: /home/user/.config/claude/claude_desktop_config.json
  Why it matters: A tool that can rewrite MCP client configs or install new packages can persist
  itself, add new malicious servers, and survive removal of the original package.
  Fix: MCP servers must never write to client configuration files or invoke package managers. Keep
  config changes manual and reviewable.

Summary: 1 file(s) scanned, 1 server(s) found. Findings: 3 critical, 7 high, 5 medium, 0 low, 0 info.
```

</details>

## What it checks

| Rule | Severity | What it catches |
| --- | --- | --- |
| MCP-001 | CRITICAL | Shell execution exposed: `subprocess`, `os.system`, `child_process`, or a config whose `command` is a shell |
| MCP-002 | CRITICAL | Exfiltration path: one server that can both fetch the network and write files |
| MCP-003 | HIGH | Unscoped filesystem access: file tools driven by raw input paths with no root or allowlist check |
| MCP-004 | HIGH | Secret access: environment variables exposed as tools, credential file reads, the `169.254.169.254` metadata endpoint, plaintext secrets in config `env` |
| MCP-005 | HIGH | Network transport without authentication: HTTP/SSE servers or config `url` servers with no auth headers |
| MCP-006 | MEDIUM | Mutating tool with no input schema: write/delete/exec tools whose arguments are untyped or undeclared |
| MCP-007 | MEDIUM | Overbroad tool description: "run any command", "access all files", and other escape-hatch language aimed at the model |
| MCP-008 | MEDIUM | Self-modifying server: tools that rewrite MCP client configs or run `pip install` / `npm install` |
| MCP-009 | HIGH | Package provenance: unpinned or `latest` auto-installs via `npx -y` / `uvx`, and package names within edit distance 2 of well-known MCP packages (typosquats) |
| MCP-010 | HIGH | Dynamic code execution: `eval`, `exec`, `__import__`, `new Function` inside a tool handler |

Rules are data, not code: severities, explanations, fixes, and detection hints live in [`src/mcp_scan/rules.yaml`](src/mcp_scan/rules.yaml). Point `--rules` at your own copy to tune them.

## Output formats

```bash
mcp-scan server.py                    # grouped terminal report
mcp-scan server.py --format json      # machine-readable findings
mcp-scan server.py --format sarif     # SARIF 2.1.0 for GitHub code scanning
```

## GitHub Action

Fail the build when a scanned server has a CRITICAL finding:

```yaml
name: mcp-security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AdamDiStefanoAI/MCP-Scanner@v0.1.1
        with:
          targets: "mcp/ examples/"
```

For SARIF upload to GitHub code scanning, run the CLI directly:

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install runtime-mcp-scanner
      - run: mcp-scan servers/ --format sarif > results.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## What a risky config looks like

```json
{
  "mcpServers": {
    "helper": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesytem"]
    },
    "shell": {
      "command": "bash",
      "args": ["-lc", "run the bridge"]
    },
    "docs": {
      "url": "http://docs.internal:8000/sse"
    }
  }
}
```

That config gets flagged for a shell-wrapped server (MCP-001), an unpinned auto-install and a one-character typosquat of `server-filesystem` (MCP-009), and a remote server with no auth headers (MCP-005). The full version, with a plaintext database password for good measure, is in [`examples/vulnerable_config.json`](examples/vulnerable_config.json).

## Honest limits

MCP-Scanner is a heuristic static check, not a proof of safety. It flags visible risk patterns in code and config; it does not sandbox servers, trace data flow across files, or catch a server that behaves during review and turns later. Run it as one layer: before install, in CI, and whenever a config changes. A clean scan means "nothing obviously dangerous," which is a much better starting point than "nobody looked."

## Contributing

Issues and pull requests are welcome. New rules are the highest-value contribution: if a malicious or sloppy MCP pattern is circulating, open an issue with a sample. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

Built by [Adam DiStefano](https://github.com/AdamDiStefanoAI), creator of the [ACR Standard](https://github.com/AdamDiStefanoAI/acr-standard) for runtime control of AI agents. Companion tool: [AI-Key-Scanner](https://github.com/AdamDiStefanoAI/AI-Key-Scanner).
