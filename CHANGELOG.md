# Changelog

All notable changes to MCP-Scanner are documented here. The format is
based on Keep a Changelog, and the project follows semantic versioning.

## [0.1.0] - 2026-10-19

### Added

- `mcp-scan` CLI with two scan modes: MCP client configs (Claude Desktop,
  Cursor, VS Code, Claude Code formats) and server source code (Python
  via `ast`, TypeScript/JavaScript via pattern matching).
- Ten rules, MCP-001 through MCP-010, covering shell execution,
  exfiltration paths, unscoped filesystem access, secret access,
  unauthenticated network transports, schema-less mutating tools,
  overbroad tool descriptions, self-modifying servers, package
  provenance (unpinned installs and typosquats), and dynamic code
  execution.
- Data-driven rule pack (`rules.yaml`): severities, explanations, fixes,
  and detection hints are editable without touching code, and a custom
  pack can be supplied with `--rules`.
- Terminal, JSON, and SARIF 2.1.0 output. Exit code 1 when any CRITICAL
  finding exists.
- Composite GitHub Action (`action.yml`) for CI scanning.
- Intentionally vulnerable examples plus a clean reference server under
  `examples/`, and a pytest suite with a positive and negative fixture
  for every rule.
