"""Code mode (TypeScript/JavaScript): pattern scan of MCP server source.

Uses line-level pattern matching against common @modelcontextprotocol/sdk
shapes: server.tool(), server.setRequestHandler(), transports, express.
"""

from __future__ import annotations

import re

from .rules import Finding, RulePack

_MUTATING_WORDS = (
    "write", "delete", "remove", "exec", "execute", "update", "create",
    "move", "rename", "kill", "drop", "insert", "send", "upload",
)
_VALIDATION_TOKENS = (
    "startsWith", "resolve(", "isAbsolute", "allowed", "ALLOWED",
    "SAFE_ROOT", "BASE_DIR", "normalize(",
)


def _tool_name_at(text: str, pos: int) -> str:
    """Look backwards from a match for the nearest server.tool('name') call."""
    window = text[max(0, pos - 1200):pos]
    matches = re.findall(
        r"(?:server|this|app)\s*\.\s*tool\s*\(\s*['\"`]([^'\"`]+)['\"`]",
        window,
    )
    return matches[-1] if matches else ""


def scan_ts(path: str, source: str, pack: RulePack) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    lines = source.splitlines()
    lowered = source.lower()

    def add(rule_id: str, lineno: int, evidence: str) -> None:
        key = (rule_id, lineno)
        if key in seen:
            return
        seen.add(key)
        findings.append(pack.finding(rule_id, path, lineno, evidence))

    secret_frags = pack.detection.get("secret_path_fragments", [])
    metadata = pack.detection.get("metadata_endpoints", [])
    config_frags = pack.detection.get("config_file_fragments", [])
    phrases = [p.lower() for p in pack.detection.get("overbroad_phrases", [])]
    has_child_process = "child_process" in source

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # MCP-001: shell execution via child_process.
        if has_child_process and re.search(
            r"\b(execSync|spawnSync|execFileSync|exec|spawn)\s*\(", line
        ):
            add("MCP-001", i, stripped)

        # MCP-010: dynamic code execution.
        if re.search(r"\beval\s*\(", line) or re.search(r"new\s+Function\s*\(", line):
            add("MCP-010", i, stripped)

        # MCP-004: secret access.
        if "process.env" in line:
            add("MCP-004", i, stripped)
        else:
            for frag in secret_frags + metadata:
                if frag in line and not stripped.startswith(("//", "*", "#")):
                    add("MCP-004", i, stripped)
                    break

        # MCP-008: self-modifying / package installs.
        low = line.lower()
        if "pip install" in low or "npm install" in low:
            add("MCP-008", i, stripped)
        elif any(f in line for f in config_frags) and re.search(
            r"writeFile|writeFileSync|appendFile", line
        ):
            add("MCP-008", i, stripped)

        # MCP-007: overbroad description.
        if "description" in low:
            m = re.search(r"description\s*[:=]\s*['\"`]([^'\"`]{0,300})", line)
            if m:
                desc = m.group(1).lower()
                for phrase in phrases:
                    if phrase in desc:
                        add("MCP-007", i, f'description: "{phrase}"')
                        break

    # MCP-002: exfil path (fetch/axios + fs write in the same server file).
    has_fetch = bool(re.search(r"\bfetch\s*\(|axios\s*\.", source))
    write_match = re.search(r"\b(fs\.)?writeFile(Sync)?\s*\(", source)
    if has_fetch and write_match:
        add("MCP-002", 1, "server combines network fetch with local file writes")

    # MCP-003: unscoped filesystem access driven by tool input.
    validated = any(tok in source for tok in _VALIDATION_TOKENS)
    for m in re.finditer(
        r"\b(fs\.)?(readFile(Sync)?|writeFile(Sync)?|createReadStream|createWriteStream)\s*\(",
        source,
    ):
        lineno = source.count("\n", 0, m.start()) + 1
        line = lines[lineno - 1]
        if re.search(r"\b(args|params|input|req|request|argv)\b", line) and not validated:
            add("MCP-003", lineno, line.strip())

    # MCP-005: network transport without auth.
    transport_match = re.search(
        r"SSEServerTransport|StreamableHTTPServerTransport|\.listen\s*\(",
        source,
    )
    if transport_match:
        if not re.search(r"auth|Authorization|token|middleware", lowered):
            add(
                "MCP-005",
                source.count("\n", 0, transport_match.start()) + 1,
                "network transport started with no authentication check in file",
            )

    # MCP-006: mutating tool with empty schema.
    for m in re.finditer(
        r"(?:properties\s*:\s*\{\s*\}|inputSchema\s*:\s*\{\s*\})", source
    ):
        name = _tool_name_at(source, m.start())
        if name and any(w in name.lower() for w in _MUTATING_WORDS):
            add(
                "MCP-006",
                source.count("\n", 0, m.start()) + 1,
                f"tool {name} mutates state but declares an empty input schema",
            )

    # Count tools for the summary.
    tool_count = len(re.findall(r"(?:server|this|app)\s*\.\s*tool\s*\(", source))
    handler_count = len(re.findall(r"setRequestHandler\s*\(", source))
    return findings, 1
