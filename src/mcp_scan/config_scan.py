"""Config mode: scan MCP client/server JSON configs for risky deployments."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .rules import Finding, RulePack

_LAUNCHERS = {"npx", "uvx", "npm", "pnpm", "yarn", "bunx", "dnx"}


def _server_section(config: dict) -> dict:
    """Support the shapes used by the major MCP clients."""
    if not isinstance(config, dict):
        return {}
    if isinstance(config.get("mcpServers"), dict):
        return config["mcpServers"]
    if isinstance(config.get("servers"), dict):
        return config["servers"]
    mcp = config.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    # Bare dict of servers, e.g. {"github": {"command": ...}}
    if config and all(
        isinstance(v, dict) and ("command" in v or "url" in v)
        for v in config.values()
    ):
        return config
    return {}


def _line_of(lines: list[str], server: str, key: str, after: int = 0) -> int:
    """Best-effort file:line for a server/key in raw JSON text."""
    server_line = None
    for i, raw in enumerate(lines):
        if f'"{server}"' in raw:
            server_line = i
            break
    if server_line is None:
        return 1
    for i in range(server_line + after, len(lines)):
        if f'"{key}"' in lines[i]:
            return i + 1
        # Stop once we leave this server's block at the same indent.
        if i > server_line and f'"{server}"' in lines[i]:
            break
    return server_line + 1


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _split_version(spec: str) -> tuple[str, str | None]:
    """Split name@version, handling scoped packages like @scope/name@1.2.3."""
    if spec.startswith("@"):
        rest = spec[1:]
        scope, _, name = rest.partition("/")
        if "@" in name:
            name, _, version = name.rpartition("@")
            return "@" + scope + "/" + name, version or None
        return "@" + scope + "/" + name, None
    name, _, version = spec.partition("@")
    return name, version or None


def _package_from_args(command: str, args: list[str]) -> tuple[str | None, bool, list[str]]:
    """Return (package_spec, auto_confirm, flags) for npx/uvx-style launches."""
    flags: list[str] = []
    spec: str | None = None
    auto = False
    it = iter(range(len(args)))
    skip_next = False
    for i in it:
        if skip_next:
            skip_next = False
            continue
        a = args[i]
        if a in ("-y", "--yes"):
            auto = True
            continue
        if a in ("-p", "--package", "--from"):
            if i + 1 < len(args):
                spec = args[i + 1]
            skip_next = True
            continue
        if a.startswith("-"):
            flags.append(a)
            continue
        if spec is None:
            spec = a
    return spec, auto, flags


def scan_config(path: str, text: str, pack: RulePack) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], 0
    servers = _server_section(config)
    lines = text.splitlines()
    shell_cmds = {c.lower() for c in pack.detection.get("shell_commands", [])}
    known = pack.detection.get("known_packages", [])

    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue

        command = entry.get("command")
        args = entry.get("args") or []
        url = entry.get("url")

        if isinstance(command, str):
            cmd_line = _line_of(lines, name, "command")
            base = command.strip().lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if base in shell_cmds:
                findings.append(
                    pack.finding(
                        "MCP-001",
                        path,
                        cmd_line,
                        f'server "{name}": "command": "{command}"',
                    )
                )
            if base in _LAUNCHERS:
                spec, auto, _ = _package_from_args(base, [str(a) for a in args])
                if spec:
                    pkg_name, version = _split_version(spec)
                    if version is None or version.lower() == "latest":
                        findings.append(
                            pack.finding(
                                "MCP-009",
                                path,
                                cmd_line,
                                f'server "{name}": {base} installs "{spec}" with no pinned version'
                                + (" (-y auto-confirm)" if auto else ""),
                            )
                        )
                    if pkg_name not in known:
                        best = min(
                            ((_edit_distance(pkg_name, k), k) for k in known),
                            default=(999, ""),
                        )
                        if best[0] <= 2:
                            findings.append(
                                pack.finding(
                                    "MCP-009",
                                    path,
                                    cmd_line,
                                    f'server "{name}": package "{pkg_name}" looks like a typosquat of "{best[1]}"',
                                )
                            )

        if isinstance(url, str):
            url_line = _line_of(lines, name, "url")
            headers = entry.get("headers")
            if not headers:
                findings.append(
                    pack.finding(
                        "MCP-005",
                        path,
                        url_line,
                        f'server "{name}": "url": "{url}" with no auth headers',
                    )
                )
            for frag in pack.detection.get("metadata_endpoints", []):
                if frag in url:
                    findings.append(
                        pack.finding(
                            "MCP-004",
                            path,
                            url_line,
                            f'server "{name}": url points at cloud metadata endpoint {frag}',
                        )
                    )

        env = entry.get("env")
        if isinstance(env, dict):
            env_line = _line_of(lines, name, "env")
            for k, v in env.items():
                if isinstance(v, str) and v and not v.startswith("${"):
                    findings.append(
                        pack.finding(
                            "MCP-004",
                            path,
                            env_line,
                            f'server "{name}": plaintext secret in "env": "{k}"',
                        )
                    )
                    break

    return findings, len(servers)
