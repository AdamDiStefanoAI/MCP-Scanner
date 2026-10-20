"""Dispatch: walk targets, classify files, run the right engine."""

from __future__ import annotations

import json
from pathlib import Path

from .config_scan import scan_config
from .python_scan import scan_python
from .rules import Finding, RulePack
from .ts_scan import scan_ts

_CONFIG_EXTS = {".json"}
_PYTHON_EXTS = {".py"}
_TS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv"}


def collect_targets(paths: list[str]) -> list[Path]:
    """Expand file and directory arguments into scannable files."""
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if any(part in _SKIP_DIRS for part in child.parts):
                    continue
                if child.is_file() and child.suffix.lower() in (
                    _CONFIG_EXTS | _PYTHON_EXTS | _TS_EXTS
                ):
                    out.append(child)
        elif p.is_file():
            out.append(p)
    return out


def _looks_like_mcp_config(text: str) -> bool:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return False
    if isinstance(data, dict):
        return any(
            k in data for k in ("mcpServers", "servers", "mcp")
        ) or any(
            isinstance(v, dict) and ("command" in v or "url" in v)
            for v in data.values()
        )
    return False


def scan_file(path: Path, display: str, pack: RulePack) -> tuple[list[Finding], int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    ext = path.suffix.lower()
    if ext in _PYTHON_EXTS:
        return scan_python(display, text, pack)
    if ext in _TS_EXTS:
        return scan_ts(display, text, pack)
    if ext in _CONFIG_EXTS:
        if _looks_like_mcp_config(text):
            return scan_config(display, text, pack)
        return [], 0
    # Unknown extension: guess by content.
    if _looks_like_mcp_config(text):
        return scan_config(display, text, pack)
    return [], 0


def scan_targets(
    targets: list[Path], displays: dict[Path, str], pack: RulePack
) -> tuple[list[Finding], int, int]:
    all_findings: list[Finding] = []
    servers = 0
    for t in targets:
        findings, count = scan_file(t, displays[t], pack)
        all_findings.extend(findings)
        servers += count
    all_findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return all_findings, len(targets), servers
