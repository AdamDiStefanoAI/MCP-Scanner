"""Output rendering: terminal text, JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
import os
import sys

from .rules import SEVERITY_ORDER, Finding, RulePack

_ANSI = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[90m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}


def _color_enabled(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _wrap(text: str, indent: str, width: int = 100) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = indent
    for w in words:
        if len(cur) + len(w) + 1 > width and cur.strip():
            lines.append(cur)
            cur = indent
        cur = (cur + " " + w) if cur.strip() else indent + w
    if cur.strip():
        lines.append(cur)
    return lines


def render_text(
    findings: list[Finding],
    files_scanned: int,
    servers_scanned: int,
    version: str,
    no_color: bool = False,
) -> str:
    color = _color_enabled(no_color)
    c = _ANSI if color else {k: "" for k in _ANSI}
    out: list[str] = []
    out.append(f"{c['BOLD']}MCP-Scanner v{version}{c['RESET']}")
    out.append("")

    by_sev: dict[str, list[Finding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    if not findings:
        out.append("No findings. The scanned servers look clean.")
        out.append("")
    for sev in SEVERITY_ORDER:
        group = by_sev.get(sev)
        if not group:
            continue
        out.append(f"{c[sev]}{sev} ({len(group)}){c['RESET']}")
        for f in group:
            out.append(f"  [{f.rule_id}] {f.file}:{f.line}")
            out.append(f"  {f.name}")
            out.append(f"  {c['DIM']}Evidence: {f.evidence}{c['RESET']}")
            out.extend(_wrap(f"Why it matters: {f.why}", "  "))
            out.extend(_wrap(f"Fix: {f.fix}", "  "))
            out.append("")
    counts = {sev: len(by_sev.get(sev, [])) for sev in SEVERITY_ORDER}
    summary = ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER)
    out.append(
        f"Summary: {files_scanned} file(s) scanned, {servers_scanned} server(s) found. "
        f"Findings: {summary}."
    )
    return "\n".join(out)


def render_json(
    findings: list[Finding],
    files_scanned: int,
    servers_scanned: int,
    version: str,
) -> str:
    by_sev = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    payload = {
        "tool": "mcp-scanner",
        "version": version,
        "files_scanned": files_scanned,
        "servers_scanned": servers_scanned,
        "summary": {k.lower(): v for k, v in by_sev.items()},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def render_sarif(
    findings: list[Finding],
    pack: RulePack,
    version: str,
) -> str:
    level = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    rules = [
        {
            "id": r.id,
            "name": r.name.replace(" ", ""),
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.why},
            "help": {"text": f"Why it matters: {r.why}\nFix: {r.fix}"},
            "defaultConfiguration": {"level": level.get(r.severity, "warning")},
            "properties": {"security-severity": r.severity},
        }
        for r in sorted(pack.rules.values(), key=lambda r: r.id)
    ]
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level.get(f.severity, "warning"),
                "message": {"text": f"{f.name}: {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine": f.line,
                                "snippet": {"text": f.evidence},
                            },
                        }
                    }
                ],
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP-Scanner",
                        "version": version,
                        "informationUri": "https://github.com/AdamDiStefanoAI/mcp-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)
