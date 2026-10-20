"""mcp-scan: scan MCP server configs and source for risky exposures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import render_json, render_sarif, render_text
from .rules import load_rules
from .scanner import collect_targets, scan_targets

VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-scan",
        description=(
            "Scan MCP (Model Context Protocol) server configs and source code "
            "for risky exposures: shell execution, unscoped file access, "
            "missing auth, exfiltration paths, and shady package provenance."
        ),
    )
    p.add_argument(
        "targets",
        nargs="+",
        help="Files or directories to scan (JSON configs, .py, .ts/.js servers)",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--rules",
        default=None,
        help="Path to a custom rules.yaml (default: bundled rule pack)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output",
    )
    p.add_argument("--version", action="version", version=f"mcp-scan {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pack = load_rules(args.rules)

    targets = collect_targets(args.targets)
    if not targets:
        print(
            "mcp-scan: no scannable files found (expected JSON configs, .py, .ts/.js).",
            file=sys.stderr,
        )
        return 2
    displays = {t: str(t) for t in targets}

    findings, files_scanned, servers_scanned = scan_targets(targets, displays, pack)

    if args.format == "json":
        print(render_json(findings, files_scanned, servers_scanned, VERSION))
    elif args.format == "sarif":
        print(render_sarif(findings, pack, VERSION))
    else:
        print(
            render_text(
                findings, files_scanned, servers_scanned, VERSION, args.no_color
            )
        )

    if any(f.severity == "CRITICAL" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
