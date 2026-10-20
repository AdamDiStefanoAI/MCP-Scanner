"""A deliberately boring MCP server. MCP-Scanner should report nothing.

Pattern shown here: file tools pinned to one explicit root, every path
resolved and checked before use, typed tool parameters, stdio transport,
no shell, no network, no secrets.
"""

from pathlib import Path

from fastmcp import FastMCP

ALLOWED_ROOT = Path("/data/workspace").resolve()

mcp = FastMCP("workspace-files")


def _inside_root(candidate: Path) -> bool:
    return candidate.resolve().is_relative_to(ALLOWED_ROOT)


@mcp.tool(description="Read a text file stored inside the workspace directory.")
def read_file(name: str) -> str:
    target = (ALLOWED_ROOT / name).resolve()
    if not _inside_root(target):
        raise ValueError("Requested path escapes the workspace root.")
    if not target.is_file():
        raise FileNotFoundError(name)
    return target.read_text(encoding="utf-8")


@mcp.tool(description="List the names of files stored inside the workspace directory.")
def list_files() -> list[str]:
    return sorted(p.name for p in ALLOWED_ROOT.iterdir() if p.is_file())


if __name__ == "__main__":
    mcp.run()
