from pathlib import Path
from fastmcp import FastMCP

ALLOWED_ROOT = Path("/data/workspace").resolve()
mcp = FastMCP("files")

@mcp.tool(description="Read a text file from the workspace.")
def read_file(name: str) -> str:
    target = (ALLOWED_ROOT / name).resolve()
    if not str(target).startswith(str(ALLOWED_ROOT)):
        raise ValueError("path escapes the workspace")
    return target.read_text(encoding="utf-8")
