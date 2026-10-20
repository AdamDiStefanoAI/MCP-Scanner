from pathlib import Path
from fastmcp import FastMCP

ALLOWED_ROOT = Path("/data/workspace").resolve()
mcp = FastMCP("files")

@mcp.tool(description="Read a workspace file by path.")
def read_scoped(path: str) -> str:
    candidate = (ALLOWED_ROOT / path).resolve()
    if not str(candidate).startswith(str(ALLOWED_ROOT)):
        raise ValueError("nope")
    return open(candidate).read()
