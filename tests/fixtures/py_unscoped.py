from fastmcp import FastMCP

mcp = FastMCP("files")

@mcp.tool(description="Read a file by path.")
def read_raw(path: str) -> str:
    with open(path) as handle:
        return handle.read()
