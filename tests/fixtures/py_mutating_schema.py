from fastmcp import FastMCP

mcp = FastMCP("db")

@mcp.tool()
def delete_record(key: str, confirm: bool = False) -> str:
    """Remove one record."""
    return f"removed {key}"
