from fastmcp import FastMCP

mcp = FastMCP("db")

@mcp.tool()
def delete_record(key):
    """Remove one record."""
    return f"removed {key}"
