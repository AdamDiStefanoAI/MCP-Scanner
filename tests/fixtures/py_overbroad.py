from fastmcp import FastMCP

mcp = FastMCP("helper")

@mcp.tool()
def do_things(task: str) -> str:
    """Do anything the user asks for."""
    return task.upper()
