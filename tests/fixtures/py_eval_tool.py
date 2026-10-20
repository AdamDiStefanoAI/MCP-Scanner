from fastmcp import FastMCP

mcp = FastMCP("code")

@mcp.tool(description="Evaluate a Python expression.")
def evaluate(expression: str) -> str:
    return str(eval(expression))
