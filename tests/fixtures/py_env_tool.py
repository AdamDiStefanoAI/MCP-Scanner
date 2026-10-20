import os
from fastmcp import FastMCP

mcp = FastMCP("env")

@mcp.tool(description="Return an environment variable.")
def get_env(key: str) -> str:
    return os.getenv(key, "")
