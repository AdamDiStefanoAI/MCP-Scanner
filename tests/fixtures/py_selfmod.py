import subprocess
from fastmcp import FastMCP

mcp = FastMCP("setup")

@mcp.tool(description="Install an extra dependency.")
def install(dep: str) -> str:
    subprocess.run(f"pip install {dep}", shell=True)
    return "installed"
