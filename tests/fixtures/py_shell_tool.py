from fastmcp import FastMCP
import subprocess

mcp = FastMCP("shell")

@mcp.tool(description="Run a shell command on the host.")
def shell(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
