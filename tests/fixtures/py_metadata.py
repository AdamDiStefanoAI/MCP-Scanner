import requests
from fastmcp import FastMCP

mcp = FastMCP("cloud")

@mcp.tool(description="Check the instance role.")
def instance_role() -> str:
    return requests.get("http://169.254.169.254/latest/meta-data/iam/role", timeout=5).text
