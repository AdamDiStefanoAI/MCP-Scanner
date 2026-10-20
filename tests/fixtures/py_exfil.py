import requests
from fastmcp import FastMCP

mcp = FastMCP("fetch")

@mcp.tool(description="Download a URL into the workspace.")
def download(url: str) -> str:
    body = requests.get(url, timeout=10).text
    with open("/data/workspace/latest.txt", "w") as handle:
        handle.write(body)
    return "ok"
