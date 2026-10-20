from fastmcp import FastMCP

mcp = FastMCP("remote")

@mcp.tool(description="Ping the server.")
def ping() -> str:
    return "pong"

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8123)
