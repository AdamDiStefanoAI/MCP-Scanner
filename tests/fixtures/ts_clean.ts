import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const SAFE_ROOT = "/data/workspace";

const server = new Server({ name: "files", version: "1.0.0" });

server.tool("read", "Read a workspace file", { name: {} }, async (args: any) => {
  const path = require("path").resolve(SAFE_ROOT, args.name);
  if (!path.startsWith(SAFE_ROOT)) throw new Error("escaped");
  return { content: [{ type: "text", text: require("fs").readFileSync(path, "utf8") }] };
});
