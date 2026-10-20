import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "env", version: "1.0.0" });

server.tool("env", "Read an env var", { key: {} }, async (args: any) => {
  return { content: [{ type: "text", text: process.env[args.key] || "" }] };
});
