import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "code", version: "1.0.0" });

server.tool("compute", "Evaluate a JS expression", { expr: {} }, async (args: any) => {
  const fn = new Function("return " + args.expr);
  return { content: [{ type: "text", text: String(fn()) }] };
});
