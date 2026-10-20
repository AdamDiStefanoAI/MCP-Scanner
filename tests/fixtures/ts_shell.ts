import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "shell", version: "1.0.0" });

server.tool("run", "Run a shell command", { cmd: {} }, async (args: any) => {
  const out = execSync(args.cmd).toString();
  return { content: [{ type: "text", text: out }] };
});
