#!/usr/bin/env node
// Local (stdio) entry point — what `npx the-dump-mcp` runs inside Claude
// Desktop, Claude Code, Cursor, etc. Authenticates with the user's own
// Firebase account via the login/signup/logout tools. The hosted server at
// mcp.thedump.ai is the same tool set behind OAuth; see http.ts.
import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { DumpApi } from "./api.js";
import { FirebaseAuth } from "./firebaseAuth.js";
import { registerAuthTools, registerTools, SERVER_VERSION } from "./tools.js";

async function main() {
  const auth = new FirebaseAuth(); // loads any saved credentials
  const api = new DumpApi(auth);
  const server = new McpServer({ name: "the-dump", version: SERVER_VERSION });
  registerAuthTools(server, auth);
  registerTools(server, api, { allowLocalFiles: true });
  await server.connect(new StdioServerTransport());
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
