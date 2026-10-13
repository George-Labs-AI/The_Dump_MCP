// Hosted entry point: Streamable HTTP MCP server for mcp.thedump.ai.
//
// Auth model (see the monorepo's docs/mcp-remote-oauth-workos-plan.md):
//   1. The AI client authenticates with WorkOS (AuthKit) — our OAuth
//      authorization server in "Standalone Connect" mode. Users log in with
//      their normal Firebase account on thedump.ai during that flow.
//   2. Every request here carries a WorkOS access token; we verify it against
//      WorkOS's public keys and require audience == MCP_PUBLIC_URL and the
//      email claim. Missing/invalid → 401 + WWW-Authenticate (that is what
//      makes clients start or refresh sign-in).
//   3. Tools call The Dump's API with THIS service's own Google identity plus
//      X-Dump-Acting-User (never the client's token).
// Stateless: one McpServer + transport per request, so Cloud Run can scale
// without sticky sessions.
import express, { type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/server";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { DumpApi } from "./api.js";
import { IdentityTokenCache, ServiceIdentityAuth, type IdentityTokenSource } from "./serviceIdentity.js";
import { registerTools, SERVER_VERSION } from "./tools.js";
import { createWorkosVerifier, TokenRejected, type WorkosVerifier } from "./workosAuth.js";

export interface HttpServerConfig {
  /** Public URL clients use, e.g. https://mcp.thedump.ai/mcp (token audience + resource indicator). */
  mcpPublicUrl: string;
  /** AuthKit domain (issuer host). */
  authkitDomain: string;
  /** The Dump web API base (direct Cloud Run URL, bypassing the LB throttle). */
  dumpBaseUrl: string;
  /** Audience for our Google identity token = what Flask expects (defaults to dumpBaseUrl). */
  selfAudience?: string;
  /** Test hooks. */
  verifier?: WorkosVerifier;
  identitySource?: IdentityTokenSource;
}

export const PROTECTED_RESOURCE_SCOPES = ["openid", "email", "profile", "offline_access"];

export function createHttpApp(cfg: HttpServerConfig) {
  const publicUrl = new URL(cfg.mcpPublicUrl);
  const mcpPath = publicUrl.pathname.replace(/\/$/, "") || "/mcp";
  const metadataUrl = `${publicUrl.origin}/.well-known/oauth-protected-resource`;
  const issuer = `https://${cfg.authkitDomain}`;
  const verify = cfg.verifier ?? createWorkosVerifier({ authkitDomain: cfg.authkitDomain, mcpPublicUrl: cfg.mcpPublicUrl });
  const identity = new IdentityTokenCache(cfg.selfAudience ?? cfg.dumpBaseUrl, cfg.identitySource);

  const protectedResourceMetadata = {
    resource: cfg.mcpPublicUrl,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: PROTECTED_RESOURCE_SCOPES,
    resource_name: "The Dump",
  };

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "8mb" }));

  // RFC 9728 discovery: at the root and at the path-suffixed location, both of
  // which MCP clients probe when the 401 header is missing.
  app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json(protectedResourceMetadata));
  app.get(`/.well-known/oauth-protected-resource${mcpPath}`, (_req, res) => res.json(protectedResourceMetadata));

  // Cloud Run swallows /healthz with its own 404, so use /health.
  app.get("/health", (_req, res) => res.json({ ok: true, version: SERVER_VERSION }));
  app.get("/", (_req, res) =>
    res
      .type("text/plain")
      .send(`The Dump MCP server ${SERVER_VERSION}. Add ${cfg.mcpPublicUrl} to your AI assistant. Docs: https://thedump.ai/mcp\n`)
  );

  function unauthorized(res: Response, description: string) {
    // Claude requires a 401 with resource_metadata to start sign-in; the scope hint
    // tells spec-compliant clients what to request.
    res.set(
      "WWW-Authenticate",
      `Bearer resource_metadata="${metadataUrl}", scope="${PROTECTED_RESOURCE_SCOPES.join(" ")}", ` +
        `error="invalid_token", error_description="${description.replace(/"/g, "'")}"`
    );
    res.status(401).json({ error: "unauthorized", error_description: description });
  }

  async function authenticate(req: Request, res: Response) {
    try {
      return await verify(req.headers.authorization);
    } catch (e) {
      unauthorized(res, e instanceof TokenRejected ? e.description : "Invalid token");
      return null;
    }
  }

  app.post(mcpPath, async (req, res) => {
    const caller = await authenticate(req, res);
    if (!caller) return;

    const api = new DumpApi(new ServiceIdentityAuth(identity, caller.email), {
      baseUrl: cfg.dumpBaseUrl,
      ingestUrl: `${cfg.dumpBaseUrl}/api/ingest`,
    });
    const server = new McpServer({ name: "the-dump", version: SERVER_VERSION });
    registerTools(server, api, { allowLocalFiles: false });

    const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      console.error("mcp request failed:", e);
      if (!res.headersSent) res.status(500).json({ error: "internal_error" });
    }
  });

  // Stateless server: no server-initiated stream, no sessions to delete.
  app.get(mcpPath, async (req, res) => {
    const caller = await authenticate(req, res);
    if (!caller) return;
    res.set("Allow", "POST").status(405).json({ error: "method_not_allowed", error_description: "stateless server: no GET stream" });
  });
  app.delete(mcpPath, (_req, res) => res.set("Allow", "POST").status(405).end());

  return app;
}

function requiredEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`missing required environment variable ${name}`);
    process.exit(1);
  }
  return v;
}

export function main(): void {
  const cfg: HttpServerConfig = {
    mcpPublicUrl: requiredEnv("MCP_PUBLIC_URL"),
    authkitDomain: requiredEnv("WORKOS_AUTHKIT_DOMAIN"),
    dumpBaseUrl: requiredEnv("THE_DUMP_BASE_URL").replace(/\/$/, ""),
    selfAudience: process.env.SELF_AUDIENCE,
  };
  const port = Number(process.env.PORT || 8080);
  createHttpApp(cfg).listen(port, "0.0.0.0", () => {
    console.log(
      `the-dump-mcp ${SERVER_VERSION} listening on :${port}; resource=${cfg.mcpPublicUrl}; issuer=https://${cfg.authkitDomain}; api=${cfg.dumpBaseUrl}`
    );
  });
}

// Run when executed directly (node dist/http.js), not when imported by tests.
if (process.argv[1] && /\/http\.(js|ts)$/.test(process.argv[1])) {
  main();
}
