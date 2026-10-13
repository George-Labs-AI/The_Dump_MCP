// Hosted server contract tests: discovery document, the 401 challenge that
// starts client sign-in, token verification rules, and a real tools/list +
// tools/call round trip through the MCP client library against a local
// instance (The Dump API is stubbed with a local HTTP server).
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, createLocalJWKSet, type KeyLike } from "jose";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createHttpApp } from "./http.js";
import { createWorkosVerifier, EMAIL_CLAIM } from "./workosAuth.js";
import { ACTING_USER_HEADER } from "./serviceIdentity.js";

const AUTHKIT = "unit-test.authkit.app";
const ISSUER = `https://${AUTHKIT}`;

let privateKey: KeyLike;
let keySet: ReturnType<typeof createLocalJWKSet>;
let fakeDump: Server;
let fakeDumpUrl: string;
let mcp: Server;
let mcpUrl: string;
const seenDumpRequests: Array<{ path: string; auth?: string; acting?: string }> = [];

async function mint(claims: Record<string, unknown>, opts: { aud?: string; iss?: string; expSeconds?: number } = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test" })
    .setIssuer(opts.iss ?? ISSUER)
    .setAudience(opts.aud ?? mcpUrl)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + (opts.expSeconds ?? 600))
    .sign(privateKey);
}

beforeAll(async () => {
  const kp = await generateKeyPair("RS256");
  privateKey = kp.privateKey;
  const jwk = await exportJWK(kp.publicKey);
  keySet = createLocalJWKSet({ keys: [{ ...jwk, kid: "test", alg: "RS256", use: "sig" }] });

  // Stub of The Dump's Flask API: records the identity + acting user it was called with.
  fakeDump = createServer((req, res) => {
    seenDumpRequests.push({
      path: req.url ?? "",
      auth: req.headers.authorization,
      acting: req.headers[ACTING_USER_HEADER.toLowerCase()] as string | undefined,
    });
    if (req.url === "/api/category_map") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ categories: ["work"], subcategories_by_category: { work: ["meetings"] } }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  await new Promise<void>((r) => fakeDump.listen(0, "127.0.0.1", r));
  fakeDumpUrl = `http://127.0.0.1:${(fakeDump.address() as AddressInfo).port}`;

  // The MCP server under test, on an ephemeral port; mcpPublicUrl is set after we know it.
  await new Promise<void>((resolve) => {
    mcp = createServer();
    mcp.listen(0, "127.0.0.1", () => {
      mcpUrl = `http://127.0.0.1:${(mcp.address() as AddressInfo).port}/mcp`;
      const app = createHttpApp({
        mcpPublicUrl: mcpUrl,
        authkitDomain: AUTHKIT,
        dumpBaseUrl: fakeDumpUrl,
        verifier: createWorkosVerifier({ authkitDomain: AUTHKIT, mcpPublicUrl: mcpUrl, keySet }),
        identitySource: async (aud) => `fake-identity-token-for-${aud}`,
      });
      mcp.on("request", app);
      resolve();
    });
  });
});

afterAll(async () => {
  await new Promise((r) => mcp.close(r));
  await new Promise((r) => fakeDump.close(r));
});

describe("discovery", () => {
  it("serves protected-resource metadata at both well-known locations", async () => {
    const origin = new URL(mcpUrl).origin;
    for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const r = await fetch(origin + p);
      expect(r.status).toBe(200);
      const body = await r.json();
      expect(body.resource).toBe(mcpUrl); // must equal the URL exactly as clients enter it
      expect(body.authorization_servers).toEqual([ISSUER]); // Claude uses only the first entry
      expect(body.bearer_methods_supported).toEqual(["header"]);
      expect(body.scopes_supported).toContain("offline_access");
    }
  });

  it("answers an unauthenticated POST with 401 + resource_metadata challenge", async () => {
    const r = await fetch(mcpUrl, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(401);
    const www = r.headers.get("www-authenticate") ?? "";
    expect(www).toMatch(/^Bearer /);
    expect(www).toContain(`resource_metadata="${new URL(mcpUrl).origin}/.well-known/oauth-protected-resource"`);
    expect(www).toContain('scope="openid email profile offline_access"');
  });
});

describe("token verification", () => {
  async function post(token: string) {
    return fetch(mcpUrl, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    });
  }

  it("rejects a token for another audience", async () => {
    const r = await post(await mint({ [EMAIL_CLAIM]: "a@b.co" }, { aud: "https://other.example/mcp" }));
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toContain("resource_metadata=");
  });

  it("rejects a token from another issuer", async () => {
    const r = await post(await mint({ [EMAIL_CLAIM]: "a@b.co" }, { iss: "https://evil.example" }));
    expect(r.status).toBe(401);
  });

  it("rejects an expired token", async () => {
    const r = await post(await mint({ [EMAIL_CLAIM]: "a@b.co" }, { expSeconds: -60 }));
    expect(r.status).toBe(401);
  });

  it("rejects a valid token without the email claim (fail closed)", async () => {
    const r = await post(await mint({}));
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toContain("email claim");
  });

  it("rejects a tampered token", async () => {
    const good = await mint({ [EMAIL_CLAIM]: "a@b.co" });
    const [h, p] = good.split(".");
    const r = await post(`${h}.${p}.AAAA`);
    expect(r.status).toBe(401);
  });
});

describe("tool round trip", () => {
  it("lists tools without the Firebase account tools and calls The Dump as the service identity", async () => {
    const token = await mint({ [EMAIL_CLAIM]: "  Test1@TheDump.ai " });
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
      authProvider: { token: async () => token },
    });
    const client = new Client({ name: "test", version: "0" });
    await client.connect(transport);

    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toContain("list_categories");
    expect(names).toContain("create_note");
    expect(names).not.toContain("login");
    expect(names).not.toContain("signup");
    expect(names).not.toContain("logout");

    const r = await client.callTool({ name: "list_categories", arguments: {} });
    const textOut = (r.content as Array<{ text: string }>).map((c) => c.text).join("\n");
    expect(textOut).toContain("work");
    await client.close();

    const call = seenDumpRequests.find((x) => x.path === "/api/category_map");
    expect(call).toBeDefined();
    expect(call!.auth).toBe(`Bearer fake-identity-token-for-${fakeDumpUrl}`); // our identity, never the client's token
    expect(call!.acting).toBe("test1@thedump.ai"); // normalised email from the WorkOS token
  });

  it("refuses file_path on the hosted server", async () => {
    const token = await mint({ [EMAIL_CLAIM]: "a@b.co" });
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), { authProvider: { token: async () => token } });
    const client = new Client({ name: "test", version: "0" });
    await client.connect(transport);
    const r = await client.callTool({ name: "create_note", arguments: { file_path: "/etc/passwd" } });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.content)).toContain("not available on the hosted server");
    await client.close();
  });
});
