// Verification of the access tokens WorkOS (AuthKit / Connect) issues to MCP
// clients for the hosted server. The token must be signed by our AuthKit
// domain, unexpired, issued for exactly this server's URL (audience) and carry
// the email claim our WorkOS JWT template adds. Anything else is a 401 with
// the WWW-Authenticate challenge that tells the client where to authenticate.
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

export const EMAIL_CLAIM = "urn:thedump:email";

export interface VerifiedCaller {
  email: string;
  claims: JWTPayload;
}

export interface WorkosVerifierOptions {
  /** AuthKit domain, e.g. "astounding-verse-51-staging.authkit.app" (issuer = https://<domain>). */
  authkitDomain: string;
  /** This server's public MCP URL — the token's required audience. */
  mcpPublicUrl: string;
  /** Override the key set (tests pass a local JWKS). Defaults to the AuthKit JWKS endpoint. */
  keySet?: JWTVerifyGetKey;
}

export class TokenRejected extends Error {
  constructor(public readonly description: string) {
    super(description);
  }
}

export function createWorkosVerifier(opts: WorkosVerifierOptions) {
  const issuer = `https://${opts.authkitDomain}`;
  const keySet = opts.keySet ?? createRemoteJWKSet(new URL(`${issuer}/oauth2/jwks`));

  return async function verify(bearer: string | undefined): Promise<VerifiedCaller> {
    const m = /^Bearer\s+(.+)$/i.exec(bearer ?? "");
    if (!m) throw new TokenRejected("Authorization needed");
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(m[1], keySet, {
        issuer,
        audience: opts.mcpPublicUrl,
      }));
    } catch (e: any) {
      throw new TokenRejected(`Invalid token: ${e?.code ?? e?.message ?? "unknown"}`);
    }
    const raw = payload[EMAIL_CLAIM];
    const email = typeof raw === "string" ? raw.trim().toLowerCase() : "";
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      throw new TokenRejected("Token has no usable email claim");
    }
    return { email, claims: payload };
  };
}

export type WorkosVerifier = ReturnType<typeof createWorkosVerifier>;
