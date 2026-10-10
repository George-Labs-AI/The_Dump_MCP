// Hosted server → The Dump API authentication.
//
// The MCP spec forbids forwarding the client's (WorkOS) access token to
// upstream APIs, so the hosted server calls The Dump as ITSELF: a Google-signed
// identity token for its own Cloud Run service account (audience = the Flask
// service's URL) plus an X-Dump-Acting-User header naming the user whose
// WorkOS token was verified at the HTTP edge. Flask honours that header only
// from this service account and only on an allowlist of routes.
import { decodeJwt } from "jose";
import type { AuthStrategy } from "./api.js";

export const ACTING_USER_HEADER = "X-Dump-Acting-User";

const METADATA_IDENTITY_URL =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

export type IdentityTokenSource = (audience: string) => Promise<string>;

/** Cloud Run / GCE metadata server: mints an identity token for this service account. */
export const metadataServerIdentity: IdentityTokenSource = async (audience) => {
  const url = `${METADATA_IDENTITY_URL}?audience=${encodeURIComponent(audience)}&format=full`;
  const res = await fetch(url, { headers: { "Metadata-Flavor": "Google" } });
  if (!res.ok) {
    throw new Error(`metadata server returned ${res.status} for an identity token`);
  }
  return res.text();
};

/**
 * Caches one identity token per audience and re-mints it a few minutes before
 * expiry. Shared across requests (module-level) so each tool call does not hit
 * the metadata server.
 */
export class IdentityTokenCache {
  private token: string | null = null;
  private expiresAtMs = 0;
  private inFlight: Promise<string> | null = null;

  constructor(
    private readonly audience: string,
    private readonly source: IdentityTokenSource = metadataServerIdentity,
    private readonly refreshMarginMs = 5 * 60_000
  ) {}

  async get(force = false): Promise<string> {
    if (!force && this.token && Date.now() < this.expiresAtMs - this.refreshMarginMs) {
      return this.token;
    }
    if (!this.inFlight) {
      this.inFlight = this.source(this.audience)
        .then((tok) => {
          let exp = 0;
          try {
            exp = (decodeJwt(tok).exp ?? 0) * 1000;
          } catch {
            exp = Date.now() + 10 * 60_000;
          }
          this.token = tok;
          this.expiresAtMs = exp;
          return tok;
        })
        .finally(() => {
          this.inFlight = null;
        });
    }
    return this.inFlight;
  }
}

export class ServiceIdentityAuth implements AuthStrategy {
  readonly unauthorizedMessage =
    "The Dump's API refused this server's identity. This is a server-side configuration problem, not your login — please try again later.";

  constructor(
    private readonly cache: IdentityTokenCache,
    private readonly actingUserEmail: string
  ) {}

  async apply(init: RequestInit, attempt: number): Promise<RequestInit> {
    const token = await this.cache.get(attempt > 0);
    return {
      ...init,
      headers: {
        ...(init.headers ?? {}),
        Authorization: `Bearer ${token}`,
        [ACTING_USER_HEADER]: this.actingUserEmail,
      },
    };
  }

  /** A 401 most likely means a stale identity token; re-mint once and retry. */
  async onUnauthorized(): Promise<boolean> {
    return true;
  }
}
