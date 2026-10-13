// HTTP client for The Dump's web API, with the authentication strategy
// injected. Two strategies exist:
//   - stdio (npx the-dump-mcp): the user's own Firebase session (firebaseAuth.ts)
//   - hosted (mcp.thedump.ai): the server's Cloud Run identity acting for a
//     user whose WorkOS token was already verified at the HTTP edge
//     (serviceIdentity.ts)
// Every tool goes through this file, so the tools themselves never know which
// one is in use.

export const DEFAULT_INGEST_URL = "https://thedump.ai/api/ingest";

export interface AuthStrategy {
  /** Add credentials to a request. `attempt` is 0 for the first try, 1 for the retry after a 401. */
  apply(init: RequestInit, attempt: number): Promise<RequestInit>;
  /** Called once when the API answered 401; return true to retry a single time. */
  onUnauthorized(): Promise<boolean>;
  /** Message shown when the API still answers 401 after the retry. */
  readonly unauthorizedMessage: string;
}

/** fetch() that turns network-level failures into a readable message. */
export async function safeFetch(
  url: string,
  init: RequestInit,
  target: string
): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch {
    throw new Error(
      `Could not reach ${target} (network error). Check your internet connection and try again.`
    );
  }
}

/** Parse a response body as JSON, with a readable error instead of a raw parser message. */
export async function readJson(res: Response, context: string): Promise<any> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(
      `${context} returned an unexpected response (status ${res.status}). Please try again.`
    );
  }
}

export interface IngestPayload {
  source: string;
  command: string;
  title?: string;
  messages?: Array<{ role: string; content: string }>;
  summary?: string;
  url?: string;
  metadata?: Record<string, unknown>;
}

export interface UploadTicket {
  uploadUrl: string;
  storagePath: string;
  uuid: string;
}

export class DumpApi {
  readonly baseUrl: string;
  readonly ingestUrl: string;

  constructor(
    private readonly auth: AuthStrategy,
    opts: { baseUrl?: string; ingestUrl?: string } = {}
  ) {
    this.ingestUrl = opts.ingestUrl ?? process.env.THE_DUMP_API_URL ?? DEFAULT_INGEST_URL;
    // Read endpoints live on the same host as ingest; THE_DUMP_BASE_URL overrides.
    this.baseUrl = (
      opts.baseUrl ?? process.env.THE_DUMP_BASE_URL ?? new URL(this.ingestUrl).origin
    ).replace(/\/$/, "");
  }

  /**
   * Authenticated request with a single 401-retry.
   *
   * The strategy decides what a 401 means (expired Firebase token → refresh;
   * stale service identity token → re-mint) and whether to retry. A second
   * 401 surfaces the strategy's message; any other status falls through to the
   * caller's own handling so a 402/429/500 reports as itself.
   */
  async request(url: string, init: RequestInit, target = "The Dump"): Promise<Response> {
    let res = await safeFetch(url, await this.auth.apply(init, 0), target);
    if (res.status === 401) {
      const retry = await this.auth.onUnauthorized();
      if (retry) {
        res = await safeFetch(url, await this.auth.apply(init, 1), target);
      }
      if (res.status === 401) {
        throw new Error(this.auth.unauthorizedMessage);
      }
    }
    return res;
  }

  async ingest(payload: IngestPayload): Promise<string> {
    const res = await this.request(this.ingestUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = await res.text();

    if (!res.ok) {
      const messages: Record<number, string> = {
        400: "Bad request — check your input.",
        402: "No active subscription. Please subscribe at The Dump to continue.",
        429: "Monthly usage limit exceeded.",
        500: "Server error on The Dump backend.",
      };
      throw new Error(messages[res.status] ?? `Request failed (${res.status}): ${body}`);
    }

    // 2xx means the note was accepted even if the body isn't the JSON we expect
    let json: any = null;
    try {
      json = JSON.parse(body);
    } catch {
      return "Saved to The Dump!";
    }
    const details = [
      json?.uuid ? `UUID: ${json.uuid}` : null,
      json?.gcs_path ? `Path: ${json.gcs_path}` : null,
    ].filter(Boolean);
    return ["Saved to The Dump!", ...details].join("\n");
  }

  async read(path: string, init: RequestInit = {}): Promise<any> {
    const res = await this.request(`${this.baseUrl}${path}`, init);

    if (!res.ok) {
      let detail = "";
      try {
        const errBody = await res.clone().json();
        if (typeof errBody?.error === "string") detail = errBody.error;
      } catch {
        // non-JSON error body — status-based message is enough
      }
      const messages: Record<number, string> = {
        400: "Bad request — check your input.",
        402: "No active subscription. Please subscribe at The Dump to continue.",
        429: "Too many requests. Please wait a moment and try again.",
        500: "Server error on The Dump backend.",
      };
      const base = messages[res.status] ?? `Request failed (${res.status}).`;
      throw new Error(detail ? `${base} (${detail})` : base);
    }

    return readJson(res, "The Dump");
  }

  /** Ask the web app for a signed PUT URL (same route the iOS app uses). */
  async uploadTicket(
    filename: string,
    contentType: string,
    isQuickNote: boolean
  ): Promise<UploadTicket> {
    const res = await this.request(`${this.baseUrl}/api/mobile/upload_file`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, contentType, isQuickNote }),
    });
    if (!res.ok) {
      let detail = "";
      try {
        const errBody = await res.clone().json();
        if (typeof errBody?.error === "string") detail = errBody.error;
      } catch {
        // status-based message is enough
      }
      const messages: Record<number, string> = {
        400: "Bad request — check the filename.",
        402: "No active subscription. Please subscribe at The Dump to continue.",
        429: "Monthly usage limit exceeded.",
        500: "Server error on The Dump backend.",
      };
      const base = messages[res.status] ?? `Could not start upload (${res.status}).`;
      throw new Error(detail ? `${base} (${detail})` : base);
    }
    const ticket = await readJson(res, "The Dump");
    if (typeof ticket?.uploadUrl !== "string" || typeof ticket?.uuid !== "string") {
      throw new Error("The Dump returned an unexpected upload response. Please try again.");
    }
    return ticket as UploadTicket;
  }
}
