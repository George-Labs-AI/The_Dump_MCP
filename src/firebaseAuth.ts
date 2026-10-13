// Firebase email/password session for the stdio (npx) server: the user logs
// in once with the `login` tool, the tokens live in ~/.the-dump/credentials.json
// and refresh themselves. Not used by the hosted server.
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { AuthStrategy } from "./api.js";
import { readJson, safeFetch } from "./api.js";

const FIREBASE_API_KEY = "AIzaSyDNqivcHgxiSgAfe289TqPD7e_gcP7z8dc";
const FIREBASE_SIGN_IN_URL = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`;
const FIREBASE_SIGN_UP_URL = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`;
const FIREBASE_REFRESH_URL = `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`;

const CREDENTIALS_DIR = path.join(os.homedir(), ".the-dump");
const CREDENTIALS_FILE = path.join(CREDENTIALS_DIR, "credentials.json");

export interface StoredCredentials {
  email: string;
  idToken: string;
  refreshToken: string;
  expiresAt: number; // unix ms
}

interface FirebaseAuthResponse {
  idToken: string;
  refreshToken: string;
  expiresIn: string;
  email: string;
  localId: string;
}

interface FirebaseErrorResponse {
  error: { message: string; code: number };
}

export class FirebaseAuth implements AuthStrategy {
  private credentials: StoredCredentials | null = null;
  private refreshInFlight: Promise<void> | null = null;
  readonly unauthorizedMessage = "Session expired. Please log in again using the login tool.";

  constructor() {
    this.loadCredentials();
  }

  get email(): string | null {
    return this.credentials?.email ?? null;
  }

  get isLoggedIn(): boolean {
    return this.credentials !== null;
  }

  private loadCredentials(): void {
    try {
      if (fs.existsSync(CREDENTIALS_FILE)) {
        const data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8"));
        // A wrong-shape file would otherwise send "Bearer undefined" to the API
        if (
          data &&
          typeof data.email === "string" &&
          typeof data.idToken === "string" &&
          typeof data.refreshToken === "string" &&
          typeof data.expiresAt === "number"
        ) {
          this.credentials = data;
        } else {
          this.credentials = null;
        }
      }
    } catch {
      this.credentials = null;
    }
  }

  saveCredentials(creds: StoredCredentials): void {
    if (!fs.existsSync(CREDENTIALS_DIR)) {
      fs.mkdirSync(CREDENTIALS_DIR, { mode: 0o700 });
    }
    fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(creds, null, 2), {
      mode: 0o600,
    });
    // writeFileSync's mode only applies at creation; tighten pre-existing files too
    fs.chmodSync(CREDENTIALS_FILE, 0o600);
    this.credentials = creds;
  }

  clearCredentials(): void {
    this.credentials = null;
    try {
      if (fs.existsSync(CREDENTIALS_FILE)) {
        fs.unlinkSync(CREDENTIALS_FILE);
      }
    } catch {
      // ignore
    }
  }

  async signIn(email: string, password: string): Promise<StoredCredentials> {
    const res = await safeFetch(
      FIREBASE_SIGN_IN_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      },
      "The Dump's sign-in service"
    );

    const body = await readJson(res, "The Dump's sign-in service");

    if (!res.ok) {
      const err = body as FirebaseErrorResponse;
      const msg = err.error?.message ?? "Unknown error";
      const friendly: Record<string, string> = {
        EMAIL_NOT_FOUND: "No account found with that email.",
        INVALID_PASSWORD: "Incorrect password.",
        USER_DISABLED: "This account has been disabled.",
        INVALID_LOGIN_CREDENTIALS: "Invalid email or password.",
        TOO_MANY_ATTEMPTS_TRY_LATER: "Too many failed attempts. Please try again later.",
      };
      throw new Error(friendly[msg] ?? `Login failed: ${msg}`);
    }

    const auth = body as FirebaseAuthResponse;
    const creds = {
      email: auth.email,
      idToken: auth.idToken,
      refreshToken: auth.refreshToken,
      expiresAt: Date.now() + parseInt(auth.expiresIn) * 1000,
    };
    this.saveCredentials(creds);
    return creds;
  }

  async signUp(email: string, password: string): Promise<StoredCredentials> {
    const res = await safeFetch(
      FIREBASE_SIGN_UP_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      },
      "The Dump's sign-up service"
    );

    const body = await readJson(res, "The Dump's sign-up service");

    if (!res.ok) {
      const err = body as FirebaseErrorResponse;
      const msg = err.error?.message ?? "Unknown error";
      const friendly: Record<string, string> = {
        EMAIL_EXISTS: "An account with that email already exists. Use the login tool instead.",
        WEAK_PASSWORD: "Password is too weak. Please use at least 6 characters.",
        INVALID_EMAIL: "Invalid email address.",
        TOO_MANY_ATTEMPTS_TRY_LATER: "Too many attempts. Please try again later.",
      };
      throw new Error(friendly[msg] ?? `Sign-up failed: ${msg}`);
    }

    const auth = body as FirebaseAuthResponse;
    const creds = {
      email: auth.email,
      idToken: auth.idToken,
      refreshToken: auth.refreshToken,
      expiresAt: Date.now() + parseInt(auth.expiresIn) * 1000,
    };
    this.saveCredentials(creds);
    return creds;
  }

  /** Single-flight: concurrent callers share one refresh request. */
  private refreshIdToken(): Promise<void> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.doRefreshIdToken().finally(() => {
        this.refreshInFlight = null;
      });
    }
    return this.refreshInFlight;
  }

  private async doRefreshIdToken(): Promise<void> {
    if (!this.credentials) {
      throw new Error("Not logged in. Please use the login tool first.");
    }

    // safeFetch throws on network failure WITHOUT clearing credentials —
    // a connectivity blip must not log the user out
    const res = await safeFetch(
      FIREBASE_REFRESH_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: this.credentials.refreshToken,
        }).toString(),
      },
      "The Dump's sign-in service"
    );

    if (!res.ok) {
      this.clearCredentials();
      throw new Error("Session expired. Please log in again using the login tool.");
    }

    const body = await readJson(res, "The Dump's sign-in service");

    if (typeof body.id_token !== "string" || typeof body.refresh_token !== "string") {
      // Unexpected 200 — don't clear what may still be valid credentials
      throw new Error(
        "The Dump's sign-in service returned an unexpected response. Please try again."
      );
    }

    this.saveCredentials({
      email: this.credentials.email,
      idToken: body.id_token,
      refreshToken: body.refresh_token,
      expiresAt: Date.now() + parseInt(body.expires_in) * 1000,
    });
  }

  private async getValidToken(): Promise<string> {
    if (!this.credentials) {
      throw new Error(
        "Not logged in. Please use the login tool first to authenticate with The Dump."
      );
    }
    // Refresh if token expires within 5 minutes
    if (Date.now() > this.credentials.expiresAt - 5 * 60 * 1000) {
      await this.refreshIdToken();
    }
    return this.credentials!.idToken;
  }

  async apply(init: RequestInit, _attempt: number): Promise<RequestInit> {
    const token = await this.getValidToken();
    return {
      ...init,
      headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}` },
    };
  }

  /** A 401 may mean the token was revoked — refresh once and let the caller retry once. */
  async onUnauthorized(): Promise<boolean> {
    await this.refreshIdToken(); // throws the right message itself on a real rejection
    return true;
  }
}
