#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
// ── Configuration ──────────────────────────────────────────────────────────────
const FIREBASE_API_KEY = "AIzaSyDNqivcHgxiSgAfe289TqPD7e_gcP7z8dc";
const FIREBASE_SIGN_IN_URL = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`;
const FIREBASE_SIGN_UP_URL = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`;
const FIREBASE_REFRESH_URL = `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`;
const INGEST_URL = process.env.THE_DUMP_API_URL ?? "https://thedump.ai/api/ingest";
const CREDENTIALS_DIR = path.join(os.homedir(), ".the-dump");
const CREDENTIALS_FILE = path.join(CREDENTIALS_DIR, "credentials.json");
let credentials = null;
function loadCredentials() {
    try {
        if (fs.existsSync(CREDENTIALS_FILE)) {
            const data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8"));
            credentials = data;
        }
    }
    catch {
        credentials = null;
    }
}
function saveCredentials(creds) {
    if (!fs.existsSync(CREDENTIALS_DIR)) {
        fs.mkdirSync(CREDENTIALS_DIR, { mode: 0o700 });
    }
    fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(creds, null, 2), {
        mode: 0o600,
    });
    credentials = creds;
}
function clearCredentials() {
    credentials = null;
    try {
        if (fs.existsSync(CREDENTIALS_FILE)) {
            fs.unlinkSync(CREDENTIALS_FILE);
        }
    }
    catch {
        // ignore
    }
}
async function firebaseSignIn(email, password) {
    const res = await fetch(FIREBASE_SIGN_IN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
    });
    const body = await res.json();
    if (!res.ok) {
        const err = body;
        const msg = err.error?.message ?? "Unknown error";
        const friendly = {
            EMAIL_NOT_FOUND: "No account found with that email.",
            INVALID_PASSWORD: "Incorrect password.",
            USER_DISABLED: "This account has been disabled.",
            INVALID_LOGIN_CREDENTIALS: "Invalid email or password.",
            TOO_MANY_ATTEMPTS_TRY_LATER: "Too many failed attempts. Please try again later.",
        };
        throw new Error(friendly[msg] ?? `Login failed: ${msg}`);
    }
    const auth = body;
    return {
        email: auth.email,
        idToken: auth.idToken,
        refreshToken: auth.refreshToken,
        expiresAt: Date.now() + parseInt(auth.expiresIn) * 1000,
    };
}
async function firebaseSignUp(email, password) {
    const res = await fetch(FIREBASE_SIGN_UP_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
    });
    const body = await res.json();
    if (!res.ok) {
        const err = body;
        const msg = err.error?.message ?? "Unknown error";
        const friendly = {
            EMAIL_EXISTS: "An account with that email already exists. Use the login tool instead.",
            WEAK_PASSWORD: "Password is too weak. Please use at least 6 characters.",
            INVALID_EMAIL: "Invalid email address.",
            TOO_MANY_ATTEMPTS_TRY_LATER: "Too many attempts. Please try again later.",
        };
        throw new Error(friendly[msg] ?? `Sign-up failed: ${msg}`);
    }
    const auth = body;
    return {
        email: auth.email,
        idToken: auth.idToken,
        refreshToken: auth.refreshToken,
        expiresAt: Date.now() + parseInt(auth.expiresIn) * 1000,
    };
}
async function refreshIdToken() {
    if (!credentials) {
        throw new Error("Not logged in. Please use the login tool first.");
    }
    const res = await fetch(FIREBASE_REFRESH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=refresh_token&refresh_token=${credentials.refreshToken}`,
    });
    const body = await res.json();
    if (!res.ok) {
        clearCredentials();
        throw new Error("Session expired. Please log in again using the login tool.");
    }
    const updated = {
        email: credentials.email,
        idToken: body.id_token,
        refreshToken: body.refresh_token,
        expiresAt: Date.now() + parseInt(body.expires_in) * 1000,
    };
    saveCredentials(updated);
}
async function getValidToken() {
    if (!credentials) {
        throw new Error("Not logged in. Please use the login tool first to authenticate with The Dump.");
    }
    // Refresh if token expires within 5 minutes
    if (Date.now() > credentials.expiresAt - 5 * 60 * 1000) {
        await refreshIdToken();
    }
    return credentials.idToken;
}
// ── Shared schemas ─────────────────────────────────────────────────────────────
const messageSchema = z.object({
    role: z.string().describe("The role of the message sender (e.g. 'user', 'assistant')"),
    content: z.string().describe("The text content of the message"),
});
const metadataSchema = z
    .record(z.unknown())
    .optional()
    .describe("Optional metadata (model name, message count, timestamps, etc.)");
const sourceSchema = z
    .string()
    .min(1)
    .describe("LLM app identifier (e.g. 'claude', 'chatgpt', 'gemini')");
async function callIngest(payload) {
    const token = await getValidToken();
    const res = await fetch(INGEST_URL, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
    });
    const body = await res.text();
    if (res.status === 401) {
        // Token might have been revoked — try one refresh
        try {
            await refreshIdToken();
            const retryToken = credentials.idToken;
            const retry = await fetch(INGEST_URL, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${retryToken}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            });
            if (retry.ok) {
                const json = JSON.parse(await retry.text());
                return `Saved to The Dump!\nUUID: ${json.uuid}\nPath: ${json.gcs_path}`;
            }
        }
        catch {
            // refresh failed
        }
        clearCredentials();
        throw new Error("Session expired. Please log in again using the login tool.");
    }
    if (!res.ok) {
        const status = res.status;
        const messages = {
            400: "Bad request — check your input.",
            402: "No active subscription. Please subscribe at The Dump to continue.",
            429: "Monthly usage limit exceeded.",
            500: "Server error on The Dump backend.",
        };
        throw new Error(messages[status] ?? `Request failed (${status}): ${body}`);
    }
    const json = JSON.parse(body);
    return `Saved to The Dump!\nUUID: ${json.uuid}\nPath: ${json.gcs_path}`;
}
// ── Server setup ───────────────────────────────────────────────────────────────
const server = new McpServer({
    name: "the-dump",
    version: "1.0.0",
});
// Load any saved credentials on startup
loadCredentials();
// ── Auth tools ─────────────────────────────────────────────────────────────────
server.tool("login", "Log in to The Dump with your email and password", {
    email: z.string().email().describe("Your email address"),
    password: z.string().min(1).describe("Your password"),
}, async ({ email, password }) => {
    const creds = await firebaseSignIn(email, password);
    saveCredentials(creds);
    return {
        content: [
            {
                type: "text",
                text: `Logged in as ${creds.email}. Your session is saved and will auto-refresh — you won't need to log in again unless you explicitly log out.`,
            },
        ],
    };
});
server.tool("signup", "Create a new account on The Dump (includes a 14-day free trial)", {
    email: z.string().email().describe("Your email address"),
    password: z
        .string()
        .min(6)
        .describe("Choose a password (at least 6 characters)"),
}, async ({ email, password }) => {
    const creds = await firebaseSignUp(email, password);
    saveCredentials(creds);
    return {
        content: [
            {
                type: "text",
                text: `Account created and logged in as ${creds.email}. You have a 14-day free trial. Your session is saved and will auto-refresh.`,
            },
        ],
    };
});
server.tool("logout", "Log out of The Dump and clear saved credentials", {}, async () => {
    const wasLoggedIn = credentials !== null;
    clearCredentials();
    return {
        content: [
            {
                type: "text",
                text: wasLoggedIn
                    ? "Logged out and credentials cleared."
                    : "No active session to log out from.",
            },
        ],
    };
});
// ── Tool 1: share_conversation ─────────────────────────────────────────────────
server.tool("share_conversation", "Save a full LLM conversation (all messages) to The Dump", {
    source: sourceSchema,
    title: z.string().optional().describe("Optional title for the conversation"),
    messages: z.array(messageSchema).min(1).describe("The conversation messages"),
    summary: z.string().optional().describe("Optional summary"),
    url: z.string().optional().describe("Optional conversation URL"),
    metadata: metadataSchema,
}, async ({ source, title, messages, summary, url, metadata }) => {
    const result = await callIngest({
        source,
        command: "share_conversation",
        title,
        messages,
        summary,
        url,
        metadata,
    });
    return { content: [{ type: "text", text: result }] };
});
// ── Tool 2: summarize_conversation ─────────────────────────────────────────────
server.tool("summarize_conversation", "Save an AI-generated summary of a conversation to The Dump", {
    source: sourceSchema,
    title: z.string().optional().describe("Optional title"),
    summary: z.string().min(1).describe("The summary text"),
    url: z.string().optional().describe("Optional conversation URL"),
    metadata: metadataSchema,
}, async ({ source, title, summary, url, metadata }) => {
    const result = await callIngest({
        source,
        command: "summarize_conversation",
        title,
        summary,
        url,
        metadata,
    });
    return { content: [{ type: "text", text: result }] };
});
// ── Tool 3: send_initial_prompt ────────────────────────────────────────────────
server.tool("send_initial_prompt", "Save just the opening prompt from a conversation to The Dump", {
    source: sourceSchema,
    title: z.string().optional().describe("Optional title"),
    messages: z
        .array(messageSchema)
        .min(1)
        .describe("The conversation messages (only the first message will be used)"),
    summary: z.string().optional().describe("Optional summary"),
    url: z.string().optional().describe("Optional conversation URL"),
    metadata: metadataSchema,
}, async ({ source, title, messages, summary, url, metadata }) => {
    const result = await callIngest({
        source,
        command: "send_initial_prompt",
        title,
        messages,
        summary,
        url,
        metadata,
    });
    return { content: [{ type: "text", text: result }] };
});
// ── Tool 4: conversation_link_and_title ────────────────────────────────────────
server.tool("conversation_link_and_title", "Bookmark a conversation with its link and title in The Dump", {
    source: sourceSchema,
    title: z.string().min(1).describe("Title for the bookmarked conversation"),
    url: z.string().min(1).describe("URL of the conversation"),
    summary: z.string().optional().describe("Optional summary"),
    metadata: metadataSchema,
}, async ({ source, title, url, summary, metadata }) => {
    const result = await callIngest({
        source,
        command: "conversation_link_and_title",
        title,
        url,
        summary,
        metadata,
    });
    return { content: [{ type: "text", text: result }] };
});
// ── Tool 5: share_selection ────────────────────────────────────────────────────
server.tool("share_selection", "Save a highlighted/selected portion of a conversation to The Dump", {
    source: sourceSchema,
    title: z.string().optional().describe("Optional title"),
    messages: z
        .array(messageSchema)
        .min(1)
        .describe("The selected messages to save"),
    summary: z.string().optional().describe("Optional summary"),
    url: z.string().optional().describe("Optional conversation URL"),
    metadata: metadataSchema,
}, async ({ source, title, messages, summary, url, metadata }) => {
    const result = await callIngest({
        source,
        command: "share_selection",
        title,
        messages,
        summary,
        url,
        metadata,
    });
    return { content: [{ type: "text", text: result }] };
});
// ── Tool 6: share_response ─────────────────────────────────────────────────────
server.tool("share_response", "Save a specific assistant response to The Dump", {
    source: sourceSchema,
    title: z.string().optional().describe("Optional title"),
    messages: z
        .array(messageSchema)
        .min(1)
        .describe("The response message(s) to save"),
    summary: z.string().optional().describe("Optional summary"),
    url: z.string().optional().describe("Optional conversation URL"),
    metadata: metadataSchema,
}, async ({ source, title, messages, summary, url, metadata }) => {
    const result = await callIngest({
        source,
        command: "share_response",
        title,
        messages,
        summary,
        url,
        metadata,
    });
    return { content: [{ type: "text", text: result }] };
});
// ── Start ──────────────────────────────────────────────────────────────────────
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
