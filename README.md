# The Dump MCP Server

An MCP (Model Context Protocol) server that lets LLM clients (Claude Desktop, Claude Code, Cursor, etc.) save conversations directly to [The Dump](https://thedump.ai) — and read your saved notes back as context, so your assistant can answer questions about them.

Full setup guide: https://thedump.ai/mcp

## Quick start (npm)

No install step needed — point your MCP client at `npx`:

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "the-dump": {
      "command": "npx",
      "args": ["-y", "the-dump-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add the-dump -- npx -y the-dump-mcp
```

### Cursor

Add the same JSON block as Claude Desktop to `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally.

## Running from source (alternative)

```bash
git clone https://github.com/George-Labs-AI/The_Dump_MCP.git
cd The_Dump_MCP
npm install
npm run build
```

Then use `"command": "node", "args": ["/absolute/path/to/The_Dump_MCP/dist/index.js"]` in the configs above (or `claude mcp add the-dump -- node /absolute/path/to/The_Dump_MCP/dist/index.js`).

## Authentication

No tokens or environment variables needed. Once the server is connected, tell your assistant to "log in to The Dump" — it will use the `login` tool with your Dump email and password. Credentials are stored locally in `~/.the-dump/credentials.json` (mode 0600) and refresh automatically; use the `logout` tool to clear them.

| Variable | Required | Description |
|----------|----------|-------------|
| `THE_DUMP_API_URL` | No | Backend ingest URL override (defaults to production) |
| `THE_DUMP_BASE_URL` | No | Base URL for read endpoints (defaults to the ingest URL's origin) |

## Tools

### Saving

| Tool | Description |
|------|-------------|
| `share_conversation` | Save a full conversation (all messages) |
| `summarize_conversation` | Save an AI-generated summary |
| `send_initial_prompt` | Save just the opening prompt |
| `conversation_link_and_title` | Bookmark a conversation with link + title |
| `share_selection` | Save a highlighted portion of a conversation |
| `share_response` | Save a specific assistant response |
| `create_note` | Create a note from plain text, a local file, or a file URL — saved as-is, like an iOS capture |

The `share_*` tools save a conversation transcript (with role labels and a
"Saved from …" provenance line). `create_note` is different: it saves content
exactly as given, with no conversation framing, and can attach a file — so a
grocery list, a draft, an HTML artifact, or a photo lands in The Dump the same
way it would from the iOS app. Pass exactly one of `content`, `file_path`
(absolute or `~/…` on this machine), or `file_url` (public http/https link).
Images are described and OCR'd, audio is transcribed, and documents are
parsed, then The Dump chooses the category, title, and type. Supported types:
jpg/png/gif/bmp/webp/heic/tiff, pdf/doc/docx/txt/md/html/json/xml/csv, and
mp3/wav/flac/m4a/aac/ogg/webm/opus, up to 100 MB. For a text note, `title` is
prepended as a heading; `filename` sets the extension (e.g. `report.html`).

### Reading your notes

| Tool | Description |
|------|-------------|
| `list_categories` | List your note categories and sub-categories |
| `list_notes` | Browse or search your notes (semantic search + filters; returns previews) |
| `get_notes` | Fetch the full content of specific notes by ID (max 50 per call) |

Ask things like *"summarize my notes in the Recipes category from last month"* — your assistant will translate that into the right search and filters. You can only ever read notes belonging to the account you're logged in as; the server derives your identity from your auth token, never from request parameters.

### Routines (read-only)

Routines are long-running processes that maintain living "canon" documents (e.g. a project dashboard or plan) from your notes, and queue judgment calls as approval requests (ASKs).

| Tool | Description |
|------|-------------|
| `list_routines` | List your routines, their canon documents, and open approval-request counts |
| `get_routine_document` | Read the full text of one canon document |
| `list_asks` | List a routine's approval requests (ASKs) and their status |

Ask things like *"what does my renovation plan say about the septic system?"* — your assistant will find the right routine and read its canon docs. These tools are strictly read-only: canon documents are written only by the routine's runner, and approval requests are answered in The Dump's web UI.

Very large canon documents are returned as a short preview by default; your assistant will ask you before loading the whole thing into the conversation (some canon docs are hundreds of thousands of characters).

**A note on agent safety:** retrieved notes are returned clearly framed as data, with instructions to the model not to treat note content as commands. Still, notes can contain text you saved from elsewhere (web clippings, OCR'd images, shared conversations). If you run an agent with broad, auto-approved permissions over your notes, you are trusting everything you've ever saved — keep permission prompts on when in doubt. The same applies to `create_note` with `file_path`: it uploads any file the assistant can read on this machine into your own account, so keep the permission prompt on for it.

### Account

| Tool | Description |
|------|-------------|
| `login` | Log in with your Dump email and password |
| `signup` | Create a new account (14-day free trial) |
| `logout` | Log out and clear saved credentials |
