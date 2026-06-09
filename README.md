# The Dump MCP Server

An MCP (Model Context Protocol) server that lets LLM clients (Claude Desktop, Claude Code, Cursor, etc.) save conversations directly to [The Dump](https://thedump.ai).

Full setup guide: https://thedump.ai/mcp

## Setup

```bash
git clone https://github.com/George-Labs-AI/The_Dump_MCP.git
cd The_Dump_MCP
npm install
npm run build
```

## Adding to an MCP client

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "the-dump": {
      "command": "node",
      "args": ["/absolute/path/to/The_Dump_MCP/dist/index.js"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add the-dump -- node /absolute/path/to/The_Dump_MCP/dist/index.js
```

### Cursor

Add the same JSON block as Claude Desktop to `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally.

## Authentication

No tokens or environment variables needed. Once the server is connected, tell your assistant to "log in to The Dump" — it will use the `login` tool with your Dump email and password. Credentials are stored locally in `~/.the-dump/credentials.json` (mode 0600) and refresh automatically; use the `logout` tool to clear them.

| Variable | Required | Description |
|----------|----------|-------------|
| `THE_DUMP_API_URL` | No | Backend ingest URL override (defaults to production) |

## Tools

| Tool | Description |
|------|-------------|
| `login` | Log in with your Dump email and password |
| `signup` | Create a new account (14-day free trial) |
| `logout` | Log out and clear saved credentials |
| `share_conversation` | Save a full conversation (all messages) |
| `summarize_conversation` | Save an AI-generated summary |
| `send_initial_prompt` | Save just the opening prompt |
| `conversation_link_and_title` | Bookmark a conversation with link + title |
| `share_selection` | Save a highlighted portion of a conversation |
| `share_response` | Save a specific assistant response |
