# The Dump MCP Server

An MCP (Model Context Protocol) server that lets LLM clients (Claude Desktop, Cursor, etc.) save conversations directly to The Dump.

## Setup

```bash
npm install
npm run build
```

## Configuration

Set these environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `THE_DUMP_TOKEN` | Yes | Firebase ID token for authentication |
| `THE_DUMP_API_URL` | No | Backend ingest URL (defaults to production) |

## Adding to an MCP client

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "the-dump": {
      "command": "node",
      "args": ["/absolute/path/to/The_Dump_MCP/dist/index.js"],
      "env": {
        "THE_DUMP_TOKEN": "your-firebase-id-token"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "the-dump": {
      "command": "node",
      "args": ["/absolute/path/to/The_Dump_MCP/dist/index.js"],
      "env": {
        "THE_DUMP_TOKEN": "your-firebase-id-token"
      }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `share_conversation` | Save a full conversation (all messages) |
| `summarize_conversation` | Save an AI-generated summary |
| `send_initial_prompt` | Save just the opening prompt |
| `conversation_link_and_title` | Bookmark a conversation with link + title |
| `share_selection` | Save a highlighted portion of a conversation |
| `share_response` | Save a specific assistant response |
