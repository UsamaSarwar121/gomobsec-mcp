# GoMobSec MCP server

<!-- mcp-name: io.github.UsamaSarwar121/gomobsec-mcp -->

The official [Model Context Protocol](https://modelcontextprotocol.io) server for
[GoMobSec](https://gomobsec.ai). Use it to scan Android and iOS apps for security
issues from Claude, Cursor, VS Code or any other MCP client. Results are mapped to
OWASP MASVS, CWE and CVSS, and you can download the full pentest-style report.

```text
You: Scan ./build/app-release.apk and tell me what to fix first.
AI:  start_scan → wait_for_scan → get_findings → a prioritised fix plan
```

## Use it in Claude without installing anything

GoMobSec also runs this server for you at **`https://mcp.gomobsec.ai/mcp`**. In
Claude, go to **Settings → Connectors → Add custom connector**, enter that URL,
and sign in with your GoMobSec account (Professional and Enterprise plans). Setup,
tools, security and privacy are covered in [docs/HOSTED.md](docs/HOSTED.md).

The rest of this page is about the **local** server, which reads apps straight
from your disk and authenticates with an API key.

## Requirements

- A GoMobSec account with an **API key**. Create one under **API keys** in GoMobSec.
  API keys come with the Professional and Enterprise plans.
- [`uv`](https://docs.astral.sh/uv/) (recommended) or Python 3.10+.

## Install

The server runs locally over stdio. Your API key stays on your machine, and the
server reads the APK or IPA straight from disk.

### Claude Code

```bash
claude mcp add gomobsec --env GOMOBSEC_API_KEY=your-key -- uvx gomobsec-mcp
```

### Claude Desktop, Cursor, Windsurf and others

Add this to the client's MCP config file. For Claude Desktop that is
`claude_desktop_config.json`; for Cursor it is `~/.cursor/mcp.json`.

```json
{
  "mcpServers": {
    "gomobsec": {
      "command": "uvx",
      "args": ["gomobsec-mcp"],
      "env": { "GOMOBSEC_API_KEY": "your-key" }
    }
  }
}
```

### VS Code

Add this to `.vscode/mcp.json`. VS Code asks for the key on first use and
stores it securely:

```json
{
  "inputs": [
    { "type": "promptString", "id": "gomobsec-key", "description": "GoMobSec API key", "password": true }
  ],
  "servers": {
    "gomobsec": {
      "command": "uvx",
      "args": ["gomobsec-mcp"],
      "env": { "GOMOBSEC_API_KEY": "${input:gomobsec-key}" }
    }
  }
}
```

Without `uv`, run `pip install gomobsec-mcp` and use `gomobsec-mcp` as the command.

## Tools

| Tool | What it does |
|---|---|
| `whoami` | The account and plan the key belongs to |
| `get_usage` | Scans used this month against the plan limit |
| `list_scans` | Recent scans, newest first |
| `get_scan` | Status of one scan and, once it is complete, the findings count by severity |
| `get_findings` | Findings with severity, CWE, MASVS category, CVSS, location and description. Can filter by severity; false positives are hidden unless asked for |
| `start_scan` | Uploads a local `.apk`, `.xapk`, `.apks`, `.apkm` or `.ipa` file and starts a scan (`quick`, `static` or `full`) |
| `wait_for_scan` | Waits for a scan to finish and reports progress meanwhile |
| `download_report` | Saves the DOCX, XLSX, JSON or SARIF report to your download folder |

There is also one prompt, **`security_review`**, which turns a finished scan into
a prioritised fix plan.

Scans you start here count against your GoMobSec plan, exactly like scans from
the web app or CI. The scan modes and limits are the ones your plan allows.

## Configuration

| Variable | Default | |
|---|---|---|
| `GOMOBSEC_API_KEY` | — | **Required.** Your GoMobSec API key |
| `GOMOBSEC_DOWNLOAD_DIR` | `~/Downloads/gomobsec` | The only folder `download_report` writes to |
| `GOMOBSEC_API_URL` | `https://api.gomobsec.ai` | Change this only for a dedicated or on-prem GoMobSec |
| `GOMOBSEC_APP_URL` | `https://gomobsec.ai` | Base URL for the report links |

## Security

- **Your key stays local.** It is read from the environment and only ever sent to
  GoMobSec over HTTPS. It is never written to a file or included in tool output.
- **Uploads are limited to app packages.** `start_scan` only sends files that are
  mobile app packages: the right extension, a zip archive, and at most 250 MB.
  It cannot be used to upload any other file from your machine.
- **Downloads never overwrite.** `download_report` takes no path. It writes new
  files (mode `0600`) into `GOMOBSEC_DOWNLOAD_DIR` and never replaces an
  existing file.
- **Finding text is treated as untrusted.** Titles and descriptions can contain
  strings from the scanned app, and an app author controls those. The server
  strips control and bidi characters, keeps the text inside a fenced data block,
  and tells the model to treat it as data. Still, review what your assistant
  does after reading the results of a scan of an app you don't trust.
- **Access is limited to your own scans.** The key only sees scans on its own
  account or organisation. Revoke it in GoMobSec at any time.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Privacy

The local server keeps nothing. It reads your API key from the environment,
sends requests only to GoMobSec, and writes only the reports you ask for. What
GoMobSec does with the apps you scan is in the
[GoMobSec privacy policy](https://gomobsec.ai/privacy). For the hosted connector,
see [its privacy policy](https://gomobsec.ai/mcp/privacy).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest
```

Try it with the MCP Inspector: `npx @modelcontextprotocol/inspector gomobsec-mcp`.

The hosted connector's tests (`tests/test_hosted.py`) run a real HTTP server on a
free port and go through the whole OAuth flow, with GoMobSec's side faked.

### Releasing

1. Bump the version in `src/gomobsec_mcp/__init__.py` **and** both `version` fields
   in `server.json` (the tests and the release workflow check they match), and
   add a `CHANGELOG.md` entry.
2. Publish a GitHub release tagged `vX.Y.Z`. The `Publish` workflow tests and
   builds it, uploads it to PyPI (Trusted Publishing), then lists it in the MCP
   Registry (GitHub OIDC). No tokens are stored in the repository.

## License

MIT
