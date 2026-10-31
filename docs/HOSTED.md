# GoMobSec connector for Claude (hosted MCP server)

GoMobSec runs this server at **`https://mcp.gomobsec.ai/mcp`**. Add it to Claude
or to any MCP client that supports remote servers with OAuth, sign in with your
GoMobSec account, and you can scan Android and iOS apps and review the findings
without leaving the conversation. You don't need an API key or a local install.

> The local `gomobsec-mcp` package (stdio, API key) is still there and works as
> before; see the [README](../README.md). Both serve the same tools from the same
> code.

## Who can use it

GoMobSec **Professional** and **Enterprise** plans include API access, and the
connector is part of that. If your account is on another plan, the sign-in page
offers an upgrade. A tool call made after your plan has lapsed returns an
"upgrade" message instead of a result.

## Connect

### Claude (claude.ai, Desktop, mobile)

1. Go to **Settings → Connectors → Add custom connector**.
2. Name it `GoMobSec` and enter the URL `https://mcp.gomobsec.ai/mcp`. Leave the
   advanced OAuth fields empty.
3. Click **Connect**. Sign in to GoMobSec (password or SSO), check that the page
   says *Claude* and *claude.ai*, then click **Approve**.

On Team and Enterprise plans, an Owner adds the connector for the organisation
first. Each member then connects their own GoMobSec account.

### Claude Code

```bash
claude mcp add --transport http gomobsec https://mcp.gomobsec.ai/mcp
```

Then run `/mcp` in Claude Code and choose **Authenticate** for `gomobsec`.

### Other MCP clients

Point the client at `https://mcp.gomobsec.ai/mcp`. It discovers the rest from
the server's OAuth metadata (see [How sign-in works](#how-sign-in-works)).

### Disconnect

Remove the connector in your client, or revoke its **"MCP connector: …"** key
under **API keys** in GoMobSec. Either one ends the connection.

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `whoami` | read-only | The connected account and its plan |
| `get_usage` | read-only | Scans used this month against the plan limit |
| `list_scans` | read-only | Recent scans, newest first |
| `get_scan` | read-only | Status of one scan, and its findings by severity once it completes |
| `get_findings` | read-only | Findings with severity, CWE, MASVS, CVSS, location and description, most severe first |
| `wait_for_scan` | read-only | Waits up to 4 minutes for a scan to finish, reporting progress (call again for longer) |
| `get_upload_link` | read-only | Link to upload an `.apk`/`.ipa` from your computer in GoMobSec |
| `get_report_link` | read-only | Link to the full report (DOCX pentest report, XLSX, JSON, SARIF) |
| `start_scan` | **write** | Downloads an app from a public **https** link (such as a CI artifact or release asset) and starts a scan. Uses one scan from your plan |

There is also one prompt, `security_review`, which turns a finished scan into a
prioritised fix plan.

A hosted server can't read files on your computer. So `start_scan` takes a link
instead of a path, and reports open in the web app instead of being saved to
disk. For a local file, ask for an upload link, upload it in GoMobSec, and then
let Claude follow the scan.

Every tool has a title and a read-only or write annotation, so Claude can run the
read-only tools without asking and asks you before `start_scan`.

### Try it

- *"Which of my GoMobSec scans have critical findings? Summarise the worst one."*
- *"Scan https://github.com/acme/app/releases/download/v2.3.0/app-release.apk and tell me what to fix first."*
- *"Give me a prioritised fix plan for my latest iOS scan, with code-level changes, and link the full report."*

## How sign-in works

The server is both the OAuth 2.1 **authorization server** and the **resource
server**. GoMobSec itself only shows the consent page.

```
Claude ──► POST /mcp                       401 + WWW-Authenticate: resource_metadata=…
       ──► /.well-known/oauth-protected-resource/mcp   (RFC 9728)
       ──► /.well-known/oauth-authorization-server     (RFC 8414)
       ──► client_id = its metadata-document URL (CIMD), or POST /register (DCR)
browser ─► /authorize (PKCE S256, resource=https://mcp.gomobsec.ai/mcp)
        ─► /oauth/consent      binds this sign-in to the browser (cookie)
        ─► gomobsec.ai/integrations/mcp/approve   sign in, plan check, Approve
              GoMobSec mints an API key for this connection only
        ─► /oauth/callback     cookie + one-time nonce → claim the key once
        ─► https://claude.ai/api/mcp/auth_callback?code=…&state=…&iss=…
Claude ──► POST /token (code + PKCE verifier)   → access token (1 h) + refresh token (30 d, rotating)
       ──► POST /mcp  Authorization: Bearer …   → tools run as you, with your connection's key
```

What it implements from the MCP authorization spec (2026-07-28) and Claude's
connector requirements:

- Protected Resource Metadata, and a `401` with `resource_metadata` on every unauthenticated request.
- Authorization Server Metadata advertising `client_id_metadata_document_supported`,
  `token_endpoint_auth_methods_supported: ["none", …]` and `code_challenge_methods_supported: ["S256"]`.
- **Client ID Metadata Documents** (preferred), fetched over https from public
  addresses only and cached for an hour. **Dynamic Client Registration** remains
  available for clients without CIMD.
- PKCE S256 on every authorization, and `iss` in every authorization response (RFC 9207).
- Resource indicators (RFC 8707). Tokens are bound to `https://mcp.gomobsec.ai/mcp`,
  and a request for any other resource gets `invalid_target`.
- Redirect URIs must be https or loopback. Loopback URIs match on any port
  (RFC 8252 §7.3), which Claude Code needs.
- Refresh tokens rotate on every use. Replaying an old one after a 60-second
  grace period revokes the whole connection. Expired refresh tokens return
  `invalid_grant`.
- Token revocation (RFC 7009), including for public clients.
- `Origin` validation on `/mcp` (claude.ai and claude.com are allowed; requests
  without an Origin header pass), plus `Host` validation against DNS rebinding.

## Security model

- **No token passthrough.** The tokens Claude holds are valid only at this server.
  They are never sent to GoMobSec. Tool calls reach the GoMobSec API with the
  per-connection key, so they see exactly what your account sees.
- **Your approval, in GoMobSec.** Every connection is approved by you, signed in
  to GoMobSec. The consent page shows the app's name and the address it returns
  to. To finish, the sign-in needs both the cookie from the browser that started
  it and a nonce that GoMobSec gives only to the browser that approved it. A
  consent link sent to someone else can't be completed by the sender.
- **Nothing readable at rest.** Tokens are stored as SHA-256 hashes. Each
  connection's GoMobSec key is sealed with AES-256-GCM, bound to that connection.
- **Links to scan can't reach inside.** `start_scan` fetches only https on port
  443, from hosts whose addresses are **all** public. It connects to the address
  it checked, so a DNS answer that changes in between can't redirect it. It
  re-checks every redirect, stops at 250 MB, and accepts only zip-format app
  packages.
- **Finding text is untrusted.** Text from the scanned app is sanitised and
  fenced as data, the same as in the local server.

Report vulnerabilities to security@gomobsec.ai ([SECURITY.md](../SECURITY.md)).

## Privacy

The privacy policy for the connector is at **https://gomobsec.ai/mcp/privacy**.
In short:

- **What it keeps:** for each connection, your user ID and username, the sealed
  key, the app's registration (name and return addresses) and hashed tokens.
  While a sign-in is in progress, it also keeps one-off codes for up to ten
  minutes.
- **What it never receives:** your conversations, the client's memory or your
  files. It sees only the tool calls and their arguments, and it keeps none of
  those after answering.
- **Apps passed by link:** downloaded to a private temporary file, sent to
  GoMobSec under your account, and deleted straight away. After that, the main
  [GoMobSec privacy policy](https://gomobsec.ai/privacy) applies.
- **Retention:** access tokens last 1 hour. A connection unused for 30 days is
  deleted. Disconnecting in the client, or revoking the key in GoMobSec, ends it
  sooner.
- **Use:** only to run the connector. It is not sold, not used for advertising
  and not used for training.

## Running it

`gomobsec-mcp-hosted` (`pip install "gomobsec-mcp[hosted]"`) serves the connector
on `0.0.0.0:8080` by default. Put TLS in front of it.

| Variable | |
|---|---|
| `GOMOBSEC_MCP_PUBLIC_URL` | **Required.** The public https origin, e.g. `https://mcp.gomobsec.ai`. It is also the OAuth issuer |
| `GOMOBSEC_MCP_SERVICE_TOKEN` | **Required.** At least 32 characters, shared with the platform (`MCP_CONNECTOR_SERVICE_TOKEN`) |
| `GOMOBSEC_MCP_ENCRYPTION_KEY` | **Required.** 32 random bytes, urlsafe-base64. Seals the stored keys; changing it disconnects everyone |
| `GOMOBSEC_MCP_REDIS_URL` | **Required.** A Redis that does **not** evict (`maxmemory-policy noeviction`) and persists (AOF) |
| `GOMOBSEC_API_URL` | Where the server reaches the GoMobSec API (default `https://api.gomobsec.ai`) |
| `GOMOBSEC_APP_URL` | The web app, for links (default `https://gomobsec.ai`) |
| `GOMOBSEC_MCP_ALLOWED_ORIGINS` | Extra browser origins allowed on `/mcp`, comma-separated |
| `GOMOBSEC_MCP_HOST` / `GOMOBSEC_MCP_PORT` | Listen address (default `0.0.0.0:8080`) |

The server refuses to start if a required setting is missing or malformed. It
answers `GET /healthz` with `{"ok": true}` when Redis is reachable.

GoMobSec's own deployment (compose service, host nginx and runbook) lives with the
platform, in `mobsecai-backend/docs/MCP_CONNECTOR.md`.
