# Changelog

## 0.2.0 — 2026-10-31

- **Hosted connector.** `gomobsec-mcp-hosted` (`pip install "gomobsec-mcp[hosted]"`)
  serves the same tools over Streamable HTTP with OAuth 2.1, for Claude's custom
  connectors and the Connectors Directory. It runs at `https://mcp.gomobsec.ai/mcp`
  ([docs/HOSTED.md](docs/HOSTED.md)). It supports Client ID Metadata Documents and
  Dynamic Client Registration, PKCE, resource-bound rotating tokens, and sign-in
  through GoMobSec's consent page. It is available on Professional and Enterprise plans.
- Hosted tools that can't touch the user's disk: `start_scan` takes an https
  `file_url` (fetched only from public addresses), and `get_upload_link` and
  `get_report_link` link to the web app. `wait_for_scan` waits up to 4 minutes per call.
- Local server: unchanged tools and behaviour. `whoami` says "connected account"
  rather than "API key".

## 0.1.1 — 2026-11-01

- `get_findings` without a severity filter now always lists the most severe findings first.
  The API applies its limit before sorting, so a small page could miss a CRITICAL finding.
  Hidden false positives no longer use up the limit.
- Request logging from httpx is quiet unless something goes wrong.

## 0.1.0 — 2026-11-01

First release: `whoami`, `get_usage`, `list_scans`, `get_scan`, `get_findings`,
`start_scan`, `wait_for_scan`, `download_report` and the `security_review`
prompt. Local stdio server authenticated with a GoMobSec API key.
