# Changelog

## 0.2.2 — 2026-11-14

- **The hosted connector now works on every plan, Free included.** Connecting is
  how most new accounts reach GoMobSec, and refusing a Free account on its first
  tool call turned people away before they had seen a single finding. What a plan
  allows is unchanged and is enforced by the platform per request — the monthly
  scan quota, the scan modes a tier may run, the paid report formats — so those
  limits now arrive as a clear error on the call that exceeds them.
- The connector asks the platform directly (`ai_connector` on `/api/v1/me`)
  instead of inferring the answer from `api_access`, which answers a different
  question: whether the account may mint a *general* REST API key. That is still
  a paid feature, and the **local** server, which uses such a key, still needs a
  paid plan. Against an older platform that does not send the new field, the
  connector falls back to the previous paid-tier rule.

## 0.2.1 — 2026-11-02

- Registry manifest now advertises the hosted connector (`remotes`:
  `https://mcp.gomobsec.ai/mcp`, Streamable HTTP), so the one-click connector is
  discoverable in the MCP registry and the directories that mirror it — not just
  the local pip package.
- Plan copy corrected throughout: the hosted connector and API keys are available
  on **every paid plan (Individual and up)**, not only Professional and Enterprise.

## 0.2.0 — 2026-10-31

- **Hosted connector.** `gomobsec-mcp-hosted` (`pip install "gomobsec-mcp[hosted]"`)
  serves the same tools over Streamable HTTP with OAuth 2.1, for Claude's custom
  connectors and the Connectors Directory. It runs at `https://mcp.gomobsec.ai/mcp`
  ([docs/HOSTED.md](docs/HOSTED.md)). It supports Client ID Metadata Documents and
  Dynamic Client Registration, PKCE, resource-bound rotating tokens, and sign-in
  through GoMobSec's consent page. It is available on every paid plan (Individual and up).
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
