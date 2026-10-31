"""The hosted GoMobSec connector: the same tools over Streamable HTTP with OAuth.

``gomobsec-mcp-hosted`` serves ``https://mcp.gomobsec.ai/mcp`` for Claude's
custom connectors and the Connectors Directory (and any other MCP client that
speaks OAuth 2.1). It is both the OAuth authorization server and the resource
server; GoMobSec itself only shows the consent page.

How a user connects:

1. Claude registers itself (Client ID Metadata Document, or Dynamic Client
   Registration) and sends the user's browser to ``/authorize`` with PKCE.
2. The connector opens a link request on the platform (service token) and
   sends the browser to GoMobSec's consent page, where the user signs in as
   usual (password or SSO). GoMobSec checks the plan (Professional or
   Enterprise) and, on approval, mints an API key for this connection only.
3. The browser comes back to ``/oauth/callback``; the connector claims that
   key once, seals it, and redirects to Claude with an authorization code.
4. Claude trades the code for this server's own access and refresh tokens.
   Those never leave this server: tool calls reach ``/api/v1`` with the
   user's connection key, as the user.

Revoking the "MCP connector" key in GoMobSec → API keys disconnects it.
See ``docs/HOSTED.md``.
"""
