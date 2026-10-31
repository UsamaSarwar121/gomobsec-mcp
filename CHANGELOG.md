# Changelog

## 0.1.1 — 2026-11-01

- `get_findings` without a severity filter now always lists the most severe findings first.
  The API applies its limit before sorting, so a small page could miss a CRITICAL finding.
  Hidden false positives no longer use up the limit.
- Request logging from httpx is quiet unless something goes wrong.

## 0.1.0 — 2026-11-01

First release: `whoami`, `get_usage`, `list_scans`, `get_scan`, `get_findings`,
`start_scan`, `wait_for_scan`, `download_report` and the `security_review`
prompt. Local stdio server authenticated with a GoMobSec API key.
