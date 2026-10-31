"""A fake GoMobSec API (``/api/v1``) for the tests. No network, no real account."""

from __future__ import annotations

import uuid

import httpx

KEY = "mbsk_test_key_0123456789abcdef"
APK = b"PK\x03\x04" + b"\x00" * 4096


class FakeApi:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.scans: dict[str, dict] = {}
        self.findings: dict[str, list[dict]] = {}
        self.submit_error: tuple[int, object] | None = None
        self.status_sequence: list[str] = []
        self.tier = "professional"
        self.key = KEY

    def add_scan(self, status="COMPLETED", package="com.example.bank") -> str:
        sid = str(uuid.uuid4())
        self.scans[sid] = {
            "scan_id": sid, "status": status, "progress": 100, "findings_count": 3, "critical_count": 1,
            "high_count": 1, "medium_count": 1, "low_count": 0, "created_at": "2026-10-30T10:00:00+00:00",
            "completed_at": "2026-10-30T10:20:00+00:00" if status == "COMPLETED" else None,
            "error_message": None, "package_name": package, "platform": "Android",
        }
        return sid

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("X-API-Key") != self.key:
            return httpx.Response(401, json={"detail": "Invalid API key"})
        path, method = request.url.path, request.method
        if path == "/api/v1/me":
            return httpx.Response(200, json={"user_id": "u", "username": "sam", "tier": self.tier,
                                             "is_paid": self.tier != "free"})
        if path == "/api/v1/usage":
            return httpx.Response(200, json={"total_scans": 12, "scans_this_month": 3, "scan_limit": 50})
        if path == "/api/v1/scans" and method == "GET":
            return httpx.Response(200, json={"scans": list(self.scans.values())[: int(request.url.params["limit"])]})
        if path == "/api/v1/scans" and method == "POST":
            if self.submit_error:
                code, body = self.submit_error
                return httpx.Response(code, json=body)
            sid = self.add_scan("PENDING")
            return httpx.Response(200, json={"scan_id": sid, "status": "PENDING", "message": "ok"})
        parts = path.split("/")
        sid = parts[4] if len(parts) > 4 else ""
        if sid not in self.scans:
            return httpx.Response(404, json={"detail": "Scan not found"})
        if len(parts) == 5:
            if self.status_sequence:
                self.scans[sid]["status"] = self.status_sequence.pop(0)
            return httpx.Response(200, json=self.scans[sid])
        if parts[5] == "findings":
            rows = self.findings.get(sid, [])
            if "severity" in request.url.params:
                rows = [r for r in rows if r["severity"] == request.url.params["severity"]]
            return httpx.Response(200, json={"scan_id": sid, "total": len(rows), "findings": rows})
        if parts[5] == "report":
            fmt = request.url.params["format"]
            return httpx.Response(200, content=f"report-{fmt}".encode())
        return httpx.Response(404, json={"detail": "nope"})
