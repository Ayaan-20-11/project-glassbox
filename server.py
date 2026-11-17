#!/usr/bin/env python3
"""Newton Dashboard Security Research Lab (Isolated Local Simulation).

Runs a self-contained HTTP server bound strictly to 127.0.0.1 using purely
synthetic accounts and simulated vulnerabilities for educational security
research. Never connects to external hosts or real student records.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


STATIC_DIR = Path(__file__).resolve().parent / "static"

ACTIVE_SESSION: dict[str, str] = {
    "session_id": "sim_sess_9f4a21c8",
    "student_id": "STU-1042",
    "name": "Aarav Sharma (Synthetic)",
    "role": "student",
    "cohort": "NST-SIM-2026-B1",
}

SYNTHETIC_STUDENTS: dict[str, dict[str, Any]] = {
    "STU-1042": {
        "student_id": "STU-1042",
        "name": "Aarav Sharma (Synthetic)",
        "cohort": "NST-SIM-2026-B1",
        "email": "aarav.sim1042@lab.local",
        "overall_pct": 75.74,
        "attended": 128,
        "counted_total": 169,
        "scheduled_total": 189,
        "subjects": [
            {"code": "CS201", "name": "Data Structures", "attended": 42, "total": 52, "unmarked": 4},
            {"code": "CS204", "name": "Operating Systems", "attended": 38, "total": 49, "unmarked": 5},
            {"code": "ENG102", "name": "English Communication", "attended": 26, "total": 36, "unmarked": 3},
            {"code": "YOGA-B1", "name": "Yoga & Wellness B1", "attended": 22, "total": 32, "unmarked": 8},
        ],
    },
    "STU-1099": {
        "student_id": "STU-1099",
        "name": "Diya Verma (Synthetic Peer)",
        "cohort": "NST-SIM-2026-B1",
        "email": "diya.sim1099@lab.local",
        "overall_pct": 88.10,
        "attended": 148,
        "counted_total": 168,
        "scheduled_total": 189,
        "subjects": [
            {"code": "CS201", "name": "Data Structures", "attended": 48, "total": 52, "unmarked": 4},
            {"code": "CS204", "name": "Operating Systems", "attended": 44, "total": 49, "unmarked": 5},
            {"code": "ENG102", "name": "English Communication", "attended": 31, "total": 36, "unmarked": 3},
            {"code": "YOGA-B1", "name": "Yoga & Wellness B1", "attended": 25, "total": 31, "unmarked": 9},
        ],
    },
    "STU-1108": {
        "student_id": "STU-1108",
        "name": "Rohan Nair (Synthetic Peer)",
        "cohort": "NST-SIM-2026-B2",
        "email": "rohan.sim1108@lab.local",
        "overall_pct": 64.50,
        "attended": 109,
        "counted_total": 169,
        "scheduled_total": 189,
        "subjects": [
            {"code": "CS201", "name": "Data Structures", "attended": 35, "total": 52, "unmarked": 4},
            {"code": "CS204", "name": "Operating Systems", "attended": 31, "total": 49, "unmarked": 5},
            {"code": "ENG102", "name": "English Communication", "attended": 24, "total": 36, "unmarked": 3},
            {"code": "YOGA-B1", "name": "Yoga & Wellness B1", "attended": 19, "total": 32, "unmarked": 8},
        ],
    },
}


def build_findings(mode: str) -> list[dict[str, Any]]:
    """Return simulated vulnerability findings calibrated to the selected lab mode."""
    is_vuln = mode != "secure"
    return [
        {
            "id": "SIM-001",
            "title": "Reflected Cross-Site Scripting (XSS) in Course Search Preview",
            "severity": "High" if is_vuln else "Info",
            "status": "Open (Simulated)" if is_vuln else "Remediated",
            "cwe": "CWE-79",
            "component": "GET /lab/xss-preview?q=...",
            "description": (
                "Untrusted query parameter 'q' is interpolated directly into HTML without context-aware "
                "encoding or strict Content-Security-Policy."
                if is_vuln
                else "Query parameter 'q' is HTML-escaped on the server, rendered via textContent, and guarded by strict CSP."
            ),
            "remediation": "Encode output with html.escape() / textContent and enforce script-src 'self' with object-src 'none'.",
        },
        {
            "id": "SIM-002",
            "title": "Broken Object-Level Authorization (IDOR) on Student Attendance Endpoint",
            "severity": "Critical" if is_vuln else "Info",
            "status": "Open (Simulated)" if is_vuln else "Remediated",
            "cwe": "CWE-639",
            "component": "GET /api/student/attendance?student_id=...",
            "description": (
                "Endpoint trusts client-supplied student_id without verifying that the authenticated session "
                "owns the record or holds faculty/admin privileges."
                if is_vuln
                else "Server validates session.student_id == requested student_id (or elevated role) before returning data."
            ),
            "remediation": "Derive target identity from the verified server session or enforce strict object ownership checks.",
        },
        {
            "id": "SIM-003",
            "title": "Attendance Summary State-Desync on Cold Page Refresh (0/0 Anomaly)",
            "severity": "Medium",
            "status": "Observed Pattern",
            "cwe": "CWE-662",
            "component": "Frontend Summary Hydration / State Store",
            "description": (
                "Simulated reproduction of summary widget resetting to 0/0 (0%) on refresh while lecture "
                "list remains populated due to default-zero fallback before async summary hydration."
            ),
            "remediation": "Distinguish loading/error states from 0/0 counts and derive totals from a single authoritative response.",
        },
        {
            "id": "SIM-004",
            "title": "Ambiguous Unmarked Status Representation ('-' vs Absent Filter)",
            "severity": "Low",
            "status": "Observed Pattern",
            "cwe": "CWE-1025",
            "component": "Attendance Filter & Table Formatter",
            "description": (
                "Sessions displaying '-' (unmarked/pending/excluded) appear under 'Session Attended = No', "
                "creating confusion between true absences and uncounted sessions (e.g., 169 counted vs 189 scheduled)."
            ),
            "remediation": "Separate statuses explicitly into Present, Absent, Excused, and Unmarked/Scheduled in both API and filter UI.",
        },
        {
            "id": "SIM-005",
            "title": "Missing Defense-in-Depth Security Headers on Legacy Lab Preview Route",
            "severity": "Medium" if is_vuln else "Info",
            "status": "Open (Simulated)" if is_vuln else "Remediated",
            "cwe": "CWE-693",
            "component": "HTTP Response Middleware",
            "description": (
                "Vulnerable lab route omits Content-Security-Policy and X-Content-Type-Options headers."
                if is_vuln
                else "Enforced CSP, X-Content-Type-Options: nosniff, Referrer-Policy, and frame-ancestors restrictions."
            ),
            "remediation": "Apply CSP, X-Content-Type-Options: nosniff, Referrer-Policy, and frame-ancestors across all routes.",
        },
        {
            "id": "SIM-006",
            "title": "Verbose Student Metadata Exposure in Attendance API Payload",
            "severity": "Low" if is_vuln else "Info",
            "status": "Open (Simulated)" if is_vuln else "Remediated",
            "cwe": "CWE-200",
            "component": "GET /api/student/attendance",
            "description": (
                "Response includes unneeded PII fields (email, internal cohort metadata) alongside attendance counts."
                if is_vuln
                else "Payload minimized to required attendance fields only."
            ),
            "remediation": "Apply response DTO schemas that strip unnecessary PII from summary endpoints.",
        },
    ]


def render_xss_preview_html(query: str, mode: str) -> str:
    """Render isolated sandboxed iframe HTML for the Reflected XSS lab."""
    is_vuln = mode != "secure"
    rendered_query = query if is_vuln else html.escape(query, quote=True)
    badge_text = "VULNERABLE MODE (Unescaped Reflection)" if is_vuln else "REMEDIATED MODE (HTML-Escaped + CSP)"
    badge_color = "#ff5f6d" if is_vuln else "#10f982"

    # Inside the sandboxed iframe (opaque origin, no allow-same-origin),
    # override alert() and provide simAlert() so educational XSS payloads
    # trigger a harmless visual banner and notify the parent execution log.
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sandboxed Mock Course Search</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0;
      padding: 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #0a1017;
      color: #d6f5e3;
      font-size: 13px;
    }}
    .banner {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 10px;
      border: 1px solid {badge_color};
      background: rgba(16, 24, 34, 0.9);
      border-radius: 6px;
      margin-bottom: 12px;
      font-size: 11px;
      color: {badge_color};
    }}
    .result-box {{
      padding: 12px;
      background: #101822;
      border: 1px solid #1f3344;
      border-radius: 6px;
    }}
    .sim-alert {{
      display: none;
      margin-top: 12px;
      padding: 10px 12px;
      border-radius: 6px;
      border: 1px solid #ffbe0b;
      background: rgba(255, 190, 11, 0.14);
      color: #ffe28a;
    }}
    .sim-alert.active {{ display: block; }}
  </style>
  <script>
    function triggerSimBanner(msg) {{
      var el = document.getElementById('sim-alert');
      if (el) {{
        el.textContent = '[SIMULATED HARMLESS SECURITY ALERT] ' + String(msg || 'Script execution inside sandboxed mock frame');
        el.classList.add('active');
      }}
      if (window.parent && window.parent !== window) {{
        window.parent.postMessage({{ type: 'xss-sim-triggered', message: String(msg || 'Payload executed') }}, '*');
      }}
    }}
    window.simAlert = triggerSimBanner;
    window.alert = triggerSimBanner;
  </script>
</head>
<body>
  <div class="banner">
    <span>MOCK STUDENT PORTAL // COURSE SEARCH WIDGET (SANDBOXED IFRAME)</span>
    <strong>{badge_text}</strong>
  </div>
  <div class="result-box">
    <div>Search Query Echo: <span id="echo">{rendered_query}</span></div>
    <p style="color:#8aa4b8;margin:8px 0 0;">Matching synthetic courses: CS201 (Data Structures), YOGA-B1 (Wellness), ENG102 (English).</p>
  </div>
  <div id="sim-alert" class="sim-alert" role="status"></div>
</body>
</html>"""


def generate_markdown_report(mode: str) -> str:
    """Build a Markdown security assessment report for the current simulated lab state."""
    findings = build_findings(mode)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = [
        "# Newton Dashboard Security Research Lab — Assessment Report (Simulated)",
        "",
        f"- **Generated:** {ts}",
        f"- **Environment:** Isolated Local Simulation (`127.0.0.1`, synthetic accounts only)",
        f"- **Lab Configuration Mode:** `{mode}`",
        f"- **Severity Summary:** Critical: {counts['Critical']} | High: {counts['High']} | Medium: {counts['Medium']} | Low: {counts['Low']} | Info: {counts['Info']}",
        "",
        "> **Disclaimer:** All accounts (`STU-1042`, `STU-1099`, `STU-1108`), endpoints, and vulnerability tests in this report were executed strictly inside an isolated local simulation.",
        "",
        "## Findings Inventory",
        "",
        "| ID | Title | Severity | CWE | Component | Status |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| {f['id']} | {f['title']} | {f['severity']} | {f['cwe']} | `{f['component']}` | {f['status']} |"
        )
    lines.extend(["", "## Detailed Analysis & Remediation", ""])
    for f in findings:
        lines.extend(
            [
                f"### {f['id']}: {f['title']} ({f['severity']})",
                f"- **Component:** `{f['component']}` ({f['cwe']})",
                f"- **Observation:** {f['description']}",
                f"- **Recommended Remediation:** {f['remediation']}",
                "",
            ]
        )
    return "\n".join(lines)


class SecurityLabHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the isolated Newton Dashboard Security Research Lab."""

    server_version = "NewtonSecurityLab/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence noisy default stderr access logs during tests/runs."""
        return

    def _send_security_headers(self, *, strict_csp: bool = True, allow_same_origin_frame: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "SAMEORIGIN" if allow_same_origin_frame else "DENY")
        if strict_csp:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; frame-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'self'",
            )

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self._send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self._send_security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            self._send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/styles.css":
            self._send_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._send_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
            return

        if parsed.path == "/api/session":
            self._send_json(HTTPStatus.OK, {"session": ACTIVE_SESSION, "synthetic_ids": list(SYNTHETIC_STUDENTS)})
            return

        if parsed.path == "/api/student/attendance":
            student_id = params.get("student_id", [ACTIVE_SESSION["student_id"]])[0]
            mode = params.get("mode", ["vulnerable"])[0]
            record = SYNTHETIC_STUDENTS.get(student_id)
            if record is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Synthetic student ID not found", "student_id": student_id})
                return

            if mode == "secure" and student_id != ACTIVE_SESSION["student_id"]:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Forbidden: Ownership check failed",
                        "detail": f"Authenticated student {ACTIVE_SESSION['student_id']} cannot access {student_id}.",
                        "control": "CWE-639 server-side ownership validation enforced",
                    },
                )
                return

            if mode == "secure":
                minimized = {k: v for k, v in record.items() if k != "email"}
                self._send_json(HTTPStatus.OK, {"mode": mode, "authorized_owner": True, "record": minimized})
            else:
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "mode": mode,
                        "idor_exposed": student_id != ACTIVE_SESSION["student_id"],
                        "authenticated_as": ACTIVE_SESSION["student_id"],
                        "record": record,
                    },
                )
            return

        if parsed.path == "/lab/xss-preview":
            query = params.get("q", ["Algorithms"])[0]
            mode = params.get("mode", ["vulnerable"])[0]
            body = render_xss_preview_html(query, mode).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            if mode == "secure":
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'self'",
                )
            else:
                # Vulnerable mode intentionally omits CSP inside the sandboxed frame for local demonstration.
                self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api/findings":
            mode = params.get("mode", ["vulnerable"])[0]
            self._send_json(HTTPStatus.OK, {"mode": mode, "findings": build_findings(mode)})
            return

        if parsed.path == "/api/report":
            mode = params.get("mode", ["vulnerable"])[0]
            fmt = params.get("format", ["json"])[0]
            md = generate_markdown_report(mode)
            if fmt == "markdown":
                data = md.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self._send_security_headers()
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="newton-lab-security-report.md"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send_json(HTTPStatus.OK, {"mode": mode, "markdown": md, "findings": build_findings(mode)})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Unknown route")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(min(length, 4096)) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                body = {}
            mode = str(body.get("mode", "vulnerable"))
            findings = build_findings(mode)
            checks = [
                {"step": 1, "check": "Session & Cookie Isolation", "result": "PASS (Lab Local)"},
                {"step": 2, "check": "Output Encoding & Reflected XSS Probe", "result": "FAIL (High)" if mode != "secure" else "PASS"},
                {"step": 3, "check": "Object-Level Access Control (IDOR)", "result": "FAIL (Critical)" if mode != "secure" else "PASS"},
                {"step": 4, "check": "Attendance Summary State Consistency", "result": "WARN (Medium)"},
                {"step": 5, "check": "CSP & Security Headers Inspection", "result": "FAIL (Medium)" if mode != "secure" else "PASS"},
                {"step": 6, "check": "API Payload PII Minimization", "result": "WARN (Low)" if mode != "secure" else "PASS"},
            ]
            self._send_json(HTTPStatus.OK, {"mode": mode, "checks": checks, "findings": findings})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Unknown route")


def create_server(host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    """Create the local-only HTTP server instance."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("Refusing to bind outside localhost for isolation.")
    return ThreadingHTTPServer((host, port), SecurityLabHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Newton Dashboard Security Research Lab (Isolated Local Simulation)")
    parser.add_argument("--port", type=int, default=8787, help="Local port to bind on 127.0.0.1 (default: 8787)")
    args = parser.parse_args()

    server = create_server("127.0.0.1", args.port)
    print(f"Newton Security Research Lab listening on http://127.0.0.1:{args.port}")
    print("Isolated local simulation (synthetic data only). Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down local lab server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
