# Project GlassBox

> *Understanding what's happening behind the interface.*

**Project GlassBox** is an isolated, localhost-only (`127.0.0.1`) web application security research lab, attendance calculation consistency toolkit, and OWASP-aligned assessment framework built with zero external dependencies and synthetic accounts only.

> **Ethical Research Notice:** Project GlassBox is an educational local simulation and defensive research toolkit. It does **not** connect to Newton School of Technology's production servers, does **not** use real student accounts or credentials, and does **not** claim that the live Newton portal was compromised or contains any confirmed vulnerabilities.

---

## Technology Stack

- **Backend & CLI Tooling:** Python 3 (`http.server.ThreadingHTTPServer`, `decimal`, `html`, `hashlib`, `json`, `unittest`) — zero third-party packages required.
- **Frontend Console:** Semantic HTML5, modern CSS (`color-scheme: dark`, `@container` responsive tables, accessible ARIA tabs), and vanilla JavaScript (`textContent`-safe DOM rendering, validated `postMessage` iframe bridge).
- **Reversibility & Safety:** Custom SHA-256 snapshot/rollback engine ([lab_rollback.py](lab_rollback.py)) + local Git branch isolation (`main` + `experiment/security-lab`).

---

## Repository Structure

```text
project-glassbox/
├── server.py                              # Localhost-only (127.0.0.1) dual-mode lab server
├── lab_rollback.py                        # Immutable baseline, snapshots & emergency reset
├── static/
│   ├── index.html                         # Dark-mode security research console UI
│   ├── styles.css                         # Cybersecurity terminal & responsive table styling
│   └── app.js                             # Safe DOM telemetry, scanner, XSS & IDOR controls
├── tools/
│   └── attendance_consistency_audit/
│       ├── attendance_analyzer.py         # Multi-formula attendance rounding & aggregation CLI
│       ├── template_input.json            # Sample input schema for manual UI observations
│       └── test_attendance_analyzer.py    # Unit tests for calculation & anomaly detection
├── test_lab.py                            # Endpoint, security header, XSS & IDOR tests
├── test_rollback.py                       # Baseline immutability, revert & reset tests
├── ROLLBACK_GUIDE.md                      # Reversibility & emergency reset documentation
├── SECURITY_VALIDATION_REPORT.md          # Phase 2 validation report (10/10 checks pass)
├── ADVANCED_SECURITY_RESEARCH.md          # Phase 3 technical deep-dive & line-by-line diffs
├── PHASE4_OWASP_ASSESSMENT_MATRIX.md      # OWASP Top 10 (2021) testing matrix
├── PHASE4_API_SECURITY_MATRIX.md          # OWASP API Security Top 10 (2023) matrix
├── PHASE4_ASSESSMENT_SCOPE.md             # Blank authorization & rules-of-engagement template
├── PHASE4_SEVERITY_FRAMEWORK.md           # CVSS v4.0 severity classification guide
├── PHASE4_EVIDENCE_TEMPLATE.md            # Redacted 16-field evidence collection template
├── PHASE4_TESTING_METHODOLOGY.md          # Tiered safe testing methodology
├── FINAL_SECURITY_ASSESSMENT.md           # Phase 5 technical & executive assessment report
├── DEMONSTRATION_WALKTHROUGH.md           # 10–15 minute live demonstration script
└── PHASE5_COMPLETION_REPORT.md            # Final QA & artifact index
```

---

## Features

1. **Vulnerable vs. Remediated Posture Toggle:** Switch live between intentionally vulnerable local routes and hardened implementations.
2. **Automated Local Scanner (`POST /api/scan`):** Runs 6 deterministic checks across session isolation, XSS, IDOR, attendance hydration, CSP headers, and PII minimization.
3. **Sandboxed Reflected XSS Lab (`GET /lab/xss-preview`):** Demonstrates HTML/event-handler reflection inside an opaque-origin `<iframe sandbox="allow-scripts">` vs. `html.escape()` + `script-src 'none'`.
4. **Broken Access Control / IDOR Lab (`GET /api/student/attendance`):** Demonstrates `200 OK` cross-account read (`STU-1042` -> `STU-1099`) vs. `403 Forbidden` ownership enforcement + PII stripping.
5. **Attendance State-Hydration Simulator:** Reproduces the `128/169 -> 0/0` cold-refresh UI desync locally for analysis.
6. **Attendance Consistency Analyzer ([attendance_analyzer.py](tools/attendance_consistency_audit/attendance_analyzer.py)):** Compares manually entered attendance counts across `half_up`, `half_even`, `floor`, and `ceil` rounding, excused/late/cancelled numerator-denominator variants, and pooled vs. unweighted mean aggregation.
7. **Findings Panel & Report Export:** Severity-filterable inventory (`Critical`–`Info`) with live `.md` report download (`GET /api/report`).
8. **Reversibility & Emergency Reset:** Immutable SHA-256 baseline protection, before/after snapshots, individual revert, and one-command `reset` ([ROLLBACK_GUIDE.md](ROLLBACK_GUIDE.md)).

---

## Quick Start

Requires Python 3.10+ (no `pip install` or `npm install` needed).

### 1. Start the Local Security Research Lab
```bash
python3 server.py --port 8787
```
Open `http://127.0.0.1:8787` in your browser. Follow [DEMONSTRATION_WALKTHROUGH.md](DEMONSTRATION_WALKTHROUGH.md) for a guided 10–15 minute walkthrough.

### 2. Run the Attendance Consistency Analyzer
```bash
python3 tools/attendance_consistency_audit/attendance_analyzer.py --input tools/attendance_consistency_audit/template_input.json
```
Or run interactively with `python3 tools/attendance_consistency_audit/attendance_analyzer.py`.

---

## Screenshots & UI Views

Start the server (`python3 server.py --port 8787`) to view and capture:
1. **Security Research Console & Scanner:** Top posture toggle, synthetic KPI hydration strip, 6-step scanner progress bar, and green terminal execution log.
2. **Sandboxed Reflected XSS Lab:** Harmless in-frame security alert inside `<iframe sandbox="allow-scripts">` alongside `textContent` source inspection.
3. **Broken Access Control (IDOR) Explorer:** `200 OK (IDOR LEAK)` in `Vulnerable` mode vs. `403 FORBIDDEN (BLOCKED)` in `Remediated` mode.
4. **Findings Panel & Assessment Report:** Responsive severity table and live Markdown report preview.

---

## Test Results

Run all automated tests across both the lab and the attendance analyzer:

```bash
python3 -m unittest discover -s . -p "test_*.py" -v
```

- **[test_lab.py](test_lab.py):** `5/5` tests passing (localhost-only bind check, security headers, IDOR `200` vs. `403`, XSS unescaped vs. escaped + CSP, scanner & Markdown report).
- **[test_rollback.py](test_rollback.py):** `3/3` tests passing (immutable baseline protection, change tracking + individual revert, full emergency reset).
- **[test_attendance_analyzer.py](tools/attendance_consistency_audit/test_attendance_analyzer.py):** `5/5` tests passing (rounding variants, excused denominator handling, count contradiction checks, pooled vs. mean aggregation, Markdown report generation).
- **Phase 2 Validation:** `10/10` validation checks passed ([SECURITY_VALIDATION_REPORT.md](SECURITY_VALIDATION_REPORT.md)).

---

## Security Limitations & Ethical Statement

- All lab endpoints use synthetic JSON fixtures (`STU-1042`, `STU-1099`, `STU-1108`) and refuse to bind outside `127.0.0.1` / `localhost`.
- `mode=vulnerable` is intentionally insecure **inside the local sandboxed lab** for educational comparison and must never be exposed on public interfaces.
- Attendance UI observations (`0/0` refresh, `'-'` status) are documented as unconfirmed hypotheses pending authorized source review.
- No live institutional portals were probed, no real student data was accessed or altered, and no unauthorized testing was performed.
