# Newton Dashboard Security Research Lab — Final Security Assessment (Simulated)

> **Critical Scope Notice:** Every vulnerability, scan result, and exploit demonstration in this assessment was executed **exclusively inside an isolated local simulation** (`127.0.0.1`, synthetic accounts `STU-1042`, `STU-1099`, `STU-1108`). **Zero production systems were tested, and zero vulnerabilities are claimed on the live Newton School of Technology portal.**

---

## 1. Executive Summary

This project built, validated, and documented a self-contained **Security Research Lab** modeled around common web application and student-portal security risks. Using a dual-posture toggle (`VULNERABLE LAB` vs. `REMEDIATED`), the simulation demonstrates how high-impact vulnerabilities arise in code, how they behave in a controlled browser/API context, and how layered engineering controls eliminate them.

### Key Outcomes
- **Isolated Lab Built & Validated:** `10/10` Phase 2 security validation checks passed.
- **Simulated Risks Demonstrated:** `6` structured findings (`1` Critical IDOR, `1` High Reflected XSS, `2` Medium header/state issues, `2` Low PII/status-ambiguity issues) in `Vulnerable` mode; all technical vulnerabilities transition to `Remediated` / `PASS` when switching to `Secure` mode.
- **Reversibility Guaranteed:** Immutable SHA-256 baseline (`9` core files), before/after snapshots, local Git branch isolation (`experiment/security-lab`), and verified emergency reset.
- **Automated Verification:** `8/8` unit and integration tests passing in `test_lab.py` and `test_rollback.py`.

---

## 2. Project Architecture

```text
+-----------------------------------------------------------------------+
|  Browser UI (Dark Security Console — static/index.html, styles.css)   |
|  - Active Synthetic Persona: STU-1042 (Aarav Sharma)                  |
|  - Posture Toggle: [VULNERABLE LAB] <--> [REMEDIATED]                 |
|  - Sandboxed XSS Frame: <iframe sandbox="allow-scripts"> (opaque)     |
|  - Terminal Telemetry Log + Mock Security Alert Banner                |
+-----------------------------------+-----------------------------------+
                                    |  Relative Same-Origin Calls (/api/*, /lab/*)
                                    v
+-----------------------------------------------------------------------+
|  Localhost Python 3 HTTP Server (server.py — bound strictly 127.0.0.1)|
|  - GET  /api/session              (Synthetic persona metadata)        |
|  - GET  /api/student/attendance   (IDOR vulnerable vs. 403 secure)    |
|  - GET  /lab/xss-preview          (Raw echo vs. html.escape + CSP)    |
|  - POST /api/scan                 (6-step simulated security audit)   |
|  - GET  /api/findings & /report   (Severity inventory & .md export)   |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Reversibility & Safety Layer (lab_rollback.py + .lab_backups/)       |
|  - Immutable baseline (SHA-256 manifest) + before/after snapshots     |
|  - Git local branch isolation (main -> experiment/security-lab)       |
+-----------------------------------------------------------------------+
```

---

## 3. Methodology

The research followed a five-phase defensive engineering lifecycle:
1. **Phase 1 (Lab Construction):** Implemented the localhost-only server, synthetic student dataset, dark console UI, sandboxed XSS preview, IDOR endpoint, and rollback engine.
2. **Phase 2 (Security Validation):** Verified `10/10` isolation, functional, and recovery controls (recorded in [SECURITY_VALIDATION_REPORT.md](SECURITY_VALIDATION_REPORT.md)).
3. **Phase 3 (Deep Technical Analysis):** Documented parser mechanics, authorization logic, session isolation, attendance state-desync hypotheses, and line-by-line code diffs ([ADVANCED_SECURITY_RESEARCH.md](ADVANCED_SECURITY_RESEARCH.md)).
4. **Phase 4 (Assessment Governance):** Produced OWASP Top 10 (2021) and OWASP API Top 10 (2023) matrices, blank authorization scope template, CVSS v4.0 severity framework, redacted evidence template, and safe testing methodology.
5. **Phase 5 (Final Demonstration & QA):** Packaged executive reporting, a 10–15 minute live walkthrough, portfolio documentation, and end-to-end verification.

---

## 4. Simulated Vulnerability Inventory

> **Simulated vs. Production Distinction:** All entries below with IDs `SIM-001`–`SIM-006` are **intentionally simulated behaviors** inside `server.py` / `app.js` (or UI patterns modeled after user-supplied observations for `SIM-003`/`SIM-004`). **None** represent verified production findings.

| ID | Title | Vulnerable Mode Severity | Remediated Mode Status | CWE | OWASP Mapping |
| --- | --- | --- | --- | --- | --- |
| `SIM-001` | Reflected XSS in Course Search Preview | **High** | **Remediated (`Info`)** | `CWE-79` | `A03:2021` Injection |
| `SIM-002` | Broken Object-Level Authorization (IDOR) | **Critical** | **Remediated (`Info`)** | `CWE-639` | `A01:2021` / `API1:2023` |
| `SIM-003` | Attendance Summary Refresh Desync (`0/0`) | **Medium** | **Observed Pattern** | `CWE-662` | `A04:2021` Insecure Design |
| `SIM-004` | Ambiguous Unmarked Status (`'-'` vs. Absent) | **Low** | **Observed Pattern** | `CWE-1025` | `A04:2021` Insecure Design |
| `SIM-005` | Missing CSP & Security Headers on Legacy Preview | **Medium** | **Remediated (`Info`)** | `CWE-693` | `A05:2021` / `API8:2023` |
| `SIM-006` | Excessive Student Metadata (`email`) in API Payload | **Low** | **Remediated (`Info`)** | `CWE-200` | `API3:2023` |

---

## 5. Technical Explanations & Security Impact

- **Reflected XSS (`SIM-001`):** Unescaped query parameter `q` transitions the HTML parser from text into markup/event attributes (`<img onerror=...>`, `<svg onload=...>`). In a real unprotected app, this allows same-origin script execution, DOM manipulation, and action forgery. In the lab, `<iframe sandbox="allow-scripts">` isolates execution to an opaque `"null"` origin.
- **Broken Access Control / IDOR (`SIM-002`, `SIM-006`):** Trusting client-supplied `?student_id=STU-1099` without checking `session.student_id` allows any authenticated student to enumerate synthetic peer attendance and PII (`email`).
- **Attendance State Consistency (`SIM-003`, `SIM-004`):** Coercing unhydrated summary counts to `0/0` (`0%`) while a `189`-item lecture list loads creates misleading UI state; conflating unmarked (`-`) sessions with absences obscures denominator exclusions (`169` counted vs. `189` scheduled).

---

## 6. Remediation Strategies

1. **Output Encoding & CSP:** Apply `html.escape(query, quote=True)` server-side, use `textContent` / `setHTML()` client-side (avoiding `innerHTML`), and enforce `Content-Security-Policy: script-src 'self'` (or `'none'` on static views) with `object-src 'none'` and `frame-ancestors 'self'`.
2. **Server-Side Ownership & DTO Minimization:** Derive user scope from the verified server session or enforce `student_id == session.student_id` (returning HTTP `403 Forbidden` otherwise), and filter responses through strict DTO allowlists removing unneeded PII.
3. **Deterministic State & Explicit Enums:** Separate `loading`/`error`/`ready` UI states from numeric `0` values, and distinguish `PRESENT`, `ABSENT`, `EXCUSED`, and `UNMARKED` statuses at both API and filter layers.

---

## 7. Automated Testing & Rollback Verification

- **Automated Test Suite (`test_lab.py` & `test_rollback.py`):** **8/8 tests passing** covering localhost-only binding enforcement, HTTP security headers, IDOR `200` vs. `403`, XSS unescaped vs. escaped + CSP, 6-step scanner execution, Markdown report export, baseline immutability, individual change revert, and emergency reset.
- **Rollback Verification:** Live snapshot/revert drills recorded in `.lab_backups/CHANGELOG.md` and isolated baseline reset verified **9/9 baseline SHA-256 checksums** intact.

---

## 8. Limitations & Future Recommendations

### Limitations
- All behavioral demonstrations are local simulations using synthetic JSON fixtures (`SYNTHETIC_STUDENTS`), not a copy of Newton's proprietary backend or database.
- The `0/0` refresh anomaly and `'-'` Yoga B1 filter behavior remain **unconfirmed UI hypotheses** until authorized source code or passive DevTools network traces are available.

### Future Recommendations
1. Complete [PHASE4_ASSESSMENT_SCOPE.md](PHASE4_ASSESSMENT_SCOPE.md) with written authorization before evaluating any non-local staging environment.
2. Perform Phase 1 static source-code reconnaissance if authorized repository access is granted by the engineering team.
3. Keep automated scanners disabled against live institutional infrastructure.
