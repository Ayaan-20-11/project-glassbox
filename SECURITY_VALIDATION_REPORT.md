# Newton Security Research Lab — Phase 2 Security Validation Report

- **Date (UTC):** `2026-11-17T07:09:21Z`
- **Target Scope:** Isolated Local Simulation (`/Users/ayaankapoor/.gemini/antigravity/scratch/newton_security_lab`)
- **Immutable Baseline Created At:** `2026-11-17T07:06:53Z` (`9` tracked files, verified protected against overwrite)
- **Production Disclaimer:** All tests ran strictly against an ephemeral `127.0.0.1` server using synthetic accounts (`STU-1042`, `STU-1099`, `STU-1108`). No connections were made to Newton production infrastructure, and no claims are made regarding vulnerabilities in the live Newton portal.

---

## Validation Summary

- **Total Validation Checks:** 10
- **Passed:** 10
- **Failed:** 0

| # | Test Name | Pass/Fail |
| --- | --- | --- |
| 1 | Public Network Interface Binding Prevention | **PASS** |
| 2 | Zero Production / External Network Traffic | **PASS** |
| 3 | Synthetic Student Account Isolation | **PASS** |
| 4 | Independent Vulnerable vs. Remediated Mode Behavior | **PASS** |
| 5 | Simulated XSS Sandbox Containment | **PASS** |
| 6 | Simulated IDOR Synthetic Data Isolation | **PASS** |
| 7 | All Six Simulated Scanner Checks | **PASS** |
| 8 | Report Exports Free of Secrets & Credentials | **PASS** |
| 9 | Individual Rollback & Full Emergency Reset | **PASS** |
| 10 | Complete Change-Tracking Audit Trail | **PASS** |

---

## Detailed Validation Results

### 1. Public Network Interface Binding Prevention
- **Test Name:** Non-Localhost Bind Rejection
- **Test Procedure:** Invoked `server.create_server("0.0.0.0", 0)` and `server.create_server("192.168.1.10", 0)` directly, and verified `main()` binds to `"127.0.0.1"`.
- **Expected Result:** `create_server()` raises `ValueError` for any host other than `"127.0.0.1"` or `"localhost"`.
- **Actual Result:** Both `"0.0.0.0"` and `"192.168.1.10"` raised `ValueError: Refusing to bind outside localhost for isolation.`.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK1_BIND: {"0.0.0.0": "BLOCKED: Refusing to bind outside localhost for isolation.", "192.168.1.10": "BLOCKED: Refusing to bind outside localhost for isolation."}`

---

### 2. Zero Production / External Network Traffic
- **Test Name:** External URL & Production Reference Scan
- **Test Procedure:** Scanned `server.py`, `static/index.html`, `static/app.js`, and `static/styles.css` with regex for `http://`, `https://`, and `newtonschool.co`.
- **Expected Result:** Zero external URLs or `newtonschool.co` references in runtime server or frontend code; only localhost display string allowed.
- **Actual Result:** Only one match found: `"http://127.0.0.1:{args.port}"` in `server.py` startup banner; zero references to `newtonschool.co` or any external origin.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK2_EXTERNAL_URLS: [["server.py", "http://127.0.0.1:{args.port}"]]`

---

### 3. Synthetic Student Account Isolation
- **Test Name:** Synthetic Account & Unknown-ID Boundary Verification
- **Test Procedure:** Queried `GET /api/session` and `GET /api/student/attendance?student_id=STU-9999&mode=vulnerable`, and inspected `SYNTHETIC_STUDENTS`.
- **Expected Result:** Only synthetic `@lab.local` accounts (`STU-1042`, `STU-1099`, `STU-1108`) exist; unknown IDs return HTTP `404`.
- **Actual Result:** Active session is `STU-1042`; synthetic IDs are `["STU-1042", "STU-1099", "STU-1108"]` with `.local` emails (`aarav.sim1042@lab.local`, `diya.sim1099@lab.local`, `rohan.sim1108@lab.local`); unknown ID `STU-9999` returned HTTP `404`.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK3_ISOLATION: {"session_student": "STU-1042", "synthetic_ids": ["STU-1042", "STU-1099", "STU-1108"], "emails": ["aarav.sim1042@lab.local", "diya.sim1099@lab.local", "rohan.sim1108@lab.local"], "unknown_id_status": 404}`

---

### 4. Independent Vulnerable vs. Remediated Mode Behavior
- **Test Name:** Mode Isolation (`mode=vulnerable` vs. `mode=secure`)
- **Test Procedure:** Tested `/api/student/attendance?student_id=STU-1099` and `/lab/xss-preview` independently with `mode=vulnerable` and `mode=secure`.
- **Expected Result:** `vulnerable` demonstrates simulated IDOR (`200 OK`, `idor_exposed: true`) and unescaped XSS reflection; `secure` enforces `403 Forbidden`, HTML entity escaping, and `script-src 'none'`.
- **Actual Result:** `vulnerable` returned `200 OK` (`idor_exposed: true`) and raw `<svg onload=...>`; `secure` returned `403 Forbidden`, escaped `&lt;svg ...&gt;`, and CSP `script-src 'none'`.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK4_6_IDOR` (`secure_status: 403`, `vuln_idor_exposed: true`) and `TASK5_XSS_SANDBOX` (`vuln_raw_reflected: true`, `sec_escaped: true`).

---

### 5. Simulated XSS Sandbox Containment
- **Test Name:** Iframe Sandbox & `postMessage` Origin Guard Verification
- **Test Procedure:** Inspected the iframe attributes in `static/index.html`, the `message` listener in `static/app.js`, and response headers from `GET /lab/xss-preview`.
- **Expected Result:** Iframe uses `sandbox="allow-scripts"` without `allow-same-origin` (forcing opaque `"null"` origin), and parent validates `event.source` and `event.origin === 'null'` before calling `textContent`.
- **Actual Result:** Confirmed `<iframe id="xss-frame" ... sandbox="allow-scripts"></iframe>`, guard `if (event.source !== els.xssFrame.contentWindow || event.origin !== 'null') return;`, and strict `script-src 'none'` CSP in `secure` mode.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK5_XSS_SANDBOX: {"iframe_tag": "<iframe id=\"xss-frame\" class=\"xss-iframe\" title=\"Sandboxed mock course search reflection preview\" sandbox=\"allow-scripts\"></iframe>", "postmessage_guard": "if (event.source !== els.xssFrame.contentWindow || event.origin !== 'null') return;", "vuln_raw_reflected": true, "vuln_csp": null, "sec_escaped": true, "sec_csp": "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'self'"}`

---

### 6. Simulated IDOR Synthetic Data Isolation
- **Test Name:** Peer-Record Access Scope Verification
- **Test Procedure:** Requested `GET /api/student/attendance?student_id=STU-1099&mode=vulnerable` while authenticated as `STU-1042`.
- **Expected Result:** Returned record contains only fabricated synthetic test data.
- **Actual Result:** Returned `Diya Verma (Synthetic Peer)` with `diya.sim1099@lab.local`.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK4_6_IDOR: {"vuln_idor_exposed": true, "vuln_record_name": "Diya Verma (Synthetic Peer)", "vuln_record_email": "diya.sim1099@lab.local", "secure_status": 403}`

---

### 7. All Six Simulated Scanner Checks
- **Test Name:** Scanner Coverage (`POST /api/scan`)
- **Test Procedure:** Executed `POST /api/scan` with `{"mode": "vulnerable"}` and `{"mode": "secure"}` and inspected all six returned steps.
- **Expected Result:** All 6 checks execute; `vulnerable` flags XSS (`FAIL (High)`), IDOR (`FAIL (Critical)`), Headers (`FAIL (Medium)`), PII (`WARN (Low)`), and Hydration (`WARN (Medium)`); `secure` transitions checks 2, 3, 5, and 6 to `PASS`.
- **Actual Result:** Both modes returned all 6 checks with the exact expected state transitions.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK7_SCANS`:
  - `vulnerable`: Step 1 `PASS (Lab Local)`, Step 2 `FAIL (High)`, Step 3 `FAIL (Critical)`, Step 4 `WARN (Medium)`, Step 5 `FAIL (Medium)`, Step 6 `WARN (Low)`.
  - `secure`: Step 1 `PASS (Lab Local)`, Step 2 `PASS`, Step 3 `PASS`, Step 4 `WARN (Medium)`, Step 5 `PASS`, Step 6 `PASS`.

---

### 8. Report Exports Free of Secrets & Credentials
- **Test Name:** Assessment Report Secret-Leak Scan
- **Test Procedure:** Fetched `GET /api/report?mode=vulnerable&format=markdown` and `mode=secure&format=markdown` and scanned for API keys, bearer tokens, passwords, and production domains.
- **Expected Result:** Zero matches against secret/credential/production patterns.
- **Actual Result:** Both Markdown exports (`4192` bytes and `4050` bytes) returned `0` pattern hits.
- **Pass/Fail:** **PASS**
- **Evidence:** `TASK8_REPORTS: {"vulnerable": {"length": 4192, "secret_hits": []}, "secure": {"length": 4050, "secret_hits": []}}`

---

### 9. Individual Rollback & Full Emergency Reset
- **Test Name:** Live Individual Revert, Emergency Reset, and Baseline Immutability
- **Test Procedure:**
  1. Verified `python3 lab_rollback.py init-baseline` refuses overwrite (`ERROR: Baseline already exists and is protected from overwrite.`).
  2. Ran `begin-change --id val-drill-002`, appended a test comment to `ROLLBACK_GUIDE.md`, ran `commit-change`, then ran `revert-change val-drill-002` and `verify --no-tests`.
  3. Modified `ROLLBACK_GUIDE.md` again, created `temp_validation_artifact.txt`, and ran `python3 lab_rollback.py reset`.
- **Expected Result:** Individual revert restores the modified file to baseline; full emergency reset removes extra files, restores all 9 baseline files with matching SHA-256 hashes, and passes all 8 unit tests.
- **Actual Result:** `revert-change val-drill-002` passed `Hash verification PASSED: 9/9 files match immutable baseline`; `reset` removed `temp_validation_artifact.txt`, passed `Hash verification PASSED: 9/9 files match immutable baseline`, and passed `Ran 8 tests in 0.544s -> OK`.
- **Pass/Fail:** **PASS**
- **Evidence:**
  - `ERROR: Baseline already exists and is protected from overwrite.`
  - `Reverted individual change 'val-drill-002'.` -> `Hash verification PASSED: 9/9 files match immutable baseline.`
  - `Workspace files restored from immutable baseline.` -> `Ran 8 tests in 0.544s` (`OK`) -> `Automated test verification PASSED.`

---

### 10. Complete Change-Tracking Audit Trail
- **Test Name:** Changelog & Before/After Snapshot Verification
- **Test Procedure:** Inspected `.lab_backups/CHANGELOG.md`, `.lab_backups/changelog.jsonl`, and `.lab_backups/snapshots/`.
- **Expected Result:** Every change, revert, and emergency reset is logged with UTC timestamp, reason, affected files, and `before/` + `after/` + `diff.patch` directories.
- **Actual Result:** All events (`drill-001`, `reset-20261117070705`, `val-drill-002` change + revert, and `reset-20261117070921`) are recorded in `.lab_backups/CHANGELOG.md` and `.lab_backups/changelog.jsonl`, with snapshot directories `drill-001` and `val-drill-002` preserved under `.lab_backups/snapshots/`.
- **Pass/Fail:** **PASS**
- **Evidence:** `.lab_backups/CHANGELOG.md` contains 5 timestamped audit entries and `.lab_backups/snapshots` lists `drill-001` and `val-drill-002`.
