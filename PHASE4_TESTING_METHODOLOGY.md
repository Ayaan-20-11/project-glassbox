# Phase 4 — Safe Security Testing Methodology

> **Core Policy:** **Production testing is DISABLED by default.** No active probing, fuzzing, or automated scanning may be run against Newton production infrastructure unless a signed `PHASE4_ASSESSMENT_SCOPE.md` explicitly authorizes it. Automated scanners must **never** be pointed at Newton production.

---

## 1. Approved Testing Environments (Tiered Progression)

| Tier | Environment | Permitted Activities | Prohibited Activities |
| --- | --- | --- | --- |
| **Tier 1** | **Local Isolated Applications** (`127.0.0.1` simulation, cloned authorized repo) | Static code analysis, unit/integration tests, dependency CVE scans, UI/XSS/IDOR simulation, rollback drills | Binding to `0.0.0.0`, embedding production secrets or real student datasets |
| **Tier 2** | **Intentionally Vulnerable Training Apps** (e.g., OWASP Juice Shop, WebGoat, local Newton Security Lab) | Practicing payload mechanics, CSP bypass analysis, RBAC/IDOR patterns, and defensive remediation diffs | Reusing training payloads against unauthorized external targets |
| **Tier 3** | **Synthetic Accounts in Isolated Fixtures** | Multi-role differential tests (`Student A` vs `Student B` vs `Faculty` vs `Admin`), attendance math & state-desync tests | Using real student credentials or querying real student identifiers |
| **Tier 4** | **Explicitly Authorized Staging Environment** *(requires signed scope doc)* | Bounded manual verification of static findings, header checks, role-separation tests within approved rate limits & time windows | DoS/load testing, destructive DB edits, unapproved automated scanning |

---

## 2. Category-by-Category Safe Testing Guide

### 2.1 Broken Access Control & API Authorization (`A01` / `API1`, `API3`, `API5`)
- **Local / Static:** Audit every route decorator/middleware in source code to confirm server-side ownership (`record.student_id == session.student_id`) and role checks (`student`, `faculty`, `admin`). Run `unittest` cases comparing `200 OK` vs `403 Forbidden` on synthetic records.
- **Training App / Local Lab:** Use the Newton Security Research Lab's IDOR tab (`STU-1042` requesting `STU-1099`) across `Vulnerable` and `Remediated` modes.
- **Authorized Staging:** Replay a single benign `GET` request from synthetic Student A referencing synthetic Student B's ID; verify `403` and check audit logs.

### 2.2 Injection & Reflected/DOM XSS (`A03`)
- **Local / Static:** Grep for unsafe SQL string interpolation and dangerous DOM sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`). Verify parameter binding and `textContent` / `setHTML()` usage.
- **Training App / Local Lab:** Test harmless markers inside the sandboxed `<iframe sandbox="allow-scripts">` preview (`simAlert(...)`), confirming opaque `"null"` origin containment and `html.escape()` + `script-src 'none'` blocking in `Remediated` mode.
- **Authorized Staging:** Use non-executing canary strings (e.g., `probe"'>test`) to observe encoding in DOM/responses—avoid intrusive payloads on shared staging pages.

### 2.3 Authentication & Session Isolation (`A02`, `A07` / `API2`)
- **Local / Static:** Inspect password hashing (`Argon2id`/`bcrypt`), JWT library verification (`algorithms=[...]`, `exp`, `aud`, `iss`), cookie attributes (`__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`), and logout invalidation.
- **Authorized Staging:** Using a synthetic test account, inspect `Set-Cookie` flags in DevTools and verify an old session token is rejected after logout. Never run brute-force/credential stuffing.

### 2.4 Insecure Design & Attendance State Logic (`A04` / `API6`)
- **Local / Static:** Inspect attendance aggregation queries, rounding modes, timezone handling, DB uniqueness constraints, and frontend loading/error state transitions.
- **Synthetic Data Verification:** Run [attendance_analyzer.py](file:///Users/ayaankapoor/.gemini/antigravity/scratch/attendance_consistency_audit/attendance_analyzer.py) on synthetic counts and test concurrent/refresh edge cases locally.

### 2.5 Security Misconfiguration & Components (`A05`, `A06` / `API8`, `API9`)
- **Local / Static:** Run offline lockfile scanners (`npm audit`, `pip-audit`) against local manifests; inspect server/proxy header middleware (`CSP`, `HSTS`, `X-Content-Type-Options`, `CORS`).
- **Authorized Staging:** Inspect HTTP response headers from a normal authenticated page load (`curl -I` or browser DevTools Network tab).

### 2.6 Logging, Integrity & SSRF (`A08`, `A09`, `A10` / `API7`, `API10`)
- **Local / Static:** Verify webhook signature validation, SRI attributes on external scripts, absence of `pickle`/`yaml.load`, log redaction filters, and outbound URL allowlists/IP blocks.
- **Local Simulation:** Test outbound URL validation against a harmless localhost mock listener only.

---

## 3. Pre-Test Safety Gate (Go / No-Go Checklist)
Before testing any environment beyond `127.0.0.1`:
1. Is [PHASE4_ASSESSMENT_SCOPE.md](file:///Users/ayaankapoor/.gemini/antigravity/scratch/newton_security_lab/PHASE4_ASSESSMENT_SCOPE.md) completely filled out and signed?
2. Are dedicated synthetic accounts provisioned for every role?
3. Are automated scanners disabled for live targets?
4. Is the rollback mechanism (`python3 lab_rollback.py verify`) verified for all local experiments?

If **any** answer is "No", remain strictly in **Tier 1 / Tier 2 (local simulation & static analysis)**.
