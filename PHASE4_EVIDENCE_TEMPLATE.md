# Phase 4 — Reusable Vulnerability Evidence Collection Template

> **Strict Redaction Policy:** **NEVER** store or include real passwords, session cookies, JWTs, API keys, private student names/emails/roll numbers, or production secrets in any field or screenshot. Replace any sensitive token with `[REDACTED]` and use synthetic test identifiers (`STU-1042`, `STU-1099`) whenever demonstrating behavior.

---

## Finding Record Template

1. **Finding ID:** `[e.g., LAB-2026-001]`
2. **Vulnerability Title:** `[Concise descriptive title]`
3. **Affected Component:** `[Service / file path / endpoint / UI view]`
4. **Severity:** `[Critical | High | Medium | Low | Informational]` *(include CVSS v4.0 vector if applicable)*
5. **CWE:** `[e.g., CWE-639]`
6. **OWASP Category:** `[e.g., OWASP Top 10 A01:2021 / OWASP API1:2023]`
7. **Description:**
   `[Clear technical summary of the flaw and why it occurs.]`
8. **Preconditions:**
   `[Environment (local/staging), required role/authentication state, and configuration flags.]`
9. **Reproduction Steps:**
   1. `[Step 1 — e.g., Authenticate as synthetic Student Account A in staging/local lab]`
   2. `[Step 2 — Issue bounded request or UI action targeting synthetic Account B]`
   3. `[Step 3 — Observe response status and payload]`
   *(Sanitized HTTP request/response excerpt — redact all `Cookie`, `Authorization`, and PII fields.)*
10. **Expected Behavior:**
    `[What the secure system must enforce, e.g., HTTP 403 Forbidden with audit log entry.]`
11. **Actual Behavior:**
    `[Observed response/behavior, clearly noting whether it is from local simulation, staging, or static code review.]`
12. **Evidence Screenshots:**
    - `[Relative path or attachment reference — verify all cookies, tokens, and real PII are masked before saving.]`
13. **Security Impact:**
    `[Confidentiality, Integrity, and Availability consequences under realistic conditions.]`
14. **Root Cause:**
    `[Exact missing check, unsafe sink, state race, or misconfiguration in source/config.]`
15. **Recommended Remediation:**
    `[Actionable code-level fix, defense-in-depth controls, and regression test recommendation.]`
16. **Retest Result:**
    - **Status:** `[Pending | Verified Fixed | Still Reproducible]`
    - **Retest Date & Build/Commit:** `[YYYY-MM-DD — commit/tag]`
    - **Retest Notes:** `[Verification command / test case result]`
