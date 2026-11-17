# Phase 4 — Security Assessment Scope Document (Template)

> **Authorization Rule:** All unknown authorization fields below are intentionally left blank. **Do not assume permission** and **do not perform active testing** against any live or non-local environment until this document is completed and signed by the authorizing institution/system owner.

---

## 1. Target Application
- **Application Name:** `[BLANK — e.g., Newton Student Dashboard / Institutional Portal]`
- **Repository / Commit / Build Version:** `[BLANK]`
- **Application Owner / Department:** `[BLANK]`

## 2. Authorized Domains
- **In-Scope Domains / Subdomains:** `[BLANK — DO NOT POPULATE WITHOUT WRITTEN AUTHORIZATION]`
- **Explicitly Out-of-Scope Domains:** `[BLANK — e.g., shared third-party SaaS, production identity providers, unrelated institutional domains]`

## 3. Authorized Environments
- **Local Isolated Simulation (Currently Active):** `http://127.0.0.1:<port>` (synthetic data only)
- **Authorized Staging / QA URL:** `[BLANK]`
- **Production Environment Status:** **PROHIBITED / DISABLED** unless explicitly authorized in writing below: `[BLANK — Signed Authorization Required]`

## 4. Permitted Testing Techniques
- [ ] Static source-code review (read-only)
- [ ] Offline dependency / SCA manifest inspection
- [ ] Passive observation of authorized test account UI/DevTools
- [ ] Manual, bounded functional security checks on **staging** with synthetic accounts
- [ ] Other explicitly approved techniques: `[BLANK]`

## 5. Prohibited Testing Techniques
- Any testing against production without signed written authorization.
- Denial-of-Service (DoS/DDoS), load/stress flooding, or resource exhaustion attacks.
- Automated vulnerability scanning / fuzzing / directory brute-forcing against live infrastructure.
- Credential stuffing or password brute-forcing.
- Accessing, viewing, modifying, or exfiltrating real student/faculty PII or attendance records.
- Social engineering, phishing, or physical security testing.
- Modifying production configurations, code, or database state.

## 6. Test Accounts and Roles
*(Must be dedicated, synthetic, non-production accounts provisioned by the IT/Dev team.)*

| Role | Account Identifier / Email | Environment | Provisioned By |
| --- | --- | --- | --- |
| Student (Primary) | `[BLANK]` | `[BLANK]` | `[BLANK]` |
| Student (Secondary — for IDOR verification) | `[BLANK]` | `[BLANK]` | `[BLANK]` |
| Faculty | `[BLANK]` | `[BLANK]` | `[BLANK]` |
| Administrator | `[BLANK]` | `[BLANK]` | `[BLANK]` |

## 7. Testing Time Windows
- **Start Date / Time (Timezone):** `[BLANK]`
- **End Date / Time (Timezone):** `[BLANK]`
- **Blackout Windows (e.g., Exams / Peak Attendance Sync):** `[BLANK]`

## 8. Rate Limits
- **Maximum Requests per Second (RPS):** `[BLANK — e.g., <= 2 req/sec manual testing only]`
- **Automated Scanner Policy:** **Disabled** unless explicitly permitted here: `[BLANK]`

## 9. Data Handling Requirements
- **PII / Secrets Redaction:** Passwords, session tokens, cookies, API keys, and any incidental personal data must never appear unredacted in screenshots, logs, or reports.
- **Evidence Storage Location:** `[BLANK — e.g., encrypted institutional repository]`
- **Retention & Secure Disposal Date:** `[BLANK]`

## 10. Emergency Stop Procedure
1. Immediately halt all testing activity if unexpected latency, service degradation, error spikes, or accidental exposure of real PII occurs.
2. Preserve local timestamp and last benign request details (redacting secrets).
3. Notify the Primary Emergency Contact within **15 minutes** using the contacts in Section 11.
4. For local simulation experiments, run `python3 lab_rollback.py reset` to restore the clean baseline.

## 11. Reporting Contacts
- **Primary Security / IT Contact (Name, Role, Email, Phone):** `[BLANK]`
- **Engineering Lead Contact:** `[BLANK]`
- **Out-of-Hours Escalation Contact:** `[BLANK]`

## 12. Explicit Authorization Confirmation
- **Authorizing Official Name & Title:** `[BLANK]`
- **Organization:** `[BLANK]`
- **Authorization Reference / Ticket ID:** `[BLANK]`
- **Signature & Date:** `[BLANK]`
- **Authorization Status:** **NOT YET AUTHORIZED FOR NON-LOCAL ENVIRONMENTS**
