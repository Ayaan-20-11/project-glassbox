# Phase 4 — Vulnerability Severity & Risk Classification Framework

> **Reference Standard:** Aligned with **CVSS v4.0** (FIRST Common Vulnerability Scoring System v4.0) alongside institutional context for academic portals (attendance integrity, student PII protection, and role separation).

---

## 1. Severity Tiers

| Severity | CVSS v4.0 Score Range | Institutional Definition | Target Remediation SLA (Guidance) |
| --- | --- | --- | --- |
| **Critical** | `9.0 – 10.0` | Direct, low-barrier compromise of core system integrity, mass PII exposure, or unauthenticated/trivial privilege escalation to Admin/Faculty across all accounts. | Immediate hotfix / containment (`24–72 hours`) |
| **High** | `7.0 – 8.9` | Significant exposure of confidential peer records (e.g., cross-student IDOR), stored/reflected XSS enabling session/action hijacking, or bypass of key business controls. | Priority patch (`7–14 days`) |
| **Medium** | `4.0 – 6.9` | Conditional security weakness, state/calculation integrity flaw requiring specific preconditions, missing defense-in-depth headers (CSP/CORS) with limited direct impact. | Scheduled sprint fix (`30 days`) |
| **Low** | `0.1 – 3.9` | Minimal exploitability or minor information leakage (e.g., unneeded metadata in an already-authorized payload, ambiguous non-security UI status representation). | Backlog / hardening (`90 days`) |
| **Informational** | `0.0` | Architectural observations, best-practice recommendations, or confirmed remediated controls with no direct exploit path. | Advisory / documentation |

---

## 2. Assessment Dimensions (How Each Finding Is Evaluated)

### 2.1 Exploitability Metrics
1. **Attack Vector (AV) & Complexity (AC) / Requirements (AT):**
   - Can the issue be triggered remotely over the network (`AV:N`) with zero special preconditions (`AC:L`, `AT:N`), or does it require race timing, local access, or non-default configuration?
2. **Authentication Requirements & Privileges Required (PR):**
   - **None (`PR:N`):** Triggerable by any unauthenticated visitor.
   - **Low (`PR:L`):** Triggerable by a standard authenticated **Student** account.
   - **High (`PR:H`):** Requires **Faculty** or **Administrator** privileges already.
3. **User Interaction (UI):**
   - **None (`UI:N`):** Direct API/server call (e.g., IDOR on an API endpoint).
   - **Passive (`UI:P`) / Active (`UI:A`):** Victim must view a page or click a crafted link (e.g., Reflected XSS).

### 2.2 Impact Metrics (CIA Triad — Vulnerable & Subsequent Systems)
1. **Confidentiality (`VC` / `SC`):**
   - *High:* Bulk or cross-account read of other students' grades, attendance, emails, or credentials.
   - *Low:* Read of non-sensitive metadata or single-field minor leakage.
2. **Integrity (`VI` / `SI`):**
   - *High:* Unauthorized modification of attendance records, grades, roles, or arbitrary DOM execution in a victim's browser session.
   - *Low:* Cosmetic or non-persistent UI state distortion.
3. **Availability (`VA` / `SA`):**
   - *High:* Sustained service outage or database lock affecting cohort-wide dashboard access.
   - *Low:* Minor per-request latency or isolated client rendering failure.

---

## 3. CVSS v4.0 Reference Mapping Examples (Simulated Lab Scenarios Only)

> **Note:** The examples below score **only the synthetic local lab behaviors** for educational calibration—not any live portal.

| Lab ID | Scenario (Simulated) | Illustrative CVSS v4.0 Base Vector | Score / Tier | Rationale |
| --- | --- | --- | --- | --- |
| `SIM-002` | Simulated IDOR reading peer student attendance & PII | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | `7.1` (**High**) — elevated to **Critical** in lab if cross-cohort bulk enumeration is unthrottled | Network-accessible (`AV:N`), student privilege (`PR:L`), zero user interaction (`UI:N`), high confidentiality loss (`VC:H`). |
| `SIM-001` | Simulated Reflected XSS in search preview | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` | `5.1–7.1` (**Medium–High** depending on session cookie `HttpOnly` / origin scope) | Requires user interaction (`UI:A`); impact scales with whether session tokens/actions are reachable in the origin. |
| `SIM-003` | Simulated `0/0` refresh state desync | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N` | `2.1–4.8` (**Low–Medium**) | Integrity/availability reliability defect in UI display rather than direct data tampering. |
| `SIM-005` | Missing CSP / security headers | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` | **Medium / Low** (defense-in-depth) | Reduces exploit mitigation layers rather than introducing a standalone injection sink. |

---

## 4. Confirmed vs. Theoretical Scoring Rules
1. **Never inflate severity on unverified hypotheses:** Theoretical or UI-only anomalies without confirmed backend impact must be labeled **Unconfirmed / Informational** or scoped strictly to their observed layer.
2. **Account for compensating controls:** If `HttpOnly` cookies, gateway WAF rules, or strict CSP are verified active in the target environment, adjust subsequent-system impact accordingly.
