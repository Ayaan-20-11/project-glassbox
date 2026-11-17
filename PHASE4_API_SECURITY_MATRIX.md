# Phase 4 — OWASP API Security Top 10 (2023) Assessment Matrix

> **Disclaimer:** Framework for authorized code audits, local simulations, and approved staging environments. No production APIs are probed and no claims are made regarding Newton's live APIs.

---

## Summary Matrix

| ID | Category | Primary API Risk | Relevant CWEs |
| --- | --- | --- | --- |
| `API1` | Broken Object Level Authorization | Cross-user record access via ID manipulation | `CWE-639`, `CWE-284` |
| `API2` | Broken Authentication | Weak token validation, credential stuffing, session flaws | `CWE-287`, `CWE-384`, `CWE-613` |
| `API3` | Broken Object Property Level Authorization | Excessive data exposure & mass assignment | `CWE-200`, `CWE-213`, `CWE-915` |
| `API4` | Unrestricted Resource Consumption | Missing rate limits, pagination caps, upload limits | `CWE-400`, `CWE-770`, `CWE-799` |
| `API5` | Broken Function Level Authorization | Student invoking faculty/admin endpoints | `CWE-285`, `CWE-862`, `CWE-863` |
| `API6` | Unrestricted Access to Sensitive Business Flows | Automated abuse of attendance/enrollment workflows | `CWE-799`, `CWE-840` |
| `API7` | Server Side Request Forgery | Unvalidated webhook/URL fetching by API server | `CWE-918` |
| `API8` | Security Misconfiguration | Permissive CORS, missing TLS/headers, verb tampering | `CWE-16`, `CWE-693`, `CWE-942` |
| `API9` | Improper Inventory Management | Forgotten `/v1`/debug/staging APIs bypassing controls | `CWE-1059`, `CWE-1188` |
| `API10` | Unsafe Consumption of APIs | Blindly trusting third-party/LMS/webhook payloads | `CWE-20`, `CWE-345`, `CWE-502` |

---

## Detailed API Category Breakdown

### API1:2023 — Broken Object Level Authorization (BOLA / IDOR)
- **What it means:** API endpoints accept object IDs (student ID, course ID, attendance record ID) without verifying that the authenticated caller has rights to that specific object.
- **Why it matters:** Single most common API vulnerability; allows automated enumeration of peer records.
- **Typical implementation mistakes:** Checking `is_authenticated` only; trusting `student_id` in query/body; missing row-level ownership filters in ORM queries.
- **Evidence establishing presence:** Code review showing unguarded primary-key lookups or staging test where synthetic Account A reads synthetic Account B's record (`200 OK` vs. `403 Forbidden`).
- **Safe testing methodology:** Static authorization review + controlled cross-account checks between two synthetic staging accounts.
- **Recommended remediation:** Enforce server-side ownership checks (`record.owner_id == session.user_id` or verified faculty-course assignment) inside the data-access/service layer.
- **Relevant CWE references:** `CWE-639`, `CWE-284`, `CWE-862`.

### API2:2023 — Broken Authentication
- **What it means:** Flaws in API token issuance, signature verification, refresh rotation, or login throttling allow attackers to impersonate users.
- **Why it matters:** All downstream API protections fail if caller identity cannot be trusted.
- **Typical implementation mistakes:** Accepting unsigned/weakly signed JWTs; missing `exp`/`aud`/`iss` validation; reusable refresh tokens; unlimited OTP/login attempts.
- **Evidence establishing presence:** Auth middleware code accepting weak algorithms/missing claims, or staging token-replay test succeeding after logout/expiration.
- **Safe testing methodology:** Static audit of JWT/OAuth/session middleware + isolated staging replay tests using synthetic tokens.
- **Recommended remediation:** Use standard vetted auth libraries, enforce short-lived access tokens + rotating/revocable refresh tokens, and rate-limit auth endpoints.
- **Relevant CWE references:** `CWE-287`, `CWE-384`, `CWE-613`, `CWE-798`.

### API3:2023 — Broken Object Property Level Authorization
- **What it means:** Combines **Excessive Data Exposure** (returning sensitive/internal fields in JSON responses) and **Mass Assignment** (binding raw request JSON directly onto DB models, letting users overwrite `role`, `attendance_status`, or `verified`).
- **Why it matters:** Leaks PII/internal metadata in responses and enables privilege or record tampering via extra JSON keys.
- **Typical implementation mistakes:** Returning `SELECT *` / raw ORM model dicts to clients; passing `request.json` directly into `Model(**payload)` or `Object.assign`.
- **Evidence establishing presence:** Response payload inspection revealing unrequested PII or serializer code accepting unallowlisted writable fields.
- **Safe testing methodology:** Static schema/serializer audit + local unit tests submitting extra restricted properties (`role`, `is_admin`) against synthetic fixtures.
- **Recommended remediation:** Separate input and output DTO/schema classes (Pydantic/Zod/DRF serializers) with strict field allowlists (`extra="forbid"`).
- **Relevant CWE references:** `CWE-200`, `CWE-213`, `CWE-915`.

### API4:2023 — Unrestricted Resource Consumption
- **What it means:** APIs lack limits on request rate, payload size, pagination `limit`, query complexity, or expensive exports.
- **Why it matters:** Enables denial-of-service, scraping of permitted data, or cloud cost spikes.
- **Typical implementation mistakes:** Unbounded `?limit=1000000`; unthrottled PDF/CSV export or login/OTP routes; missing request body size caps.
- **Evidence establishing presence:** Route/gateway configuration audit showing absence of rate-limit middleware, max page size, or upload caps.
- **Safe testing methodology:** Inspect gateway/app middleware config and run small bounded unit tests locally (never run load/DoS tests against live infrastructure).
- **Recommended remediation:** Enforce gateway + per-user rate limits, strict pagination ceilings (e.g., `max=100`), body-size limits, and timeouts.
- **Relevant CWE references:** `CWE-400`, `CWE-770`, `CWE-799`.

### API5:2023 — Broken Function Level Authorization
- **What it means:** Lower-privileged roles (students) can invoke administrative or faculty API routes (e.g., `/api/admin/...`, `/api/attendance/override`, `DELETE`/`PATCH` methods).
- **Why it matters:** Allows unauthorized modification of records, rosters, or system configuration.
- **Typical implementation mistakes:** Protecting `GET` routes but forgetting `POST`/`PUT`/`DELETE`; hiding admin UI tabs without guarding backend endpoints; relying on obscure URL names.
- **Evidence establishing presence:** Backend router/decorator inspection missing role guards on privileged endpoints, verified via synthetic student-role request in staging returning non-`403`.
- **Safe testing methodology:** Enumerate all routes and HTTP methods from backend router definitions; test each privileged route with a synthetic low-privilege token in staging/local lab.
- **Recommended remediation:** Apply explicit deny-by-default RBAC decorators/policies to every route and HTTP method; log and alert on all `403` denials.
- **Relevant CWE references:** `CWE-285`, `CWE-862`, `CWE-863`.

### API6:2023 — Unrestricted Access to Sensitive Business Flows
- **What it means:** Business workflows (e.g., attendance dispute submission, QR/OTP check-in, course registration) lack anti-abuse, temporal, or state-transition controls.
- **Why it matters:** Legitimate endpoints can be abused at scale or out of sequence without violating syntax checks.
- **Typical implementation mistakes:** Allowing repeat attendance check-ins without window/uniqueness locks; missing state-machine checks on dispute approvals.
- **Evidence establishing presence:** Business-logic trace or staging workflow test allowing invalid state transitions or duplicate submissions.
- **Safe testing methodology:** Sequence-diagram review and local integration tests exercising out-of-order or concurrent synthetic workflow requests.
- **Recommended remediation:** Enforce server-side state machines, time windows, idempotency keys, DB unique constraints, and anomaly throttling.
- **Relevant CWE references:** `CWE-799`, `CWE-840`.

### API7:2023 — Server Side Request Forgery (SSRF)
- **What it means:** API endpoints trigger outbound HTTP calls from user-controlled URLs (webhooks, external LTI/LMS links, file imports) without egress validation.
- **Why it matters:** Exposes internal microservices and cloud instance credentials.
- **Typical implementation mistakes:** Unfiltered URL parameters passed to HTTP clients; following 30x redirects blindly.
- **Evidence establishing presence:** Outbound HTTP client calls in API handlers accepting unvalidated URL strings.
- **Safe testing methodology:** Static code search for outbound HTTP calls (`requests`, `urllib`, `fetch`, `axios`) + local mock-endpoint testing.
- **Recommended remediation:** Strict URL scheme/domain allowlists, private IP/loopback blocking post-DNS resolution, and redirect suppression.
- **Relevant CWE references:** `CWE-918`.

### API8:2023 — Security Misconfiguration
- **What it means:** Weak TLS, permissive CORS (`Access-Control-Allow-Origin` reflecting arbitrary origins), unnecessary HTTP methods, or verbose JSON error stack traces.
- **Why it matters:** Facilitates cross-origin data theft and leaks internal architecture details.
- **Typical implementation mistakes:** Returning Python/Node stack traces in `500` JSON responses; wildcard/reflected CORS with credentials; missing `Cache-Control: no-store` on sensitive endpoints.
- **Evidence establishing presence:** Middleware config or staging API error responses returning stack traces or overly broad CORS headers.
- **Safe testing methodology:** Config audit and controlled invalid-input tests in local/staging to verify sanitized error envelopes.
- **Recommended remediation:** Centralized exception handler returning opaque correlation IDs, strict origin allowlists, `Cache-Control: no-store` on PII endpoints.
- **Relevant CWE references:** `CWE-16`, `CWE-209`, `CWE-693`, `CWE-942`.

### API9:2023 — Improper Inventory Management
- **What it means:** Undocumented, deprecated (`/api/v1/`), or staging/debug endpoints remain deployed and reachable without modern auth, rate limits, or patches.
- **Why it matters:** Attackers target legacy API versions to bypass security fixes applied only to `/v2`.
- **Typical implementation mistakes:** Leaving legacy routes mounted alongside new ones; unauthenticated `/swagger`, `/metrics`, or `/debug` endpoints; stale OpenAPI specs.
- **Evidence establishing presence:** Route table vs. OpenAPI inventory comparison revealing undocumented or unauthenticated legacy endpoints.
- **Safe testing methodology:** Static route-tree extraction from codebase/gateway configs (never brute-force directories on production).
- **Recommended remediation:** Maintain an authoritative OpenAPI inventory, sunset deprecated versions cleanly, and block dev/debug routes outside local environments.
- **Relevant CWE references:** `CWE-1059`, `CWE-1188`.

### API10:2023 — Unsafe Consumption of APIs
- **What it means:** The backend blindly trusts data, redirects, or status codes from external/third-party APIs (LMS webhooks, SSO IdPs, biometric sync feeds) without schema validation, timeouts, or signature checks.
- **Why it matters:** Compromise or malformed data from an upstream integration can inject XSS/SQLi or corrupt attendance records downstream.
- **Typical implementation mistakes:** Skipping HMAC/JWS verification on incoming webhooks; trusting external JSON without schema validation; no HTTP client timeouts.
- **Evidence establishing presence:** Integration handlers parsing external API/webhook JSON straight into database writes or HTML templates without validation or signature verification.
- **Safe testing methodology:** Static review of third-party client/webhook handlers + local unit tests feeding malformed/oversized mock upstream payloads.
- **Recommended remediation:** Validate all third-party responses with strict schemas, verify webhook signatures/timestamps, enforce timeouts/circuit breakers, and treat upstream strings as untrusted.
- **Relevant CWE references:** `CWE-20`, `CWE-345`, `CWE-502`.
