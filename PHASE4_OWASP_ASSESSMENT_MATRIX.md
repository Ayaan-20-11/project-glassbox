# Phase 4 — OWASP Top 10 (2021) Web Application Assessment Matrix

> **Disclaimer:** This matrix is a standardized assessment framework for authorized source-code audits, local simulations, and explicitly authorized staging environments. It makes **no claims** about the live Newton production portal.

---

## Summary Matrix

| ID | Category | Primary Focus | Relevant CWEs |
| --- | --- | --- | --- |
| `A01` | Broken Access Control | RBAC, IDOR, ownership enforcement, CORS | `CWE-200`, `CWE-284`, `CWE-285`, `CWE-639`, `CWE-862`, `CWE-863` |
| `A02` | Cryptographic Failures | TLS, password hashing, key/secret storage | `CWE-259`, `CWE-319`, `CWE-327`, `CWE-328`, `CWE-798`, `CWE-916` |
| `A03` | Injection | SQLi, XSS, SSTI, command/LDAP injection | `CWE-20`, `CWE-77`, `CWE-78`, `CWE-79`, `CWE-89`, `CWE-94` |
| `A04` | Insecure Design | Business logic, state machines, rate/abuse design | `CWE-209`, `CWE-256`, `CWE-501`, `CWE-662`, `CWE-840`, `CWE-1025` |
| `A05` | Security Misconfiguration | Headers, CSP, defaults, verbose errors, CORS | `CWE-16`, `CWE-209`, `CWE-611`, `CWE-693`, `CWE-942`, `CWE-1004` |
| `A06` | Vulnerable and Outdated Components | Third-party packages, transitive CVEs, EOL runtimes | `CWE-1035`, `CWE-1104`, `CWE-1395` |
| `A07` | Identification and Authentication Failures | Session lifecycle, JWT, MFA, reset flows | `CWE-287`, `CWE-384`, `CWE-521`, `CWE-613`, `CWE-640`, `CWE-798` |
| `A08` | Software and Data Integrity Failures | Deserialization, CI/CD, SRI, unsigned updates | `CWE-345`, `CWE-353`, `CWE-494`, `CWE-502`, `CWE-829` |
| `A09` | Security Logging and Monitoring Failures | Audit trails, alert hygiene, log injection/PII | `CWE-117`, `CWE-223`, `CWE-532`, `CWE-778` |
| `A10` | Server-Side Request Forgery (SSRF) | Outbound URL fetchers, webhooks, metadata access | `CWE-918` |

---

## Detailed Category Breakdown

### A01:2021 — Broken Access Control
- **What it means:** Authenticated or unauthenticated users can act outside their intended permissions—viewing, modifying, or deleting records belonging to other users or invoking privileged functions.
- **Why it matters:** Enables horizontal privilege escalation (e.g., student reading another student's records via IDOR) and vertical privilege escalation (e.g., student invoking faculty/admin endpoints).
- **Typical implementation mistakes:** Relying solely on frontend route hiding; trusting client-supplied `student_id` or `role` fields without server-side ownership checks; missing auth middleware on secondary endpoints; overly permissive CORS (`Access-Control-Allow-Origin: *` or reflected `Origin` with credentials).
- **Evidence establishing presence:** Backend route handler code lacking ownership/role checks, or a controlled test between two **synthetic** test accounts in an authorized staging/local lab returning `200 OK` instead of `403 Forbidden`.
- **Safe testing methodology:** Static route-by-route middleware auditing; isolated local/staging differential testing between synthetic Student, Faculty, and Admin accounts.
- **Recommended remediation:** Deny by default; derive user identity from verified server session; enforce centralized object-level and function-level authorization middleware; minimize returned DTO fields.
- **Relevant CWE references:** `CWE-200`, `CWE-284`, `CWE-285`, `CWE-639`, `CWE-862`, `CWE-863`.

### A02:2021 — Cryptographic Failures
- **What it means:** Sensitive data is exposed in transit or at rest due to missing encryption, weak algorithms, improper key management, or insecure token randomness.
- **Why it matters:** Leads to credential theft, session forgery, or bulk exposure of student/faculty personal records.
- **Typical implementation mistakes:** Plaintext or fast-hash (`MD5`/`SHA-1`) password storage; hardcoded JWT signing secrets or static keys in source/frontend bundles; missing `Secure` cookie flag; weak PRNG for reset tokens; unencrypted internal links.
- **Evidence establishing presence:** Source-code inspection showing weak hashes, hardcoded secrets, insecure cookie flags, or plaintext sensitive columns in database schemas.
- **Safe testing methodology:** Static secret and crypto-API audit; local config/TLS header inspection on staging; never extract or publish real secrets.
- **Recommended remediation:** Use `Argon2id` or `bcrypt` for passwords; store keys in a managed secrets vault; enforce TLS 1.2+/HSTS; set `Secure`, `HttpOnly`, `__Host-` on session cookies; use CSPRNG (`secrets`/`crypto.getRandomValues`).
- **Relevant CWE references:** `CWE-259`, `CWE-319`, `CWE-327`, `CWE-328`, `CWE-798`, `CWE-916`.

### A03:2021 — Injection
- **What it means:** Untrusted user input is concatenated into an interpreter command or markup (SQL, NoSQL, HTML/JS/XSS, OS shell, template engine) without parameterization or context-aware encoding.
- **Why it matters:** Allows arbitrary data extraction/tampering (SQLi), client-side script execution and session hijacking (XSS), or server takeover (RCE).
- **Typical implementation mistakes:** String interpolation in SQL/ORM raw queries; assigning untrusted strings to `innerHTML`, `dangerouslySetInnerHTML`, or unescaped HTML templates; missing context-specific output encoding.
- **Evidence establishing presence:** Tainted dataflow from request input to an unparameterized query sink or unsafe DOM sink confirmed via static analysis or harmless sandboxed proof-of-concept in local/staging tests.
- **Safe testing methodology:** Static taint tracing; isolated local/sandboxed iframe XSS verification (e.g., harmless DOM banner); parameterized query unit tests using synthetic inputs.
- **Recommended remediation:** Parameterized queries/prepared statements everywhere; context-aware output encoding (`html.escape`, `textContent`, `setHTML()`); strict CSP with nonces/hashes and `object-src 'none'`.
- **Relevant CWE references:** `CWE-20`, `CWE-77`, `CWE-78`, `CWE-79`, `CWE-89`, `CWE-94`.

### A04:2021 — Insecure Design
- **What it means:** Architectural or business-logic flaws where controls were never designed into workflows (e.g., attendance dispute/override workflows, race conditions, state-machine confusion, missing anti-automation).
- **Why it matters:** Even bug-free code implements broken rules—allowing inconsistent calculations, duplicate attendance submissions, or workflow bypasses.
- **Typical implementation mistakes:** Computing critical ratios client-side only; missing DB uniqueness constraints allowing duplicate records; ambiguous status enums (e.g., conflating `Unmarked` with `Absent`); missing concurrency locks/idempotency keys.
- **Evidence establishing presence:** Architectural/sequence diagrams, DB schema inspection lacking constraints, or deterministic logic tests demonstrating contradictory outputs from valid inputs.
- **Safe testing methodology:** Threat modeling, state-machine review, DB schema constraint audit, and local deterministic unit/concurrency tests on synthetic datasets.
- **Recommended remediation:** Enforce server-side canonical business rules, database uniqueness constraints, atomic transactions, explicit status enums, and fail-closed defaults.
- **Relevant CWE references:** `CWE-209`, `CWE-256`, `CWE-501`, `CWE-662`, `CWE-840`, `CWE-1025`.

### A05:2021 — Security Misconfiguration
- **What it means:** Insecure server, framework, cloud, or HTTP header defaults—verbose debug traces, unused endpoints, missing CSP/HSTS/nosniff, or permissive CORS.
- **Why it matters:** Gives attackers reconnaissance data (stack traces, versions) and removes browser-enforced defense-in-depth layers.
- **Typical implementation mistakes:** `DEBUG=True` in production configs; missing `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `frame-ancestors`; default credentials; open directory listing or exposed `.env`/source maps.
- **Evidence establishing presence:** Configuration file audit or HTTP response header inspection on an authorized staging target showing missing security headers or stack-trace leaks.
- **Safe testing methodology:** Read-only inspection of config files, Dockerfiles, and staging response headers; automated linter checks locally.
- **Recommended remediation:** Harden baseline configs via Infrastructure-as-Code, disable debug/source maps in prod, enforce strict security headers across all routes and error handlers.
- **Relevant CWE references:** `CWE-16`, `CWE-209`, `CWE-611`, `CWE-693`, `CWE-942`, `CWE-1004`.

### A06:2021 — Vulnerable and Outdated Components
- **What it means:** Relying on libraries, frameworks, container base images, or runtimes with known published vulnerabilities or end-of-life status.
- **Why it matters:** Known CVEs often have public exploit patterns that compromise apps even if first-party code is sound.
- **Typical implementation mistakes:** Unpinned dependencies, stale lockfiles, unpatched transitive dependencies, unmaintained frontend packages.
- **Evidence establishing presence:** Local SCA scan (`npm audit`, `pip-audit`, `trivy`) matching locked dependency versions to known CVE advisories.
- **Safe testing methodology:** Offline/local SBOM and lockfile vulnerability scanning only; verify reachability in code before prioritizing.
- **Recommended remediation:** Maintain automated dependency updates (Dependabot/Renovate), pin lockfiles, remove unused packages, and patch high-risk transitive CVEs promptly.
- **Relevant CWE references:** `CWE-1035`, `CWE-1104`, `CWE-1395`.

### A07:2021 — Identification and Authentication Failures
- **What it means:** Flaws in login, password policies, MFA, JWT verification, session rotation, or password reset allowing account takeover or session fixation.
- **Why it matters:** Compromising authentication grants full access to a victim's identity and privileges.
- **Typical implementation mistakes:** Accepting `alg: none` or unverified JWT signatures; failing to regenerate session IDs on login; storing tokens in `localStorage`; non-expiring sessions after logout; predictable or non-expiring reset tokens; missing brute-force lockouts.
- **Evidence establishing presence:** Source-code audit of auth middleware/token verification or staging tests with synthetic accounts showing stale sessions remaining valid post-logout.
- **Safe testing methodology:** Static review of auth/JWT/session code; controlled staging tests using synthetic credentials (no brute-force on production).
- **Recommended remediation:** Enforce `HttpOnly`/`Secure`/`SameSite` cookies, strict JWT `alg` & `iss`/`aud`/`exp` validation, session rotation on login, server-side revocation on logout, and rate-limited MFA/auth flows.
- **Relevant CWE references:** `CWE-287`, `CWE-384`, `CWE-521`, `CWE-613`, `CWE-640`, `CWE-798`.

### A08:2021 — Software and Data Integrity Failures
- **What it means:** Accepting code, serialized objects, updates, or third-party scripts without cryptographic integrity verification.
- **Why it matters:** Can lead to remote code execution via unsafe deserialization or supply-chain compromise via tampered CDN scripts/CI artifacts.
- **Typical implementation mistakes:** Using `pickle`/`yaml.load` on untrusted data; loading unpinned CDN scripts without `integrity` (SRI); unsigned webhooks; lax CI/CD pipeline permissions.
- **Evidence establishing presence:** Code search revealing unsafe deserializers, missing webhook HMAC verification, or `<script>` tags to external CDNs without SRI hashes.
- **Safe testing methodology:** Static code and CI/CD workflow review; template inspection for external script SRI attributes.
- **Recommended remediation:** Use JSON with strict schemas instead of native deserializers; verify HMAC signatures on webhooks; enforce SRI (`sha384`) on immutable third-party scripts; pin CI actions by commit SHA.
- **Relevant CWE references:** `CWE-345`, `CWE-353`, `CWE-494`, `CWE-502`, `CWE-829`.

### A09:2021 — Security Logging and Monitoring Failures
- **What it means:** Insufficient logging of security-relevant events (failed logins, `403` access denials, role changes), or unsafe logging of sensitive tokens/PII.
- **Why it matters:** Delays breach detection and prevents forensic reconstruction, while overly verbose logs can leak credentials.
- **Typical implementation mistakes:** Swallowing auth/exception errors silently; failing to log authorization denials; logging `Authorization` headers, cookies, or passwords; unescaped user input in logs (log forging).
- **Evidence establishing presence:** Logging middleware review showing missing audit events for auth/RBAC failures or plaintext secrets in log formatters.
- **Safe testing methodology:** Local/staging log inspection during synthetic failed-login and `403` tests.
- **Recommended remediation:** Emit structured security audit logs (timestamp, actor ID, action, outcome, correlation ID), redact credentials/PII at the logger boundary, and alert on anomalous bursts.
- **Relevant CWE references:** `CWE-117`, `CWE-223`, `CWE-532`, `CWE-778`.

### A10:2021 — Server-Side Request Forgery (SSRF)
- **What it means:** The backend fetches a user-supplied URL (e.g., profile avatar import, PDF/link preview, webhook callback) without validating destination host/IP.
- **Why it matters:** Allows attackers to pivot into internal VPC services, localhost admin ports, or cloud metadata endpoints (`169.254.169.254`).
- **Typical implementation mistakes:** Passing user URLs straight to `fetch`/`requests`/`urllib`; validating hostnames before DNS resolution (vulnerable to DNS rebinding or IPv6/octal encoding); following HTTP redirects into internal IPs.
- **Evidence establishing presence:** Code paths invoking HTTP clients on user-controlled URLs without allowlists or private-IP egress blocks.
- **Safe testing methodology:** Static code review of outbound HTTP calls; isolated local mock listener testing on localhost/staging (never targeting cloud metadata in production).
- **Recommended remediation:** Enforce strict domain allowlists, disable redirects, resolve DNS and block RFC1918/loopback/link-local IP ranges at the network/socket layer, and require IMDSv2.
- **Relevant CWE references:** `CWE-918`.
