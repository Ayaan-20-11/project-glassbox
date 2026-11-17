# Newton Security Research Lab — Phase 3: Advanced Security Research

> **Scope & Ethical Disclaimer:** All vulnerabilities, code paths, and behaviors analyzed in this document come strictly from the **isolated local simulation** (`/Users/ayaankapoor/.gemini/antigravity/scratch/newton_security_lab`) using synthetic accounts (`STU-1042`, `STU-1099`, `STU-1108`). Nothing in this document claims or implies that any vulnerability exists on the live Newton production portal.

---

## 1. Technical Implementation of Simulated Vulnerabilities

| ID | Simulated Weakness | CWE | OWASP Top 10 (2021) | Lab Implementation Location |
| --- | --- | --- | --- | --- |
| `SIM-001` | Reflected Cross-Site Scripting (XSS) | `CWE-79` | `A03:2021` Injection | `server.py:L175-L255`, `L393-L412` |
| `SIM-002` | Broken Object-Level Authorization (IDOR) | `CWE-639` | `A01:2021` Broken Access Control | `server.py:L359-L391` |
| `SIM-003` | Attendance Summary State-Desync (`0/0` Refresh Bug) | `CWE-662` | `A04:2021` Insecure Design | `static/app.js:L126-L137` |
| `SIM-004` | Ambiguous Unmarked Status (`-` vs. Absent Filter) | `CWE-1025` | `A04:2021` Insecure Design | `server.py:L135-L143` |
| `SIM-005` | Missing Defense-in-Depth Security Headers | `CWE-693` | `A05:2021` Security Misconfiguration | `server.py:L308-L318`, `L398-L407` |
| `SIM-006` | Excessive Metadata / PII Exposure in API Response | `CWE-200` | `A01:2021` / `A04:2021` | `server.py:L378-L390` |

---

## 2. Reflected Cross-Site Scripting (XSS) — Deep Dive (`SIM-001`)

### 2.1 Four-Stage Execution Lifecycle

1. **Input Reflection (`GET /lab/xss-preview?q=...`):**
   The HTTP query parameter `q` is URL-decoded by `parse_qs()` (`server.py:L343`, `L394`) and passed directly into `render_xss_preview_html(query, mode)` (`server.py:L175`). In `vulnerable` mode (`server.py:L178`), `query` is assigned verbatim to `rendered_query` and interpolated inside `<span id="echo">{rendered_query}</span>` (`server.py:L250`).
2. **Browser Parser Interpretation:**
   Because the response has `Content-Type: text/html; charset=utf-8` (`server.py:L408`), the browser's HTML tokenizer does not know which bytes came from the template and which came from `q`. Characters such as `<`, `>`, `"`, `'`, and `=` transition the parser out of `DATA` state (plain text) into `TAG OPEN` / `ATTRIBUTE VALUE` states, creating real DOM nodes (`<img>`, `<svg>`) and attaching inline event handlers (`onerror=...`, `onload=...`).
3. **Execution Context & Sandbox Containment:**
   In a real unprotected application served on the primary origin, injected scripts execute in the **same origin** as the logged-in dashboard, gaining access to `document.cookie` (unless `HttpOnly`), `localStorage`/`sessionStorage`, and authenticated `fetch()` calls.
   In this lab, the preview runs inside `<iframe id="xss-frame" ... sandbox="allow-scripts">` (`static/index.html:L103`) **without** `allow-same-origin`. The browser assigns the frame an **opaque origin** (serialized as `"null"`), so injected script cannot access the parent window's DOM, cookies, or storage. The parent's `message` listener (`static/app.js:L238-L247`) verifies both `event.source === els.xssFrame.contentWindow` and `event.origin === 'null'` before rendering the notification via `textContent`.
4. **Multi-Layer Remediation:**
   - **Layer 1 (Server Output Encoding):** Escape `&`, `<`, `>`, `"`, and `'` using `html.escape(query, quote=True)` (`server.py:L178`).
   - **Layer 2 (Safe Client DOM Sinks):** Never assemble HTML strings for `innerHTML` or `outerHTML`; write untrusted strings exclusively with `element.textContent` (`static/app.js:L205`, `L217`) or sanitize rich HTML via the Sanitizer API (`element.setHTML()`).
   - **Layer 3 (Content Security Policy):** Enforce `script-src 'none'` on static preview routes (`server.py:L403`) or nonce/hash-based `script-src 'self'` with `object-src 'none'` and `base-uri 'none'` (`server.py:L315-L317`) on interactive pages.

### 2.2 Line-by-Line Comparison (`server.py:L177-L178` & `L398-L407`)

```python
# VULNERABLE (mode != "secure")
# server.py:L178 — Unencoded string interpolated into HTML body
rendered_query = query
# server.py:L406-L407 — No Content-Security-Policy header emitted
self.send_header("X-Frame-Options", "SAMEORIGIN")
```

```python
# REMEDIATED (mode == "secure")
# server.py:L178 — Context-appropriate HTML entity escaping including quotes
rendered_query = html.escape(query, quote=True)
# server.py:L399-L404 — Defense-in-depth MIME sniffing & CSP script block
self.send_header("X-Content-Type-Options", "nosniff")
self.send_header("X-Frame-Options", "SAMEORIGIN")
self.send_header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'self'",
)
```

**Client-side reflection inspection (`static/app.js:L204-L217`):**
Even when displaying raw HTML snippets in the "Safe Source Inspection" panel, `app.js` uses `els.xssRawEcho.textContent = ...` rather than `innerHTML`, preventing secondary DOM-XSS in the parent console.

---

## 3. Broken Object-Level Authorization / IDOR (`SIM-002` & `SIM-006`)

### 3.1 Authentication vs. Authorization
- **Authentication** answers *"Who are you?"* (in the lab, `ACTIVE_SESSION["student_id"] == "STU-1042"`, `role == "student"`).
- **Object-Level Authorization** answers *"Does this authenticated principal own or have permission to access object `X`?"*

IDOR (`CWE-639`) occurs when an endpoint assumes that possessing a valid session token authorizes access to any object identifier (`?student_id=STU-1099`) supplied in a query parameter, path segment, or JSON body. Hiding another student's ID in the frontend UI provides **zero security** because any authenticated client can alter the request parameter directly.

### 3.2 Line-by-Line Comparison (`server.py:L359-L391`)

```python
# VULNERABLE (mode != "secure")
student_id = params.get("student_id", [ACTIVE_SESSION["student_id"]])[0]
record = SYNTHETIC_STUDENTS.get(student_id)
# Missing ownership check! Any valid session can read STU-1099 or STU-1108.
# Also returns full `record` including `email` PII (SIM-006 / CWE-200).
self._send_json(
    HTTPStatus.OK,
    {
        "mode": mode,
        "idor_exposed": student_id != ACTIVE_SESSION["student_id"],
        "authenticated_as": ACTIVE_SESSION["student_id"],
        "record": record,
    },
)
```

```python
# REMEDIATED (mode == "secure")
# 1. Server-side ownership check against trusted session state (never client claims)
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

# 2. Response DTO minimization: strip unneeded PII (`email`) before serialization
minimized = {k: v for k, v in record.items() if k != "email"}
self._send_json(HTTPStatus.OK, {"mode": mode, "authorized_owner": True, "record": minimized})
```

### 3.3 Production Architectural Guidance (RBAC + Ownership)
1. **Derive self-scoped queries from session:** Prefer `/api/me/attendance` using `session.student_id` instead of accepting `student_id` from the client for student views.
2. **Centralized policy middleware for multi-role endpoints:** When faculty or admins legitimately query a student record, enforce an explicit server-side policy:
   - `student` -> `target_student_id == session.student_id`
   - `faculty` -> `target_student_id in courses_taught_by(session.faculty_id)`
   - `admin` -> explicit `attendance:read_all` scope + audit logging.
3. **Use opaque/non-enumerable identifiers** (UUIDv4) as defense-in-depth—never as a substitute for authorization checks.

---

## 4. Session Isolation & Transport Hardening (`SIM-005`)

Strong session isolation ensures that neither cross-site requests (CSRF), same-host scripts (XSS), nor cross-origin framing (Clickjacking) can hijack or inspect an authenticated user's session:

1. **Cookie Attributes (`Set-Cookie`):**
   - `__Host-session=<opaque_random_token>; Path=/; Secure; HttpOnly; SameSite=Lax`
   - `HttpOnly` prevents `document.cookie` exfiltration if an XSS bug occurs elsewhere.
   - `__Host-` prefix forces `Secure`, `Path=/`, and disallows `Domain=` cookie-tossing from sibling subdomains.
   - `SameSite=Lax` mitigates cross-site state-changing CSRF requests while preserving top-level navigation.
2. **Avoid Storing Long-Lived Bearer Tokens in `localStorage`:**
   - Any script running in the origin can read `localStorage` (`OWASP ASVS V3.5` / `A07:2021`). Prefer `HttpOnly` server-managed session cookies.
3. **Server-Side Session Termination & `Clear-Site-Data`:**
   - Logout must invalidate the server-side session record/refresh token (not merely delete a client cookie) and emit `Clear-Site-Data: "cookies", "storage", "cache"`.
4. **Header Defense-in-Depth (`server.py:L308-L318`):**
   - `X-Content-Type-Options: nosniff` prevents MIME-confusion script execution.
   - `Referrer-Policy: strict-origin-when-cross-origin` prevents leaking URL query parameters across origins.
   - `Content-Security-Policy: frame-ancestors 'self'` + `X-Frame-Options: SAMEORIGIN` (or `'none'` / `DENY`) prevents clickjacking.
   - Strict `Access-Control-Allow-Origin` allowlisting (never `*` with `Access-Control-Allow-Credentials: true`).

---

## 5. Attendance Hydration Bug (`0/0` Refresh Desync) & Status Ambiguity (`SIM-003`, `SIM-004`)

### 5.1 Root-Cause Mechanisms for the Simulated `128/169 -> 0/0` Refresh Bug
Simulated in `static/app.js:L126-L137`, the pattern where an attendance summary shows `128/169 (76%)` on initial view but drops to `0/0 (0%)` after a hard page refresh—while the `189`-item lecture list stays visible—typically stems from one of four architectural flaws:

| Mechanism | Why Initial Load Works | Why Hard Refresh Shows `0/0` |
| --- | --- | --- |
| **Ephemeral Route / Store State** | SPA navigation passes summary totals via router state or parent store from the overview page. | Hard refresh wipes in-memory state; component initializes `{ attended: 0, total: 0 }` and never re-fetches summary independently. |
| **Split-Endpoint Auth/Timing Race** | Auth context is already warm during in-app navigation, so both `list` and `summary` calls succeed. | On reload, `summary` fires before token refresh completes (or hits a transient error) and its `catch` handler falls back to `{ attended: 0, total: 0 }`. |
| **Default-Zero Loading Fallback** | Data resolves fast or from memory cache. | Before async data resolves, `attended ?? 0` / `total ?? 0` renders `0/0` (`0%`) instead of a loading skeleton. |
| **Partial Cache Hydration** | Both slices are populated in memory. | Persisted storage hydrates the lecture array cleanly while the summary slice is stale, missing, or overwritten by default initial state. |

### 5.2 Ambiguous Unmarked Status (`'-'` vs. `Absent`, `SIM-004`)
In `SYNTHETIC_STUDENTS["STU-1042"]` (`server.py:L34-L45`), `attended = 128`, `counted_total = 169`, and `scheduled_total = 189` (leaving `20` unmarked/excluded sessions, including `8` in `YOGA-B1`). When a UI maps `attended === true` to `"Yes"` and *all non-true values* (`false`, `null`, `"UNMARKED"`, `"SCHEDULED"`) to a `"Session Attended = No"` filter while rendering `null`/`UNMARKED` as `"-"`, users cannot tell whether `"-"` lowers their percentage or is excluded from the denominator.

### 5.3 Concrete Remediation
1. **Separate `loading` / `error` / `ready` states:** Never coerce `null`/`undefined` counts to `0` prior to response resolution.
2. **Single authoritative payload or synchronized state:** Return `summary` (`attended`, `counted_total`, `scheduled_total`, `percentage`) alongside or deterministically derived from the canonical attendance dataset, with explicit `status` enums (`PRESENT`, `ABSENT`, `EXCUSED`, `UNMARKED`, `CANCELLED`).

---

## 6. OWASP Technical References

- **OWASP Top 10 (2021) — A01:2021 Broken Access Control:** Object-level authorization checks (`CWE-639`), least privilege, and PII minimization (`CWE-200`).
- **OWASP Top 10 (2021) — A03:2021 Injection (Cross-Site Scripting):** Context-aware output encoding, safe DOM sinks, and CSP (`CWE-79`).
- **OWASP Top 10 (2021) — A04:2021 Insecure Design:** Explicit state machines (`loading` vs. `0`), canonical attendance status enums (`CWE-662`, `CWE-1025`).
- **OWASP Top 10 (2021) — A05:2021 Security Misconfiguration:** Hardened HTTP response headers (`CSP`, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors`, `CWE-693`).
- **OWASP Top 10 (2021) — A07:2021 Identification and Authentication Failures:** `HttpOnly` / `Secure` / `SameSite` session cookies and server-side session invalidation (`CWE-384`, `CWE-613`).
- **OWASP API Security Top 10 (2023) — API1:2023 Broken Object Level Authorization & API3:2023 Broken Object Property Level Authorization:** Directly demonstrated by `SIM-002` and `SIM-006`.
