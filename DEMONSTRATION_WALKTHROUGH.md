# Demonstration Walkthrough Script (10–15 Minutes)

> **Presenter Note:** State clearly at the start that **this is a 100% isolated local simulation (`127.0.0.1`) using synthetic accounts only**—never connected to Newton's live production portal.

---

## Pre-Flight Setup (Before Presenting)

1. Open a terminal in `/Users/ayaankapoor/.gemini/antigravity/scratch/newton_security_lab`.
2. Verify clean baseline & tests:
   ```bash
   python3 -m unittest discover -s . -p "test_*.py" -v
   ```
3. Start the local lab server:
   ```bash
   python3 server.py --port 8787
   ```
4. Open `http://127.0.0.1:8787` in your browser.

---

## Segment 1 — Architecture & Local Isolation (2 Minutes)
- **What to open:** Top header and KPI strip on `http://127.0.0.1:8787`.
- **What to point out:**
  - `ACTIVE SIM PERSONA: STU-1042 (Aarav Sharma)` — synthetic identity.
  - `VULNERABLE LAB` vs. `REMEDIATED` posture toggle.
  - Bottom `TERMINAL // EXECUTION TELEMETRY LOG` showing real-time event logging.
- **What to explain:** The Python server refuses non-localhost binds (`0.0.0.0` raises `ValueError`), contains zero external links, and lets us compare insecure vs. hardened code paths side-by-side.

---

## Segment 2 — Attendance Hydration Desync Simulation (1.5 Minutes)
- **What to click:** Click **`Simulate Refresh 0/0 Bug`** in the KPI strip.
- **Expected observation:** KPI card flips from `76% (128 / 169 counted)` to `0% (0 / 0 attended)` while a yellow **Mock Dashboard Security Alert** banner appears and the terminal logs the hydration race.
- **Technical explanation:** Demonstrates how a frontend store or loading-state fallback (`attended ?? 0`) can display `0/0` after a cold refresh even when the lecture list remains populated—without claiming a confirmed backend cause on the real portal.
- **Cleanup:** Click **`Restore`** and **`Dismiss`**.

---

## Segment 3 — Automated Lab Scanner (2 Minutes)
- **What to click:** Tab **`1. Console & Scanner`** -> click **`Run Simulated Audit Scan`**.
- **Expected observation:** Progress bar advances across 6 simulated audit phases, outputting cards for Session Isolation (`PASS`), XSS (`FAIL High`), IDOR (`FAIL Critical`), Hydration (`WARN Medium`), CSP (`FAIL Medium`), and PII Minimization (`WARN Low`).
- **Technical explanation:** Maps each simulated check to OWASP Top 10 / API Top 10 categories and explains why automated checks in this lab target local routes only.

---

## Segment 4 — Reflected XSS in a Sandboxed Iframe (2.5 Minutes)
- **What to click:** Tab **`2. Reflected XSS Lab`** -> click the **`SVG onload`** or **`IMG onerror`** preset button (or submit the prefilled payload).
- **Expected observation:**
  1. Inside the sandboxed `<iframe>`, the mock widget displays `[SIMULATED HARMLESS SECURITY ALERT]`.
  2. The parent dashboard raises the Mock Security Alert banner and logs `Sandboxed Reflected XSS Triggered` in the terminal.
  3. The right-hand **Safe Source Inspection** box prints the raw HTML tag safely using `textContent`.
- **Technical explanation:** Explain input reflection -> HTML parser tag/attribute transition -> why `<iframe sandbox="allow-scripts">` (without `allow-same-origin`) traps execution inside an opaque `"null"` origin so parent cookies/DOM stay protected.

---

## Segment 5 — Broken Access Control / IDOR Simulation (2 Minutes)
- **What to click:** Tab **`3. Broken Access Control`** -> click **`STU-1042 (Own Record)`**, then click **`STU-1099 (Synthetic Peer)`**.
- **Expected observation:** Status badge turns red **`200 OK (IDOR LEAK)`** and JSON reveals synthetic peer `Diya Verma (Synthetic Peer)` including `email` PII (`SIM-006`).
- **Technical explanation:** Trusts client-supplied `?student_id=` without verifying server-side session ownership (`CWE-639` / `API1:2023`).

---

## Segment 6 — Switching to Remediated Mode & Report Export (2.5 Minutes)
- **What to click:**
  1. Click **`REMEDIATED`** in the top-right posture toggle.
  2. Click **`STU-1099 (Synthetic Peer)`** in Tab 3 -> observe **`403 FORBIDDEN (BLOCKED)`**.
  3. Click **`STU-1042 (Own Record)`** -> observe `email` PII stripped (`SIM-006` fixed).
  4. Switch to Tab 2 (`Reflected XSS Lab`) -> observe payload rendered as inert escaped text (`&lt;img ...&gt;`) under `script-src 'none'`.
  5. Open Tab 4 (**Findings Panel**) and Tab 5 (**Assessment Report**) to show updated `Remediated` statuses and click **`Copy Markdown`** or **`Download .md Report`**.

---

## Segment 7 — Reversibility, Rollback & Emergency Reset (2 Minutes)
- **What to open:** Terminal in `/Users/ayaankapoor/.gemini/antigravity/scratch/newton_security_lab`.
- **What to run & explain:**
  1. Show immutable baseline protection:
     ```bash
     python3 lab_rollback.py init-baseline
     ```
     *(Observe `ERROR: Baseline already exists and is protected from overwrite.`)*
  2. Show change tracking & individual revert (`test_rollback.py` or `.lab_backups/CHANGELOG.md` inspection):
     ```bash
     cat .lab_backups/CHANGELOG.md
     ```
  3. Show how `python3 lab_rollback.py verify` checks SHA-256 hashes and runs all `8/8` automated tests (`python3 -m unittest discover -s . -p "test_*.py" -v`).
  4. Mention the one-command Emergency Reset (`python3 lab_rollback.py reset`) documented in [ROLLBACK_GUIDE.md](ROLLBACK_GUIDE.md) for restoring any experimental modifications cleanly.
