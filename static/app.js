(() => {
  'use strict';

  const state = {
    mode: 'vulnerable',
    severityFilter: 'ALL',
    findings: [],
  };

  const els = {
    modeVuln: document.getElementById('mode-vuln'),
    modeSecure: document.getElementById('mode-secure'),
    kpiPct: document.getElementById('kpi-pct'),
    kpiRatio: document.getElementById('kpi-ratio'),
    kpiPosture: document.getElementById('kpi-posture'),
    kpiOpenCount: document.getElementById('kpi-open-count'),
    btnSimRefresh: document.getElementById('btn-sim-refresh-bug'),
    btnRestoreKpi: document.getElementById('btn-restore-kpi'),
    alertBanner: document.getElementById('mock-alert-banner'),
    alertText: document.getElementById('mock-alert-text'),
    dismissAlert: document.getElementById('dismiss-alert'),
    tabs: Array.from(document.querySelectorAll('[role="tab"]')),
    panels: Array.from(document.querySelectorAll('[role="tabpanel"]')),
    btnRunScan: document.getElementById('btn-run-scan'),
    scanStatusText: document.getElementById('scan-status-text'),
    scanPercent: document.getElementById('scan-percent'),
    scanProgressbar: document.getElementById('scan-progressbar'),
    scanProgressFill: document.getElementById('scan-progress-fill'),
    scanChecksGrid: document.getElementById('scan-checks-grid'),
    xssForm: document.getElementById('xss-form'),
    xssInput: document.getElementById('xss-input'),
    xssFrame: document.getElementById('xss-frame'),
    xssRawEcho: document.getElementById('xss-raw-echo'),
    xssDefenseNote: document.getElementById('xss-defense-note'),
    idorButtons: Array.from(document.querySelectorAll('.idor-target')),
    idorHttpStatus: document.getElementById('idor-http-status'),
    idorResponseBox: document.getElementById('idor-response-box'),
    sevButtons: Array.from(document.querySelectorAll('.sev-filter')),
    findingsTbody: document.getElementById('findings-tbody'),
    findingDetail: document.getElementById('finding-detail'),
    reportPreview: document.getElementById('report-preview'),
    btnCopyReport: document.getElementById('btn-copy-report'),
    btnDownloadReport: document.getElementById('btn-download-report'),
    terminalLog: document.getElementById('terminal-log'),
    btnClearLog: document.getElementById('btn-clear-log'),
  };

  function logLine(level, message) {
    const line = document.createElement('div');
    const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
    line.className = 'log-line';
    if (level === 'ALERT') line.classList.add('log-alert');
    if (level === 'FAIL') line.classList.add('log-fail');
    line.textContent = `[${now}] [${level}] ${message}`;
    els.terminalLog.appendChild(line);
    els.terminalLog.scrollTop = els.terminalLog.scrollHeight;
  }

  function showMockAlert(message) {
    els.alertText.textContent = message;
    els.alertBanner.hidden = false;
  }

  function selectTab(targetTab) {
    const index = els.tabs.indexOf(targetTab);
    if (index === -1) return;
    els.tabs.forEach((tab, idx) => {
      const selected = idx === index;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      const panel = els.panels[idx];
      if (panel) {
        panel.hidden = !selected;
        if (selected) {
          panel.setAttribute('tabindex', '0');
        } else {
          panel.removeAttribute('tabindex');
        }
      }
    });
  }

  els.tabs.forEach((tab, idx) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (event) => {
      let nextIdx = null;
      if (event.key === 'ArrowRight') nextIdx = (idx + 1) % els.tabs.length;
      if (event.key === 'ArrowLeft') nextIdx = (idx - 1 + els.tabs.length) % els.tabs.length;
      if (event.key === 'Home') nextIdx = 0;
      if (event.key === 'End') nextIdx = els.tabs.length - 1;
      if (nextIdx !== null) {
        event.preventDefault();
        selectTab(els.tabs[nextIdx]);
        els.tabs[nextIdx].focus();
      }
    });
  });

  function updateModeUI() {
    const isVuln = state.mode === 'vulnerable';
    els.modeVuln.setAttribute('aria-pressed', String(isVuln));
    els.modeSecure.setAttribute('aria-pressed', String(!isVuln));
    els.kpiPosture.textContent = isVuln ? 'VULNERABLE' : 'REMEDIATED';
    els.kpiPosture.style.color = isVuln ? 'var(--red)' : 'var(--green)';
    els.btnDownloadReport.href = `/api/report?mode=${encodeURIComponent(state.mode)}&format=markdown`;
    loadFindings();
    loadReport();
    runXssPreview(els.xssInput.value);
    logLine('INFO', `Switched local lab posture to ${state.mode.toUpperCase()} mode.`);
  }

  els.modeVuln.addEventListener('click', () => {
    state.mode = 'vulnerable';
    updateModeUI();
  });

  els.modeSecure.addEventListener('click', () => {
    state.mode = 'secure';
    updateModeUI();
  });

  els.dismissAlert.addEventListener('click', () => {
    els.alertBanner.hidden = true;
  });

  els.btnSimRefresh.addEventListener('click', () => {
    els.kpiPct.textContent = '0%';
    els.kpiRatio.textContent = '0 / 0 attended (189 scheduled list retained)';
    showMockAlert('Simulated Refresh Desync: Summary widget fell back to 0/0 while 189 lectures remained loaded.');
    logLine('ALERT', 'Simulated cold-refresh hydration race: attendance summary collapsed to 0/0 (0%).');
  });

  els.btnRestoreKpi.addEventListener('click', () => {
    els.kpiPct.textContent = '76%';
    els.kpiRatio.textContent = '128 / 169 counted (189 scheduled)';
    logLine('INFO', 'Restored synthetic KPI summary to 128/169 (76%).');
  });

  function renderScanChecks(checks) {
    els.scanChecksGrid.replaceChildren();
    checks.forEach((item) => {
      const card = document.createElement('div');
      card.className = 'scan-item';

      const label = document.createElement('span');
      label.textContent = `[${item.step}/6] ${item.check}`;

      const badge = document.createElement('span');
      badge.className = 'status-badge';
      if (item.result.startsWith('FAIL')) badge.classList.add('fail');
      if (item.result.startsWith('WARN')) badge.classList.add('warn');
      badge.textContent = item.result;

      card.append(label, badge);
      els.scanChecksGrid.appendChild(card);
    });
  }

  async function runScanner() {
    els.btnRunScan.disabled = true;
    els.scanChecksGrid.replaceChildren();
    const phases = [
      'Checking local session & cookie isolation...',
      'Probing sandboxed XSS reflection sink...',
      'Testing object-level access control (IDOR)...',
      'Inspecting attendance summary hydration logic...',
      'Auditing HTTP response security headers...',
      'Compiling final lab severity inventory...',
    ];

    for (let i = 0; i < phases.length; i += 1) {
      const pct = Math.round(((i + 1) / phases.length) * 90);
      els.scanStatusText.textContent = phases[i];
      els.scanPercent.textContent = `${pct}%`;
      els.scanProgressbar.setAttribute('aria-valuenow', String(pct));
      els.scanProgressFill.style.width = `${pct}%`;
      logLine('SCAN', phases[i]);
      await new Promise((r) => setTimeout(r, 180));
    }

    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: state.mode }),
    });
    const data = await res.json();

    els.scanStatusText.textContent = `Audit complete (${state.mode.toUpperCase()} profile).`;
    els.scanPercent.textContent = '100%';
    els.scanProgressbar.setAttribute('aria-valuenow', '100');
    els.scanProgressFill.style.width = '100%';
    renderScanChecks(data.checks || []);
    state.findings = data.findings || [];
    renderFindings();
    els.btnRunScan.disabled = false;
    logLine('INFO', `Scanner finished: ${state.findings.length} entries evaluated.`);
  }

  els.btnRunScan.addEventListener('click', runScanner);

  function runXssPreview(rawQuery) {
    const encodedQ = encodeURIComponent(rawQuery);
    els.xssFrame.src = `/lab/xss-preview?q=${encodedQ}&mode=${encodeURIComponent(state.mode)}`;
    if (state.mode === 'vulnerable') {
      els.xssRawEcho.textContent = `<span id="echo">${rawQuery}</span>`;
      els.xssDefenseNote.textContent =
        '// VULNERABLE: Raw query interpolated directly into HTML.\n' +
        '// Inside the sandboxed frame, event handlers / script tags execute.\n' +
        '// REMEDIATION: Switch to REMEDIATED mode to apply html.escape() + strict CSP.';
    } else {
      const escaped = rawQuery
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
      els.xssRawEcho.textContent = `<span id="echo">${escaped}</span>`;
      els.xssDefenseNote.textContent =
        '// SECURE: Server escapes HTML entities and sets:\n' +
        '// Content-Security-Policy: script-src \'none\';\n' +
        '// Client inspection uses textContent instead of innerHTML.';
    }
    logLine('XSS-LAB', `Loaded sandboxed preview (${state.mode}) for query: ${rawQuery}`);
  }

  els.xssForm.addEventListener('submit', (event) => {
    event.preventDefault();
    runXssPreview(els.xssInput.value);
  });

  document.querySelectorAll('[data-xss-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      els.xssInput.value = btn.getAttribute('data-xss-preset') || '';
      runXssPreview(els.xssInput.value);
    });
  });

  window.addEventListener('message', (event) => {
    // Sandboxed iframe without allow-same-origin has opaque origin serialized as "null".
    if (event.source !== els.xssFrame.contentWindow || event.origin !== 'null') return;
    const data = event.data;
    if (data && data.type === 'xss-sim-triggered') {
      const msg = `Sandboxed Reflected XSS Triggered: ${String(data.message || '')}`;
      showMockAlert(msg);
      logLine('ALERT', msg);
    }
  });

  async function runIdorTest(studentId) {
    const url = `/api/student/attendance?student_id=${encodeURIComponent(studentId)}&mode=${encodeURIComponent(state.mode)}`;
    const res = await fetch(url);
    const data = await res.json();

    els.idorHttpStatus.className = 'status-badge';
    if (res.status === 403) {
      els.idorHttpStatus.textContent = '403 FORBIDDEN (BLOCKED)';
      logLine('PASS', `IDOR check blocked cross-account access to ${studentId} (HTTP 403).`);
    } else if (data.idor_exposed) {
      els.idorHttpStatus.classList.add('fail');
      els.idorHttpStatus.textContent = '200 OK (IDOR LEAK)';
      showMockAlert(`Simulated Broken Access Control: STU-1042 read synthetic peer ${studentId} record.`);
      logLine('FAIL', `Simulated IDOR exposed synthetic record ${studentId} while logged in as STU-1042.`);
    } else {
      els.idorHttpStatus.textContent = '200 OK (AUTHORIZED)';
      logLine('INFO', `Authorized read of own synthetic record ${studentId}.`);
    }
    els.idorResponseBox.textContent = JSON.stringify(data, null, 2);
  }

  els.idorButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-student-id') || 'STU-1042';
      runIdorTest(target);
    });
  });

  function renderFindingDetail(finding) {
    els.findingDetail.replaceChildren();
    const heading = document.createElement('h3');
    heading.textContent = `${finding.id} — ${finding.title}`;

    const meta = document.createElement('p');
    meta.className = 'muted';
    meta.textContent = `Severity: ${finding.severity} | CWE: ${finding.cwe} | Component: ${finding.component} | Status: ${finding.status}`;

    const desc = document.createElement('p');
    desc.textContent = `Analysis: ${finding.description}`;

    const rem = document.createElement('p');
    rem.textContent = `Remediation: ${finding.remediation}`;

    els.findingDetail.append(heading, meta, desc, rem);
  }

  function renderFindings() {
    els.findingsTbody.replaceChildren();
    const openCount = state.findings.filter((f) => f.status.startsWith('Open')).length;
    els.kpiOpenCount.textContent = `${openCount} active simulated flaws`;

    const filtered = state.findings.filter(
      (f) => state.severityFilter === 'ALL' || f.severity === state.severityFilter
    );

    filtered.forEach((f) => {
      const tr = document.createElement('tr');
      tr.tabIndex = 0;

      const tdId = document.createElement('td');
      tdId.textContent = f.id;

      const tdTitle = document.createElement('td');
      tdTitle.textContent = f.title;

      const tdSev = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = `sev-pill sev-${f.severity}`;
      pill.textContent = f.severity;
      tdSev.appendChild(pill);

      const tdCwe = document.createElement('td');
      tdCwe.textContent = f.cwe;

      const tdComp = document.createElement('td');
      tdComp.textContent = f.component;

      const tdStatus = document.createElement('td');
      tdStatus.textContent = f.status;

      tr.append(tdId, tdTitle, tdSev, tdCwe, tdComp, tdStatus);
      tr.addEventListener('click', () => renderFindingDetail(f));
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          renderFindingDetail(f);
        }
      });
      els.findingsTbody.appendChild(tr);
    });
  }

  els.sevButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      state.severityFilter = btn.getAttribute('data-sev') || 'ALL';
      els.sevButtons.forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
      renderFindings();
    });
  });

  async function loadFindings() {
    const res = await fetch(`/api/findings?mode=${encodeURIComponent(state.mode)}`);
    const data = await res.json();
    state.findings = data.findings || [];
    renderFindings();
  }

  async function loadReport() {
    const res = await fetch(`/api/report?mode=${encodeURIComponent(state.mode)}&format=json`);
    const data = await res.json();
    els.reportPreview.textContent = data.markdown || '';
  }

  els.btnCopyReport.addEventListener('click', async () => {
    await navigator.clipboard.writeText(els.reportPreview.textContent);
    logLine('INFO', 'Copied simulated security assessment Markdown report to clipboard.');
  });

  els.btnClearLog.addEventListener('click', () => {
    els.terminalLog.replaceChildren();
    logLine('INFO', 'Terminal telemetry cleared.');
  });

  logLine('INFO', 'Newton Security Research Lab initialized on 127.0.0.1 (isolated simulation).');
  updateModeUI();
})();
