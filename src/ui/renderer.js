const state = {
  data: null
};

// ---- Navigation ----
const railItems = document.querySelectorAll('.rail-item');
const views = document.querySelectorAll('.view');
const viewTitle = document.getElementById('view-title');

function setStatus(message, tone = 'ready') {
  railStatus.textContent = message;
  railStatus.dataset.tone = tone;
  document.querySelector('.status-dot').dataset.tone = tone;
}

railItems.forEach(item => {
  item.addEventListener('click', () => {
    railItems.forEach(i => i.classList.remove('active'));
    item.classList.add('active');

    const target = item.dataset.view;
    views.forEach(v => v.classList.add('hidden'));
    document.getElementById(`view-${target}`).classList.remove('hidden');
    viewTitle.textContent = item.querySelector('span:last-child').textContent;
  });
});

// ---- Scan button ----
const scanBtn = document.getElementById('scan-btn');
const railStatus = document.getElementById('rail-status');

scanBtn.addEventListener('click', async () => {
  scanBtn.disabled = true;
  scanBtn.innerHTML = '<span class="scan-symbol scan-spinner">o</span> Scanning';
  setStatus('Collecting telemetry...', 'working');

  try {
    const data = await window.sentinel.runScan();
    state.data = data;
    renderAll(data);
    setStatus(`Last scan ${new Date().toLocaleTimeString()}`, 'ready');
  } catch (err) {
    setStatus('Scan failed', 'error');
    console.error(err);
    showScanError(err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span class="scan-symbol">+</span> Run scan';
  }
});

// ---- Render everything once data comes back ----
function renderAll(data) {
  const metrics = {
    processes: (data.processes || []).length,
    connections: (data.connections || []).length,
    findings: (data.findings || []).length,
    drives: (data.drives || []).length
  };
  document.getElementById('metric-processes').textContent = metrics.processes;
  document.getElementById('metric-connections').textContent = metrics.connections;
  document.getElementById('metric-findings').textContent = metrics.findings;
  document.getElementById('metric-drives').textContent = metrics.drives;
  document.getElementById('posture-score').textContent = metrics.findings === 0 ? 'OK' : metrics.findings;
  document.getElementById('report-timestamp').textContent = `Captured ${new Date().toLocaleString()}`;
  setBar('bar-processes', metrics.processes, Math.max(metrics.processes, metrics.connections, 1));
  setBar('bar-connections', metrics.connections, Math.max(metrics.processes, metrics.connections, 1));
  setBar('bar-findings', metrics.findings, Math.max(metrics.findings, 5));
  setBar('bar-drives', metrics.drives, Math.max(metrics.drives, 5));
  renderActivity(metrics);
  renderFindings(data.findings || []);
  renderTable('table-processes', data.processes || [], p => [
    p.name, p.pid, p.cpu?.toFixed(1), `${p.memMB} MB`, p.path
  ], p => p.path);

  renderTable('table-startup', data.startup_items || [], s => [
    s.name, s.source, s.command
  ], null);

  renderTable('table-network', data.connections || [], c => [
    c.process, c.local_address, c.remote_address || '—', c.status
  ], null);

  renderTable('table-ports', data.listening_ports || [], p => [
    p.process, p.local_address
  ], null);

  renderStorage(data.drives || []);
}

// ---- Findings (Overview tab) ----
function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  const empty = document.getElementById('overview-empty');
  container.innerHTML = '';

  if (findings.length === 0) {
    empty.classList.add('hidden');
    container.innerHTML = '<div class="finding-clean">No findings — everything checked out clean.</div>';
    return;
  }

  empty.classList.add('hidden');

  findings.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card ${f.severity || 'info'}`;
    card.innerHTML = `
      <div class="finding-title">${escapeHtml(f.title || '')}</div>
      <div class="finding-detail">${escapeHtml(f.detail || '')}</div>
    `;
    container.appendChild(card);
  });
}

// ---- Generic table filler ----
// rowFn(item) => array of cell values to display, in column order
// pathFn(item) => the file path to open on click, or null if not clickable
function renderTable(tableId, items, rowFn, pathFn) {
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  tbody.innerHTML = '';

  items.forEach(item => {
    const tr = document.createElement('tr');
    const cells = rowFn(item);
    tr.innerHTML = cells.map(c => `<td>${escapeHtml(String(c ?? ''))}</td>`).join('');

    if (pathFn) {
      const targetPath = pathFn(item);
      if (targetPath && targetPath !== 'Unknown') {
        tr.addEventListener('click', () => {
          if (confirm(`Open the location of this file?\n\n${targetPath}`)) {
            window.sentinel.openLocation(targetPath);
          }
        });
      }
    }

    tbody.appendChild(tr);
  });
}

// ---- Storage tab ----
function renderStorage(drives) {
  const container = document.getElementById('storage-drives');
  container.innerHTML = '';

  drives.forEach(d => {
    const card = document.createElement('div');
    card.className = 'drive-card';
    card.innerHTML = `
      <div>${escapeHtml(d.drive)} — ${d.used_gb} GB used of ${d.total_gb} GB (${d.percent_used}%)</div>
      <div class="drive-bar"><div class="drive-bar-fill" style="width:${d.percent_used}%"></div></div>
    `;
    container.appendChild(card);
  });
}

// ---- Safety: escape any text before injecting into HTML ----
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function showScanError(message) {
  const empty = document.getElementById('overview-empty');
  empty.className = 'empty-state error-state';
  empty.innerHTML = `<strong>Scan engine unavailable</strong><span>${escapeHtml(message)}</span><small>Check that the bundled engine is present, then try again.</small>`;
  empty.classList.remove('hidden');
}

function setBar(id, value, maximum) {
  document.getElementById(id).style.width = `${Math.max(8, Math.round((value / maximum) * 100))}%`;
}

function renderActivity(metrics) {
  const points = document.querySelectorAll('.activity-visual span');
  const seed = [metrics.processes, metrics.connections, metrics.findings * 8, metrics.drives * 10];
  points.forEach((point, index) => {
    const signal = seed[index % seed.length];
    const variation = (index * 17 + signal) % 31;
    point.style.height = `${16 + variation}%`;
  });
}