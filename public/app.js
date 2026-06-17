// ── Master Security State Registry ───────────────────────────────────────────
let currentSessionId = null; 
let currentActiveView = "overview";
let fullTelemetryCache = { network: [], processes: [], hashes: [], children: [], geo: [] };

// Chart.js Tracking Reference Map
let registeredCharts = { protocols: null, threats: null, timeline: null };

// ── Universal Deep Search Engine ─────────────────────────────────────────────
// Scans properties dynamically regardless of how deep they exist in JSON payloads
function evaluateDeepSearchString(object, queryToken) {
  if (!object) return false;
  const stringified = JSON.stringify(object).toLowerCase();
  return stringified.includes(queryToken.toLowerCase());
}

document.getElementById("global-search").addEventListener("input", (e) => {
  const query = e.target.value.trim().toLowerCase();
  
  if (query.length < 2) {
    renderNetworkLayer(fullTelemetryCache.network);
    renderProcessLayer(fullTelemetryCache.processes);
    renderHashLayer(fullTelemetryCache.hashes);
    return;
  }

  // Pivot filtering structures immediately across the data layers
  const filteredNet = fullTelemetryCache.network.filter(item => evaluateDeepSearchString(item, query));
  const filteredProc = fullTelemetryCache.processes.filter(item => evaluateDeepSearchString(item, query));
  const filteredHashes = fullTelemetryCache.hashes.filter(item => evaluateDeepSearchString(item, query));

  renderNetworkLayer(filteredNet);
  renderProcessLayer(filteredProc);
  renderHashLayer(filteredHashes);
});

// ── Structured Logical Query Parser ─────────────────────────────────────────
// Evaluates compound boolean and comparison conditions (e.g., remote_port==443)
function evaluateLogicalExpression(row, phrase) {
  if (!phrase) return true;
  try {
    const segments = phrase.split(/\s+(?:and|or)\s+/i);
    const expressionsPassed = [];
    
    // Fallback search normalization if standard comparative terms are missing
    if (!phrase.includes("==") && !phrase.includes("!=") && !phrase.includes(">") && !phrase.includes("<")) {
      return evaluateDeepSearchString(row, phrase);
    }

    const matches = phrase.match(/([a-zA-Z0-9_\.]+)\s*(==|!=|>|<)\s*([a-zA-Z0-9_\-\.\:\/]+)/);
    if (!matches) return true;

    const field = matches[1].trim();
    const operator = matches[2].trim();
    const value = matches[3].trim().replace(/['"]/g, "");

    let scopeTarget = row.connection || row.process || row;
    if (!scopeTarget || scopeTarget[field] === undefined) return false;

    let extractedValue = scopeTarget[field];

    if (operator === "==") return String(extractedValue).toLowerCase() === value.toLowerCase();
    if (operator === "!=") return String(extractedValue).toLowerCase() !== value.toLowerCase();
    if (operator === ">") return Number(extractedValue) > Number(value);
    if (operator === "<") return Number(extractedValue) < Number(value);
  } catch (e) {
    return true; 
  }
  return true;
}

document.getElementById("filter-net-query").addEventListener("input", (e) => {
  const phrase = e.target.value.trim();
  const targetedRows = fullTelemetryCache.network.filter(item => evaluateLogicalExpression(item, phrase));
  renderNetworkLayer(targetedRows);
});

// ── Analytics & Statistics Charting Engines ──────────────────────────────────
function buildTelemetryMetricsAndCharts(net, proc, hashes) {
  if (typeof Chart === "undefined") return; // Offline safety validation escape

  // 1. Protocols Pie Chart Extraction
  const protocolMap = {};
  net.forEach(n => {
    if (n.connection) {
      const p = n.connection.protocol_type || "UNKNOWN";
      protocolMap[p] = (protocolMap[p] || 0) + 1;
    }
  });

  if (registeredCharts.protocols) registeredCharts.protocols.destroy();
  const ctxProto = document.getElementById("chart-protocols").getContext("2d");
  registeredCharts.protocols = new Chart(ctxProto, {
    type: "pie",
    data: {
      labels: Object.keys(protocolMap),
      datasets: [{
        data: Object.values(protocolMap),
        backgroundColor: ["#38bdf8", "#00ffaa", "#ffb300", "#ff3366"]
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#94a3b8" } } } }
  });

  // 2. Threat Risk Breakdown (Clean vs Malicious)
  const threatMap = { CLEAN: 0, MALICIOUS: 0 };
  hashes.forEach(h => { threatMap[h.status] = (threatMap[h.status] || 0) + 1; });

  if (registeredCharts.threats) registeredCharts.threats.destroy();
  const ctxThreat = document.getElementById("chart-threats").getContext("2d");
  registeredCharts.threats = new Chart(ctxThreat, {
    type: "doughnut",
    data: {
      labels: Object.keys(threatMap),
      datasets: [{
        data: Object.values(threatMap),
        backgroundColor: ["#00ffaa", "#ff3366"]
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#94a3b8" } } } }
  });

  // 3. Volumetric Traffic Chart (Aggregation grouped across timeline nodes)
  const timeBuckets = {};
  net.slice(-100).forEach(n => {
    if (!n.timestamp) return;
    const secondMarker = n.timestamp.split("T")[1]?.substring(0, 5) || "Live Tracking";
    timeBuckets[secondMarker] = (timeBuckets[secondMarker] || 0) + 1;
  });

  if (registeredCharts.timeline) registeredCharts.timeline.destroy();
  const ctxTime = document.getElementById("chart-traffic-timeline").getContext("2d");
  registeredCharts.timeline = new Chart(ctxTime, {
    type: "line",
    data: {
      labels: Object.keys(timeBuckets),
      datasets: [{
        label: "Interceptions over Timeline Window",
        data: Object.values(timeBuckets),
        borderColor: "#38bdf8",
        backgroundColor: "rgba(56, 189, 248, 0.1)",
        fill: true,
        tension: 0.3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } }
      },
      plugins: { legend: { labels: { color: "#94a3b8" } } }
    }
  });
}

// ── Forensic Core Pipeline Sourcing ──────────────────────────────────────────
function getApiPath(fileKey) {
  if (currentSessionId) return `/api/session/${currentSessionId}/${fileKey}`;
  return `/api/live/${fileKey}`;
}

async function evaluateDataPipeline() {
  try {
    const [net, proc, hashes, children, geo] = await Promise.all([
      fetch(getApiPath("network")).then(r => r.json()).catch(() => []),
      fetch(getApiPath("process")).then(r => r.json()).catch(() => []),
      fetch(getApiPath("hashes")).then(r => r.json()).catch(() => []),
      fetch(getApiPath("children")).then(r => r.json()).catch(() => []),
      fetch(getApiPath("geo")).then(r => r.json()).catch(() => []),
    ]);

    fullTelemetryCache = { network: net, processes: proc, hashes: hashes, children: children, geo: geo };

    renderOverviewMetrics(net, proc, hashes);
    
    // Prevent overriding real-time selections during search inputs
    if (document.getElementById("global-search").value.trim().length < 2) {
      renderNetworkLayer(net);
      renderProcessLayer(proc);
      renderHashLayer(hashes);
    }
    
    renderLineageTree(children, proc);
    buildTelemetryMetricsAndCharts(net, proc, hashes);
  } catch (error) {
    console.error("Telemetry sync error on log capture cycle", error);
  }
}

// ── Navigation Framework ─────────────────────────────────────────────────────
document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", (e) => {
    document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    
    link.classList.add("active");
    currentActiveView = link.dataset.target;
    document.getElementById(`panel-${currentActiveView}`).classList.add("active");
    
    if (currentActiveView === "history") fetchHistoricalSessions();
    else evaluateDataPipeline();
  });
});

// ── Engine Daemon Supervisors ────────────────────────────────────────────────
document.getElementById("btn-start").addEventListener("click", async () => {
  await fetch("/api/scan/start", { method: "POST" });
  currentSessionId = null;
  checkEngineStatus();
});

document.getElementById("btn-stop").addEventListener("click", async () => {
  await fetch("/api/scan/stop", { method: "POST" });
  checkEngineStatus();
});

async function checkEngineStatus() {
  const status = await fetch("/api/status").then(r => r.json());
  const pulse = document.getElementById("engine-pulse");
  if (status.running) {
    pulse.className = "pulse-indicator";
    document.getElementById("session-lbl").textContent = `ENGAGED: ${status.session_dir}`;
  } else {
    pulse.className = "pulse-indicator idle";
    document.getElementById("session-lbl").textContent = "ENGINE IDLE";
  }
}

// ── Presentation Layout Generators ───────────────────────────────────────────
function renderOverviewMetrics(net, proc, hashes) {
  document.getElementById("count-net").textContent = net.length;
  document.getElementById("count-proc").textContent = proc.length;
  document.getElementById("count-hash").textContent = hashes.length;

  let threats = hashes.filter(h => h.status === "MALICIOUS").length;
  document.getElementById("count-threat").textContent = threats;
  document.getElementById("count-threat").style.color = threats > 0 ? "var(--accent-alert)" : "var(--accent-neon)";

  const outbounds = net.filter(e => e.connection && e.connection.direction === "OUTBOUND");
  const tbody = document.getElementById("table-overview-net");
  tbody.innerHTML = outbounds.slice(-8).reverse().map(e => `
    <tr onclick="launchForensicDrawer('Network Node Target', ${styleJsonRow(e)})">
      <td>${formatTime(e.timestamp)}</td>
      <td><span class="badge ${e.action==='OPEN'?'badge-neon':'badge-alert'}">${e.action}</span></td>
      <td>${e.connection.remote_ip}</td>
      <td>${e.connection.remote_port}</td>
      <td><span class="badge badge-nominal">${e.connection.protocol_type}</span></td>
      <td>${e.connection.status || "UNKNOWN"}</td>
    </tr>
  `).join("");
}

function renderNetworkLayer(rows) {
  const tbody = document.getElementById("table-network-all");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No logs match the current query filter parameter.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.slice(-150).reverse().map(e => `
    <tr onclick="launchForensicDrawer('Network Stream Payload', ${styleJsonRow(e)})">
      <td>${formatTime(e.timestamp)}</td>
      <td><span class="badge ${e.action==='OPEN'?'badge-neon':'badge-alert'}">${e.action}</span></td>
      <td>${e.connection.local_ip}:${e.connection.local_port}</td>
      <td>${e.connection.remote_ip || "—"}:${e.connection.remote_port || "—"}</td>
      <td>${e.connection.protocol_type}</td>
      <td>${e.connection.direction}</td>
      <td>${e.connection.status || "STATELESS"}</td>
    </tr>
  `).join("");
}

function renderProcessLayer(rows) {
  const tbody = document.getElementById("table-processes-all");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Process registry workspace target clear.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(e => {
    const p = e.process || {};
    const indicators = p.threat_flags && p.threat_flags.length 
      ? p.threat_flags.map(f => `<span class="badge badge-alert">${f}</span>`).join(" ")
      : `<span style="color:var(--text-muted)">NOMINAL</span>`;
    return `
      <tr onclick="launchForensicDrawer('Execution Context Node', ${styleJsonRow(e)})">
        <td>${formatTime(e.timestamp)}</td>
        <td>${p.pid}</td>
        <td style="color:var(--accent-nominal); font-weight:600;">${p.name}</td>
        <td>${p.username || "SYSTEM"}</td>
        <td title="${p.path || ''}">${p.path || "Memory Core Image"}</td>
        <td>${indicators}</td>
      </tr>
    `;
  }).join("");
}

function renderHashLayer(rows) {
  const tbody = document.getElementById("table-hashes-all");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">Signature array evaluations missing.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr onclick="launchForensicDrawer('Cryptographic Context Signatures', ${styleJsonRow(r)})">
      <td>${formatTime(r.timestamp)}</td>
      <td>${r.file_name}</td>
      <td style="color:var(--text-muted); font-size:11px;">${r.sha256}</td>
      <td><span class="badge ${r.status==='MALICIOUS'?'badge-alert':'badge-neon'}">${r.status}</span></td>
    </tr>
  `).join("");
}

function renderLineageTree(children, processes) {
  const container = document.getElementById("tree-container");
  if (!children.length) {
    container.innerHTML = `<div style="color:var(--text-muted)">Process relationship link paths unpopulated.</div>`;
    return;
  }
  const nameRegistry = {};
  processes.forEach(p => { if(p.process) nameRegistry[p.process.process_guid] = p.process.name; });

  let htmlTree = `<div class="tree-node">`;
  children.slice(0, 30).forEach(c => {
    const parentName = nameRegistry[c.parent_process_guid] || "Unknown Parent context";
    htmlTree += `
      <div class="tree-leaf" onclick="launchForensicDrawer('Process Lineage Pivot', ${styleJsonRow(c)})">
        <span style="color:var(--text-muted);">${parentName}</span> ➔ <span style="color:var(--accent-neon); font-weight:700;">Child Spawned:</span> 
        <span>${c.child_name} (PID: ${c.child_pid})</span>
      </div>
    `;
  });
  htmlTree += `</div>`;
  container.innerHTML = htmlTree;
}

// ── History Platform Indexer ──────────────────────────────────────────────────
async function fetchHistoricalSessions() {
  const sessions = await fetch("/api/sessions").then(r => r.json());
  const tbody = document.getElementById("table-history-sessions");
  if (!sessions.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No logs found on system storage.</td></tr>`;
    return;
  }
  tbody.innerHTML = sessions.map(s => `
    <tr onclick="pivotToSession('${s.id}')">
      <td style="color:var(--accent-nominal); font-weight:600;">${s.id}</td>
      <td>${new Date(s.started_at).toLocaleString()}</td>
      <td>${s.network_count} Connections</td>
      <td>${s.process_count} Images</td>
      <td><span class="badge ${s.has_threats?'badge-alert':'badge-neon'}">${s.threat_count} Alerts</span></td>
    </tr>
  `).join("");
}

function pivotToSession(id) {
  currentSessionId = id;
  document.querySelector('[data-target="overview"]').click();
}

// ── Cross-Comparison Matrix Engine ───────────────────────────────────────────
document.getElementById("btn-execute-compare").addEventListener("click", async () => {
  const sessionAlpha = document.getElementById("comp-session-a").value.trim();
  const sessionBeta = document.getElementById("comp-session-b").value.trim();

  if(!sessionAlpha || !sessionBeta) return;

  const alphaProc = await fetch(`/api/session/${sessionAlpha}/process`).then(r=>r.json()).catch(()=>[]);
  const betaProc = await fetch(`/api/session/${sessionBeta}/process`).then(r=>r.json()).catch(()=>[]);

  const extractNames = (list) => new Set(list.map(p => p.process ? p.process.name : null).filter(Boolean));
  const alphaSet = extractNames(alphaProc);
  const betaSet = extractNames(betaProc);

  const alphaDiff = [...alphaSet].filter(x => !betaSet.has(x));
  const betaDiff = [...betaSet].filter(x => !alphaSet.has(x));

  document.getElementById("matrix-alpha-diff").innerHTML = alphaDiff.length 
    ? alphaDiff.map(n => `<li style="color:var(--accent-alert)">[-] Absent inside Beta Target: ${n}</li>`).join("")
    : `<li>Identity variance set matches fully.</li>`;

  document.getElementById("matrix-beta-diff").innerHTML = betaDiff.length 
    ? betaDiff.map(n => `<li style="color:var(--accent-neon)">[+] Unique inside Beta Signal: ${n}</li>`).join("")
    : `<li>Identity variance set matches fully.</li>`;
});

// ── Context Forensic Drawer Overlay System ───────────────────────────────────
function styleJsonRow(obj) {
  return JSON.stringify(obj).replace(/"/g, '&quot;');
}

function launchForensicDrawer(title, rawRowData) {
  document.getElementById("drawer-title-id").textContent = title;
  document.getElementById("forensic-drawer").classList.add("open");
  document.getElementById("drawer-json-pre").textContent = JSON.stringify(rawRowData, null, 2);

  let summaryMarkup = `<div style="display:flex; flex-direction:column; gap:12px;">`;
  let targetNode = rawRowData.connection || rawRowData.process || rawRowData;
  for(const [key, val] of Object.entries(targetNode)) {
    if(typeof val !== 'object') {
      summaryMarkup += `<div><strong style="color:var(--text-muted)">${key}:</strong> <span style="font-family:var(--font-mono)">${val}</span></div>`;
    }
  }
  summaryMarkup += `</div>`;
  document.getElementById("drawer-content-summary").innerHTML = summaryMarkup;
}

document.getElementById("drawer-close-btn").addEventListener("click", () => {
  document.getElementById("forensic-drawer").classList.remove("open");
});

document.querySelectorAll(".drawer-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".drawer-tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    if(tab.dataset.tab === "json") {
      document.getElementById("drawer-content-json").style.display = "block";
      document.getElementById("drawer-content-summary").style.display = "none";
    } else {
      document.getElementById("drawer-content-json").style.display = "none";
      document.getElementById("drawer-content-summary").style.display = "block";
    }
  });
});

function formatTime(timestampStr) {
  if (!timestampStr) return "—";
  const dateObj = new Date(timestampStr);
  return isNaN(dateObj) ? timestampStr : dateObj.toLocaleTimeString();
}

// ── Polling Automation ───────────────────────────────────────────────────────
setInterval(() => {
  checkEngineStatus();
  if (!currentSessionId && currentActiveView !== "history" && currentActiveView !== "compare") {
    evaluateDataPipeline();
  }
}, 3000);

checkEngineStatus();
evaluateDataPipeline();