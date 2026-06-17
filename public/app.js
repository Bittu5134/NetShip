let currentSessionId = null; 
let currentActiveView = "overview";
let fullTelemetryCache = { network: [], processes: [], hashes: [], children: [], geo: [] };
let registeredCharts = { protocols: null, threats: null, timeline: null };
let leafletMapInstance = null;
let leafletMarkerLayerGroup = null;

// Leaflet Dark-Mode Base Layer Initialization
function initializeGeospatialEngine() {
  if (leafletMapInstance) return;
  
  // Build map canvas target node explicitly inside panel target bounding frame
  leafletMapInstance = L.map('map-canvas-container').setView([20.0, 0.0], 2);
  
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 20
  }).addTo(leafletMapInstance);

  leafletMarkerLayerGroup = L.layerGroup().addTo(leafletMapInstance);
}

function processGeospatialPoints(geoRows) {
  if (!leafletMarkerLayerGroup) return;
  leafletMarkerLayerGroup.clearLayers();

  geoRows.forEach(loc => {
    if (!loc.lat || !loc.lon) return;

    // Pulse Alert Color adjustments matched against observed perimeter breaches
    const markerOptions = {
      radius: 6,
      fillColor: "#ff3366",
      color: "#fff",
      weight: 1,
      opacity: 1,
      fillOpacity: 0.8
    };

    const marker = L.circleMarker([loc.lat, loc.lon], markerOptions);
    marker.bindPopup(`
      <div style="color:#000; font-family:monospace; font-size:11px;">
        <strong>IP:</strong> ${loc.ip}<br>
        <strong>Geo:</strong> ${loc.city}, ${loc.country}<br>
        <strong>ISP:</strong> ${loc.isp}<br>
        <strong>GUID:</strong> ${loc.process_guid}
      </div>
    `);
    leafletMarkerLayerGroup.addLayer(marker);
  });
}

// Deep Object Variable Search Evaluation Engine
function evaluateDeepSearchString(object, queryToken) {
  if (!object) return false;
  return JSON.stringify(object).toLowerCase().includes(queryToken.toLowerCase());
}

document.getElementById("global-search").addEventListener("input", (e) => {
  const query = e.target.value.trim().toLowerCase();
  if (query.length < 2) {
    renderNetworkLayer(fullTelemetryCache.network);
    renderProcessLayer(fullTelemetryCache.processes);
    renderHashLayer(fullTelemetryCache.hashes);
    return;
  }
  renderNetworkLayer(fullTelemetryCache.network.filter(item => evaluateDeepSearchString(item, query)));
  renderProcessLayer(fullTelemetryCache.processes.filter(item => evaluateDeepSearchString(item, query)));
  renderHashLayer(fullTelemetryCache.hashes.filter(item => evaluateDeepSearchString(item, query)));
});

// Structural Parsing Evaluation Algorithm logic rules
function evaluateLogicalExpression(row, phrase) {
  if (!phrase) return true;
  try {
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
  } catch (e) { return true; }
  return true;
}

document.getElementById("filter-net-query").addEventListener("input", (e) => {
  renderNetworkLayer(fullTelemetryCache.network.filter(item => evaluateLogicalExpression(item, e.target.value.trim())));
});

function buildTelemetryMetricsAndCharts(net, proc, hashes) {
  if (typeof Chart === "undefined") return;

  const protocolMap = {};
  net.forEach(n => { if (n.connection) { const p = n.connection.protocol_type || "UNKNOWN"; protocolMap[p] = (protocolMap[p] || 0) + 1; } });

  if (registeredCharts.protocols) registeredCharts.protocols.destroy();
  registeredCharts.protocols = new Chart(document.getElementById("chart-protocols").getContext("2d"), {
    type: "pie",
    data: { labels: Object.keys(protocolMap), datasets: [{ data: Object.values(protocolMap), backgroundColor: ["#38bdf8", "#00ffaa", "#ffb300", "#ff3366"] }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#94a3b8" } } } }
  });

  const threatMap = { CLEAN: 0, MALICIOUS: 0 };
  hashes.forEach(h => { threatMap[h.status] = (threatMap[h.status] || 0) + 1; });

  if (registeredCharts.threats) registeredCharts.threats.destroy();
  registeredCharts.threats = new Chart(document.getElementById("chart-threats").getContext("2d"), {
    type: "doughnut",
    data: { labels: Object.keys(threatMap), datasets: [{ data: Object.values(threatMap), backgroundColor: ["#00ffaa", "#ff3366"] }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#94a3b8" } } } }
  });

  const timeBuckets = {};
  net.slice(-60).forEach(n => {
    if (!n.timestamp) return;
    const marker = n.timestamp.split("T")[1]?.substring(0, 5) || "Live";
    timeBuckets[marker] = (timeBuckets[marker] || 0) + 1;
  });

  if (registeredCharts.timeline) registeredCharts.timeline.destroy();
  registeredCharts.timeline = new Chart(document.getElementById("chart-traffic-timeline").getContext("2d"), {
    type: "line",
    data: { labels: Object.keys(timeBuckets), datasets: [{ label: "Signal Activity Volume", data: Object.values(timeBuckets), borderColor: "#38bdf8", fill: false }] },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { color: "#94a3b8" } }, y: { ticks: { color: "#94a3b8" } } } }
  });
}

function getApiPath(fileKey) {
  return currentSessionId ? `/api/session/${currentSessionId}/${fileKey}` : `/api/live/${fileKey}`;
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
    if (document.getElementById("global-search").value.trim().length < 2) {
      renderNetworkLayer(net);
      renderProcessLayer(proc);
      renderHashLayer(hashes);
    }
    renderLineageTree(children, proc);
    buildTelemetryMetricsAndCharts(net, proc, hashes);
    processGeospatialPoints(geo);
  } catch (error) { console.error(error); }
}

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", (e) => {
    document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    
    link.classList.add("active");
    currentActiveView = link.dataset.target;
    document.getElementById(`panel-${currentActiveView}`).classList.add("active");
    
    if (currentActiveView === "geoportal") {
      initializeGeospatialEngine();
      setTimeout(() => { leafletMapInstance.invalidateSize(); }, 200);
    }
    if (currentActiveView === "history") fetchHistoricalSessions();
    else evaluateDataPipeline();
  });
});

document.getElementById("btn-start").addEventListener("click", async () => { await fetch("/api/scan/start", { method: "POST" }); currentSessionId = null; checkEngineStatus(); });
document.getElementById("btn-stop").addEventListener("click", async () => { await fetch("/api/scan/stop", { method: "POST" }); checkEngineStatus(); });

async function checkEngineStatus() {
  const status = await fetch("/api/status").then(r => r.json());
  const pulse = document.getElementById("engine-pulse");
  pulse.className = status.running ? "pulse-indicator" : "pulse-indicator idle";
  document.getElementById("session-lbl").textContent = status.running ? `ENGAGED: ${status.session_dir}` : "ENGINE IDLE";
}

function renderOverviewMetrics(net, proc, hashes) {
  document.getElementById("count-net").textContent = net.length;
  document.getElementById("count-proc").textContent = proc.length;
  document.getElementById("count-hash").textContent = hashes.length;
  let threats = proc.filter(p => p.process && p.process.threat_score > 50).length;
  document.getElementById("count-threat").textContent = threats;

  const outbounds = net.filter(e => e.connection && e.connection.direction === "OUTBOUND");
  document.getElementById("table-overview-net").innerHTML = outbounds.slice(-6).reverse().map(e => `
    <tr onclick="launchForensicDrawer('Network Link Context', ${styleJsonRow(e)})">
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
  document.getElementById("table-network-all").innerHTML = rows.slice(-80).reverse().map(e => `
    <tr onclick="launchForensicDrawer('Network Telemetry Payload', ${styleJsonRow(e)})">
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
  document.getElementById("table-processes-all").innerHTML = rows.map(e => {
    const p = e.process || {};
    const scoreColor = p.threat_score > 60 ? "var(--accent-alert)" : (p.threat_score > 25 ? "var(--accent-warn)" : "var(--accent-neon)");
    const flags = p.threat_flags?.map(f => `<span class="badge badge-alert">${f}</span>`).join(" ") || "NOMINAL";
    return `
      <tr onclick="launchForensicDrawer('Process Registry Core', ${styleJsonRow(e)})">
        <td>${formatTime(e.timestamp)}</td>
        <td style="font-size:11px; color:var(--text-muted);">${p.pid} / ${p.process_guid}</td>
        <td style="color:var(--accent-nominal); font-weight:600;">${p.name}</td>
        <td>${p.username || "SYSTEM"}</td>
        <td style="color:${scoreColor}; font-weight:bold;">${p.threat_score || 0} / 100</td>
        <td>${flags}</td>
      </tr>
    `;
  }).join("");
}

function renderHashLayer(rows) {
  document.getElementById("table-hashes-all").innerHTML = rows.map(r => `
    <tr onclick="launchForensicDrawer('Cryptographic Context Signature', ${styleJsonRow(r)})">
      <td>${formatTime(r.timestamp)}</td>
      <td>${r.file_name}</td>
      <td style="color:var(--text-muted); font-size:11px;">${r.sha256}</td>
      <td><span class="badge ${r.status==='MALICIOUS'?'badge-alert':'badge-neon'}">${r.status}</span></td>
    </tr>
  `).join("");
}

function renderLineageTree(children, processes) {
  const container = document.getElementById("tree-container");
  if (!children.length) { container.innerHTML = `<div style="color:var(--text-muted)">Syncing links...</div>`; return; }
  const nameRegistry = {};
  processes.forEach(p => { if(p.process) nameRegistry[p.process.process_guid] = p.process.name; });

  let htmlTree = `<div class="tree-node">`;
  children.slice(0, 20).forEach(c => {
    htmlTree += `
      <div class="tree-leaf" onclick="launchForensicDrawer('Relationship Pivot Artifact', ${styleJsonRow(c)})">
        <span style="color:var(--text-muted);">${nameRegistry[c.parent_process_guid] || "Parent Process"}</span> ➔ <span style="color:var(--accent-neon); font-weight:700;">Child:</span> 
        <span>${c.child_name} (PID: ${c.child_pid})</span>
      </div>
    `;
  });
  container.innerHTML = htmlTree + `</div>`;
}

async function fetchHistoricalSessions() {
  const sessions = await fetch("/api/sessions").then(r => r.json());
  document.getElementById("table-history-sessions").innerHTML = sessions.map(s => `
    <tr onclick="currentSessionId='${s.id}'; document.querySelector('[data-target=\\'overview\\']').click();">
      <td style="color:var(--accent-nominal); font-weight:600;">${s.id}</td>
      <td>${new Date(s.started_at).toLocaleString()}</td>
      <td>${s.network_count} Rows</td>
      <td>${s.process_count} Images</td>
      <td><span class="badge ${s.has_threats?'badge-alert':'badge-neon'}">${s.threat_count} Flags</span></td>
    </tr>
  `).join("");
}

function styleJsonRow(obj) { return JSON.stringify(obj).replace(/"/g, '&quot;'); }
function launchForensicDrawer(title, rawRowData) {
  document.getElementById("drawer-title-id").textContent = title;
  document.getElementById("forensic-drawer").classList.add("open");
  document.getElementById("drawer-json-pre").textContent = JSON.stringify(rawRowData, null, 2);

  let summary = `<div style="display:flex; flex-direction:column; gap:12px;">`;
  let node = rawRowData.connection || rawRowData.process || rawRowData;
  for(const [k, v] of Object.entries(node)) { if(typeof v !== 'object') { summary += `<div><strong>${k}:</strong> <span>${v}</span></div>`; } }
  document.getElementById("drawer-content-summary").innerHTML = summary + `</div>`;
}

document.getElementById("drawer-close-btn").addEventListener("click", () => document.getElementById("forensic-drawer").classList.remove("open"));

function formatTime(ts) { if (!ts) return "—"; const d = new Date(ts); return isNaN(d) ? ts : d.toLocaleTimeString(); }

setInterval(() => { checkEngineStatus(); if (!currentSessionId && currentActiveView !== "history") evaluateDataPipeline(); }, 3000);
checkEngineStatus(); evaluateDataPipeline();