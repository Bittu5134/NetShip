// Master State
let state = {
  mode: "offline", // "live", "history", "offline"
  sessionId: null,
  data: { network: [], processes: [], hashes: [], children: [], geo: [] },
  charts: {} // Store Chart.js instances for destruction/re-rendering
};

// --- Initialization & Polling ---
async function init() {
  setupNav();
  setupControls();
  await updateState();
  setInterval(updateState, 3000); // Poll every 3s
}

async function updateState() {
  const statusResp = await fetch("/api/status").then(r => r.json()).catch(() => null);
  
  if (!statusResp) return;

  const banner = document.getElementById("status-banner");
  if (statusResp.running) {
    state.mode = "live";
    state.sessionId = statusResp.session_dir;
    banner.className = "status-banner live";
    banner.innerText = `🟢 LIVE SCAN: ${state.sessionId}`;
  } else if (state.mode !== "history") {
    state.mode = "offline";
    banner.className = "status-banner offline";
    banner.innerText = "SYSTEM IDLE";
  } else {
    banner.className = "status-banner history";
    banner.innerText = `🕰️ VIEWING HISTORY: ${state.sessionId}`;
  }

  if (state.mode !== "offline") await fetchTelemetry();
  if (document.getElementById("panel-history").classList.contains("active")) await populateHistory();
}

async function fetchTelemetry() {
  const base = state.mode === "live" ? "/api/live/" : `/api/session/${state.sessionId}/`;
  
  try {
    const [net, proc, hash, child, geo] = await Promise.all([
      fetch(base + "network").then(r => r.json()),
      fetch(base + "process").then(r => r.json()),
      fetch(base + "hashes").then(r => r.json()),
      fetch(base + "children").then(r => r.json()),
      fetch(base + "geo").then(r => r.json())
    ]);

    state.data = { network: net||[], processes: proc||[], hashes: hash||[], children: child||[], geo: geo||[] };
    
    // Apply search filter if active, otherwise render everything
    const searchQ = document.getElementById("global-search").value.toLowerCase();
    if (searchQ.length > 1) {
      executeDeepSearch(searchQ);
    } else {
      renderAllDashboards(state.data);
    }
  } catch(e) { console.error("Telemetry fetch failed", e); }
}

// --- Universal Deep Search ---
function executeDeepSearch(query) {
  // Recursively stringifies objects to search across ANY nested field (Hash, IP, Country, PID)
  const filterFn = (item) => JSON.stringify(item).toLowerCase().includes(query);
  
  const filteredData = {
    network: state.data.network.filter(filterFn),
    processes: state.data.processes.filter(filterFn),
    hashes: state.data.hashes.filter(filterFn),
    children: state.data.children.filter(filterFn), // Note: geo not usually table-rendered directly
  };
  
  renderAllDashboards(filteredData);
}

document.getElementById("global-search").addEventListener("input", () => {
  if (state.mode === "offline") return;
  const q = document.getElementById("global-search").value.toLowerCase();
  q.length > 1 ? executeDeepSearch(q) : renderAllDashboards(state.data);
});

// --- UI Renderers ---
function renderAllDashboards(data) {
  renderOverview(data);
  renderTables(data);
  if (document.getElementById("panel-analytics").classList.contains("active")) renderCharts(data);
  if (document.getElementById("panel-tree").classList.contains("active")) renderProcessTree(data);
}

function renderOverview(data) {
  document.getElementById("count-proc").innerText = data.processes.length;
  document.getElementById("count-net").innerText = data.network.length;
  document.getElementById("count-hash").innerText = data.hashes.length;
  
  let totalScore = 0;
  let alertsHtml = "";
  
  // Aggregate Threat Score and find Alerts
  data.processes.forEach(p => {
    if(!p.process) return;
    totalScore += (p.process.threat_score || 0);
    if (p.process.threat_score > 30 || (p.process.threat_flags && p.process.threat_flags.length > 0)) {
      alertsHtml += `<tr>
        <td>${new Date(p.timestamp).toLocaleTimeString()}</td>
        <td style="color:var(--neon)">${p.process.name}</td>
        <td style="color:var(--alert)">${p.process.threat_score}</td>
        <td>${(p.process.threat_flags || []).join(", ")}</td>
      </tr>`;
    }
  });
  
  document.getElementById("count-threat").innerText = totalScore;
  document.getElementById("table-alerts").innerHTML = alertsHtml || "<tr><td colspan='4'>No critical alerts detected.</td></tr>";
}

function renderTables(data) {
  document.getElementById("table-network").innerHTML = data.network.slice(-50).reverse().map(n => {
    const c = n.connection || {};
    return `<tr><td>${new Date(n.timestamp).toLocaleTimeString()}</td><td>${c.pid}</td><td>${c.local_ip}:${c.local_port}</td><td>${c.remote_ip||'-'}:${c.remote_port||'-'}</td><td>${c.status||'-'}</td></tr>`;
  }).join("");

  document.getElementById("table-processes").innerHTML = data.processes.slice(-50).reverse().map(p => {
    const d = p.process || {};
    return `<tr><td>${new Date(p.timestamp).toLocaleTimeString()}</td><td>${d.pid}</td><td>${d.name}</td><td>${d.threat_score||0}</td><td>${(d.threat_flags||[]).join(" ")}</td></tr>`;
  }).join("");

  document.getElementById("table-hashes").innerHTML = data.hashes.slice(-50).reverse().map(h => {
    const statusColor = h.status === "MALICIOUS" ? "color:var(--alert)" : "color:var(--neon)";
    return `<tr><td>${new Date(h.timestamp).toLocaleTimeString()}</td><td>${h.file_name}</td><td>${h.sha256}</td><td style="${statusColor}">${h.status}</td></tr>`;
  }).join("");
}

// --- Advanced Charting Engine ---
function renderCharts(data) {
  if (typeof Chart === "undefined") return;

  // Helper to safely destroy old charts
  const makeChart = (id, type, labels, datasetData, colors, label="Count") => {
    if(state.charts[id]) state.charts[id].destroy();
    const ctx = document.getElementById(id).getContext('2d');
    state.charts[id] = new Chart(ctx, {
      type: type,
      data: { labels, datasets: [{ label, data: datasetData, backgroundColor: colors, borderColor: '#161924' }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#ccc'} } }, scales: type === 'line' || type === 'bar' ? {x:{ticks:{color:'#ccc'}}, y:{ticks:{color:'#ccc'}}} : {} }
    });
  };

  // 1. Top Talker Processes (Bar)
  let procCount = {};
  data.processes.forEach(p => { if(p.process) procCount[p.process.name] = (procCount[p.process.name]||0) + 1; });
  let sortProc = Object.entries(procCount).sort((a,b)=>b[1]-a[1]).slice(0, 5);
  makeChart('chart-top-procs', 'bar', sortProc.map(k=>k[0]), sortProc.map(k=>k[1]), '#00ffaa', 'Executions');

  // 2. Global Destinations (Pie)
  let geoCount = {};
  data.geo.forEach(g => { geoCount[g.country] = (geoCount[g.country]||0) + 1; });
  let sortGeo = Object.entries(geoCount).sort((a,b)=>b[1]-a[1]).slice(0, 5);
  makeChart('chart-top-geo', 'doughnut', sortGeo.map(k=>k[0]), sortGeo.map(k=>k[1]), ['#38bdf8', '#00ffaa', '#ffb300', '#ff3366', '#a855f7']);

  // 3. Ports (Pie)
  let portCount = {};
  data.network.forEach(n => { if(n.connection && n.connection.remote_port) portCount[n.connection.remote_port] = (portCount[n.connection.remote_port]||0) + 1; });
  let sortPort = Object.entries(portCount).sort((a,b)=>b[1]-a[1]).slice(0, 5);
  makeChart('chart-ports', 'pie', sortPort.map(k=>k[0]), sortPort.map(k=>k[1]), ['#ffb300', '#38bdf8', '#ff3366', '#00ffaa', '#a855f7']);

  // 4. Threats (Doughnut)
  let tCount = { "CLEAN": 0, "WARNING": 0, "MALICIOUS": 0 };
  data.processes.forEach(p => {
    let s = p.process?.threat_score || 0;
    if(s === 0) tCount.CLEAN++; else if(s < 50) tCount.WARNING++; else tCount.MALICIOUS++;
  });
  makeChart('chart-threats', 'doughnut', Object.keys(tCount), Object.values(tCount), ['#00ffaa', '#ffb300', '#ff3366']);

  // 5. Timeline (Line)
  let timeBuckets = {};
  data.network.forEach(n => {
    if (!n.timestamp) return;
    const time = n.timestamp.split("T")[1]?.substring(0, 5); // HH:MM granularity
    if(time) timeBuckets[time] = (timeBuckets[time] || 0) + 1;
  });
  const tLabels = Object.keys(timeBuckets).sort().slice(-30); // Last 30 mins
  makeChart('chart-timeline', 'line', tLabels, tLabels.map(l=>timeBuckets[l]), '#38bdf8', 'Connections/Min');
}

// --- Process Tree Visualizer ---
function renderProcessTree(data) {
  const container = document.getElementById("tree-container");
  if(data.children.length === 0) { container.innerHTML = "No relationships mapped yet."; return; }

  // Map Guid -> Name for lookup
  const nameMap = {};
  data.processes.forEach(p => { if(p.process) nameMap[p.process.process_guid] = p.process.name; });

  let html = "";
  // Create a simplistic visual representation (indentation based)
  data.children.slice(0, 50).forEach(c => {
    const pName = nameMap[c.parent_process_guid] || "Unknown Parent";
    const cName = c.child_name;
    const isBad = cName.toLowerCase().includes("powershell") || cName.toLowerCase().includes("cmd");
    html += `
      <div class="tree-node">
        <span class="tree-item">${pName}</span> spawned 
        <span class="tree-item ${isBad ? 'bad' : ''}">↘ ${cName} (PID: ${c.child_pid})</span>
      </div>
    `;
  });
  container.innerHTML = html;
}

// --- Differential Compare Engine ---
async function populateHistory() {
  const sessions = await fetch("/api/sessions").then(r => r.json()).catch(()=>[]);
  
  // Populate the history table
  document.getElementById("table-history").innerHTML = sessions.map(s => `
    <tr style="cursor:pointer" onclick="state.mode='history'; state.sessionId='${s.id}'; updateState();">
      <td style="color:var(--neon)">${s.id}</td><td>${new Date(s.started_at).toLocaleString()}</td>
      <td>${s.network_count + s.process_count}</td><td>${s.threat_count}</td>
    </tr>
  `).join("");

  // Populate Dropdowns in Compare tab
  const opts = sessions.map(s => `<option value="${s.id}">${s.id}</option>`).join("");
  document.getElementById("comp-a").innerHTML = opts;
  document.getElementById("comp-b").innerHTML = opts;
}

document.getElementById("btn-exec-compare").addEventListener("click", async () => {
  const a = document.getElementById("comp-a").value;
  const b = document.getElementById("comp-b").value;
  if(!a || !b || a===b) return alert("Select two different sessions.");

  try {
    const [procA, procB] = await Promise.all([
      fetch(`/api/session/${a}/process`).then(r=>r.json()),
      fetch(`/api/session/${b}/process`).then(r=>r.json())
    ]);

    // Extract unique process names using a Set
    const namesA = new Set(procA.map(p => p.process?.name).filter(Boolean));
    const namesB = new Set(procB.map(p => p.process?.name).filter(Boolean));

    // Calculate Diff
    const missing = [...namesA].filter(x => !namesB.has(x));
    const added = [...namesB].filter(x => !namesA.has(x));

    document.getElementById("diff-missing").innerHTML = missing.length ? missing.map(n => `<li>${n}</li>`).join("") : "<li>None</li>";
    document.getElementById("diff-new").innerHTML = added.length ? added.map(n => `<li>${n}</li>`).join("") : "<li>None</li>";
  } catch(e) { console.error("Compare failed", e); }
});

// --- Nav & Controls ---
function setupNav() {
  document.querySelectorAll(".nav-link").forEach(link => {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      link.classList.add("active");
      const target = link.dataset.target;
      document.getElementById(`panel-${target}`).classList.add("active");
      
      // Trigger lazy loads
      if(target === "history" || target === "compare") populateHistory();
      if(target === "analytics") renderCharts(state.data);
      if(target === "tree") renderProcessTree(state.data);
    });
  });
}

function setupControls() {
  document.getElementById("btn-start").addEventListener("click", async () => {
    await fetch("/api/scan/start", { method: "POST" });
    state.mode = "live";
    updateState();
  });
  document.getElementById("btn-stop").addEventListener("click", async () => {
    await fetch("/api/scan/stop", { method: "POST" });
    updateState();
  });
}

// Boot
window.addEventListener("DOMContentLoaded", init);