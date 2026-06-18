// Master State
let state = {
  mode: "offline",
  sessionId: null,
  data: { network: [], processes: [], hashes: [], children: [], geo: [] },
  charts: {},
  sort: { column: 'timestamp', dir: 'desc' }
};

let mapInstance = null;
let mapLayer = null;

async function init() {
  setupNav();
  setupControls();
  setupSorting();
  await updateState();
  setInterval(updateState, 3000);
}

async function updateState() {
  const statusResp = await fetch("/api/status").then(r => r.json()).catch(() => null);
  if (!statusResp) return;

  const banner = document.getElementById("status-banner");
  if (statusResp.running) {
    state.mode = "live";
    state.sessionId = statusResp.session_dir;
    banner.className = "status-banner live";
    banner.innerText = `LIVE: ${state.sessionId}`;
  } else if (state.mode !== "history") {
    state.mode = "offline";
    banner.className = "status-banner offline";
    banner.innerText = "SYSTEM IDLE";
  } else {
    banner.className = "status-banner history";
    banner.innerText = `HISTORY: ${state.sessionId}`;
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
    
    const searchQ = document.getElementById("global-search").value.toLowerCase();
    if (searchQ.length > 1) {
      const filterFn = (i) => JSON.stringify(i).toLowerCase().includes(searchQ);
      renderAllDashboards({
        network: state.data.network.filter(filterFn),
        processes: state.data.processes.filter(filterFn),
        hashes: state.data.hashes.filter(filterFn),
        children: state.data.children,
        geo: state.data.geo
      });
    } else {
      renderAllDashboards(state.data);
    }
  } catch(e) { console.error("Fetch failed", e); }
}

document.getElementById("global-search").addEventListener("input", () => {
  if (state.mode !== "offline") fetchTelemetry();
});

// --- Renders ---
function renderAllDashboards(data) {
  renderOverview(data);
  renderTables(data);
  
  if (document.getElementById("panel-analytics").classList.contains("active")) renderCharts(data);
  if (document.getElementById("panel-tree").classList.contains("active")) renderProcessTree(data);
  if (document.getElementById("panel-map").classList.contains("active")) renderMap(data.geo);
}

function renderOverview(data) {
  // Count only active processes by looking for STARTs without STOPs (or just count total logs as before)
  document.getElementById("count-proc").innerText = data.processes.filter(p => p.action === "START" || p.action === "PROC_START").length;
  document.getElementById("count-net").innerText = data.network.length;
  document.getElementById("count-hash").innerText = data.hashes.length;
  
  let totalScore = 0;
  let alerts = [];
  
  data.processes.forEach(p => {
    if(!p.process) return;
    totalScore += (p.process.threat_score || 0);
    if (p.process.threat_score > 20 || (p.process.threat_flags && p.process.threat_flags.length > 0)) {
      alerts.push(p);
    }
  });
  
  document.getElementById("count-threat").innerText = totalScore;
  
  const alertsHtml = alerts.slice(-10).reverse().map(p => {
    return `<tr onclick='openDrawer("Alert Details", ${JSON.stringify(p)})'>
      <td>${fmtTime(p.timestamp)}</td>
      <td style="color:var(--neon)">${p.process.name}</td>
      <td style="color:var(--alert)">${p.process.threat_score}</td>
      <td>${(p.process.threat_flags || []).join(", ")}</td>
    </tr>`;
  }).join("");
  document.getElementById("table-alerts").innerHTML = alertsHtml || "<tr><td colspan='4'>No alerts.</td></tr>";
}

// --- Sorting Helpers ---
function setupSorting() {
  document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (state.sort.column === col) {
        state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        state.sort.column = col;
        state.sort.dir = 'desc';
      }
      
      document.querySelectorAll('th.sortable').forEach(el => el.classList.remove('sort-asc', 'sort-desc'));
      th.classList.add(state.sort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
      
      renderTables(state.data);
    });
  });
}

function sortData(array, getValueFn) {
  return [...array].sort((a, b) => {
    const valA = getValueFn(a);
    const valB = getValueFn(b);
    if (valA < valB) return state.sort.dir === 'asc' ? -1 : 1;
    if (valA > valB) return state.sort.dir === 'asc' ? 1 : -1;
    return 0;
  });
}

function renderTables(data) {
  const netSorted = sortData(data.network, (n) => {
    const c = n.connection || {};
    if(state.sort.column === 'pid') return c.pid || 0;
    if(state.sort.column === 'local') return c.local_port || 0;
    if(state.sort.column === 'remote') return c.remote_ip || '';
    if(state.sort.column === 'status') return c.status || '';
    return n.timestamp || '';
  });
  
  document.getElementById("table-network").innerHTML = netSorted.slice(0, 100).map(n => {
    const c = n.connection || {};
    return `<tr onclick='openDrawer("Network Event", ${JSON.stringify(n)})'>
      <td>${fmtTime(n.timestamp)}</td><td>${c.pid}</td><td>${c.local_ip}:${c.local_port}</td>
      <td>${c.remote_ip||'-'}:${c.remote_port||'-'}</td><td>${c.status||'-'}</td></tr>`;
  }).join("");

  const procSorted = sortData(data.processes, (p) => {
    const d = p.process || {};
    if(state.sort.column === 'pid') return d.pid || 0;
    if(state.sort.column === 'name') return d.name || '';
    if(state.sort.column === 'score') return d.threat_score || 0;
    return p.timestamp || '';
  });

  document.getElementById("table-processes").innerHTML = procSorted.slice(0, 100).map(p => {
    const d = p.process || {};
    return `<tr onclick='openDrawer("Process Details", ${JSON.stringify(p)})'>
      <td>${fmtTime(p.timestamp)}</td><td>${d.pid}</td><td style="color:var(--neon)">${d.name}</td>
      <td style="color:${d.threat_score>0?'var(--alert)':'var(--text)'}">${d.threat_score||0}</td>
      <td>${(d.threat_flags||[]).join(", ")}</td></tr>`;
  }).join("");

  const hashSorted = sortData(data.hashes, (h) => {
    if(state.sort.column === 'name') return h.file_name || '';
    if(state.sort.column === 'status') return h.status || '';
    return h.timestamp || '';
  });

  document.getElementById("table-hashes").innerHTML = hashSorted.slice(0, 100).map(h => {
    const color = h.status === "MALICIOUS" ? "var(--alert)" : "var(--neon)";
    return `<tr onclick='openDrawer("Hash Details", ${JSON.stringify(h)})'>
      <td>${fmtTime(h.timestamp)}</td><td>${h.file_name}</td><td>${h.sha256}</td>
      <td style="color:${color}">${h.status}</td></tr>`;
  }).join("");
}

// --- JSON Drawer ---
function openDrawer(title, rawData) {
  document.getElementById("drawer-title").innerText = title;
  document.getElementById("drawer-json").innerText = JSON.stringify(rawData, null, 2);
  document.getElementById("json-drawer").classList.add("open");
}

document.getElementById("close-drawer").addEventListener("click", () => {
  document.getElementById("json-drawer").classList.remove("open");
});

// --- Graphic Timeline & Analytics Charts ---
function renderCharts(data) {
  if (typeof Chart === "undefined") return;

  const makeChart = (id, type, labels, datasetData, colors, label) => {
    if(state.charts[id]) state.charts[id].destroy();
    const ctx = document.getElementById(id).getContext('2d');
    state.charts[id] = new Chart(ctx, {
      type: type,
      data: { labels, datasets: [{ label, data: datasetData, backgroundColor: colors, borderColor: type==='line'?'var(--neon)':'#161b22', fill: type==='line'}] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: type !== 'line', labels:{color:'#8b949e'} } }, scales: type === 'line' || type === 'bar' ? {x:{ticks:{color:'#8b949e'}}, y:{ticks:{color:'#8b949e'}, beginAtZero:true}} : {} }
    });
  };

  // 1. Connection Timeline (Line)
  let netTimeBuckets = {};
  data.network.forEach(n => {
    if (!n.timestamp) return;
    const time = n.timestamp.split("T")[1]?.substring(0, 8); // HH:MM:SS
    if(time) netTimeBuckets[time] = (netTimeBuckets[time] || 0) + 1;
  });
  const netLabels = Object.keys(netTimeBuckets).sort().slice(-40); 
  makeChart('chart-timeline', 'line', netLabels, netLabels.map(l=>netTimeBuckets[l]), 'rgba(88, 166, 255, 0.1)', 'Network Events');

  // 2. Process Activity Churn (Multi-Dataset Line Chart)
  let procTimeBuckets = {};
  data.processes.forEach(p => {
    if (!p.timestamp) return;
    const time = p.timestamp.split("T")[1]?.substring(0, 8); // HH:MM:SS
    if (!time) return;
    if (!procTimeBuckets[time]) procTimeBuckets[time] = { start: 0, stop: 0 };
    if (p.action === "START" || p.action === "PROC_START") procTimeBuckets[time].start++;
    if (p.action === "STOP" || p.action === "PROC_STOP") procTimeBuckets[time].stop++;
  });
  const procLabels = Object.keys(procTimeBuckets).sort().slice(-40);

  if(state.charts['chart-process-churn']) state.charts['chart-process-churn'].destroy();
  state.charts['chart-process-churn'] = new Chart(document.getElementById('chart-process-churn').getContext('2d'), {
    type: 'line',
    data: {
      labels: procLabels,
      datasets: [
        { label: 'Processes Created', data: procLabels.map(l => procTimeBuckets[l].start), borderColor: '#2ea043', backgroundColor: 'rgba(46, 160, 67, 0.1)', fill: true, tension: 0.2 },
        { label: 'Processes Ended', data: procLabels.map(l => procTimeBuckets[l].stop), borderColor: '#f85149', backgroundColor: 'rgba(248, 81, 73, 0.1)', fill: true, tension: 0.2 }
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { color: '#8b949e' } }, y: { ticks: { color: '#8b949e' }, beginAtZero: true, suggestedMax: 5 } }, plugins: { legend: { labels: { color: '#c9d1d9' } } } }
  });

  // 3. Top Processes (Bar)
  let procCount = {};
  data.processes.forEach(p => { if(p.process) procCount[p.process.name] = (procCount[p.process.name]||0) + 1; });
  let sortProc = Object.entries(procCount).sort((a,b)=>b[1]-a[1]).slice(0, 6);
  makeChart('chart-top-procs', 'bar', sortProc.map(k=>k[0]), sortProc.map(k=>k[1]), '#58a6ff', 'Executions');

  // 4. Port Usage (Doughnut)
  let portCount = {};
  data.network.forEach(n => { if(n.connection && n.connection.remote_port) portCount[n.connection.remote_port] = (portCount[n.connection.remote_port]||0) + 1; });
  let sortPort = Object.entries(portCount).sort((a,b)=>b[1]-a[1]).slice(0, 6);
  makeChart('chart-ports', 'doughnut', sortPort.map(k=>k[0]), sortPort.map(k=>k[1]), ['#58a6ff', '#2ea043', '#d29922', '#f85149', '#a371f7', '#8b949e'], 'Connections');

  // 5. TCP vs UDP (Doughnut)
  let protoCount = { TCP: 0, UDP: 0 };
  data.network.forEach(n => { if(n.connection && n.connection.protocol_type) protoCount[n.connection.protocol_type]++; });
  makeChart('chart-protocol-type', 'doughnut', Object.keys(protoCount), Object.values(protoCount), ['#58a6ff', '#a371f7'], 'Protocol');

  // 6. IPv4 vs IPv6 (Doughnut)
  let ipCount = { IPv4: 0, IPv6: 0 };
  data.network.forEach(n => { if(n.connection && n.connection.ip_version) ipCount[n.connection.ip_version]++; });
  makeChart('chart-ip-version', 'doughnut', Object.keys(ipCount), Object.values(ipCount), ['#2ea043', '#d29922'], 'IP Version');
}

// --- Geographic Map (Leaflet) ---
function renderMap(geoData) {
  if (typeof L === "undefined") return;
  if (!mapInstance) {
    mapInstance = L.map('map-canvas-container').setView([20.5937, 78.9629], 3);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap &copy; CARTO'
    }).addTo(mapInstance);
    mapLayer = L.layerGroup().addTo(mapInstance);
  }

  setTimeout(() => mapInstance.invalidateSize(), 100);
  mapLayer.clearLayers();

  const homeLat = 20.5937; 
  const homeLon = 78.9629;
  
  L.circleMarker([homeLat, homeLon], { radius: 8, fillColor: "#2ea043", color: "#fff", weight: 2, fillOpacity: 1 }).addTo(mapLayer).bindPopup("Local Agent");

  geoData.forEach(loc => {
    if (!loc.lat || !loc.lon) return;

    const marker = L.circleMarker([loc.lat, loc.lon], { radius: 5, fillColor: "#58a6ff", color: "#fff", weight: 1, fillOpacity: 0.8 });
    marker.bindPopup(`<strong>${loc.ip}</strong><br>${loc.city}, ${loc.country}<br>${loc.isp}`);
    mapLayer.addLayer(marker);

    const line = L.polyline([[homeLat, homeLon], [loc.lat, loc.lon]], {
        color: '#58a6ff', weight: 1, opacity: 0.3, dashArray: '4'
    });
    mapLayer.addLayer(line);
  });
}

// --- Process Tree ---
function renderProcessTree(data) {
  const container = document.getElementById("tree-container");
  if(data.children.length === 0) { container.innerHTML = "No relationships mapped yet."; return; }

  const nameMap = {};
  data.processes.forEach(p => { if(p.process) nameMap[p.process.process_guid] = p.process.name; });

  let html = "";
  data.children.slice(-100).forEach(c => {
    const pName = nameMap[c.parent_process_guid] || "Parent Process";
    const cName = c.child_name;
    const isBad = cName.toLowerCase().includes("powershell") || cName.toLowerCase().includes("cmd");
    html += `<div class="tree-node" onclick='openDrawer("Lineage Event", ${JSON.stringify(c)})' style="cursor:pointer;">
        <span class="tree-item">${pName}</span> spawned 
        <span class="tree-item ${isBad ? 'bad' : ''}">↘ ${cName} (PID: ${c.child_pid})</span>
      </div>`;
  });
  container.innerHTML = html;
}

// --- History & Compare ---
async function populateHistory() {
  const sessions = await fetch("/api/sessions").then(r => r.json()).catch(()=>[]);
  
  document.getElementById("table-history").innerHTML = sessions.map(s => `
    <tr onclick="state.mode='history'; state.sessionId='${s.id}'; updateState();">
      <td style="color:var(--neon)">${s.id}</td><td>${new Date(s.started_at).toLocaleString()}</td>
      <td>${s.network_count + s.process_count}</td><td>${s.threat_count}</td>
    </tr>
  `).join("");

  const opts = sessions.map(s => `<option value="${s.id}">${s.id}</option>`).join("");
  document.getElementById("comp-a").innerHTML = opts || "<option>No sessions</option>";
  document.getElementById("comp-b").innerHTML = opts || "<option>No sessions</option>";
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

    const namesA = new Set(procA.map(p => p.process?.name).filter(Boolean));
    const namesB = new Set(procB.map(p => p.process?.name).filter(Boolean));

    const missing = [...namesA].filter(x => !namesB.has(x));
    const added = [...namesB].filter(x => !namesA.has(x));

    document.getElementById("diff-missing").innerHTML = missing.length ? missing.map(n => `<li>${n}</li>`).join("") : "<li>None</li>";
    document.getElementById("diff-new").innerHTML = added.length ? added.map(n => `<li>${n}</li>`).join("") : "<li>None</li>";
  } catch(e) { console.error("Compare failed", e); }
});

function setupNav() {
  document.querySelectorAll(".nav-link").forEach(link => {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      link.classList.add("active");
      const target = link.dataset.target;
      document.getElementById(`panel-${target}`).classList.add("active");
      
      if(target === "history" || target === "compare") populateHistory();
      if(target === "analytics") renderCharts(state.data);
      if(target === "tree") renderProcessTree(state.data);
      if(target === "map") renderMap(state.data.geo);
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

function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d) ? ts : d.toLocaleTimeString();
}

window.addEventListener("DOMContentLoaded", init);