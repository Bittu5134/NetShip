// Master state registry
let state = {
  mode: "offline",
  sessionId: null,
  data: { 
    network: [], 
    processes: [], 
    hashes: [], 
    children: [], 
    geo: [] 
  },
  charts: {},
  sort: { 
    column: 'timestamp', 
    dir: 'desc' 
  }
};

let mapInstance = null;
let mapLayer = null;
let cachedDataCenters = [];
let dynamicPathLines = [];
let dynamicPathLabels = [];

async function init() {
  setupNav();
  setupControls();
  setupSorting();
  
  await updateState();
  
  // Fetch updates periodically
  setInterval(async function() {
    await updateState();
  }, 3000);
}

// Check scanning status and update banners
async function updateState() {
  const statusResp = await fetch("/api/status").then(function(r) {
    return r.json();
  }).catch(function() {
    return null;
  });
  
  if (statusResp === null) {
    return;
  }

  const banner = document.getElementById("status-banner");
  const pulse = document.getElementById("engine-pulse");

  if (statusResp.running) {
    state.mode = "live";
    state.sessionId = statusResp.session_dir;
    banner.className = "status-banner live";
    banner.innerText = "LIVE SCAN: " + state.sessionId;
    
    if (pulse !== null) {
      pulse.classList.remove("idle");
      pulse.classList.add("live");
    }
  } else if (state.mode !== "history") {
    state.mode = "offline";
    banner.className = "status-banner offline";
    banner.innerText = "SYSTEM IDLE";
    
    if (pulse !== null) {
      pulse.classList.remove("live");
      pulse.classList.add("idle");
    }
  } else {
    banner.className = "status-banner history";
    banner.innerText = "HISTORY LOG: " + state.sessionId;
    
    if (pulse !== null) {
      pulse.classList.remove("live");
      pulse.classList.add("idle");
    }
  }

  if (state.mode !== "offline") {
    await fetchTelemetry();
  }
  
  const historyPanel = document.getElementById("panel-history");
  if (historyPanel.classList.contains("active")) {
    await populateHistory();
  }
}

// Fetch session log rows
async function fetchTelemetry() {
  let baseAddress = "";
  if (state.mode === "live") {
    baseAddress = "/api/live/";
  } else {
    baseAddress = "/api/session/" + state.sessionId + "/";
  }
  
  try {
    const netData = await fetch(baseAddress + "network").then(function(r) { return r.json(); });
    const procData = await fetch(baseAddress + "process").then(function(r) { return r.json(); });
    const hashData = await fetch(baseAddress + "hashes").then(function(r) { return r.json(); });
    const childData = await fetch(baseAddress + "children").then(function(r) { return r.json(); });
    const geoData = await fetch(baseAddress + "geo").then(function(r) { return r.json(); });

    state.data.network = netData || [];
    state.data.processes = procData || [];
    state.data.hashes = hashData || [];
    state.data.children = childData || [];
    state.data.geo = geoData || [];
    
    const searchInput = document.getElementById("global-search");
    const searchQuery = searchInput.value.toLowerCase();
    
    if (searchQuery.length > 1) {
      // Filter logic searching matching keys
      const filterFunction = function(item) {
        const itemString = JSON.stringify(item).toLowerCase();
        const containsMatch = itemString.includes(searchQuery);
        return containsMatch;
      };
      
      const filteredData = {
        network: state.data.network.filter(filterFunction),
        processes: state.data.processes.filter(filterFunction),
        hashes: state.data.hashes.filter(filterFunction),
        children: state.data.children,
        geo: state.data.geo
      };
      
      renderAllDashboards(filteredData);
    } else {
      renderAllDashboards(state.data);
    }
  } catch(e) { 
    console.error("Telemetry fetch operation failed", e); 
  }
}

// Handle global search input change
document.getElementById("global-search").addEventListener("input", function() {
  if (state.mode !== "offline") {
    fetchTelemetry();
  }
});

// Triggers active views redrawing
function renderAllDashboards(data) {
  renderOverview(data);
  renderTables(data);
  
  const analyticsPanel = document.getElementById("panel-analytics");
  if (analyticsPanel.classList.contains("active")) {
    renderCharts(data);
  }
  
  const treePanel = document.getElementById("panel-tree");
  if (treePanel.classList.contains("active")) {
    renderProcessTree(data);
  }
  
  const mapPanel = document.getElementById("panel-map");
  if (mapPanel.classList.contains("active")) {
    renderMap(data.geo);
  }
}

// Generate overview statistics metrics and dynamic threat status indicator
function renderOverview(data) {
  // Count running actions
  let runningProcessCount = 0;
  for (let i = 0; i < data.processes.length; i++) {
    const action = data.processes[i].action;
    if (action === "START" || action === "PROC_START") {
      runningProcessCount = runningProcessCount + 1;
    }
  }
  
  document.getElementById("count-proc").innerText = runningProcessCount;
  document.getElementById("count-net").innerText = data.network.length;
  document.getElementById("count-hash").innerText = data.hashes.length;
  
  let cumulativeRiskScore = 0;
  let alertRecords = [];
  
  for (let i = 0; i < data.processes.length; i++) {
    const item = data.processes[i];
    if (item.process) {
      const riskScore = item.process.risk_score || 0;
      cumulativeRiskScore = cumulativeRiskScore + riskScore;
      
      const reasonsList = item.process.risk_reasons || [];
      if (riskScore > 20 || reasonsList.length > 0) {
        alertRecords.push(item);
      }
    }
  }
  
  document.getElementById("count-threat").innerText = cumulativeRiskScore;
  
  // Calculate dynamic status gauge values
  const gaugeFill = document.getElementById("gauge-fill");
  const gaugeStatusText = document.getElementById("gauge-status-text");
  const gaugeScoreVal = document.getElementById("gauge-score-val");
  
  if (gaugeFill !== null && gaugeStatusText !== null && gaugeScoreVal !== null) {
    const maxReferencePoints = 250;
    const computedPercentage = Math.min((cumulativeRiskScore / maxReferencePoints) * 100, 100);
    
    gaugeFill.style.width = computedPercentage + "%";
    gaugeScoreVal.innerText = "Cumulative Score: " + cumulativeRiskScore;
    
    if (cumulativeRiskScore === 0) {
      gaugeStatusText.innerText = "SYSTEM STATUS: SAFE";
      gaugeStatusText.style.color = "var(--success)";
    } else if (cumulativeRiskScore < 100) {
      gaugeStatusText.innerText = "SYSTEM STATUS: DEVIATIONS DETECTED";
      gaugeStatusText.style.color = "var(--warn)";
    } else {
      gaugeStatusText.innerText = "SYSTEM STATUS: SUSPICIOUS/ALERT STATE";
      gaugeStatusText.style.color = "var(--alert)";
    }
  }
  
  let alertsHtml = "";
  const slicedAlerts = alertRecords.slice(-10).reverse();
  
  for (let i = 0; i < slicedAlerts.length; i++) {
    const alertItem = slicedAlerts[i];
    const proc = alertItem.process;
    const reasons = proc.risk_reasons || [];
    const formattedString = JSON.stringify(alertItem);
    
    alertsHtml = alertsHtml + `
      <tr onclick='openDrawer("Alert Details", ${formattedString})'>
        <td>${fmtTime(alertItem.timestamp)}</td>
        <td style="color:var(--neon)">${proc.name}</td>
        <td style="color:var(--alert)">${proc.risk_score}</td>
        <td>${reasons.join(", ")}</td>
      </tr>
    `;
  }
  
  if (alertsHtml === "") {
    alertsHtml = "<tr><td colspan='4'>No active alerts.</td></tr>";
  }
  
  document.getElementById("table-alerts").innerHTML = alertsHtml;
}

// Enable sorting headers listeners
function setupSorting() {
  const headers = document.querySelectorAll('th.sortable');
  for (let i = 0; i < headers.length; i++) {
    const th = headers[i];
    th.addEventListener('click', function() {
      const col = th.dataset.sort;
      if (state.sort.column === col) {
        if (state.sort.dir === 'asc') {
          state.sort.dir = 'desc';
        } else {
          state.sort.dir = 'asc';
        }
      } else {
        state.sort.column = col;
        state.sort.dir = 'desc';
      }
      
      const allHeaders = document.querySelectorAll('th.sortable');
      for (let j = 0; j < allHeaders.length; j++) {
        allHeaders[j].classList.remove('sort-asc', 'sort-desc');
      }
      
      if (state.sort.dir === 'asc') {
        th.classList.add('sort-asc');
      } else {
        th.classList.add('sort-desc');
      }
      
      renderTables(state.data);
    });
  }
}

// Basic data array sorter
function sortData(array, getValueFn) {
  const sortedArray = [...array];
  sortedArray.sort(function(a, b) {
    const valA = getValueFn(a);
    const valB = getValueFn(b);
    
    if (valA < valB) {
      if (state.sort.dir === 'asc') {
        return -1;
      } else {
        return 1;
      }
    }
    if (valA > valB) {
      if (state.sort.dir === 'asc') {
        return 1;
      } else {
        return -1;
      }
    }
    return 0;
  });
  return sortedArray;
}

// Draw network, processes, and signature log lists
function renderTables(data) {
  const sortedNetwork = sortData(data.network, function(item) {
    const socket = item.socket || {};
    if (state.sort.column === 'pid') {
      return socket.pid || 0;
    }
    if (state.sort.column === 'local') {
      return socket.local_port || 0;
    }
    if (state.sort.column === 'remote') {
      return socket.remote_ip || '';
    }
    if (state.sort.column === 'status') {
      return socket.state || '';
    }
    return item.timestamp || '';
  });
  
  let networkRowsHtml = "";
  const slicedNetwork = sortedNetwork.slice(0, 100);
  
  for (let i = 0; i < slicedNetwork.length; i++) {
    const item = slicedNetwork[i];
    const sock = item.socket || {};
    const stringified = JSON.stringify(item);
    
    let remoteText = "-";
    if (sock.remote_ip) {
      if (sock.hostname) {
        remoteText = sock.hostname + " (" + sock.remote_ip + ":" + sock.remote_port + ")";
      } else {
        remoteText = sock.remote_ip + ":" + sock.remote_port;
      }
    }
    
    networkRowsHtml = networkRowsHtml + `
      <tr onclick='openDrawer("Network Event", ${stringified})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td>${sock.pid}</td>
        <td>${sock.local_ip}:${sock.local_port}</td>
        <td>${remoteText}</td>
        <td>${sock.state || '-'}</td>
      </tr>
    `;
  }
  
  document.getElementById("table-network").innerHTML = networkRowsHtml;

  const sortedProcesses = sortData(data.processes, function(item) {
    const proc = item.process || {};
    if (state.sort.column === 'pid') {
      return proc.pid || 0;
    }
    if (state.sort.column === 'name') {
      return proc.name || '';
    }
    if (state.sort.column === 'score') {
      return proc.risk_score || 0;
    }
    return item.timestamp || '';
  });

  let processesRowsHtml = "";
  const slicedProcesses = sortedProcesses.slice(0, 100);
  
  for (let i = 0; i < slicedProcesses.length; i++) {
    const item = slicedProcesses[i];
    const proc = item.process || {};
    const stringified = JSON.stringify(item);
    const reasons = proc.risk_reasons || [];
    
    let scoreColor = "var(--text)";
    if (proc.risk_score > 0) {
      scoreColor = "var(--alert)";
    }
    
    processesRowsHtml = processesRowsHtml + `
      <tr onclick='openDrawer("Process Details", ${stringified})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td>${proc.pid}</td>
        <td style="color:var(--neon)">${proc.name}</td>
        <td style="color:${scoreColor}">${proc.risk_score || 0}</td>
        <td>${reasons.join(", ")}</td>
      </tr>
    `;
  }
  
  document.getElementById("table-processes").innerHTML = processesRowsHtml;

  const sortedHashes = sortData(data.hashes, function(item) {
    if (state.sort.column === 'name') {
      return item.file_name || '';
    }
    if (state.sort.column === 'status') {
      return item.status || '';
    }
    return item.timestamp || '';
  });

  let hashesRowsHtml = "";
  const slicedHashes = sortedHashes.slice(0, 100);
  
  for (let i = 0; i < slicedHashes.length; i++) {
    const item = slicedHashes[i];
    const stringified = JSON.stringify(item);
    
    let statusColor = "var(--neon)";
    if (item.status === "MALICIOUS") {
      statusColor = "var(--alert)";
    }
    
    hashesRowsHtml = hashesRowsHtml + `
      <tr onclick='openDrawer("Hash Details", ${stringified})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td>${item.file_name}</td>
        <td>${item.sha256}</td>
        <td style="color:${statusColor}">${item.status}</td>
      </tr>
    `;
  }
  
  document.getElementById("table-hashes").innerHTML = hashesRowsHtml;
}

// Side sliding metadata inspector
function openDrawer(title, rawData) {
  document.getElementById("drawer-title").innerText = title;
  document.getElementById("drawer-json").innerText = JSON.stringify(rawData, null, 2);
  
  const actionsEl = document.getElementById("drawer-intel-actions");
  if (actionsEl !== null) {
    actionsEl.innerHTML = "";
    
    if (rawData.sha256) {
      actionsEl.innerHTML = actionsEl.innerHTML + `
        <a href="https://www.virustotal.com/gui/file/${rawData.sha256}" target="_blank" class="intel-btn">🛡️ VirusTotal</a>
      `;
    }
    
    if (rawData.process && rawData.process.name) {
      const encodedName = encodeURIComponent(rawData.process.name);
      actionsEl.innerHTML = actionsEl.innerHTML + `
        <a href="https://www.google.com/search?q=${encodedName}+process+security" target="_blank" class="intel-btn">🔍 Search Info</a>
      `;
    } else if (rawData.child_name) {
      const encodedName = encodeURIComponent(rawData.child_name);
      actionsEl.innerHTML = actionsEl.innerHTML + `
        <a href="https://www.google.com/search?q=${encodedName}+process+security" target="_blank" class="intel-btn">🔍 Search Info</a>
      `;
    }
    
    const socketObj = rawData.socket || rawData.connection || {};
    if (socketObj.remote_ip && socketObj.remote_ip !== "127.0.0.1" && socketObj.remote_ip !== "::1") {
      actionsEl.innerHTML = actionsEl.innerHTML + `
        <a href="https://ipinfo.io/${socketObj.remote_ip}" target="_blank" class="intel-btn">🌐 IPInfo Lookup</a>
      `;
    } else if (rawData.ip && rawData.ip !== "127.0.0.1" && rawData.ip !== "::1") {
      actionsEl.innerHTML = actionsEl.innerHTML + `
        <a href="https://ipinfo.io/${rawData.ip}" target="_blank" class="intel-btn">🌐 IPInfo Lookup</a>
      `;
    }
  }

  document.getElementById("json-drawer").classList.add("open");
}

document.getElementById("close-drawer").addEventListener("click", function() {
  document.getElementById("json-drawer").classList.remove("open");
});

// Update Analytics Charts inside dashboard
function renderCharts(data) {
  if (typeof Chart === "undefined") {
    return;
  }

  const makeChart = function(id, type, labels, datasetData, colors, label) {
    const existingChart = state.charts[id];
    
    if (existingChart !== undefined) {
      existingChart.data.labels = labels;
      existingChart.data.datasets[0].data = datasetData;
      if (colors) {
        existingChart.data.datasets[0].backgroundColor = colors;
      }
      existingChart.update('none');
    } else {
      const canvasEl = document.getElementById(id);
      const ctx = canvasEl.getContext('2d');
      
      let borderStyle = "#111827";
      if (type === 'line') {
        borderStyle = "#6366f1";
      }
      
      let filledValue = false;
      if (type === 'line') {
        filledValue = true;
      }
      
      let curveTension = 0;
      if (type === 'line') {
        curveTension = 0.35;
      }

      state.charts[id] = new Chart(ctx, {
        type: type,
        data: { 
          labels: labels, 
          datasets: [{ 
            label: label, 
            data: datasetData, 
            backgroundColor: colors, 
            borderColor: borderStyle, 
            fill: filledValue,
            tension: curveTension
          }] 
        },
        options: { 
          responsive: true, 
          maintainAspectRatio: false, 
          plugins: { 
            legend: { 
              display: type !== 'line', 
              labels: { 
                color: '#cbd5e1', 
                font: { family: 'Inter', size: 11 } 
              } 
            } 
          }, 
          scales: type === 'line' || type === 'bar' ? {
            x: { 
              ticks: { color: '#64748b', font: { family: 'Inter', size: 10 } },
              grid: { color: 'rgba(255, 255, 255, 0.04)' }
            }, 
            y: { 
              ticks: { color: '#64748b', font: { family: 'Inter', size: 10 } }, 
              grid: { color: 'rgba(255, 255, 255, 0.04)' },
              beginAtZero: true
            }
          } : {} 
        }
      });
    }
  };

  let netTimeBuckets = {};
  for (let i = 0; i < data.network.length; i++) {
    const item = data.network[i];
    if (item.timestamp) {
      const splitParts = item.timestamp.split("T");
      if (splitParts.length > 1) {
        const timeSegment = splitParts[1].substring(0, 8);
        netTimeBuckets[timeSegment] = (netTimeBuckets[timeSegment] || 0) + 1;
      }
    }
  }
  
  const netLabels = Object.keys(netTimeBuckets).sort().slice(-40); 
  const netDataPoints = [];
  for (let i = 0; i < netLabels.length; i++) {
    netDataPoints.push(netTimeBuckets[netLabels[i]]);
  }
  
  makeChart('chart-timeline', 'line', netLabels, netDataPoints, 'rgba(99, 102, 241, 0.08)', 'Network Events');

  let procTimeBuckets = {};
  for (let i = 0; i < data.processes.length; i++) {
    const item = data.processes[i];
    if (item.timestamp) {
      const splitParts = item.timestamp.split("T");
      if (splitParts.length > 1) {
        const timeSegment = splitParts[1].substring(0, 8);
        if (!procTimeBuckets[timeSegment]) {
          procTimeBuckets[timeSegment] = { start: 0, stop: 0 };
        }
        
        if (item.action === "START" || item.action === "PROC_START") {
          procTimeBuckets[timeSegment].start = procTimeBuckets[timeSegment].start + 1;
        }
        if (item.action === "STOP" || item.action === "PROC_STOP") {
          procTimeBuckets[timeSegment].stop = procTimeBuckets[timeSegment].stop + 1;
        }
      }
    }
  }
  
  const procLabels = Object.keys(procTimeBuckets).sort().slice(-40);
  const churnChart = state.charts['chart-process-churn'];
  
  if (churnChart !== undefined) {
    churnChart.data.labels = procLabels;
    churnChart.data.datasets[0].data = procLabels.map(function(l) { return procTimeBuckets[l].start; });
    churnChart.data.datasets[1].data = procLabels.map(function(l) { return procTimeBuckets[l].stop; });
    churnChart.update('none');
  } else {
    const canvasEl = document.getElementById('chart-process-churn');
    const ctx = canvasEl.getContext('2d');
    
    state.charts['chart-process-churn'] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: procLabels,
        datasets: [
          { 
            label: 'Created', 
            data: procLabels.map(function(l) { return procTimeBuckets[l].start; }), 
            borderColor: '#10b981', 
            backgroundColor: 'rgba(16, 185, 129, 0.08)', 
            fill: true, 
            tension: 0.35 
          },
          { 
            label: 'Ended', 
            data: procLabels.map(function(l) { return procTimeBuckets[l].stop; }), 
            borderColor: '#ef4444', 
            backgroundColor: 'rgba(239, 68, 68, 0.08)', 
            fill: true, 
            tension: 0.35 
          }
        ]
      },
      options: { 
        responsive: true, 
        maintainAspectRatio: false, 
        scales: { 
          x: { 
            ticks: { color: '#64748b', font: { family: 'Inter', size: 10 } },
            grid: { color: 'rgba(255, 255, 255, 0.04)' }
          }, 
          y: { 
            ticks: { color: '#64748b', font: { family: 'Inter', size: 10 } }, 
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            beginAtZero: true 
          } 
        }, 
        plugins: { 
          legend: { 
            labels: { color: '#cbd5e1', font: { family: 'Inter', size: 11 } } 
          } 
        } 
      }
    });
  }

  let procCount = {};
  for (let i = 0; i < data.processes.length; i++) {
    const item = data.processes[i];
    if (item.process) {
      const name = item.process.name;
      procCount[name] = (procCount[name] || 0) + 1;
    }
  }
  
  let sortedProcessesList = Object.entries(procCount);
  sortedProcessesList.sort(function(a, b) {
    return b[1] - a[1];
  });
  
  const finalProcs = sortedProcessesList.slice(0, 6);
  makeChart('chart-top-procs', 'bar', finalProcs.map(function(k) { return k[0]; }), finalProcs.map(function(k) { return k[1]; }), '#6366f1', 'Executions');

  let portCount = {};
  for (let i = 0; i < data.network.length; i++) {
    const item = data.network[i];
    const sock = item.socket || {};
    if (sock.remote_port) {
      portCount[sock.remote_port] = (portCount[sock.remote_port] || 0) + 1;
    }
  }
  
  let sortedPortsList = Object.entries(portCount);
  sortedPortsList.sort(function(a, b) {
    return b[1] - a[1];
  });
  
  const finalPorts = sortedPortsList.slice(0, 6);
  makeChart(
    'chart-ports', 
    'doughnut', 
    finalPorts.map(function(k) { return k[0]; }), 
    finalPorts.map(function(k) { return k[1]; }), 
    ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#64748b'], 
    'Connections'
  );

  let protoCount = { TCP: 0, UDP: 0 };
  for (let i = 0; i < data.network.length; i++) {
    const item = data.network[i];
    const sock = item.socket || {};
    if (sock.protocol) {
      protoCount[sock.protocol] = protoCount[sock.protocol] + 1;
    }
  }
  makeChart('chart-protocol-type', 'doughnut', Object.keys(protoCount), Object.values(protoCount), ['#6366f1', '#8b5cf6'], 'Protocol');

  let ipCount = { IPv4: 0, IPv6: 0 };
  for (let i = 0; i < data.network.length; i++) {
    const item = data.network[i];
    const sock = item.socket || {};
    if (sock.ip_version) {
      ipCount[sock.ip_version] = ipCount[sock.ip_version] + 1;
    }
  }
  makeChart('chart-ip-version', 'doughnut', Object.keys(ipCount), Object.values(ipCount), ['#10b981', '#f59e0b'], 'IP Version');
}

// Plot live traffic vectors and datacenters onto map
async function renderMap(geoData) {
  if (typeof L === "undefined") {
    return;
  }

  if (mapInstance === null) {
    mapInstance = L.map('map-canvas-container').setView([21.1458, 79.0882], 3);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap &copy; CARTO'
    }).addTo(mapInstance);
    mapLayer = L.layerGroup().addTo(mapInstance);

    mapInstance.on('zoomend', function() {
      const zoomLevel = mapInstance.getZoom();
      const showDetails = zoomLevel >= 6;
      
      for (let i = 0; i < dynamicPathLines.length; i++) {
        let opacityValue = 0;
        if (showDetails) {
          opacityValue = 0.85;
        }
        dynamicPathLines[i].setStyle({ opacity: opacityValue });
      }
      
      for (let i = 0; i < dynamicPathLabels.length; i++) {
        let opacityValue = 0;
        if (showDetails) {
          opacityValue = 0.95;
        }
        dynamicPathLabels[i].setOpacity(opacityValue);
      }
    });
  }

  setTimeout(function() { 
    mapInstance.invalidateSize(); 
  }, 100);
  
  mapLayer.clearLayers();
  dynamicPathLines = [];
  dynamicPathLabels = [];

  if (cachedDataCenters.length === 0) {
    cachedDataCenters = await fetch('/datacenters.json').then(function(r) {
      return r.json();
    }).catch(function() {
      return [];
    });
  }

  const getHaversineDistance = function(lat1, lon1, lat2, lon2) {
    const radiusOfEarth = 6371; 
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    
    const computedArc = Math.sin(dLat/2)*Math.sin(dLat/2) + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLon/2)*Math.sin(dLon/2);
    const finalDistance = radiusOfEarth * (2 * Math.atan2(Math.sqrt(computedArc), Math.sqrt(1 - computedArc)));
    return finalDistance;
  };

  // Render datacenter coordinates
  for (let i = 0; i < cachedDataCenters.length; i++) {
    const dc = cachedDataCenters[i];
    if (dc.city_coords && dc.city_coords.length === 2) {
      L.circleMarker([dc.city_coords[0], dc.city_coords[1]], {
        radius: 4,
        fillColor: "#ffaa00",
        color: "transparent",
        fillOpacity: 0.15,
        interactive: true
      }).addTo(mapLayer).bindPopup(`<strong>Data Center Profile</strong><br>${dc.name}<br>${dc.company}`);
    }
  }

  // Plot resolved geolocation points
  for (let i = 0; i < geoData.length; i++) {
    const loc = geoData[i];
    if (loc.latitude && loc.longitude) {
      
      // Render outer glow ring
      L.circleMarker([loc.latitude, loc.longitude], {
        radius: 12,
        fillColor: "#6366f1",
        color: "transparent",
        fillOpacity: 0.25
      }).addTo(mapLayer);

      // Render inner core dot
      const trafficMarker = L.circleMarker([loc.latitude, loc.longitude], {
        radius: 6,
        fillColor: "#6366f1",
        color: "#ffffff",
        weight: 1.5,
        fillOpacity: 1.0
      });
      
      let hostText = "";
      if (loc.hostname) {
        hostText = "Domain: " + loc.hostname + "<br>";
      }
      
      trafficMarker.bindPopup(`<strong>IP Target: ${loc.ip}</strong><br>${hostText}${loc.city}, ${loc.country}<br>Carrier: ${loc.isp}`);
      mapLayer.addLayer(trafficMarker);

      let closestDc = null;
      let shortestDistance = Infinity;

      for (let j = 0; j < cachedDataCenters.length; j++) {
        const dc = cachedDataCenters[j];
        if (dc.city_coords && dc.city_coords.length === 2) {
          const d = getHaversineDistance(loc.latitude, loc.longitude, dc.city_coords[0], dc.city_coords[1]);
          if (d < shortestDistance) {
            shortestDistance = d;
            closestDc = dc;
          }
        }
      }

      // Draw connection lines to nearest datacenter
      if (closestDc !== null) {
        const dcLat = closestDc.city_coords[0];
        const dcLon = closestDc.city_coords[1];
        
        const zoomLevel = mapInstance.getZoom();
        let showPaths = false;
        if (zoomLevel >= 6) {
          showPaths = true;
        }

        let opacityValue = 0;
        if (showPaths) {
          opacityValue = 0.85;
        }

        const trafficLine = L.polyline([[loc.latitude, loc.longitude], [dcLat, dcLon]], {
          color: '#ffaa00', 
          weight: 2,
          opacity: opacityValue,
          dashArray: '2, 5'
        });
        
        mapLayer.addLayer(trafficLine);
        dynamicPathLines.push(trafficLine);

        const roundedDistance = Math.round(shortestDistance);
        const labelText = closestDc.company + " (~" + roundedDistance + " km)";
        
        let labelOpacityValue = 0;
        if (showPaths) {
          labelOpacityValue = 0.95;
        }

        const label = L.marker([(loc.latitude + dcLat)/2, (loc.longitude + dcLon)/2], {
          opacity: labelOpacityValue,
          icon: L.divIcon({
            className: 'map-path-label',
            html: `<div style="color: #fff; background: #161b22; border: 1px solid rgba(255,255,255,0.2); padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 10px; font-weight: bold; white-space: nowrap; box-shadow: 0 2px 6px rgba(0,0,0,0.5); pointer-events: none;">🏢 ${labelText}</div>`
          })
        });
        
        mapLayer.addLayer(label);
        dynamicPathLabels.push(label);
      }
    }
  }
}

// Generate relational process tree cards
function renderProcessTree(data) {
  const container = document.getElementById("tree-container");
  if (data.children.length === 0) { 
    container.innerHTML = "No relationships mapped yet."; 
    return; 
  }

  const nameMap = {};
  for (let i = 0; i < data.processes.length; i++) {
    const item = data.processes[i];
    if (item.process) {
      nameMap[item.process.guid] = item.process.name;
    }
  }

  let html = "";
  const slicedChildren = data.children.slice(-100);
  
  for (let i = 0; i < slicedChildren.length; i++) {
    const item = slicedChildren[i];
    const pName = nameMap[item.parent_guid] || "System Parent";
    const cName = item.child_name;
    
    let isBad = false;
    const lowerName = cName.toLowerCase();
    if (lowerName.includes("powershell") || lowerName.includes("cmd") || lowerName.includes("wscript") || lowerName.includes("mshta")) {
      isBad = true;
    }
    
    const stringified = JSON.stringify(item);
    
    let warningClass = "";
    if (isBad) {
      warningClass = "warning-party";
    }

    html = html + `
      <div class="tree-relation-card" onclick='openDrawer("Lineage Event", ${stringified})'>
        <div class="tree-party parent-party">
          <span class="party-tag">PARENT PROCESS</span>
          <span class="party-name">${pName}</span>
        </div>
        <div class="tree-connector">
          <span class="connector-arrow">➔</span>
          <span class="connector-label">spawned</span>
        </div>
        <div class="tree-party child-party ${warningClass}">
          <span class="party-tag">CHILD PROCESS (PID: ${item.child_pid})</span>
          <span class="party-name">${cName}</span>
        </div>
      </div>
    `;
  }
  
  container.innerHTML = html;
}

// Load historical runs list
async function populateHistory() {
  const sessions = await fetch("/api/sessions").then(function(r) {
    return r.json();
  }).catch(function() {
    return [];
  });
  
  let historyRowsHtml = "";
  for (let i = 0; i < sessions.length; i++) {
    const item = sessions[i];
    const totalLogs = item.network_count + item.process_count;
    const dateFormatted = new Date(item.started_at).toLocaleString();
    
    historyRowsHtml = historyRowsHtml + `
      <tr onclick="state.mode='history'; state.sessionId='${item.id}'; updateState();">
        <td style="color:var(--neon)">${item.id}</td>
        <td>${dateFormatted}</td>
        <td>${totalLogs}</td>
        <td>${item.threat_count}</td>
      </tr>
    `;
  }
  
  document.getElementById("table-history").innerHTML = historyRowsHtml;

  let optionsHtml = "";
  for (let i = 0; i < sessions.length; i++) {
    const id = sessions[i].id;
    optionsHtml = optionsHtml + `<option value="${id}">${id}</option>`;
  }
  
  if (optionsHtml === "") {
    optionsHtml = "<option>No sessions found</option>";
  }
  
  document.getElementById("comp-a").innerHTML = optionsHtml;
  document.getElementById("comp-b").innerHTML = optionsHtml;
}

// Compare differences in running processes between two logs
document.getElementById("btn-exec-compare").addEventListener("click", async function() {
  const sessionA = document.getElementById("comp-a").value;
  const sessionB = document.getElementById("comp-b").value;
  
  if (sessionA === sessionB) {
    alert("Select two different sessions.");
    return;
  }

  try {
    const processesA = await fetch(`/api/session/${sessionA}/process`).then(function(r) { return r.json(); });
    const processesB = await fetch(`/api/session/${sessionB}/process`).then(function(r) { return r.json(); });

    const namesA = new Set();
    for (let i = 0; i < processesA.length; i++) {
      if (processesA[i].process && processesA[i].process.name) {
        namesA.add(processesA[i].process.name);
      }
    }
    
    const namesB = new Set();
    for (let i = 0; i < processesB.length; i++) {
      if (processesB[i].process && processesB[i].process.name) {
        namesB.add(processesB[i].process.name);
      }
    }

    const missingList = [];
    namesA.forEach(function(item) {
      if (!namesB.has(item)) {
        missingList.push(item);
      }
    });
    
    const addedList = [];
    namesB.forEach(function(item) {
      if (!namesA.has(item)) {
        addedList.push(item);
      }
    });

    let missingHtml = "";
    for (let i = 0; i < missingList.length; i++) {
      missingHtml = missingHtml + "<li>" + missingList[i] + "</li>";
    }
    if (missingHtml === "") {
      missingHtml = "<li>No differences detected</li>";
    }
    
    let addedHtml = "";
    for (let i = 0; i < addedList.length; i++) {
      addedHtml = addedHtml + "<li>" + addedList[i] + "</li>";
    }
    if (addedHtml === "") {
      addedHtml = "<li>No differences detected</li>";
    }

    document.getElementById("diff-missing").innerHTML = missingHtml;
    document.getElementById("diff-new").innerHTML = addedHtml;
  } catch(e) { 
    console.error("Comparison matrix execution failed", e); 
  }
});

// Configure sidebar tab links
function setupNav() {
  const links = document.querySelectorAll(".nav-link");
  
  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    link.addEventListener("click", function() {
      const allLinks = document.querySelectorAll(".nav-link");
      for (let j = 0; j < allLinks.length; j++) {
        allLinks[j].classList.remove("active");
      }
      
      const allPanels = document.querySelectorAll(".panel");
      for (let j = 0; j < allPanels.length; j++) {
        allPanels[j].classList.remove("active");
      }
      
      link.classList.add("active");
      const targetPanelName = link.dataset.target;
      const targetPanel = document.getElementById("panel-" + targetPanelName);
      targetPanel.classList.add("active");
      
      if (targetPanelName === "history" || targetPanelName === "compare") {
        populateHistory();
      }
      if (targetPanelName === "analytics") {
        renderCharts(state.data);
      }
      if (targetPanelName === "tree") {
        renderProcessTree(state.data);
      }
      if (targetPanelName === "map") {
        renderMap(state.data.geo);
      }
    });
  }
}

// Configures controls start and stop buttons
function setupControls() {
  document.getElementById("btn-start").addEventListener("click", async function() {
    await fetch("/api/scan/start", { method: "POST" });
    state.mode = "live";
    await updateState();
  });
  
  document.getElementById("btn-stop").addEventListener("click", async function() {
    await fetch("/api/scan/stop", { method: "POST" });
    await updateState();
  });
}

function fmtTime(timestamp) {
  if (timestamp === "") {
    return "—";
  }
  if (timestamp === undefined) {
    return "—";
  }
  const dateObj = new Date(timestamp);
  const isValid = isNaN(dateObj);
  if (isValid) {
    return timestamp;
  }
  return dateObj.toLocaleTimeString();
}

window.addEventListener("DOMContentLoaded", init);

// Exporter of telemetry logs as local CSV files
function exportTableData(type) {
  const records = state.data[type];
  if (records === undefined) {
    alert("No records available to export.");
    return;
  }
  if (records.length === 0) {
    alert("No records available to export.");
    return;
  }

  let headers = [];
  let rowMapper = function() { return []; };

  if (type === "network") {
    headers = ["Timestamp", "Protocol", "PID", "Local IP", "Local Port", "Remote IP", "Remote Port", "Direction", "State"];
    rowMapper = function(item) {
      const sock = item.socket || {};
      const output = [
        item.timestamp || "",
        sock.protocol || "",
        sock.pid || "",
        sock.local_ip || "",
        sock.local_port || "",
        sock.remote_ip || "",
        sock.remote_port || "",
        sock.direction || "",
        sock.state || ""
      ];
      return output;
    };
  } else if (type === "processes") {
    headers = ["Timestamp", "Action", "PID", "Process Name", "Risk Score", "Executable Path", "Command Line", "Username"];
    rowMapper = function(item) {
      const proc = item.process || {};
      const rawCmd = proc.cmdline || "";
      const escapedCmd = rawCmd.replace(/"/g, '""');
      
      const output = [
        item.timestamp || "",
        item.action || "",
        proc.pid || "",
        proc.name || "",
        proc.risk_score || 0,
        proc.path || "",
        `"${escapedCmd}"`,
        proc.user || ""
      ];
      return output;
    };
  } else if (type === "hashes") {
    headers = ["Timestamp", "Process GUID", "File Name", "SHA256 Hash", "Status"];
    rowMapper = function(item) {
      const output = [
        item.timestamp || "",
        item.process_guid || "",
        item.file_name || "",
        item.sha256 || "",
        item.status || ""
      ];
      return output;
    };
  } else {
    alert("Unsupported export format.");
    return;
  }

  const csvRows = [headers.join(",")];
  
  for (let i = 0; i < records.length; i++) {
    const item = records[i];
    const mappedValues = rowMapper(item);
    const cleanedValues = [];
    
    for (let j = 0; j < mappedValues.length; j++) {
      const stringifiedValue = "" + mappedValues[j];
      const escapedValue = stringifiedValue.replace(/"/g, '""');
      
      let containsSpecial = false;
      if (escapedValue.includes(',')) {
        containsSpecial = true;
      }
      if (escapedValue.includes('\n')) {
        containsSpecial = true;
      }
      if (escapedValue.includes('"')) {
        containsSpecial = true;
      }
      
      if (containsSpecial) {
        cleanedValues.push(`"${escapedValue}"`);
      } else {
        cleanedValues.push(escapedValue);
      }
    }
    
    csvRows.push(cleanedValues.join(","));
  }

  const csvBlob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const csvUrl = URL.createObjectURL(csvBlob);
  const downloadLink = document.createElement("a");
  
  downloadLink.href = csvUrl;
  downloadLink.setAttribute("download", `netship_${type}_export_${Date.now()}.csv`);
  document.body.appendChild(downloadLink);
  downloadLink.click();
  document.body.removeChild(downloadLink);
}