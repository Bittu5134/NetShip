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
  setInterval(updateState, 3000);
}

async function updateState() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const status = await res.json();
    
    const banner = document.getElementById("status-banner");
    const pulse = document.getElementById("engine-pulse");

    if (status.running) {
      state.mode = "live";
      state.sessionId = status.session_dir;
      banner.className = "status-banner live";
      banner.innerText = `LIVE SCAN: ${state.sessionId}`;
      
      if (pulse) {
        pulse.classList.remove("idle");
        pulse.classList.add("live");
      }
    } else if (state.mode !== "history") {
      state.mode = "offline";
      banner.className = "status-banner offline";
      banner.innerText = "SYSTEM IDLE";
      
      if (pulse) {
        pulse.classList.remove("live");
        pulse.classList.add("idle");
      }
    } else {
      banner.className = "status-banner history";
      banner.innerText = `HISTORY LOG: ${state.sessionId}`;
      
      if (pulse) {
        pulse.classList.remove("live");
        pulse.classList.add("idle");
      }
    }

    if (state.mode !== "offline") {
      await fetchTelemetry();
    }
    
    const historyPanel = document.getElementById("panel-history");
    if (historyPanel && historyPanel.classList.contains("active")) {
      await populateHistory();
    }
  } catch (err) {
    console.error("Failed to update status state:", err);
  }
}

async function fetchTelemetry() {
  const base = state.mode === "live" ? "/api/live/" : `/api/session/${state.sessionId}/`;
  
  try {
    const [net, proc, hash, child, geo] = await Promise.all([
      fetch(`${base}network`).then(r => r.json()),
      fetch(`${base}process`).then(r => r.json()),
      fetch(`${base}hashes`).then(r => r.json()),
      fetch(`${base}children`).then(r => r.json()),
      fetch(`${base}geo`).then(r => r.json())
    ]);

    state.data.network = net || [];
    state.data.processes = proc || [];
    state.data.hashes = hash || [];
    state.data.children = child || [];
    state.data.geo = geo || [];
    
    const query = document.getElementById("global-search").value.toLowerCase();
    if (query.length > 1) {
      const match = item => JSON.stringify(item).toLowerCase().includes(query);
      renderAllDashboards({
        network: state.data.network.filter(match),
        processes: state.data.processes.filter(match),
        hashes: state.data.hashes.filter(match),
        children: state.data.children,
        geo: state.data.geo
      });
    } else {
      renderAllDashboards(state.data);
    }
  } catch (err) { 
    console.error("Telemetry fetch failed:", err); 
  }
}

document.getElementById("global-search").addEventListener("input", () => {
  if (state.mode !== "offline") {
    fetchTelemetry();
  }
});

function renderAllDashboards(data) {
  renderOverview(data);
  renderTables(data);
  
  if (document.getElementById("panel-analytics").classList.contains("active")) {
    renderCharts(data);
  }
  if (document.getElementById("panel-tree").classList.contains("active")) {
    renderProcessTree(data);
  }
  if (document.getElementById("panel-map").classList.contains("active")) {
    renderMap(data.geo);
  }
}

function renderOverview(data) {
  const activeProcesses = data.processes.filter(p => p.action === "START" || p.action === "PROC_START").length;
  
  document.getElementById("count-proc").innerText = activeProcesses;
  document.getElementById("count-net").innerText = data.network.length;
  document.getElementById("count-hash").innerText = data.hashes.length;
  
  let riskScore = 0;
  const alerts = [];
  
  data.processes.forEach(item => {
    if (item.process) {
      const score = item.process.risk_score || 0;
      riskScore += score;
      if (score > 20 || (item.process.risk_reasons && item.process.risk_reasons.length > 0)) {
        alerts.push(item);
      }
    }
  });
  
  document.getElementById("count-threat").innerText = riskScore;
  
  const gaugeFill = document.getElementById("gauge-fill");
  const gaugeStatusText = document.getElementById("gauge-status-text");
  const gaugeScoreVal = document.getElementById("gauge-score-val");
  
  if (gaugeFill && gaugeStatusText && gaugeScoreVal) {
    const pct = Math.min((riskScore / 250) * 100, 100);
    gaugeFill.style.width = `${pct}%`;
    gaugeScoreVal.innerText = `Cumulative Score: ${riskScore}`;
    
    if (riskScore === 0) {
      gaugeStatusText.innerText = "SYSTEM STATUS: SAFE";
      gaugeStatusText.style.color = "var(--success)";
    } else if (riskScore < 100) {
      gaugeStatusText.innerText = "SYSTEM STATUS: DEVIATIONS DETECTED";
      gaugeStatusText.style.color = "var(--warn)";
    } else {
      gaugeStatusText.innerText = "SYSTEM STATUS: SUSPICIOUS/ALERT STATE";
      gaugeStatusText.style.color = "var(--alert)";
    }
  }
  
  const alertsHtml = alerts.slice(-10).reverse().map(item => {
    const proc = item.process;
    const reasons = proc.risk_reasons || [];
    return `
      <tr onclick='openDrawer("Alert Details", ${JSON.stringify(item)})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td style="color:var(--neon)">${proc.name}</td>
        <td style="color:var(--alert)">${proc.risk_score}</td>
        <td>${reasons.join(", ")}</td>
      </tr>
    `;
  }).join("") || "<tr><td colspan='4'>No active alerts.</td></tr>";
  
  document.getElementById("table-alerts").innerHTML = alertsHtml;
}

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
      
      document.querySelectorAll('th.sortable').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
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
  const sortedNetwork = sortData(data.network, item => {
    const sock = item.socket || {};
    if (state.sort.column === 'pid') return sock.pid || 0;
    if (state.sort.column === 'local') return sock.local_port || 0;
    if (state.sort.column === 'remote') return sock.remote_ip || '';
    if (state.sort.column === 'status') return sock.state || '';
    return item.timestamp || '';
  });
  
  const networkRowsHtml = sortedNetwork.slice(0, 100).map(item => {
    const sock = item.socket || {};
    const remoteText = sock.remote_ip 
      ? (sock.hostname ? `${sock.hostname} (${sock.remote_ip}:${sock.remote_port})` : `${sock.remote_ip}:${sock.remote_port}`)
      : "-";
    return `
      <tr onclick='openDrawer("Network Event", ${JSON.stringify(item)})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td>${sock.pid}</td>
        <td>${sock.local_ip}:${sock.local_port}</td>
        <td>${remoteText}</td>
        <td>${sock.state || '-'}</td>
      </tr>
    `;
  }).join("");
  
  document.getElementById("table-network").innerHTML = networkRowsHtml;

  const sortedProcesses = sortData(data.processes, item => {
    const proc = item.process || {};
    if (state.sort.column === 'pid') return proc.pid || 0;
    if (state.sort.column === 'name') return proc.name || '';
    if (state.sort.column === 'score') return proc.risk_score || 0;
    return item.timestamp || '';
  });

  const processesRowsHtml = sortedProcesses.slice(0, 100).map(item => {
    const proc = item.process || {};
    const reasons = proc.risk_reasons || [];
    const scoreColor = proc.risk_score > 0 ? "var(--alert)" : "var(--text)";
    return `
      <tr onclick='openDrawer("Process Details", ${JSON.stringify(item)})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td>${proc.pid}</td>
        <td style="color:var(--neon)">${proc.name}</td>
        <td style="color:${scoreColor}">${proc.risk_score || 0}</td>
        <td>${reasons.join(", ")}</td>
      </tr>
    `;
  }).join("");
  
  document.getElementById("table-processes").innerHTML = processesRowsHtml;

  const sortedHashes = sortData(data.hashes, item => {
    if (state.sort.column === 'name') return item.file_name || '';
    if (state.sort.column === 'status') return item.status || '';
    return item.timestamp || '';
  });

  const hashesRowsHtml = sortedHashes.slice(0, 100).map(item => {
    const statusColor = item.status === "MALICIOUS" ? "var(--alert)" : "var(--neon)";
    return `
      <tr onclick='openDrawer("Hash Details", ${JSON.stringify(item)})'>
        <td>${fmtTime(item.timestamp)}</td>
        <td>${item.file_name}</td>
        <td>${item.sha256}</td>
        <td style="color:${statusColor}">${item.status}</td>
      </tr>
    `;
  }).join("");
  
  document.getElementById("table-hashes").innerHTML = hashesRowsHtml;
}

function openDrawer(title, rawData) {
  document.getElementById("drawer-title").innerText = title;
  document.getElementById("drawer-json").innerText = JSON.stringify(rawData, null, 2);
  
  const actionsEl = document.getElementById("drawer-intel-actions");
  if (actionsEl) {
    actionsEl.innerHTML = "";
    
    if (rawData.sha256) {
      actionsEl.innerHTML += `<a href="https://www.virustotal.com/gui/file/${rawData.sha256}" target="_blank" class="intel-btn">🛡️ VirusTotal</a>`;
    }
    
    if (rawData.process && rawData.process.name) {
      actionsEl.innerHTML += `<a href="https://www.google.com/search?q=${encodeURIComponent(rawData.process.name)}+process+security" target="_blank" class="intel-btn">🔍 Search Info</a>`;
    } else if (rawData.child_name) {
      actionsEl.innerHTML += `<a href="https://www.google.com/search?q=${encodeURIComponent(rawData.child_name)}+process+security" target="_blank" class="intel-btn">🔍 Search Info</a>`;
    }
    
    const socketObj = rawData.socket || rawData.connection || {};
    if (socketObj.remote_ip && socketObj.remote_ip !== "127.0.0.1" && socketObj.remote_ip !== "::1") {
      actionsEl.innerHTML += `<a href="https://ipinfo.io/${socketObj.remote_ip}" target="_blank" class="intel-btn">🌐 IPInfo Lookup</a>`;
    } else if (rawData.ip && rawData.ip !== "127.0.0.1" && rawData.ip !== "::1") {
      actionsEl.innerHTML += `<a href="https://ipinfo.io/${rawData.ip}" target="_blank" class="intel-btn">🌐 IPInfo Lookup</a>`;
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

async function populateHistory() {
  try {
    const res = await fetch("/api/sessions");
    if (!res.ok) return;
    const sessions = await res.json();

    const historyRowsHtml = sessions.map(item => {
      const totalLogs = item.network_count + item.process_count;
      const dateFormatted = new Date(item.started_at).toLocaleString();
      return `
        <tr onclick="state.mode='history'; state.sessionId='${item.id}'; updateState();">
          <td style="color:var(--neon)">${item.id}</td>
          <td>${dateFormatted}</td>
          <td>${totalLogs}</td>
          <td>${item.threat_count}</td>
        </tr>
      `;
    }).join("");
    
    document.getElementById("table-history").innerHTML = historyRowsHtml;

    const optionsHtml = sessions.map(s => `<option value="${s.id}">${s.id}</option>`).join("") || "<option>No sessions found</option>";
    document.getElementById("comp-a").innerHTML = optionsHtml;
    document.getElementById("comp-b").innerHTML = optionsHtml;
  } catch (err) {
    console.error("Failed to populate sessions history:", err);
  }
}

document.getElementById("btn-exec-compare").addEventListener("click", async () => {
  const sessionA = document.getElementById("comp-a").value;
  const sessionB = document.getElementById("comp-b").value;
  
  if (sessionA === sessionB) {
    alert("Select two different sessions.");
    return;
  }

  try {
    const [procA, procB] = await Promise.all([
      fetch(`/api/session/${sessionA}/process`).then(r => r.json()),
      fetch(`/api/session/${sessionB}/process`).then(r => r.json())
    ]);

    const namesA = new Set(procA.map(p => p.process?.name).filter(Boolean));
    const namesB = new Set(procB.map(p => p.process?.name).filter(Boolean));

    const missing = [...namesA].filter(name => !namesB.has(name));
    const added = [...namesB].filter(name => !namesA.has(name));

    document.getElementById("diff-missing").innerHTML = missing.map(name => `<li>${name}</li>`).join("") || "<li>No differences detected</li>";
    document.getElementById("diff-new").innerHTML = added.map(name => `<li>${name}</li>`).join("") || "<li>No differences detected</li>";
  } catch (err) { 
    console.error("Session comparison failed:", err); 
  }
});

function setupNav() {
  document.querySelectorAll(".nav-link").forEach(link => {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      
      link.classList.add("active");
      const target = link.dataset.target;
      document.getElementById(`panel-${target}`).classList.add("active");
      
      if (target === "history" || target === "compare") {
        populateHistory();
      } else if (target === "analytics") {
        renderCharts(state.data);
      } else if (target === "tree") {
        renderProcessTree(state.data);
      } else if (target === "map") {
        renderMap(state.data.geo);
      }
    });
  });
}

function setupControls() {
  document.getElementById("btn-start").addEventListener("click", async () => {
    await fetch("/api/scan/start", { method: "POST" });
    state.mode = "live";
    await updateState();
  });
  
  document.getElementById("btn-stop").addEventListener("click", async () => {
    await fetch("/api/scan/stop", { method: "POST" });
    await updateState();
  });
}

function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d) ? ts : d.toLocaleTimeString();
}

window.addEventListener("DOMContentLoaded", init);

function exportTableData(type) {
  const records = state.data[type];
  if (!records || records.length === 0) {
    alert("No records available to export.");
    return;
  }

  let headers = [];
  let rowMapper = () => [];

  if (type === "network") {
    headers = ["Timestamp", "Protocol", "PID", "Local IP", "Local Port", "Remote IP", "Remote Port", "Direction", "State"];
    rowMapper = item => {
      const sock = item.socket || {};
      return [
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
    };
  } else if (type === "processes") {
    headers = ["Timestamp", "Action", "PID", "Process Name", "Risk Score", "Executable Path", "Command Line", "Username"];
    rowMapper = item => {
      const proc = item.process || {};
      return [
        item.timestamp || "",
        item.action || "",
        proc.pid || "",
        proc.name || "",
        proc.risk_score || 0,
        proc.path || "",
        `"${(proc.cmdline || "").replace(/"/g, '""')}"`,
        proc.user || ""
      ];
    };
  } else if (type === "hashes") {
    headers = ["Timestamp", "Process GUID", "File Name", "SHA256 Hash", "Status"];
    rowMapper = item => [
      item.timestamp || "",
      item.process_guid || "",
      item.file_name || "",
      item.sha256 || "",
      item.status || ""
    ];
  } else {
    alert("Unsupported export format.");
    return;
  }

  const csvRows = [headers.join(",")];
  records.forEach(item => {
    const row = rowMapper(item).map(val => {
      const str = String(val).replace(/"/g, '""');
      return (str.includes(',') || str.includes('\n') || str.includes('"')) ? `"${str}"` : str;
    });
    csvRows.push(row.join(","));
  });

  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `netship_${type}_export_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}