/* netship dashboard — AniList-style stats layout.
   Three views over one snapshot endpoint. Everything the user can change
   (view, filter, sort, expansion, selection) lives in `state` and survives the
   3s refresh. No build step, no dependencies, works offline. */

'use strict';

const state = {
  view: 'cases',
  q: '',
  sev: new Set([3, 2, 1]),
  sort: 'severity',
  expanded: new Set(),
  sel: -1,
  data: null,
  lastOk: 0,
  lastPayload: '',
  failing: false,
};

const $ = (id) => document.getElementById(id);

const COLORS = {
  3: 'var(--red)',
  2: 'var(--amber)',
  1: 'var(--blue)',
  kinds: ['#3db4f2', '#b368d9', '#e85d75', '#f7b731', '#7bd555', '#4fd1c5'],
};

const SEV_NAME = { 3: 'high', 2: 'medium', 1: 'low' };

/* ── formatting ──────────────────────────────────────────── */

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const num = (n) => Number(n || 0).toLocaleString();

function rel(iso) {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.round(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.round(m / 60);
  if (h < 24) return Math.round(h) + 'h ago';
  return Math.round(h / 24) + 'd ago';
}

const clock = (iso) => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? '—' : new Date(t).toLocaleTimeString([], { hour12: false });
};

const dur = (ms) => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  return m < 60 ? m + 'm ' + (s % 60) + 's' : Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
};

const shortPath = (p, keep = 40) => (!p ? '' : p.length <= keep ? p : '…' + p.slice(-keep));

const haystack = (parts) => parts.filter(Boolean).join(' ').toLowerCase();

/* ── models ──────────────────────────────────────────────── */

function casesModel() {
  return (state.data?.cases || []).map((c) => {
    const p = c.process;
    const fs = c.findings || [];
    return {
      key: 'case:' + p.guid,
      raw: c,
      sev: c.severity,
      name: p.name,
      time: p.last_seen,
      hay: haystack([
        p.name, p.exe, p.cmdline, p.cwd, p.user, p.parent_name, c.summary,
        ...fs.map((f) => f.kind + ' ' + f.title + ' ' + (f.evidence || []).join(' ')),
        ...(c.flows || []).map((f) => `${f.remote_ip} ${f.org} ${f.country} ${f.asn}`),
      ]),
    };
  });
}

function processesModel() {
  const flows = new Map();
  for (const f of state.data?.flows || []) {
    flows.set(f.process_guid, (flows.get(f.process_guid) || 0) + (f.direction === 'LISTEN' ? 0 : 1));
  }
  return (state.data?.processes || []).map((p) => ({
    key: 'proc:' + p.guid,
    raw: p,
    sev: 0,
    name: p.name,
    time: p.last_seen,
    flows: flows.get(p.guid) || 0,
    hay: haystack([p.name, p.exe, p.cmdline, p.cwd, p.user, p.parent_name]),
  }));
}

function destinationGroups() {
  const groups = new Map();
  for (const f of state.data?.flows || []) {
    if (!f.remote_ip) continue; // listener pseudo-flow
    const label = f.org || (f.asn ? 'AS' + f.asn : f.remote_ip);
    const g = groups.get(label) || {
      label, country: f.country || '', asn: f.asn || 0, hosting: false,
      flows: 0, procs: new Set(), time: f.last_seen, ips: new Set(),
    };
    g.flows += 1;
    g.procs.add(f.process_guid);
    g.ips.add(f.remote_ip);
    g.hosting = g.hosting || !!f.hosting;
    if (Date.parse(f.last_seen) > Date.parse(g.time)) g.time = f.last_seen;
    if (!g.country && f.country) g.country = f.country;
    if (!g.asn && f.asn) g.asn = f.asn;
    groups.set(label, g);
  }
  return [...groups.values()]
    .map((g) => ({ ...g, procCount: g.procs.size, ipCount: g.ips.size }))
    .sort((a, b) => b.flows - a.flows);
}

function destinationsModel() {
  return destinationGroups().map((g) => ({
    key: 'dest:' + g.label,
    raw: g,
    sev: 0,
    name: g.label,
    time: g.time,
    flows: g.flows,
    hay: haystack([g.label, g.country, g.asn]),
  }));
}

function countryStats() {
  const by = new Map();
  for (const f of state.data?.flows || []) {
    if (!f.country) continue; // listener pseudo-flows carry no country
    const iso = String(f.country).toUpperCase();
    const g = by.get(iso) || { iso, count: 0, procs: new Set() };
    g.count += 1;
    if (f.process_guid) g.procs.add(f.process_guid);
    by.set(iso, g);
  }
  return [...by.values()].sort((a, b) => b.count - a.count || a.iso.localeCompare(b.iso));
}

/* ── sorting / filtering ─────────────────────────────────── */

const byTime = (a, b) => Date.parse(b.time) - Date.parse(a.time);

function sortRows(rows) {
  const out = rows.slice();
  switch (state.sort) {
    case 'name': return out.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    case 'recent': return out.sort(byTime);
    case 'flows': return out.sort((a, b) => (b.flows || 0) - (a.flows || 0) || byTime(a, b));
    default: return out.sort((a, b) => (b.sev || 0) - (a.sev || 0) || byTime(a, b));
  }
}

function currentRows() {
  if (state.view === 'map') {
    const q = state.q;
    return countryStats()
      .map((g) => ({
        key: 'map:' + g.iso,
        raw: { iso: g.iso, flows: g.count, processes: g.procs.size },
        sev: 0,
        name: g.iso,
        time: '',
        flows: g.count,
        hay: g.iso.toLowerCase(),
      }))
      .filter((r) => !q || r.hay.includes(q));
  }
  const model =
    state.view === 'cases' ? casesModel()
    : state.view === 'processes' ? processesModel()
    : destinationsModel();
  const q = state.q;
  return sortRows(
    model.filter((r) => (state.view !== 'cases' || state.sev.has(r.sev)) && (!q || r.hay.includes(q)))
  );
}

/* ── small components ────────────────────────────────────── */

function bars(items, colors) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return items
    .map(
      (it, i) => `<div class="bar-row">
        <div class="bar-head">
          <span class="bar-name">${esc(it.name)}</span>
          <span class="bar-val">${it.label || num(it.value)}</span>
        </div>
        <div class="bar-track"><span class="bar-fill" style="width:${Math.max(2, (it.value / max) * 100)}%;background:${
        colors[i % colors.length]
      }"></span></div>
      </div>`
    )
    .join('');
}

function donut(segments, total, centerLabel) {
  const r = 45;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const rings = segments
    .filter((s) => s.value > 0)
    .map((s) => {
      const len = (s.value / total) * c;
      const ring = `<circle cx="58" cy="58" r="${r}" stroke="${s.color}"
        stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-offset}"></circle>`;
      offset += len;
      return ring;
    })
    .join('');

  return `<div class="donut-wrap">
    <div class="donut">
      <svg viewBox="0 0 116 116">
        <circle cx="58" cy="58" r="${r}" stroke="rgba(255,255,255,0.06)"></circle>
        ${rings}
      </svg>
      <div class="donut-center">
        <span class="donut-value">${num(total)}</span>
        <span class="donut-label">${esc(centerLabel)}</span>
      </div>
    </div>
    <ul class="legend">
      ${segments
        .map(
          (s) => `<li><span class="dot" style="background:${s.color}"></span>
            <span class="lbl">${esc(s.label)}</span><span class="num">${num(s.value)}</span></li>`
        )
        .join('')}
    </ul>
  </div>`;
}

function sideCard(title, sub, body) {
  return `<section class="card side-card">
    <div class="side-title">${esc(title)}${sub ? `<span class="card-sub">${esc(sub)}</span>` : ''}</div>
    ${body}
  </section>`;
}

/* ── views ───────────────────────────────────────────────── */

function renderCases(rows) {
  const body = rows
    .map((row) => {
      const c = row.raw, p = c.process, open = state.expanded.has(row.key);
      const findings = (c.findings || [])
        .map(
          (f) => `<div class="finding">
            <span class="finding-kind">${esc(f.kind.replace(/_/g, ' ').toLowerCase())}</span>
            <div>
              <p class="finding-title">${esc(f.title)}</p>
              ${(f.evidence || []).length ? `<ul class="finding-evidence">${f.evidence.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}
            </div>
          </div>`
        )
        .join('');

      const flowRows = (c.flows || [])
        .filter((f) => f.direction !== 'LISTEN')
        .map(
          (f) => `<tr>
            <td class="mono">${esc(f.remote_ip)}:${esc(f.remote_port)}</td>
            <td>${esc(f.org || (f.asn ? 'AS' + f.asn : '—'))}</td>
            <td class="dim">${esc(f.country || '—')}</td>
            <td class="num">${num(f.ticks)}</td>
            <td class="dim">${esc(rel(f.first_seen))}</td>
          </tr>`
        )
        .join('');

      const detail = open
        ? `<div class="case-detail">
            <dl class="kv-grid">
              <div class="kv"><dt>exe</dt><dd>${copyable(p.exe)}</dd></div>
              <div class="kv"><dt>cmd</dt><dd>${copyable(p.cmdline)}</dd></div>
              <div class="kv"><dt>cwd</dt><dd>${copyable(p.cwd)}</dd></div>
              <div class="kv"><dt>parent</dt><dd>${copyable(p.parent_name)}</dd></div>
              ${hashRow(p.hash)}
              <div class="kv"><dt>origin</dt><dd><em>${esc(p.origin_risk || 0)}</em> ${esc((p.origin_why || []).join(' · ') || 'nothing unusual')}</dd></div>
              <div class="kv"><dt>first seen</dt><dd>${esc(clock(p.first_seen))} · ${esc(rel(p.first_seen))}</dd></div>
            </dl>
            <div>${findings}</div>
            ${
              flowRows
                ? `<p class="section-label">destinations</p>
                   <div class="table-wrap"><table>
                     <thead><tr><th>remote</th><th>organisation</th><th>country</th><th class="num">polls</th><th>first seen</th></tr></thead>
                     <tbody>${flowRows}</tbody></table></div>`
                : ''
            }
          </div>`
        : '';

      return `<article class="case sev-${row.sev}${open ? ' is-open' : ''}" data-key="${esc(row.key)}">
        <button class="case-head" type="button" aria-expanded="${open}">
          <span class="sev"><span class="dot dot-${{ 3: 'high', 2: 'med', 1: 'low' }[row.sev] || 'low'}"></span>${esc(SEV_NAME[row.sev] || 'info')}</span>
          <span class="case-main">
            <span class="case-line">
              <span class="case-name">${esc(p.name)}</span>
              <span class="meta-chip">pid ${esc(p.pid)}</span>
              ${p.parent_name ? `<span class="meta-chip">${esc(p.parent_name)} →</span>` : ''}
              ${p.user ? `<span class="meta-chip">${esc(p.user)}</span>` : ''}
            </span>
            <span class="case-summary">${esc(c.summary)}</span>
            <span class="case-facts">
              ${p.cwd ? `<span title="${esc(p.cwd)}">${esc(shortPath(p.cwd, 42))}</span>` : ''}
              ${p.origin_risk ? `<span>origin ${esc(p.origin_risk)}</span>` : ''}
              <span>${(c.flows || []).filter((f) => f.direction !== 'LISTEN').length} destinations</span>
            </span>
          </span>
          <span class="case-time">${esc(rel(p.last_seen))}</span>
        </button>
        ${detail}
      </article>`;
    })
    .join('');

  const kindCounts = new Map();
  for (const f of state.data?.findings || []) kindCounts.set(f.kind, (kindCounts.get(f.kind) || 0) + 1);
  const kindItems = [...kindCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ name: k.replace(/_/g, ' ').toLowerCase(), value: v }));

  return `<section class="card list-card">
      <div class="card-head">
        <h2 class="card-title">Cases</h2>
        <span class="card-sub">one card per process that broke the baseline</span>
        <span class="card-head-right">${rows.length} shown</span>
      </div>
      <div class="cols"><span>severity</span><span>process / finding</span><span class="c-age">last seen</span></div>
      ${body}
    </section>
    ${
      kindItems.length
        ? `<section class="card list-card" style="margin-top:22px">
             <div class="card-head"><h2 class="card-title">Findings by kind</h2><span class="card-sub">what triggered</span></div>
             <div style="padding:16px 18px" class="bars">${bars(kindItems, COLORS.kinds)}</div>
           </section>`
        : ''
    }`;
}

function renderProcesses(rows) {
  const body = rows
    .map((row) => {
      const p = row.raw, open = state.expanded.has(row.key);
      const flows = (state.data.flows || []).filter((f) => f.process_guid === p.guid);
      const detail = open
        ? `<tr class="tr-detail"><td colspan="6">
            <dl class="kv-grid">
              <div class="kv"><dt>exe</dt><dd>${copyable(p.exe)}</dd></div>
              <div class="kv"><dt>cmd</dt><dd>${copyable(p.cmdline)}</dd></div>
              <div class="kv"><dt>cwd</dt><dd>${copyable(p.cwd)}</dd></div>
              <div class="kv"><dt>parent</dt><dd>${copyable(p.parent_name)}</dd></div>
              ${hashRow(p.hash)}
              <div class="kv"><dt>origin</dt><dd><em>${esc(p.origin_risk || 0)}</em> ${esc((p.origin_why || []).join(' · ') || 'nothing unusual')}</dd></div>
              <div class="kv"><dt>first seen</dt><dd>${esc(rel(p.first_seen))}</dd></div>
            </dl>
            ${
              flows.length
                ? `<p class="section-label">destinations</p><div class="table-wrap"><table>
                    <thead><tr><th>remote</th><th>organisation</th><th>country</th><th class="num">polls</th><th>last seen</th></tr></thead>
                    <tbody>${flows
                      .map(
                        (f) => `<tr><td class="mono">${f.remote_ip ? esc(f.remote_ip) + ':' + esc(f.remote_port) : 'listen ' + esc(f.remote_port)}</td>
                        <td>${esc(f.org || '—')}</td><td class="dim">${esc(f.country || '—')}</td>
                        <td class="num">${num(f.ticks)}</td><td class="dim">${esc(rel(f.last_seen))}</td></tr>`
                      )
                      .join('')}</tbody></table></div>`
                : '<p class="section-label">no destinations recorded</p>'
            }
          </td></tr>`
        : '';

      return `<tr data-key="${esc(row.key)}"${open ? ' class="rowsel"' : ''}>
        <td><span class="name">${esc(p.name)}</span></td>
        <td class="mono dim">${esc(p.pid)}</td>
        <td class="dim">${esc(p.user || '—')}</td>
        <td class="num">${p.origin_risk ? esc(p.origin_risk) : '—'}</td>
        <td class="num">${num(row.flows)}</td>
        <td class="dim">${esc(rel(p.last_seen))}</td>
      </tr>${detail}`;
    })
    .join('');

  return `<section class="card list-card">
    <div class="card-head">
      <h2 class="card-title">Processes</h2>
      <span class="card-sub">everything that owned a socket this session</span>
      <span class="card-head-right">${rows.length} shown</span>
    </div>
    <div class="table-wrap"><table>
      <thead><tr>
        <th class="sortable"><button data-sort="name" type="button">process</button></th>
        <th>pid</th><th>user</th>
        <th class="sortable num"><button data-sort="origin" type="button">origin</button></th>
        <th class="sortable num"><button data-sort="flows" type="button">destinations</button></th>
        <th class="sortable"><button data-sort="recent" type="button">last seen</button></th>
      </tr></thead>
      <tbody>${body}</tbody>
    </table></div>
  </section>`;
}

function renderDestinations(rows) {
  const body = rows
    .map(
      (row) => `<tr data-key="${esc(row.key)}">
        <td><span class="name">${esc(row.raw.label)}</span></td>
        <td class="dim">${esc(row.raw.country || '—')}</td>
        <td class="mono dim">${row.raw.asn ? 'AS' + esc(row.raw.asn) : '—'}</td>
        <td class="num">${num(row.raw.ipCount)}</td>
        <td class="num">${num(row.raw.procCount)}</td>
        <td class="num">${num(row.raw.flows)}</td>
        <td class="dim">${esc(rel(row.raw.time))}</td>
      </tr>`
    )
    .join('');

  return `<section class="card list-card">
    <div class="card-head">
      <h2 class="card-title">Destinations</h2>
      <span class="card-sub">endpoints that survived the CDN filter</span>
      <span class="card-head-right">${rows.length} organisations</span>
    </div>
    <div class="table-wrap"><table>
      <thead><tr>
        <th class="sortable"><button data-sort="name" type="button">organisation</button></th>
        <th>country</th><th>asn</th>
        <th class="num">ips</th>
        <th class="sortable num"><button data-sort="flows" type="button">processes</button></th>
        <th class="num">flows</th>
        <th class="sortable"><button data-sort="recent" type="button">last seen</button></th>
      </tr></thead>
      <tbody>${body}</tbody>
    </table></div>
  </section>`;
}

/* ── aside ───────────────────────────────────────────────── */

function renderAside() {
  const findings = state.data?.findings || [];
  const counts = { 3: 0, 2: 0, 1: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const total = counts[3] + counts[2] + counts[1];

  const donutCard = sideCard(
    'Severity',
    total ? num(total) + ' findings' : 'quiet',
    total
      ? donut(
          [
            { label: 'high', value: counts[3], color: 'var(--red)' },
            { label: 'medium', value: counts[2], color: 'var(--amber)' },
            { label: 'low', value: counts[1], color: 'var(--blue)' },
          ],
          total,
          'findings'
        )
      : `<p class="card-sub" style="padding-bottom:4px">Nothing has broken the baseline yet.</p>`
  );

  let middle = '';
  if (state.view === 'processes') {
    const items = processesModel()
      .filter((r) => r.raw.origin_risk > 0)
      .sort((a, b) => b.raw.origin_risk - a.raw.origin_risk)
      .slice(0, 6)
      .map((r) => ({ name: r.name, value: r.raw.origin_risk }));
    middle = sideCard(
      'Riskiest origins',
      'where binaries live',
      items.length
        ? `<div class="bars">${bars(items, ['#e85d75', '#f7b731', '#b368d9', '#3db4f2'])}</div>`
        : `<p class="card-sub">No process is running from a suspicious location.</p>`
    );
  } else if (state.view === 'destinations' || state.view === 'map') {
    const byCountry = new Map();
    for (const f of state.data?.flows || []) {
      if (!f.country) continue;
      byCountry.set(f.country, (byCountry.get(f.country) || 0) + 1);
    }
    const items = [...byCountry.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([k, v]) => ({ name: k, value: v }));
    middle = sideCard(
      'Countries',
      'by flow count',
      items.length
        ? `<div class="bars">${bars(items, ['#3db4f2', '#4fd1c5', '#b368d9', '#7bd555'])}</div>`
        : `<p class="card-sub">No geolocated destinations yet.</p>`
    );
  } else {
    const items = destinationGroups()
      .slice(0, 6)
      .map((g) => ({ name: g.label, value: g.flows, label: num(g.flows) }));
    middle = sideCard(
      'Top destinations',
      'by flow count',
      items.length
        ? `<div class="bars">${bars(items, ['#3db4f2', '#b368d9', '#4fd1c5', '#7bd555', '#f7b731', '#e85d75'])}</div>`
        : `<p class="card-sub">No external destinations recorded.</p>`
    );
  }

  const d = state.data;
  const started = d?.started_at ? Date.parse(d.started_at) : 0;
  const session = sideCard(
    'Session',
    '',
    `<div class="stat-rows">
      <div class="stat-row"><span class="k">started</span><span class="v">${started ? clock(d.started_at) : '—'}</span></div>
      <div class="stat-row"><span class="k">uptime</span><span class="v">${started ? dur(Date.now() - started) : '—'}</span></div>
      <div class="stat-row"><span class="k">warm-up</span><span class="v">${d?.learning ? 'learning' : 'done'}</span></div>
      <div class="stat-row"><span class="k">dns lookups</span><span class="v">${num(d?.stats?.lookups)}</span></div>
      <div class="stat-row"><span class="k">cdn suppressed</span><span class="v">${num(d?.stats?.suppressed)}</span></div>
      <div class="stat-row"><span class="k">baseline</span><span class="v">every 30s</span></div>
    </div>`
  );

  $('aside').innerHTML = donutCard + middle + activityCard(d) + socketsCard(d) + session;
}

// per-minute bucket, one entry per minute since session start, oldest first
function perMinute(items, started) {
  if (!started) return [];
  const t0 = Date.parse(started);
  const minutes = Math.max(1, Math.ceil((Date.now() - t0) / 60000));
  const n = Math.min(minutes, 30); // the interesting window is the recent one
  const out = new Array(n).fill(0);
  for (const it of items) {
    const t = Date.parse(it);
    if (Number.isNaN(t) || t < t0) continue;
    const m = Math.floor((t - t0) / 60000);
    if (m >= minutes - n) out[n - 1 - (minutes - 1 - m)]++;
  }
  return out;
}

function sparkline(values, color) {
  const max = Math.max(1, ...values);
  return `<div class="spark">${values
    .map((v) => `<span style="height:${Math.max(3, (v / max) * 100)}%;background:${v ? color : 'rgba(255,255,255,0.08)'}"></span>`)
    .join('')}</div>`;
}

// Activity: when did new things appear, per minute, two series.
function activityCard(d) {
  const flows = perMinute((d?.flows || []).map((f) => f.first_seen), d?.started_at);
  const finds = perMinute((d?.findings || []).map((f) => f.first_seen), d?.started_at);
  return sideCard('Activity', 'per minute',
    `<div class="spark-rows">
      <div class="spark-row"><span class="k">destinations</span>${sparkline(flows, 'var(--blue)')}</div>
      <div class="spark-row"><span class="k">findings</span>${sparkline(finds, 'var(--red)')}</div>
      <div class="stat-rows">
        <div class="stat-row"><span class="k">newest finding</span><span class="v">${esc(rel((d?.findings || [])[0]?.first_seen))}</span></div>
        <div class="stat-row"><span class="k">newest destination</span><span class="v">${esc(rel((d?.flows || [])[0]?.first_seen))}</span></div>
      </div>
    </div>`);
}

// Sockets: which ports and protocols carry the session's external traffic.
function socketsCard(d) {
  const flows = (d?.flows || []).filter((f) => f.direction !== 'LISTEN');
  const byPort = new Map();
  let tcp = 0, udp = 0;
  for (const f of flows) {
    f.proto === 'UDP' ? udp++ : tcp++;
    byPort.set(f.remote_port, (byPort.get(f.remote_port) || 0) + 1);
  }
  const ports = [...byPort.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([p, v]) => ({ name: ':' + p, value: v, label: num(v) }));
  const total = tcp + udp;
  return sideCard('Sockets', total ? num(total) + ' flows' : 'quiet',
    (ports.length
      ? `<div class="bars" style="margin-bottom:14px">${bars(ports, ['#3db4f2', '#4fd1c5', '#b368d9', '#7bd555', '#f7b731', '#e85d75'])}</div>`
      : '') +
    `<div class="stat-rows">
      <div class="stat-row"><span class="k">tcp</span><span class="v">${num(tcp)}${total ? ' · ' + Math.round((tcp / total) * 100) + '%' : ''}</span></div>
      <div class="stat-row"><span class="k">udp</span><span class="v">${num(udp)}${total ? ' · ' + Math.round((udp / total) * 100) + '%' : ''}</span></div>
    </div>`);
}

/* ── tiles / status ──────────────────────────────────────── */

function renderTiles() {
  const d = state.data;
  const findings = d?.findings || [];
  const counts = { 3: 0, 2: 0, 1: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  $('t-find').textContent = num(d?.stats?.findings);
  $('t-find-sub').textContent = `${counts[3]} high · ${counts[2]} med · ${counts[1]} low`;
  $('t-cases').textContent = num((d?.cases || []).length);
  $('t-proc').textContent = num(d?.stats?.processes);
  $('t-proc-sub').textContent = num(d?.stats?.flows) + ' destinations';
  $('t-flows').textContent = num(destinationGroups().reduce((n, g) => n + g.ipCount, 0));
  $('t-supp').textContent = num(d?.stats?.suppressed);

  $('n-cases').textContent = num((d?.cases || []).length);
  $('n-proc').textContent = num(d?.stats?.processes);
  $('n-dest').textContent = num(destinationGroups().length);
  $('n-map').textContent = num(countryStats().length);
}

function paintStatus() {
  const d = state.data;
  const demo = !!d?.demo;
  const live = d && !state.failing && !demo;
  const liveEl = document.querySelector('.live');
  liveEl.classList.toggle('is-on', !!live);
  // In demo mode the watcher is intentionally not running; showing the red
  // "no response" state would read as a daemon failure.
  liveEl.classList.toggle('is-stale', state.failing && !demo);
  $('live-label').textContent = demo ? 'demo' : !d ? 'connecting' : !d.running && !state.failing ? 'paused' : live ? 'watching' : 'no response';

  const age = state.lastOk ? Math.round((Date.now() - state.lastOk) / 1000) : null;
  $('s-stamp').textContent =
    age === null ? 'waiting for first poll'
    : state.failing ? `last update ${age}s ago`
    : `updated ${age}s ago`;

  $('s-learning').textContent = d?.demo
    ? 'demo: synthetic data'
    : d?.learning
      ? 'warm-up: silent by design'
      : 'warm-up: complete';
  $('s-session').textContent = d?.started_at ? `session ${clock(d.started_at)}` : 'session —';

  applyDemoState(!!d?.demo, !!d?.running);
}

// Demo is a mode of the dashboard, not a separate program: the same views
// render a seeded store, and the controls that would inspect this machine are
// disabled while it is on.
function applyDemoState(demo, running = false) {
  $('demo-banner').hidden = !demo;
  $('demo').textContent = demo ? 'Exit demo' : 'Demo';
  $('toggle').disabled = demo;
  const btn = $('toggle');
  if (!demo) {
    btn.textContent = running ? 'Pause' : 'Resume';
    btn.classList.toggle('btn-primary', !running); // Resume is the primary action
  }
}

/* ── empty states ────────────────────────────────────────── */

function emptyState() {
  const d = state.data;
  if (!d) return null;

  if (state.q) {
    return ['No match', `Nothing in this view matches <b>${esc(state.q)}</b>.`];
  }
  if (state.view === 'cases') {
    if (d.learning) {
      return [
        'Learning',
        'netship is recording where each binary is allowed to talk. It stays silent during the warm-up window, then reports only what is new.',
      ];
    }
    return [
      'Nothing new',
      `Every one of the <b>${num(destinationGroups().reduce((n, g) => n + g.ipCount, 0))}</b> destinations this machine has contacted is already in the baseline, and <b>${num(
        d.stats?.suppressed
      )}</b> cloud/CDN contacts were dropped without being stored.<br><br>This is the healthy state. Run <code>netship demo</code> to see what a finding looks like.`,
    ];
  }
  if (state.view === 'processes') {
