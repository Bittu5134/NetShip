/* netship map — equirectangular dot map over the flows snapshot.
   Decodes the embedded 2-degree land mask (bit-packed, row-major from lat 90)
   and plots one accent dot per contacted country at its centroid, sized by
   flow count. No dependencies, no network, no build step. */

'use strict';

const MAP_ACCENT = '#3db4f2';
const MAP_LAND = 'rgba(255, 255, 255, 0.12)';
const MAP_RING = 'rgba(11, 22, 34, 0.9)';
const MAP_LABEL = 'rgba(237, 241, 245, 0.82)';
const MAP_MUTED = 'rgba(159, 173, 189, 0.55)';
const MAP_FONT = "11px 'Overpass', system-ui, -apple-system, 'Segoe UI', sans-serif";
const MAP_MSG_FONT = "12px 'Overpass', system-ui, -apple-system, 'Segoe UI', sans-serif";

let mapMask = null;

/* WORLD_MASK is bit-packed one bit per cell, low bit first within each byte. */
function decodeWorldMask() {
  if (mapMask) return mapMask;
  const { cols, rows, data } = WORLD_MASK;
  const raw = atob(data);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  mapMask = { cols, rows, bytes };
  return mapMask;
}

function drawLand(ctx, W, H) {
  const { cols, rows, bytes } = decodeWorldMask();
  const cw = W / cols;
  const ch = H / rows;
  ctx.fillStyle = MAP_LAND;
  ctx.beginPath();
  for (let r = 0; r < rows; r++) {
    const base = r * cols;
    const y = r * ch + ch / 2 - 1;
    for (let c = 0; c < cols; c++) {
      const i = base + c;
      if (!((bytes[i >> 3] >> (i & 7)) & 1)) continue;
      ctx.rect(c * cw + cw / 2 - 1, y, 2, 2);
    }
  }
  ctx.fill();
}

function drawCountries(ctx, W, H, stats) {
  const project = (iso) => {
    const c = COUNTRY_CENTROIDS[iso];
    if (!c) return null;
    return [((c[0] + 180) / 360) * W, ((90 - c[1]) / 180) * H];
  };

  const max = Math.max(1, stats[0].count);
  const placed = [];
  for (const s of stats) {
    const p = project(s.iso);
    if (!p) continue; // no centroid: skip silently
    const t = Math.sqrt(Math.max(0, s.count) / max);
    const r = Math.max(4, Math.min(16, 4 + 12 * t));
    ctx.beginPath();
    ctx.arc(p[0], p[1], r, 0, Math.PI * 2);
    ctx.fillStyle = MAP_ACCENT;
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = MAP_RING;
    ctx.stroke();
    placed.push({ x: p[0], y: p[1], r, iso: s.iso });
  }

  ctx.font = MAP_FONT;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = MAP_LABEL;
  for (const d of placed.slice(0, 5)) {
    const x = d.x + d.r + 5;
    if (x + 22 > W) continue;
    ctx.fillText(d.iso, x, d.y + 1);
  }
}

function renderMap(canvas, countryStats) {
  if (!canvas) return;
  const stats = (countryStats || []).filter((s) => s && s.count > 0 && s.iso);
  canvas._mapStats = stats;

  const cssW = canvas.clientWidth || (canvas.parentElement && canvas.parentElement.clientWidth) || 0;
  if (!cssW) {
    // Not laid out yet (first paint): retry a few frames, then give up.
    canvas._mapRetry = (canvas._mapRetry || 0) + 1;
    if (canvas._mapRetry <= 10) {
      requestAnimationFrame(() => renderMap(canvas, stats));
    }
    return;
  }
  canvas._mapRetry = 0;

  const cssH = cssW / 2;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const pxW = Math.round(cssW * dpr);
  const pxH = Math.round(cssH * dpr);
  if (canvas.width !== pxW || canvas.height !== pxH) {
    canvas.width = pxW;
    canvas.height = pxH;
  }
  canvas.style.height = cssH + 'px';

  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  drawLand(ctx, cssW, cssH);

  if (!stats.length) {
    ctx.font = MAP_MSG_FONT;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = MAP_MUTED;
    ctx.fillText('no external destinations yet', cssW / 2, cssH / 2);
    return;
  }

  drawCountries(ctx, cssW, cssH, stats);
}

/* Keep the projection crisp when the column resizes. */
let mapResizeTimer = 0;
window.addEventListener('resize', () => {
  clearTimeout(mapResizeTimer);
  mapResizeTimer = setTimeout(() => {
    document.querySelectorAll('canvas.map-canvas').forEach((c) => {
      if (c._mapStats) renderMap(c, c._mapStats);
    });
  }, 120);
});
