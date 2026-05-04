// MiLog dashboard frontend.
//
// One IIFE so the global namespace stays clean. Sections, in order:
//   1. token handshake + api() helper
//   2. system + nginx summary rendering (poll OR SSE)
//   3. alerts panel + drill-down modal
//   4. logs panel (live tail SSE with poll fallback)
//   5. boot: fire stream + alerts tick + meta lookup
(function () {
  // ---- token handshake ---------------------------------------------------
  // First load accepts ?t=TOKEN, stashes in sessionStorage, then strips
  // the query so the token doesn't linger in URL bar / browser history.
  var q = new URLSearchParams(location.search);
  if (q.get('t')) {
    sessionStorage.setItem('milog_token', q.get('t'));
    history.replaceState({}, '', location.pathname);
  }
  var token = sessionStorage.getItem('milog_token');
  if (!token) {
    document.getElementById('status').textContent = 'no token';
    document.getElementById('status').classList.add('bad');
    document.getElementById('err-section').hidden = false;
    document.getElementById('err').textContent =
      'No session token. Open the URL printed by `milog web` that includes ?t=…';
    return;
  }

  function api(path) {
    return fetch(path, {
      headers: { 'Authorization': 'Bearer ' + token },
      cache: 'no-store',
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  // ---- system + nginx summary -------------------------------------------
  function colour(pct) { return pct >= 90 ? 'crit' : pct >= 75 ? 'warn' : ''; }
  function setBar(id, pct) {
    var el = document.getElementById(id);
    el.className = colour(pct);
    el.style.width = Math.min(100, Math.max(0, pct)) + '%';
  }

  function render(s) {
    var sys = s.system || {};
    document.getElementById('ts').textContent = s.ts || '';
    document.getElementById('cpu').textContent  = (sys.cpu || 0) + '%';
    document.getElementById('mem').textContent  = (sys.mem_pct || 0) + '%';
    document.getElementById('disk').textContent = (sys.disk_pct || 0) + '%';
    document.getElementById('mem-sub').textContent =
      (sys.mem_used_mb || 0) + ' / ' + (sys.mem_total_mb || 0) + ' MB';
    document.getElementById('disk-sub').textContent =
      (sys.disk_used_gb || 0) + ' / ' + (sys.disk_total_gb || 0) + ' GB';
    setBar('cpu-bar', sys.cpu || 0);
    setBar('mem-bar', sys.mem_pct || 0);
    setBar('disk-bar', sys.disk_pct || 0);

    var tbody = document.querySelector('#apps tbody');
    tbody.innerHTML = '';
    (s.apps || []).forEach(function (a) {
      var tr = document.createElement('tr');
      function td(v, cls) {
        var c = document.createElement('td');
        if (cls) c.className = cls;
        c.textContent = v;
        return c;
      }
      tr.appendChild(td(a.name));
      tr.appendChild(td(a.req,  'n'));
      tr.appendChild(td(a.c2xx, 'n'));
      tr.appendChild(td(a.c3xx, 'n'));
      tr.appendChild(td(a.c4xx, 'n ' + (a.c4xx > 0 ? 'err4' : '')));
      tr.appendChild(td(a.c5xx, 'n ' + (a.c5xx > 0 ? 'err5' : '')));
      tbody.appendChild(tr);
    });
    if (!(s.apps || []).length) {
      tbody.innerHTML = '<tr><td colspan="6">no apps</td></tr>';
    }

    var pill = document.getElementById('status');
    pill.textContent = 'live · total ' + (s.total_req || 0) + ' req/min';
    pill.className = 'pill ok';
    document.getElementById('err-section').hidden = true;
  }

  function tick() {
    api('/api/summary.json').then(render).catch(function (e) {
      var pill = document.getElementById('status');
      pill.textContent = 'error';
      pill.className = 'pill bad';
      document.getElementById('err-section').hidden = false;
      document.getElementById('err').textContent =
        e.message + ' — check the token or that milog web is still running';
    });
  }

  // ---- alerts panel + drill-down modal -----------------------------------
  // Drill-down rationale: alerts.json already carries the full body, so
  // clicking a row populates the modal from the in-memory list — no extra
  // fetch. Backticks are stripped because alert_fire wraps Discord bodies
  // in ``` for code-block rendering; the <pre> here does the same job.
  function fmtWhen(ts) {
    var d = new Date(ts * 1000);
    function pad(n) { return n < 10 ? '0' + n : '' + n; }
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
         + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function stripBackticks(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/^```\n?/, '').replace(/\n?```$/, '');
  }
  function openAlertModal(a) {
    document.getElementById('alert-modal-when').textContent = fmtWhen(a.ts);
    document.getElementById('alert-modal-title').textContent = a.title || '(no title)';
    var sev = document.getElementById('alert-modal-sev');
    sev.textContent = (a.sev || 'info').toUpperCase();
    sev.className = 'v sev-' + (a.sev || 'info');
    document.getElementById('alert-modal-rule').textContent = a.rule || '(no rule key)';
    document.getElementById('alert-modal-body').textContent =
      stripBackticks(a.body || '') || '(empty body)';
    document.getElementById('alert-modal').classList.add('open');
  }
  function closeAlertModal() {
    document.getElementById('alert-modal').classList.remove('open');
  }
  document.getElementById('alert-modal-close').addEventListener('click', closeAlertModal);
  // Click inside the panel propagates up to the backdrop; filter by target.
  document.getElementById('alert-modal').addEventListener('click', function (e) {
    if (e.target === this) closeAlertModal();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' &&
        document.getElementById('alert-modal').classList.contains('open')) {
      closeAlertModal();
    }
  });

  function renderAlerts(d) {
    var tbody = document.querySelector('#alerts tbody');
    var meta = document.getElementById('alerts-count');
    tbody.innerHTML = '';
    var list = (d && d.alerts) || [];
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">no alerts in window</td></tr>';
      meta.textContent = '0 alerts';
      return;
    }
    meta.textContent = list.length + ' alert' + (list.length === 1 ? '' : 's');
    // Server returns oldest→newest; reverse so newest first.
    list.slice().reverse().forEach(function (a) {
      var tr = document.createElement('tr');
      function td(v, cls) {
        var c = document.createElement('td');
        if (cls) c.className = cls;
        c.textContent = v;
        return c;
      }
      tr.appendChild(td(fmtWhen(a.ts), 'when'));
      var sev = document.createElement('td');
      sev.className = 'sev-' + (a.sev || 'info');
      sev.textContent = (a.sev || 'info').toUpperCase();
      tr.appendChild(sev);
      tr.appendChild(td(a.rule || '', 'rule'));
      tr.appendChild(td(a.title || '', 'title'));
      tr.addEventListener('click', function () { openAlertModal(a); });
      tbody.appendChild(tr);
    });
  }
  function tickAlerts() {
    var w = document.getElementById('alerts-window').value;
    api('/api/alerts.json?window=' + encodeURIComponent(w))
      .then(renderAlerts)
      .catch(function () { /* non-fatal; summary tick already surfaces errors */ });
  }
  document.getElementById('alerts-window').addEventListener('change', tickAlerts);

  // ---- logs panel --------------------------------------------------------
  function fmtLogWhen(s) {
    // "[24/Apr/2026:12:34:56 +0000]" → "12:34:56"
    var m = /:(\d\d:\d\d:\d\d)/.exec(s || '');
    return m ? m[1] : (s || '');
  }
  function setLogsApp(apps) {
    var sel = document.getElementById('logs-app');
    if (sel.options.length) return;
    (apps || []).forEach(function (a) {
      var opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      sel.appendChild(opt);
    });
    if (sel.options.length) sel.value = sel.options[0].value;
  }
  function renderHistogram(d) {
    var el = document.getElementById('logs-histogram');
    el.innerHTML = '';
    var buckets = (d && d.buckets) || [];
    if (!buckets.length) {
      el.innerHTML = '<div style="flex:1;color:#6b7177;text-align:center;font-size:.7rem;line-height:28px;">no activity</div>';
      return;
    }
    var max = buckets.reduce(function (m, b) { return Math.max(m, b.c || 0); }, 1);
    buckets.forEach(function (b) {
      var bar = document.createElement('div');
      var pct = Math.round(((b.c || 0) / max) * 100);
      bar.className = 'bar' + ((b.c || 0) === 0 ? ' empty' : '');
      bar.style.height = ((b.c || 0) === 0 ? 2 : Math.max(4, pct)) + '%';
      bar.title = b.t + '  ' + (b.c || 0) + ' req';
      el.appendChild(bar);
    });
  }

  // Shared state across poll + SSE modes.
  var logsState = {
    rows: [],          // newest first, capped at MAX_ROWS
    paused: false,
    source: null,      // EventSource when live, null otherwise
    pollTimer: null,   // setInterval handle when in poll mode
    rateSamples: [],   // event timestamps (ms) for rolling req/s
  };
  var MAX_ROWS = 500;

  function rowFromLine(l) {
    var stClass = 'st' + String(l.status || '').charAt(0);
    return {
      ts: l.ts, ip: l.ip, method: l.method, path: l.path,
      status: l.status, ua: l.ua, stClass: stClass,
    };
  }
  function redrawLogs() {
    var tbody = document.querySelector('#logs tbody');
    var meta = document.getElementById('logs-count');
    tbody.innerHTML = '';
    if (!logsState.rows.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">no matching lines</td></tr>';
      meta.textContent = '0 lines';
      return;
    }
    meta.textContent = logsState.rows.length + ' line' + (logsState.rows.length === 1 ? '' : 's');
    logsState.rows.forEach(function (r) {
      var tr = document.createElement('tr');
      function td(v, cls) {
        var c = document.createElement('td');
        if (cls) c.className = cls;
        c.textContent = v;
        return c;
      }
      tr.appendChild(td(fmtLogWhen(r.ts), 'when'));
      tr.appendChild(td(r.ip || '', 'ip'));
      tr.appendChild(td(r.method || '', 'mth'));
      tr.appendChild(td(r.path || '', 'pth'));
      tr.appendChild(td(r.status, r.stClass));
      tbody.appendChild(tr);
    });
  }
  function recordRate() {
    var now = Date.now();
    logsState.rateSamples.push(now);
    while (logsState.rateSamples.length && now - logsState.rateSamples[0] > 10000) {
      logsState.rateSamples.shift();
    }
    var rate = logsState.rateSamples.length / 10;
    document.getElementById('logs-rate').textContent = rate.toFixed(1) + '/s';
  }
  function appendLiveLine(l) {
    if (logsState.paused) return; // freeze render but keep the rate meter live
    logsState.rows.unshift(rowFromLine(l));
    if (logsState.rows.length > MAX_ROWS) logsState.rows.length = MAX_ROWS;
    redrawLogs();
  }
  function setLogsMode(label) {
    document.getElementById('logs-mode').textContent = label;
  }

  // Initial historical slice on filter change. SSE replay covers reconnects;
  // this is for the moment between filter-change and SSE 'ready'.
  function loadLogsInitial() {
    var app = document.getElementById('logs-app').value;
    if (!app) return Promise.resolve();
    var grep = document.getElementById('logs-grep').value;
    var cls = document.getElementById('logs-class').value;
    var qs = 'app=' + encodeURIComponent(app) + '&limit=200';
    if (grep) qs += '&grep=' + encodeURIComponent(grep);
    if (cls && cls !== 'any') qs += '&class=' + encodeURIComponent(cls);
    return api('/api/logs.json?' + qs).then(function (d) {
      var list = (d && d.lines) || [];
      logsState.rows = list.slice().reverse().map(rowFromLine); // newest first
      redrawLogs();
    }).catch(function () {});
  }
  function stopLogsSources() {
    if (logsState.source) { try { logsState.source.close(); } catch (_) {} logsState.source = null; }
    if (logsState.pollTimer) { clearInterval(logsState.pollTimer); logsState.pollTimer = null; }
  }
  function startLogsStream() {
    stopLogsSources();
    var app = document.getElementById('logs-app').value;
    if (!app) { redrawLogs(); return; }
    logsState.rows = [];
    logsState.rateSamples = [];

    if (typeof EventSource === 'undefined') {
      setLogsMode('poll');
      loadLogsInitial();
      logsState.pollTimer = setInterval(loadLogsInitial, 5000);
      return;
    }

    var grep = document.getElementById('logs-grep').value;
    var cls = document.getElementById('logs-class').value;
    var qs = 'app=' + encodeURIComponent(app) + '&limit=200&t=' + encodeURIComponent(token);
    if (grep) qs += '&grep=' + encodeURIComponent(grep);
    if (cls && cls !== 'any') qs += '&class=' + encodeURIComponent(cls);

    setLogsMode('connecting…');
    var src;
    try { src = new EventSource('/api/logs/stream?' + qs); }
    catch (_) {
      setLogsMode('poll');
      loadLogsInitial();
      logsState.pollTimer = setInterval(loadLogsInitial, 5000);
      return;
    }
    logsState.source = src;

    var fellBack = false;
    var fallbackTimer = setTimeout(function () {
      if (logsState.source !== src) return;
      fellBack = true;
      stopLogsSources();
      setLogsMode('poll');
      loadLogsInitial();
      logsState.pollTimer = setInterval(loadLogsInitial, 5000);
    }, 4000);

    src.addEventListener('log', function (ev) {
      clearTimeout(fallbackTimer);
      try { appendLiveLine(JSON.parse(ev.data)); recordRate(); }
      catch (_) {}
    });
    src.addEventListener('ready', function () {
      clearTimeout(fallbackTimer);
      setLogsMode('live');
    });
    src.onerror = function () {
      if (fellBack) return;
      if (src.readyState === EventSource.CLOSED) {
        stopLogsSources();
        setLogsMode('poll');
        loadLogsInitial();
        logsState.pollTimer = setInterval(loadLogsInitial, 5000);
      }
    };
  }
  function tickHistogram() {
    var app = document.getElementById('logs-app').value;
    if (!app) return;
    api('/api/logs/histogram.json?app=' + encodeURIComponent(app) + '&minutes=60')
      .then(renderHistogram).catch(function () {});
  }
  ['logs-app', 'logs-class', 'logs-grep'].forEach(function (id) {
    document.getElementById(id).addEventListener('change', function () {
      startLogsStream();
      tickHistogram();
    });
  });
  document.getElementById('logs-grep').addEventListener('input', function () {
    // Debounce so each keystroke doesn't open + close a fresh SSE stream.
    clearTimeout(window.__milog_grep_t);
    window.__milog_grep_t = setTimeout(function () { startLogsStream(); }, 300);
  });
  document.getElementById('logs-pause').addEventListener('click', function () {
    logsState.paused = !logsState.paused;
    this.textContent = logsState.paused ? 'resume' : 'pause';
    this.style.background = logsState.paused ? '#3a2b05' : '#10141a';
  });

  // ---- live summary: SSE with poll fallback ------------------------------
  // EventSource holds one connection open; render fires on each 'summary'
  // event. If SSE doesn't deliver in 4s, drop to a 3s poll loop.
  function startSummaryStream() {
    if (typeof EventSource === 'undefined') {
      tick(); setInterval(tick, 3000); return;
    }
    var url = '/api/stream?t=' + encodeURIComponent(token);
    var src, fellBack = false;
    function fallback(reason) {
      if (fellBack) return;
      fellBack = true;
      if (src) { try { src.close(); } catch (_) {} }
      console.warn('SSE unavailable (' + reason + ') — falling back to 3s poll');
      tick(); setInterval(tick, 3000);
    }
    try { src = new EventSource(url); }
    catch (e) { fallback('constructor threw'); return; }
    var firstTimer = setTimeout(function () { fallback('no event in 4s'); }, 4000);
    src.addEventListener('summary', function (ev) {
      clearTimeout(firstTimer);
      try { render(JSON.parse(ev.data)); } catch (_) {}
    });
    src.onerror = function () {
      // Browser auto-retries; only fall back when fully closed.
      if (src.readyState === EventSource.CLOSED) fallback('readyState CLOSED');
    };
  }

  // ---- boot --------------------------------------------------------------
  api('/api/meta.json').then(function (m) {
    document.getElementById('meta-uptime').textContent = 'host uptime: ' + (m.uptime || '?');
    setLogsApp(m.apps || []);
    startLogsStream();
    tickHistogram();
  }).catch(function () { /* non-fatal */ });

  startSummaryStream();
  tickAlerts();
  setInterval(tickAlerts, 15000);
  setInterval(tickHistogram, 30000);
})();
