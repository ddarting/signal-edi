/* Signal EDI — rendering / diagnostic views */
(function (global) {
  'use strict';

  function h(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function esc(s) { return (s == null ? '' : String(s)).replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; }); }

  function sevRank(seg) {
    if (!seg.diagnostics) return null;
    if (seg.diagnostics.some(function (d) { return d.severity === 'error'; })) return 'error';
    if (seg.diagnostics.some(function (d) { return d.severity === 'warning'; })) return 'warning';
    if (seg.diagnostics.some(function (d) { return d.severity === 'info'; })) return 'info';
    return null;
  }

  // ---- Structure tree --------------------------------------------------------
  function renderTree(container, parsed, sef, onSelect) {
    container.innerHTML = '';
    parsed.interchanges.forEach(function (ich, ii) {
      container.appendChild(interchangeNode(ich, ii, sef, onSelect));
    });
    if (parsed.interchanges.length === 0) {
      container.appendChild(h('div', 'phi', 'No ISA/IEA envelope detected.'));
    }
  }

  function segRow(seg, sef, onSelect, extraClass) {
    const node = h('div', 'node');
    const row = h('div', 'row');
    row.appendChild(h('span', 'twist', ''));
    const def = sef && sef.segments[seg.id];
    const cls = (seg.id === 'ISA' || seg.id === 'GS' || seg.id === 'ST' || seg.id === 'SE' || seg.id === 'GE' || seg.id === 'IEA') ? 'env' : 'seg-id';
    row.appendChild(h('span', cls, seg.id));
    const desc = def && def.name ? def.name : '';
    if (desc) row.appendChild(h('span', 'desc', desc));
    const sr = sevRank(seg);
    if (sr) { const mini = h('span', 'mini'); mini.appendChild(h('span', 'dotmark ' + sr)); row.appendChild(mini); }
    row.dataset.segIndex = seg.index;
    row.addEventListener('click', function (e) { e.stopPropagation(); onSelect(seg, row); });
    node.appendChild(row);
    return node;
  }

  function interchangeNode(ich, ii, sef, onSelect) {
    const node = h('div', 'node');
    const row = h('div', 'row');
    const tw = h('span', 'twist', '▾');
    row.appendChild(tw);
    row.appendChild(h('span', 'env', 'ISA'));
    row.appendChild(h('span', 'desc', ich.senderId + ' → ' + ich.receiverId + '  (' + (ich.usageIndicator === 'P' ? 'Prod' : ich.usageIndicator === 'T' ? 'Test' : ich.usageIndicator) + ')'));
    row.addEventListener('click', function () { onSelect(ich.isa, row); toggle(); });
    const kids = h('div', 'children');
    ich.groups.forEach(function (g) { kids.appendChild(groupNode(g, sef, onSelect)); });
    if (ich.trailer) kids.appendChild(segRow(ich.trailer, sef, onSelect));
    node.appendChild(row); node.appendChild(kids);
    function toggle() { const open = kids.style.display !== 'none'; kids.style.display = open ? 'none' : ''; tw.textContent = open ? '▸' : '▾'; }
    return node;
  }

  function groupNode(g, sef, onSelect) {
    const node = h('div', 'node');
    const row = h('div', 'row');
    const tw = h('span', 'twist', '▾');
    row.appendChild(tw);
    row.appendChild(h('span', 'env', 'GS'));
    row.appendChild(h('span', 'desc', g.functionalId + ' · ' + g.transactions.length + ' txn'));
    row.addEventListener('click', function () { onSelect(g.gs, row); toggle(); });
    const kids = h('div', 'children');
    g.transactions.forEach(function (t) { kids.appendChild(txnNode(t, sef, onSelect)); });
    if (g.trailer) kids.appendChild(segRow(g.trailer, sef, onSelect));
    node.appendChild(row); node.appendChild(kids);
    function toggle() { const open = kids.style.display !== 'none'; kids.style.display = open ? 'none' : ''; tw.textContent = open ? '▸' : '▾'; }
    return node;
  }

  function txnNode(t, sef, onSelect) {
    const node = h('div', 'node');
    const row = h('div', 'row');
    const tw = h('span', 'twist', '▾');
    row.appendChild(tw);
    row.appendChild(h('span', 'loop', 'ST ' + t.setId));
    row.appendChild(h('span', 'desc', X12.SET_NAMES[t.setId] ? X12.SET_NAMES[t.setId].replace(/\s*\(.*\)$/, '') : t.name));
    const sr = worstOf(t.st.diagnostics);
    row.addEventListener('click', function () { onSelect(t.st, row); toggle(); });
    const kids = h('div', 'children');
    // body segments (skip the ST itself which is header)
    t.segments.forEach(function (s) { if (s === t.st) return; kids.appendChild(segRow(s, sef, onSelect)); });
    node.appendChild(row); node.appendChild(kids);
    function toggle() { const open = kids.style.display !== 'none'; kids.style.display = open ? 'none' : ''; tw.textContent = open ? '▸' : '▾'; }
    return node;
  }

  function worstOf(diags) {
    if (!diags) return null;
    if (diags.some(function (d) { return d.severity === 'error'; })) return 'error';
    if (diags.some(function (d) { return d.severity === 'warning'; })) return 'warning';
    return null;
  }

  // ---- Overview (Weka-style dashboard) --------------------------------------
  function renderOverview(container, parsed, sef, result, onGoto) {
    container.innerHTML = '';
    const s = parsed.stats;
    const ich = parsed.interchanges[0];
    const total = result.summary.error + result.summary.warning + result.summary.info;
    const healthy = result.summary.error === 0 && result.summary.warning === 0;

    // status banner (cluster header)
    const banner = h('div', 'wk-banner ' + (result.summary.error ? 'crit' : result.summary.warning ? 'warn' : 'ok'));
    const bl = h('div', 'wk-banner-l');
    bl.appendChild(h('span', 'wk-status-dot'));
    const bt = h('div');
    bt.appendChild(h('div', 'wk-banner-title', ich ? (ich.senderId + ' → ' + ich.receiverId) : 'Interchange'));
    bt.appendChild(h('div', 'wk-banner-sub', (ich ? (X12.SET_NAMES[firstSetId(parsed)] || '') : '') + (ich ? '  ·  ISA ' + ich.controlNumber : '')));
    bl.appendChild(bt);
    banner.appendChild(bl);
    const br = h('div', 'wk-banner-r');
    br.appendChild(h('span', 'wk-pill ' + (result.summary.error ? 'crit' : result.summary.warning ? 'warn' : 'ok'),
      result.summary.error ? result.summary.error + ' ERRORS' : result.summary.warning ? result.summary.warning + ' WARNINGS' : 'VALIDATED'));
    if (ich) br.appendChild(h('span', 'wk-pill ' + (ich.usageIndicator === 'P' ? 'ok' : 'warn'), ich.usageIndicator === 'P' ? 'PRODUCTION' : ich.usageIndicator === 'T' ? 'TEST' : ich.usageIndicator));
    if (sef) br.appendChild(h('span', 'wk-pill', sef.std.version || sef.source));
    banner.appendChild(br);
    container.appendChild(banner);

    // hero row: health ring | HUD readouts | topology ring
    const hero = h('div', 'wk-hero');

    // 1. health ring (capacity-style)
    const healthBox = h('div', 'wk-tile');
    healthBox.appendChild(h('div', 'wk-tile-h', 'Validation Health'));
    healthBox.appendChild(gauge(result.summary, healthy));
    hero.appendChild(healthBox);

    // 2. HUD readouts
    const hud = h('div', 'wk-tile wk-hud');
    hud.appendChild(h('div', 'wk-tile-h', 'Throughput'));
    hud.appendChild(readout(s.transactionCount, 'Transaction Sets', 'txn'));
    hud.appendChild(readout(s.segmentTotal, 'Segments', 'seg'));
    hud.appendChild(readout(sef ? countValidated(parsed) : s.groupCount, sef ? 'Elements Checked' : 'Functional Groups', sef ? 'el' : 'grp'));
    hero.appendChild(hud);

    // 3. topology ring
    const topo = h('div', 'wk-tile');
    topo.appendChild(h('div', 'wk-tile-h', 'Segment Topology'));
    topo.appendChild(topologyRing(parsed, onGoto));
    hero.appendChild(topo);

    container.appendChild(hero);

    // coverage bar + alerts
    const midGrid = h('div', 'wk-grid');

    const cov = h('div', 'wk-tile');
    cov.appendChild(h('div', 'wk-tile-h', 'Profile Coverage'));
    cov.appendChild(coverage(parsed, sef));
    // transaction distribution below coverage
    cov.appendChild(h('div', 'wk-sub-h', 'Transaction Set Distribution'));
    const setEntries = Object.keys(s.setCounts).map(function (k) { return [k, s.setCounts[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
    cov.appendChild(barChart(setEntries.map(function (e) {
      return { label: (X12.SET_NAMES[e[0]] || ('Set ' + e[0])).replace(/^(.*?)\s*\((\w+)\)$/, '$2 · $1'), value: e[1] };
    })));
    midGrid.appendChild(cov);

    // alerts / events feed
    const alerts = h('div', 'wk-tile');
    const ah = h('div', 'wk-tile-h wk-tile-h-row');
    ah.appendChild(h('span', null, 'Alerts & Events'));
    ah.appendChild(h('span', 'wk-count', String(total)));
    alerts.appendChild(ah);
    alerts.appendChild(alertsFeed(result, onGoto));
    midGrid.appendChild(alerts);

    container.appendChild(midGrid);

    // envelope + profile + segment frequency
    const grid2 = h('div', 'wk-grid');
    if (ich) {
      const envBox = h('div', 'wk-tile');
      envBox.appendChild(h('div', 'wk-tile-h', 'Interchange Envelope'));
      const kv = h('div', 'kv');
      addKV(kv, 'Sender', ich.senderQual + ':' + ich.senderId);
      addKV(kv, 'Receiver', ich.receiverQual + ':' + ich.receiverId);
      addKV(kv, 'Date / Time', ich.date + ' ' + ich.time);
      addKV(kv, 'Control #', ich.controlNumber);
      addKV(kv, 'Version', ich.version);
      envBox.appendChild(kv);
      grid2.appendChild(envBox);
    }
    const profBox = h('div', 'wk-tile');
    profBox.appendChild(h('div', 'wk-tile-h', 'Active SEF Profile'));
    const pkv = h('div', 'kv');
    if (sef) {
      addKV(pkv, 'Name', sef.std.name || sef.source);
      addKV(pkv, 'Agency / Ver', (sef.std.agency || 'X12') + ' ' + (sef.std.version || ''));
      addKV(pkv, 'Segments', sef.counts.segments + ' defined');
      addKV(pkv, 'Elements', sef.counts.elements + ' defined');
      addKV(pkv, 'Code lists', countCodeLists(sef));
      addKV(pkv, 'Structures', sef.counts.sets);
    } else {
      addKV(pkv, 'Name', 'None — structural parse only');
      addKV(pkv, 'Tip', 'Pick a profile or load a .sef file to enable validation.');
    }
    profBox.appendChild(pkv);
    grid2.appendChild(profBox);
    container.appendChild(grid2);

    const segBox = h('div', 'wk-tile');
    segBox.appendChild(h('div', 'wk-tile-h', 'Segment Frequency'));
    const segEntries = Object.keys(s.segmentCounts).map(function (k) { return [k, s.segmentCounts[k]]; }).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 18);
    segBox.appendChild(barChart(segEntries.map(function (e) {
      const def = sef && sef.segments[e[0]];
      return { label: e[0] + (def && def.name ? ' · ' + def.name : ''), value: e[1] };
    })));
    container.appendChild(segBox);
  }

  function firstSetId(parsed) {
    for (const ich of parsed.interchanges) for (const g of ich.groups) for (const t of g.transactions) return t.setId;
    return '';
  }
  function countValidated(parsed) {
    let n = 0; parsed.segments.forEach(function (s) { if (s.def) n += s.elements.length; }); return n;
  }

  // big capacity-style gauge (conic ring, status in center)
  function gauge(summary, healthy) {
    const total = summary.error + summary.warning + summary.info;
    const wrap = h('div', 'wk-gauge-wrap');
    const g = h('div', 'wk-gauge');
    if (total === 0) g.style.background = 'conic-gradient(var(--ok) 0 100%)';
    else {
      const e = summary.error / total * 100, w = summary.warning / total * 100;
      g.style.background = 'conic-gradient(var(--error) 0 ' + e + '%, var(--warning) ' + e + '% ' + (e + w) + '%, var(--info) ' + (e + w) + '% 100%)';
    }
    const c = h('div', 'wk-gauge-c');
    c.appendChild(h('b', healthy ? 'ok' : 'bad', healthy ? '✓' : String(total)));
    c.appendChild(h('span', null, healthy ? 'HEALTHY' : 'FINDINGS'));
    g.appendChild(c); wrap.appendChild(g);
    const legend = h('div', 'legend');
    [['Errors', summary.error, 'var(--error)'], ['Warnings', summary.warning, 'var(--warning)'], ['Info', summary.info, 'var(--info)']].forEach(function (l) {
      const li = h('div', 'li'); const sw = h('span', 'sw'); sw.style.background = l[2]; li.appendChild(sw); li.appendChild(h('span', null, l[0] + ' · ' + l[1])); legend.appendChild(li);
    });
    wrap.appendChild(legend);
    return wrap;
  }

  // big performance readout (number + unit + label + mini bar)
  function readout(value, label, unit) {
    const r = h('div', 'wk-readout');
    const top = h('div', 'wk-readout-v');
    top.appendChild(h('span', 'wk-num', formatNum(value)));
    top.appendChild(h('span', 'wk-unit', unit));
    r.appendChild(top);
    r.appendChild(h('div', 'wk-readout-l', label));
    return r;
  }
  function formatNum(n) { return n >= 100000 ? (n / 1000).toFixed(1) + 'k' : String(n); }

  // signature ring of dots — one per segment, colored by severity
  function topologyRing(parsed, onGoto) {
    const NS = 'http://www.w3.org/2000/svg';
    const segs = parsed.segments;
    const cap = 96;
    const shown = segs.slice(0, cap);
    const size = 210, C = size / 2, R = size / 2 - 14;
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size); svg.setAttribute('class', 'wk-topo');
    // spokes + outer ring
    const ring = document.createElementNS(NS, 'circle');
    ring.setAttribute('cx', C); ring.setAttribute('cy', C); ring.setAttribute('r', R); ring.setAttribute('class', 'wk-topo-ring');
    svg.appendChild(ring);
    const n = shown.length || 1;
    shown.forEach(function (seg, i) {
      const a = (i / n) * Math.PI * 2 - Math.PI / 2;
      const x = C + R * Math.cos(a), y = C + R * Math.sin(a);
      const sev = worstOf(seg.diagnostics);
      const spoke = document.createElementNS(NS, 'line');
      spoke.setAttribute('x1', C); spoke.setAttribute('y1', C); spoke.setAttribute('x2', x); spoke.setAttribute('y2', y);
      spoke.setAttribute('class', 'wk-spoke'); svg.appendChild(spoke);
      const dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('cx', x); dot.setAttribute('cy', y); dot.setAttribute('r', sev ? 5.5 : 4);
      dot.setAttribute('class', 'wk-node ' + (sev || 'clean'));
      const title = document.createElementNS(NS, 'title'); title.textContent = seg.id + ' #' + (seg.index + 1) + (sev ? ' — ' + sev : '');
      dot.appendChild(title);
      if (onGoto) { dot.style.cursor = 'pointer'; dot.addEventListener('click', function () { onGoto(seg.index); }); }
      svg.appendChild(dot);
    });
    const wrap = h('div', 'wk-topo-wrap');
    wrap.appendChild(svg);
    const center = h('div', 'wk-topo-center');
    center.appendChild(h('b', null, String(segs.length)));
    center.appendChild(h('span', null, 'SEGMENTS'));
    wrap.appendChild(center);
    if (segs.length > cap) wrap.appendChild(h('div', 'wk-topo-more', '+' + (segs.length - cap) + ' more'));
    return wrap;
  }

  // capacity-style coverage bar: defined vs undefined segment types
  function coverage(parsed, sef) {
    const wrap = h('div');
    const ids = Object.keys(parsed.stats.segmentCounts);
    let defined = 0;
    if (sef) ids.forEach(function (id) { if (sef.segments[id]) defined++; });
    const pct = ids.length ? Math.round(defined / ids.length * 100) : 0;
    const meta = h('div', 'wk-cap-meta');
    meta.appendChild(h('span', null, sef ? (defined + ' / ' + ids.length + ' segment types in profile') : 'No profile loaded'));
    meta.appendChild(h('span', 'wk-cap-pct', sef ? pct + '%' : '—'));
    wrap.appendChild(meta);
    const track = h('div', 'wk-cap-track');
    const fill = h('div', 'wk-cap-fill'); fill.style.width = (sef ? pct : 0) + '%';
    track.appendChild(fill); wrap.appendChild(track);
    return wrap;
  }

  function alertsFeed(result, onGoto) {
    const wrap = h('div', 'wk-alerts');
    const order = { error: 0, warning: 1, info: 2 };
    const items = result.diagnostics.slice().sort(function (a, b) { return order[a.severity] - order[b.severity] || a.segIndex - b.segIndex; }).slice(0, 7);
    if (items.length === 0) { const ok = h('div', 'wk-alert ok'); ok.appendChild(h('span', 'wk-alert-ico', '✓')); ok.appendChild(h('span', null, 'No alerts — all checks passed.')); wrap.appendChild(ok); return wrap; }
    const icons = { error: '✕', warning: '▲', info: 'ⓘ' };
    items.forEach(function (d) {
      const a = h('div', 'wk-alert ' + d.severity);
      a.appendChild(h('span', 'wk-alert-ico', icons[d.severity]));
      const b = h('div', 'wk-alert-b');
      b.appendChild(h('div', 'wk-alert-m', d.message));
      b.appendChild(h('div', 'wk-alert-meta', (d.segId ? d.segId + (d.segIndex >= 0 ? ' #' + (d.segIndex + 1) : '') + ' · ' : '') + d.code));
      a.appendChild(b);
      if (onGoto && d.segIndex >= 0) { a.style.cursor = 'pointer'; a.addEventListener('click', function () { onGoto(d.segIndex); }); }
      wrap.appendChild(a);
    });
    return wrap;
  }

  function countCodeLists(sef) {
    let n = 0; Object.keys(sef.elements).forEach(function (k) { if (Object.keys(sef.elements[k].codes || {}).length) n++; }); return n;
  }
  function statCard(k, v, cls) {
    const c = h('div', 'card'); c.appendChild(h('div', 'k', k)); c.appendChild(h('div', 'v' + (cls ? ' ' + cls : ''), String(v))); return c;
  }
  function addKV(kv, k, v) { kv.appendChild(h('div', 'kk', k)); kv.appendChild(h('div', 'vv', v)); }

  function barChart(items) {
    const wrap = h('div', 'bars');
    const max = Math.max.apply(null, items.map(function (i) { return i.value; }).concat([1]));
    if (items.length === 0) { wrap.appendChild(h('div', 'phi', 'No data.')); return wrap; }
    items.forEach(function (it) {
      const row = h('div', 'bar-row');
      row.appendChild(h('div', 'lbl', it.label));
      const track = h('div', 'bar-track'); const fill = h('div', 'bar-fill'); fill.style.width = (it.value / max * 100) + '%'; track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(h('div', 'num', String(it.value)));
      wrap.appendChild(row);
    });
    return wrap;
  }

  function severityDonut(summary) {
    const total = summary.error + summary.warning + summary.info;
    const wrap = h('div', 'donut-wrap');
    const donut = h('div', 'donut');
    if (total === 0) {
      donut.style.background = 'conic-gradient(var(--ok) 0 100%)';
    } else {
      const e = summary.error / total * 100, w = summary.warning / total * 100;
      donut.style.background = 'conic-gradient(var(--error) 0 ' + e + '%, var(--warning) ' + e + '% ' + (e + w) + '%, var(--info) ' + (e + w) + '% 100%)';
    }
    const center = h('div', 'center'); center.appendChild(h('b', null, String(total))); center.appendChild(h('span', null, 'findings')); donut.appendChild(center);
    wrap.appendChild(donut);
    const legend = h('div', 'legend');
    [['Errors', summary.error, 'var(--error)'], ['Warnings', summary.warning, 'var(--warning)'], ['Info', summary.info, 'var(--info)']].forEach(function (l) {
      const li = h('div', 'li'); const sw = h('span', 'sw'); sw.style.background = l[2]; li.appendChild(sw); li.appendChild(h('span', null, l[0] + ': ' + l[1])); legend.appendChild(li);
    });
    if (total === 0) { const li = h('div', 'li'); li.appendChild(h('span', null, '✓ No issues found')); legend.appendChild(li); }
    wrap.appendChild(legend);
    return wrap;
  }

  // ---- Inspector -------------------------------------------------------------
  function renderInspector(container, seg, sef) {
    container.innerHTML = '';
    if (!seg) { container.appendChild(h('div', 'phi', 'Select a segment from the tree to inspect it.')); return; }
    const def = sef && sef.segments[seg.id];
    const head = h('div', 'insp-head');
    head.appendChild(h('span', 'sid', seg.id));
    head.appendChild(h('span', 'sname', def && def.name ? def.name : 'Segment'));
    container.appendChild(head);
    container.appendChild(h('div', 'insp-sub', 'Position #' + (seg.index + 1) + ' · byte offset ' + seg.offset + ' · ' + seg.elements.length + ' data elements'));

    if (seg.diagnostics && seg.diagnostics.length) {
      seg.diagnostics.forEach(function (d) { container.appendChild(diagCard(d, function () {})); });
      container.appendChild(h('div', null, '')).style.height = '10px';
    }

    const table = h('table', 'elts');
    const thead = h('thead'); const htr = document.createElement('tr');
    ['Ref', 'Element', 'Req', 'Type', 'Value', 'Meaning'].forEach(function (t) { htr.appendChild(h('th', null, t)); });
    thead.appendChild(htr); table.appendChild(thead);
    const tbody = h('tbody');
    const maxLen = Math.max(seg.elements.length, def ? def.elements.length : 0);
    for (let i = 0; i < maxLen; i++) {
      const elem = seg.elements[i];
      const edef = def && def.elements[i];
      const tr = document.createElement('tr');
      const ref = edef ? edef.ref : (seg.id + (i + 1 < 10 ? '0' : '') + (i + 1));
      tr.appendChild(td('ref', ref));
      tr.appendChild(td(null, edef && edef.def && edef.def.name ? edef.def.name : (elem && elem.components ? 'Composite' : '—')));
      const reqTd = document.createElement('td');
      if (edef) { const rb = h('span', 'reqbadge ' + edef.req, edef.req); reqTd.appendChild(rb); }
      tr.appendChild(reqTd);
      tr.appendChild(td('eltype', edef && edef.def ? (edef.def.type + ' ' + edef.def.min + '/' + edef.def.max) : ''));
      const vtd = document.createElement('td');
      if (elem && elem.value !== '') {
        if (elem.components) {
          elem.components.forEach(function (c, ci) { const s = h('span', 'val', c); vtd.appendChild(s); if (ci < elem.components.length - 1) vtd.appendChild(h('span', 'rsep', ' : ')); });
        } else {
          vtd.appendChild(h('span', 'val', elem.value));
        }
      } else {
        vtd.appendChild(h('span', 'val empty', '(empty)'));
      }
      tr.appendChild(vtd);
      // meaning: code description
      const mtd = document.createElement('td');
      if (elem && edef && edef.def && edef.def.codes) {
        const desc = edef.def.codes[elem.value];
        if (desc) mtd.appendChild(h('span', 'codedesc', desc));
        else if (Object.keys(edef.def.codes).length && elem.value !== '') mtd.appendChild(h('span', 'val empty', 'not in code list'));
      }
      tr.appendChild(mtd);
      // row highlight for element diagnostics
      if (elem && elem.diag) { const worst = worstOf(elem.diag); if (worst === 'error') tr.style.background = 'rgba(248,113,113,.09)'; else if (worst === 'warning') tr.style.background = 'rgba(251,191,36,.07)'; }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  }
  function td(cls, text) { const d = document.createElement('td'); if (cls) d.className = cls; d.textContent = text == null ? '' : text; return d; }

  // ---- Diagnostics list ------------------------------------------------------
  function renderDiagnostics(container, result, onGoto) {
    container.innerHTML = '';
    const state = { error: true, warning: true, info: true };
    const filters = h('div', 'diag-filters');
    [['error', 'Errors', result.summary.error], ['warning', 'Warnings', result.summary.warning], ['info', 'Info', result.summary.info]].forEach(function (f) {
      const chip = h('div', 'chip on');
      chip.appendChild(h('span', 'n', String(f[2]))); chip.appendChild(document.createTextNode(' ' + f[1]));
      chip.addEventListener('click', function () { state[f[0]] = !state[f[0]]; chip.classList.toggle('on', state[f[0]]); draw(); });
      filters.appendChild(chip);
    });
    container.appendChild(filters);
    const listWrap = h('div');
    container.appendChild(listWrap);

    function draw() {
      listWrap.innerHTML = '';
      const order = { error: 0, warning: 1, info: 2 };
      const items = result.diagnostics.filter(function (d) { return state[d.severity]; })
        .sort(function (a, b) { return order[a.severity] - order[b.severity] || a.segIndex - b.segIndex; });
      if (items.length === 0) {
        const clean = h('div', 'clean');
        clean.appendChild(h('div', 'big', '✓'));
        clean.appendChild(h('div', null, result.diagnostics.length === 0 ? 'No issues found against the active profile.' : 'No findings match the current filters.'));
        listWrap.appendChild(clean); return;
      }
      items.forEach(function (d) { listWrap.appendChild(diagCard(d, onGoto)); });
    }
    draw();
  }

  function diagCard(d, onGoto) {
    const card = h('div', 'diag ' + d.severity);
    const icons = { error: '✕', warning: '▲', info: 'ⓘ' };
    card.appendChild(h('div', 'ico', icons[d.severity]));
    const body = h('div', 'body');
    body.appendChild(h('div', 'msg', d.message));
    const meta = h('div', 'meta');
    const parts = [];
    if (d.segId) parts.push(d.segId + (d.segIndex >= 0 ? ' #' + (d.segIndex + 1) : ''));
    if (d.elementPos) parts.push('element ' + d.elementPos);
    if (d.path) parts.push(d.path);
    meta.appendChild(h('span', 'code-tag', d.code));
    meta.appendChild(document.createTextNode('  ' + parts.join('  ·  ')));
    body.appendChild(meta);
    card.appendChild(body);
    if (onGoto && d.segIndex >= 0) card.addEventListener('click', function () { onGoto(d.segIndex); });
    return card;
  }

  // ---- Raw view --------------------------------------------------------------
  function renderRaw(container, parsed) {
    container.innerHTML = '';
    const wrap = h('div', 'raw');
    const delim = parsed.delimiters;
    parsed.segments.forEach(function (seg, i) {
      const line = h('div', 'seg-line');
      line.id = 'rawseg-' + seg.index;
      const worst = worstOf(seg.diagnostics);
      if (worst === 'error') line.classList.add('has-error');
      else if (worst === 'warning') line.classList.add('has-warning');
      line.appendChild(h('span', 'lineno', String(i + 1)));
      const env = ['ISA', 'GS', 'ST', 'SE', 'GE', 'IEA'].indexOf(seg.id) >= 0;
      line.appendChild(h('span', env ? 'renv' : 'rid', seg.id));
      seg.elements.forEach(function (e) {
        line.appendChild(h('span', 'rsep', delim.element));
        line.appendChild(document.createTextNode(e.value));
      });
      line.appendChild(h('span', 'rsep', delim.terminator === '\n' ? '~' : delim.terminator));
      wrap.appendChild(line);
    });
    container.appendChild(wrap);
  }

  global.UI = {
    renderTree: renderTree,
    renderOverview: renderOverview,
    renderInspector: renderInspector,
    renderDiagnostics: renderDiagnostics,
    renderRaw: renderRaw
  };
})(window);
