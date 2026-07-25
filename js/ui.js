/* Signal EDI — rendering / diagnostic views */
(function (global) {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  function h(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function svgEl(tag, attrs) {
    const e = document.createElementNS(NS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }

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
    row.addEventListener('click', function () { onSelect(t.st, row); toggle(); });
    const kids = h('div', 'children');
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

  function firstSetId(parsed) {
    for (const ich of parsed.interchanges) for (const g of ich.groups) for (const t of g.transactions) return t.setId;
    return '';
  }
  function countValidated(parsed) {
    let n = 0; parsed.segments.forEach(function (s) { if (s.def) n += s.elements.length; }); return n;
  }

  // ---- Overview: isometric cluster canvas (Weka-style) -----------------------
  function renderOverview(container, parsed, sef, result, onGoto) {
    container.innerHTML = '';
    const s = parsed.stats;

    const canvas = h('div', 'iso-canvas');
    canvas.appendChild(isoDiagram(parsed, onGoto));
    const legend = h('div', 'iso-legend');
    [['valid', 'Valid'], ['warning', 'Warning'], ['error', 'Error'], ['hub', 'Interchange']].forEach(function (l) {
      const li = h('span', 'iso-leg'); li.appendChild(h('span', 'iso-sw ' + l[0])); li.appendChild(document.createTextNode(l[1])); legend.appendChild(li);
    });
    canvas.appendChild(legend);
    container.appendChild(canvas);

    const charts = h('div', 'ov-charts');
    const c1 = h('div', 'panel-box');
    c1.appendChild(h('h3', null, 'Transaction Set Distribution'));
    const setEntries = Object.keys(s.setCounts).map(function (k) { return [k, s.setCounts[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
    c1.appendChild(barChart(setEntries.map(function (e) {
      return { label: (X12.SET_NAMES[e[0]] || ('Set ' + e[0])).replace(/^(.*?)\s*\((\w+)\)$/, '$2 · $1'), value: e[1] };
    })));
    const c2 = h('div', 'panel-box');
    c2.appendChild(h('h3', null, 'Segment Frequency'));
    const segEntries = Object.keys(s.segmentCounts).map(function (k) { return [k, s.segmentCounts[k]]; }).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 12);
    c2.appendChild(barChart(segEntries.map(function (e) {
      const def = sef && sef.segments[e[0]];
      return { label: e[0] + (def && def.name ? ' · ' + def.name : ''), value: e[1] };
    })));
    charts.appendChild(c1); charts.appendChild(c2);
    container.appendChild(charts);
  }

  // isometric cube cluster: hub (interchange) + one cube per segment
  function isoDiagram(parsed, onGoto) {
    const segs = parsed.segments;
    const cap = 48;
    const shown = segs.slice(0, cap);
    const W = 900, H = 470;
    const svg = svgEl('svg', { class: 'iso', viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'xMidYMid meet' });

    const size = shown.length > 30 ? 22 : 27;
    const hw = size, qh = size * 0.5;
    const cols = Math.max(1, Math.ceil(Math.sqrt(shown.length)));
    const originX = W * 0.60, originY = H * 0.24;
    const hubX = W * 0.17, hubY = H * 0.44, hubS = size * 1.25;

    // connector from hub to cluster
    svg.appendChild(svgEl('line', { x1: hubX, y1: hubY + hubS, x2: originX, y2: originY + qh * 2, class: 'iso-link' }));

    isoCube(svg, hubX, hubY, hubS, { hub: true, title: 'Interchange (ISA) — ' + (parsed.interchanges[0] ? parsed.interchanges[0].controlNumber : '') });

    const cells = shown.map(function (seg, i) { return { seg: seg, col: i % cols, row: Math.floor(i / cols) }; });
    cells.sort(function (a, b) { return (a.col + a.row) - (b.col + b.row); });
    cells.forEach(function (c) {
      const x = originX + (c.col - c.row) * hw;
      const y = originY + (c.col + c.row) * qh;
      isoCube(svg, x, y, size, { sev: worstOf(c.seg.diagnostics), title: c.seg.id + ' #' + (c.seg.index + 1), index: c.seg.index }, onGoto);
    });

    const wrap = h('div', 'iso-wrap');
    wrap.appendChild(svg);
    if (segs.length > cap) wrap.appendChild(h('div', 'iso-more', '+' + (segs.length - cap) + ' more segments'));
    return wrap;
  }

  function isoCube(svg, x, y, s, opts, onGoto) {
    const hw = s, qh = s * 0.5, ht = s;
    const g = svgEl('g', { class: 'iso-cube' });
    const top = [[x, y], [x + hw, y + qh], [x, y + 2 * qh], [x - hw, y + qh]];
    const left = [[x - hw, y + qh], [x, y + 2 * qh], [x, y + 2 * qh + ht], [x - hw, y + qh + ht]];
    const right = [[x, y + 2 * qh], [x + hw, y + qh], [x + hw, y + qh + ht], [x, y + 2 * qh + ht]];
    const pal = opts.hub
      ? { t: '#7ed957', l: '#46b45a', r: '#379143' }
      : { t: '#aadcf0', l: '#79b7d8', r: '#63a3c6' };
    g.appendChild(poly(left, pal.l));
    g.appendChild(poly(right, pal.r));
    g.appendChild(poly(top, pal.t));
    // status marker on the top face
    const cx = x, cy = y + qh, m = s * 0.34;
    const mk = [[cx, cy - m * 0.5], [cx + m, cy], [cx, cy + m * 0.5], [cx - m, cy]];
    const sevColor = { error: '#e5484d', warning: '#f5a623', info: '#3b82f6' };
    const markColor = opts.hub ? '#ffffff' : (opts.sev ? sevColor[opts.sev] : '#22c55e');
    g.appendChild(poly(mk, markColor));
    const title = svgEl('title'); title.textContent = opts.title + (opts.sev ? ' — ' + opts.sev : ''); g.appendChild(title);
    if (onGoto && typeof opts.index === 'number') {
      g.classList.add('clickable');
      g.addEventListener('click', function () { onGoto(opts.index); });
    }
    svg.appendChild(g);
  }
  function poly(points, fill) {
    return svgEl('polygon', { points: points.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' '), fill: fill });
  }

  // ---- Stat column (persistent, Weka-style) ---------------------------------
  function renderStatColumn(container, parsed, sef, result) {
    container.innerHTML = '';
    const s = parsed.stats;
    const ich = parsed.interchanges[0];
    const err = result.summary.error, warn = result.summary.warning, info = result.summary.info;
    const healthy = err === 0 && warn === 0;

    // status
    const st = h('div', 'sc-status ' + (healthy ? 'ok' : err ? 'err' : 'warn'));
    st.appendChild(h('div', 'sc-badge', healthy ? '✓' : err ? '✕' : '!'));
    st.appendChild(h('div', 'sc-status-t', healthy ? 'VALID' : err ? 'INVALID' : 'WARNINGS'));
    container.appendChild(st);

    // findings (Data-protection analog: N + N)
    const fg = h('div', 'sc-group');
    fg.appendChild(h('div', 'sc-h', 'Findings'));
    const frow = h('div', 'sc-pair');
    frow.appendChild(scMini(err, 'Errors', err ? 'err' : ''));
    frow.appendChild(h('div', 'sc-plus', '+'));
    frow.appendChild(scMini(warn, 'Warnings', warn ? 'warn' : ''));
    fg.appendChild(frow);
    container.appendChild(fg);

    container.appendChild(dualStat('Volume', 'Interchanges', s.interchangeCount, 'Groups', s.groupCount, s.transactionCount, 'Transaction Sets'));
    container.appendChild(dualStat('Segments', 'Total', s.segmentTotal, 'Types', Object.keys(s.segmentCounts).length, s.segmentTotal, 'Segments'));
    container.appendChild(dualStat('Elements', 'Checked', countValidated(parsed), 'Defined', sef ? sef.counts.elements : 0, sef ? countValidated(parsed) : 0, 'Elements'));

    // validation health semicircle gauge
    const hg = h('div', 'sc-group');
    hg.appendChild(h('div', 'sc-h', 'Validation Health'));
    const withErr = parsed.segments.filter(function (x) { return worstOf(x.diagnostics) === 'error'; }).length;
    const pct = parsed.segments.length ? Math.round((parsed.segments.length - withErr) / parsed.segments.length * 100) : 100;
    hg.appendChild(semiGauge(pct));
    container.appendChild(hg);

    // profile capacity table
    const rows = sef ? [
      ['Profile', (sef.std.name || sef.source).slice(0, 22)],
      ['Version', sef.std.version || '—'],
      ['Segments', sef.counts.segments],
      ['Elements', sef.counts.elements],
      ['Code lists', countCodeLists(sef)],
      ['Structures', sef.counts.sets],
      ['Usage', ich ? (ich.usageIndicator === 'P' ? 'Production' : ich.usageIndicator === 'T' ? 'Test' : ich.usageIndicator) : '—']
    ] : [['Profile', 'None'], ['Mode', 'Structure only']];
    container.appendChild(capTable('Active Profile', rows));
  }

  function scMini(v, label, cls) {
    const d = h('div', 'sc-mini');
    d.appendChild(h('div', 'sc-mini-v' + (cls ? ' ' + cls : ''), String(v)));
    d.appendChild(h('div', 'sc-mini-l', label));
    return d;
  }
  function dualStat(title, lLabel, lVal, rLabel, rVal, bigVal, bigLabel) {
    const g = h('div', 'sc-group');
    g.appendChild(h('div', 'sc-h', title));
    const row = h('div', 'sc-dual');
    const lc = h('div', 'sc-dual-c');
    lc.appendChild(h('div', 'sc-dual-l', lLabel)); lc.appendChild(h('div', 'sc-dual-v', String(lVal)));
    const rc = h('div', 'sc-dual-c right');
    rc.appendChild(h('div', 'sc-dual-l', rLabel)); rc.appendChild(h('div', 'sc-dual-v', String(rVal)));
    row.appendChild(lc); row.appendChild(rc);
    g.appendChild(row);
    g.appendChild(h('div', 'sc-big', String(bigVal)));
    return g;
  }
  function semiGauge(pct) {
    const wrap = h('div', 'sc-gauge');
    const cx = 60, cy = 58, r = 46;
    const svg = svgEl('svg', { viewBox: '0 0 120 68', class: 'sc-gauge-svg' });
    svg.appendChild(svgEl('path', { d: arcPath(cx, cy, r, 180, 0), class: 'sc-gauge-track', fill: 'none' }));
    svg.appendChild(svgEl('path', { d: arcPath(cx, cy, r, 180, 180 - pct / 100 * 180), class: 'sc-gauge-val', fill: 'none' }));
    wrap.appendChild(svg);
    wrap.appendChild(h('div', 'sc-gauge-t', pct + '%'));
    return wrap;
  }
  function arcPath(cx, cy, r, a0, a1) {
    const s = polar(cx, cy, r, a0), e = polar(cx, cy, r, a1);
    const large = Math.abs(a1 - a0) > 180 ? 1 : 0;
    return 'M ' + s.x.toFixed(2) + ' ' + s.y.toFixed(2) + ' A ' + r + ' ' + r + ' 0 ' + large + ' 1 ' + e.x.toFixed(2) + ' ' + e.y.toFixed(2);
  }
  function polar(cx, cy, r, deg) { const a = deg * Math.PI / 180; return { x: cx + r * Math.cos(a), y: cy - r * Math.sin(a) }; }
  function capTable(title, rows) {
    const g = h('div', 'sc-group');
    g.appendChild(h('div', 'sc-h', title));
    const t = h('div', 'sc-table');
    rows.forEach(function (r, i) {
      const row = h('div', 'sc-trow' + (i % 2 ? ' alt' : ''));
      row.appendChild(h('span', 'sc-tk', r[0]));
      row.appendChild(h('span', 'sc-tv', String(r[1])));
      t.appendChild(row);
    });
    g.appendChild(t);
    return g;
  }

  function countCodeLists(sef) {
    let n = 0; Object.keys(sef.elements).forEach(function (k) { if (Object.keys(sef.elements[k].codes || {}).length) n++; }); return n;
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

  // ---- Inspector -------------------------------------------------------------
  function renderInspector(container, seg, sef) {
    container.innerHTML = '';
    if (!seg) { container.appendChild(h('div', 'phi', 'Select a segment from the structure tree or the topology to inspect it.')); return; }
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
      const mtd = document.createElement('td');
      if (elem && edef && edef.def && edef.def.codes) {
        const desc = edef.def.codes[elem.value];
        if (desc) mtd.appendChild(h('span', 'codedesc', desc));
        else if (Object.keys(edef.def.codes).length && elem.value !== '') mtd.appendChild(h('span', 'val empty', 'not in code list'));
      }
      tr.appendChild(mtd);
      if (elem && elem.diag) { const worst = worstOf(elem.diag); if (worst === 'error') tr.classList.add('row-error'); else if (worst === 'warning') tr.classList.add('row-warning'); }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  }
  function td(cls, text) { const d = document.createElement('td'); if (cls) d.className = cls; d.textContent = text == null ? '' : text; return d; }

  // ---- Diagnostics (hierarchical: scope › segment › findings) ---------------
  function renderDiagnostics(container, result, onGoto, sef) {
    container.innerHTML = '';
    const state = { error: true, warning: true, info: true };
    const filters = h('div', 'diag-filters');
    [['error', 'Errors', result.summary.error], ['warning', 'Warnings', result.summary.warning], ['info', 'Info', result.summary.info]].forEach(function (f) {
      const chip = h('div', 'chip on');
      chip.appendChild(h('span', 'n', String(f[2]))); chip.appendChild(document.createTextNode(' ' + f[1]));
      chip.addEventListener('click', function () { state[f[0]] = !state[f[0]]; chip.classList.toggle('on', state[f[0]]); draw(); });
      filters.appendChild(chip);
    });
    // expand / collapse all
    const spacer = h('span', null, ''); spacer.style.flex = '1'; filters.appendChild(spacer);
    const exp = h('div', 'chip', 'Expand all'); exp.addEventListener('click', function () { setAll(false); });
    const col = h('div', 'chip', 'Collapse all'); col.addEventListener('click', function () { setAll(true); });
    filters.appendChild(exp); filters.appendChild(col);
    container.appendChild(filters);

    const listWrap = h('div', 'diag-tree');
    container.appendChild(listWrap);

    function setAll(collapsed) {
      listWrap.querySelectorAll('.grp-body').forEach(function (b) { b.style.display = collapsed ? 'none' : ''; });
      listWrap.querySelectorAll('.grp-head .gtw').forEach(function (t) { t.textContent = collapsed ? '▸' : '▾'; });
    }

    function draw() {
      listWrap.innerHTML = '';
      const items = result.diagnostics.filter(function (d) { return state[d.severity]; });
      if (items.length === 0) {
        const clean = h('div', 'clean');
        clean.appendChild(h('div', 'big', '✓'));
        clean.appendChild(h('div', null, result.diagnostics.length === 0 ? 'No issues found against the active profile.' : 'No findings match the current filters.'));
        listWrap.appendChild(clean); return;
      }
      // group by scope (path) in document order, then by segment
      const scopes = [], sMap = {};
      items.forEach(function (d) {
        const key = d.path || 'Interchange';
        let sc = sMap[key];
        if (!sc) { sc = sMap[key] = { key: key, segs: [], segMap: {}, counts: { error: 0, warning: 0, info: 0 } }; scopes.push(sc); }
        sc.counts[d.severity]++;
        const sk = (d.segId || '?') + '#' + d.segIndex;
        let sg = sc.segMap[sk];
        if (!sg) { sg = sc.segMap[sk] = { segId: d.segId, segIndex: d.segIndex, items: [], counts: { error: 0, warning: 0, info: 0 } }; sc.segs.push(sg); }
        sg.items.push(d); sg.counts[d.severity]++;
      });
      scopes.forEach(function (sc) { listWrap.appendChild(scopeGroup(sc, onGoto, sef)); });
    }
    draw();
  }

  function countPills(counts) {
    const w = h('span', 'grp-counts');
    [['error', counts.error], ['warning', counts.warning], ['info', counts.info]].forEach(function (c) {
      if (c[1]) { const p = h('span', 'gc ' + c[0]); p.textContent = c[1]; w.appendChild(p); }
    });
    return w;
  }

  function collapsible(headEl, bodyEl) {
    const tw = h('span', 'gtw', '▾');
    headEl.insertBefore(tw, headEl.firstChild);
    headEl.addEventListener('click', function (e) {
      if (e.target.closest('.jump')) return;
      const open = bodyEl.style.display !== 'none';
      bodyEl.style.display = open ? 'none' : '';
      tw.textContent = open ? '▸' : '▾';
    });
  }

  function scopeGroup(sc, onGoto, sef) {
    const wrap = h('div', 'diag-scope');
    const head = h('div', 'grp-head scope-head');
    head.appendChild(h('span', 'scope-name', sc.key));
    const sp = h('span', null, ''); sp.style.flex = '1'; head.appendChild(sp);
    head.appendChild(countPills(sc.counts));
    const body = h('div', 'grp-body');
    sc.segs.forEach(function (sg) { body.appendChild(segGroup(sg, onGoto, sef)); });
    collapsible(head, body);
    wrap.appendChild(head); wrap.appendChild(body);
    return wrap;
  }

  function segGroup(sg, onGoto, sef) {
    const wrap = h('div', 'diag-seg');
    const head = h('div', 'grp-head seg-head');
    const worst = sg.counts.error ? 'error' : sg.counts.warning ? 'warning' : 'info';
    head.appendChild(h('span', 'dotmark ' + worst));
    head.appendChild(h('span', 'seg-id', sg.segId || '—'));
    const def = sef && sef.segments[sg.segId];
    if (def && def.name) head.appendChild(h('span', 'seg-nm', def.name));
    if (sg.segIndex >= 0) {
      const jump = h('span', 'jump', '#' + (sg.segIndex + 1));
      jump.title = 'Open in inspector';
      if (onGoto) jump.addEventListener('click', function (e) { e.stopPropagation(); onGoto(sg.segIndex); });
      head.appendChild(jump);
    }
    const sp = h('span', null, ''); sp.style.flex = '1'; head.appendChild(sp);
    head.appendChild(countPills(sg.counts));
    const body = h('div', 'grp-body seg-body');
    sg.items.forEach(function (d) { body.appendChild(diagCard(d, onGoto)); });
    collapsible(head, body);
    wrap.appendChild(head); wrap.appendChild(body);
    return wrap;
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
    renderStatColumn: renderStatColumn,
    renderInspector: renderInspector,
    renderDiagnostics: renderDiagnostics,
    renderRaw: renderRaw
  };
})(window);
