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

  // ---- Overview --------------------------------------------------------------
  function renderOverview(container, parsed, sef, result) {
    container.innerHTML = '';
    const s = parsed.stats;

    const cards = h('div', 'cards');
    cards.appendChild(statCard('Interchanges', s.interchangeCount));
    cards.appendChild(statCard('Functional Groups', s.groupCount));
    cards.appendChild(statCard('Transaction Sets', s.transactionCount));
    cards.appendChild(statCard('Segments', s.segmentTotal));
    cards.appendChild(statCard('Errors', result.summary.error, result.summary.error ? 'error' : 'ok'));
    cards.appendChild(statCard('Warnings', result.summary.warning, result.summary.warning ? 'warning' : 'ok'));
    container.appendChild(cards);

    const grid = h('div', 'grid2');

    // Transaction breakdown
    const txnBox = h('div', 'panel-box');
    txnBox.appendChild(h('h3', null, 'Transaction Set Distribution'));
    const setEntries = Object.keys(s.setCounts).map(function (k) { return [k, s.setCounts[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
    txnBox.appendChild(barChart(setEntries.map(function (e) {
      return { label: (X12.SET_NAMES[e[0]] || ('Set ' + e[0])).replace(/^(.*?)\s*\((\w+)\)$/, '$2 · $1'), value: e[1] };
    })));
    grid.appendChild(txnBox);

    // Severity donut
    const sevBox = h('div', 'panel-box');
    sevBox.appendChild(h('h3', null, 'Diagnostics'));
    sevBox.appendChild(severityDonut(result.summary));
    grid.appendChild(sevBox);
    container.appendChild(grid);

    // Envelope details + profile
    const grid2 = h('div', 'grid2');
    const ich = parsed.interchanges[0];
    if (ich) {
      const envBox = h('div', 'panel-box');
      envBox.appendChild(h('h3', null, 'Interchange Envelope'));
      const kv = h('div', 'kv');
      addKV(kv, 'Sender', ich.senderQual + ':' + ich.senderId);
      addKV(kv, 'Receiver', ich.receiverQual + ':' + ich.receiverId);
      addKV(kv, 'Date / Time', ich.date + ' ' + ich.time);
      addKV(kv, 'Control #', ich.controlNumber);
      addKV(kv, 'Version', ich.version);
      const usage = h('span', 'tag ' + (ich.usageIndicator === 'P' ? 'prod' : 'test'), ich.usageIndicator === 'P' ? 'PRODUCTION' : ich.usageIndicator === 'T' ? 'TEST' : ich.usageIndicator);
      const uk = h('div', 'kk', 'Usage'); kv.appendChild(uk); const uv = h('div', 'vv'); uv.appendChild(usage); kv.appendChild(uv);
      envBox.appendChild(kv);
      grid2.appendChild(envBox);
    }

    const profBox = h('div', 'panel-box');
    profBox.appendChild(h('h3', null, 'Active SEF Profile'));
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

    // Segment frequency
    const segBox = h('div', 'panel-box');
    segBox.appendChild(h('h3', null, 'Segment Frequency'));
    const segEntries = Object.keys(s.segmentCounts).map(function (k) { return [k, s.segmentCounts[k]]; }).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 18);
    segBox.appendChild(barChart(segEntries.map(function (e) {
      const def = sef && sef.segments[e[0]];
      return { label: e[0] + (def && def.name ? ' · ' + def.name : ''), value: e[1] };
    })));
    container.appendChild(segBox);
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
