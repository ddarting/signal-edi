/* Signal EDI — application controller */
(function () {
  'use strict';

  const state = {
    parsed: null,
    sef: null,
    sefKey: 'auto',
    result: null,
    selected: null,
    customSefs: {}   // key -> {label, text}
  };

  const els = {};
  function $(id) { return document.getElementById(id); }

  document.addEventListener('DOMContentLoaded', function () {
    els.tree = $('tree');
    els.tabbar = $('tabbar');
    els.tabcontent = $('tabcontent');
    els.empty = $('empty');
    els.main = $('main');
    els.profileSelect = $('profileSelect');
    els.sidebarTitle = $('sidebarTitle');
    els.statcol = $('statcol');
    els.pageTitle = $('pageTitle');
    els.alertsPill = $('alertsPill');

    // Settings (restores last profile before the dropdown is built)
    if (window.Settings) {
      Settings.init({ onChange: onSettingsChange });
      if (Settings.get('rememberProfile')) {
        const lp = Settings.get('lastProfile');
        if (lp === 'auto' || lp === 'none' || (window.DEFAULT_SEFS && window.DEFAULT_SEFS[lp])) state.sefKey = lp;
      }
    }

    populateProfiles();
    wireControls();
    setActiveTab('overview');
  });

  function onSettingsChange(kind) {
    if (kind === 'validation' && state.parsed) rerun();
  }

  function populateProfiles() {
    const sel = els.profileSelect;
    sel.innerHTML = '';
    sel.appendChild(opt('auto', 'Auto-detect from ST/GS'));
    sel.appendChild(opt('none', 'None (structure only)'));
    const og = document.createElement('optgroup'); og.label = 'Bundled HIPAA profiles';
    Object.keys(window.DEFAULT_SEFS || {}).forEach(function (k) {
      og.appendChild(opt(k, window.DEFAULT_SEFS[k].label));
    });
    sel.appendChild(og);
    if (Object.keys(state.customSefs).length) {
      const cg = document.createElement('optgroup'); cg.label = 'Loaded SEF files';
      Object.keys(state.customSefs).forEach(function (k) { cg.appendChild(opt(k, state.customSefs[k].label)); });
      sel.appendChild(cg);
    }
    sel.value = state.sefKey;
  }
  function opt(v, t) { const o = document.createElement('option'); o.value = v; o.textContent = t; return o; }

  function wireControls() {
    $('openEdiBtn').addEventListener('click', function () { $('ediFile').click(); });
    $('ediFile').addEventListener('change', function (e) { if (e.target.files[0]) readEdiFile(e.target.files[0]); });
    $('loadSefBtn').addEventListener('click', function () { $('sefFile').click(); });
    $('sefFile').addEventListener('change', function (e) { if (e.target.files[0]) readSefFile(e.target.files[0]); });
    $('sampleBtn').addEventListener('click', function () { loadEdi(window.SAMPLE_EDI, 'sample-837p.edi'); });
    const sb = $('settingsBtn'); if (sb && window.Settings) sb.addEventListener('click', function () { Settings.open(); });
    const mb = $('menuBtn'); if (mb) mb.addEventListener('click', function () {
      document.querySelector('.workspace').classList.toggle('nav-collapsed');
      mb.classList.toggle('active');
    });
    els.profileSelect.addEventListener('change', function (e) {
      state.sefKey = e.target.value;
      if (window.Settings && Settings.get('rememberProfile')) Settings.set('lastProfile', state.sefKey);
      applyProfile(); rerun();
    });

    // drag & drop
    ['dragover', 'dragenter'].forEach(function (ev) {
      document.addEventListener(ev, function (e) { e.preventDefault(); els.empty.classList.add('drag'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      document.addEventListener(ev, function (e) { e.preventDefault(); if (ev === 'dragleave' && e.relatedTarget) return; els.empty.classList.remove('drag'); });
    });
    document.addEventListener('drop', function (e) {
      e.preventDefault();
      const f = e.dataTransfer.files[0]; if (!f) return;
      if (/\.sef$/i.test(f.name)) readSefFile(f); else readEdiFile(f);
    });
  }

  function readEdiFile(file) {
    const r = new FileReader();
    r.onload = function () { loadEdi(String(r.result), file.name); };
    r.onerror = function () { toast('Could not read file.', true); };
    r.readAsText(file);
  }
  function readSefFile(file) {
    const r = new FileReader();
    r.onload = function () {
      try {
        const key = 'file:' + file.name;
        state.customSefs[key] = { label: file.name + ' (loaded)', text: String(r.result) };
        state.sefKey = key;
        populateProfiles();
        els.profileSelect.value = key;
        applyProfile();
        if (state.parsed) rerun(); else toast('SEF loaded: ' + file.name + '. Open an EDI file to validate.');
      } catch (err) { toast('SEF parse error: ' + err.message, true); }
    };
    r.readAsText(file);
  }

  function loadEdi(text, name) {
    try {
      state.parsed = X12.parse(text);
    } catch (err) {
      toast(err.message, true);
      return;
    }
    els.empty.classList.add('hidden');
    els.main.classList.remove('hidden');
    if (els.statcol) els.statcol.classList.remove('hidden');
    els.sidebarTitle.textContent = name || 'Interchange';
    applyProfile(true);
    rerun();
    setActiveTab('overview');
  }

  // Resolve which SEF text to use based on state.sefKey / auto-detect.
  function applyProfile(auto) {
    let key = state.sefKey;
    if (key === 'none') { state.sef = null; return; }
    if (key === 'auto') {
      const detected = detectProfileKey();
      state.sef = detected ? parseSefByKey(detected) : null;
      return;
    }
    state.sef = parseSefByKey(key);
  }

  function detectProfileKey() {
    if (!state.parsed) return null;
    let implRef = '', setId = '';
    outer:
    for (const ich of state.parsed.interchanges) {
      for (const g of ich.groups) {
        for (const t of g.transactions) { implRef = t.implRef; setId = t.setId; break outer; }
      }
    }
    const defs = window.DEFAULT_SEFS || {};
    // 1) exact implementation reference match
    for (const k in defs) { if (defs[k].implRef && implRef && defs[k].implRef.toUpperCase() === implRef.toUpperCase()) return k; }
    // 2) setId match (first)
    for (const k in defs) { if (defs[k].setId === setId) return k; }
    return null;
  }

  function parseSefByKey(key) {
    if (key.indexOf('file:') === 0) {
      const c = state.customSefs[key];
      return SEF.parse(c.text, c.label);
    }
    const d = (window.DEFAULT_SEFS || {})[key];
    if (!d) return null;
    return SEF.parse(d.text, d.label);
  }

  function rerun() {
    if (!state.parsed) return;
    const vopts = window.Settings ? Settings.validationOptions() : undefined;
    state.result = Validator.validate(state.parsed, state.sef, vopts);
    UI.renderTree(els.tree, state.parsed, state.sef, selectSegment);
    if (els.statcol) UI.renderStatColumn(els.statcol, state.parsed, state.sef, state.result);
    updateBadges();
    renderActiveTab();
  }

  function updateBadges() {
    const eb = $('badge-validation-error'), wb = $('badge-validation-warn');
    if (eb) { eb.textContent = state.result.summary.error; eb.classList.toggle('hidden', !state.result.summary.error); }
    if (wb) { wb.textContent = state.result.summary.warning; wb.classList.toggle('hidden', !state.result.summary.warning); }
    // topbar alerts pill
    if (els.alertsPill) {
      const e = state.result.summary.error, w = state.result.summary.warning;
      els.alertsPill.className = 'alerts-pill ' + (e ? 'crit' : w ? 'warn' : 'ok');
      els.alertsPill.textContent = '● ' + (e ? e + ' ERROR' + (e > 1 ? 'S' : '') : w ? w + ' WARNING' + (w > 1 ? 'S' : '') : '0 ALERTS');
    }
    // profile note in auto mode
    const note = $('profileNote');
    if (note) {
      if (state.sefKey === 'auto') note.textContent = state.sef ? '→ ' + (state.sef.std.name || state.sef.source) : '→ no match';
      else note.textContent = '';
    }
  }

  // ---- tabs ----
  const TITLES = { overview: 'System Overview', inspector: 'Segment Inspector', validation: 'Validation', raw: 'Raw Data' };
  let activeTab = 'overview';
  function setActiveTab(id) {
    activeTab = id;
    Array.prototype.forEach.call(els.tabbar.querySelectorAll('.tab'), function (t) {
      t.classList.toggle('active', t.dataset.tab === id);
    });
    if (els.pageTitle) els.pageTitle.textContent = TITLES[id] || 'Overview';
    renderActiveTab();
  }
  function renderActiveTab() {
    if (!state.parsed) return;
    const c = els.tabcontent;
    if (activeTab === 'overview') UI.renderOverview(c, state.parsed, state.sef, state.result, gotoSegment);
    else if (activeTab === 'inspector') UI.renderInspector(c, state.selected, state.sef);
    else if (activeTab === 'validation') UI.renderDiagnostics(c, state.result, gotoSegment);
    else if (activeTab === 'raw') UI.renderRaw(c, state.parsed);
  }

  function selectSegment(seg, rowEl) {
    state.selected = seg;
    Array.prototype.forEach.call(els.tree.querySelectorAll('.row.sel'), function (r) { r.classList.remove('sel'); });
    if (rowEl) rowEl.classList.add('sel');
    setActiveTab('inspector');
  }

  function gotoSegment(index) {
    const seg = state.parsed.segments[index];
    if (!seg) return;
    state.selected = seg;
    setActiveTab('inspector');
  }

  function toast(msg, isErr) {
    const t = document.createElement('div');
    t.className = 'toast' + (isErr ? ' err' : '');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, 3800);
  }

  // expose tab handler for inline onclick
  window.__signalSetTab = setActiveTab;
})();
