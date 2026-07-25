/* Signal EDI — user settings (persisted to localStorage) */
(function (global) {
  'use strict';

  const KEY = 'signalEdiSettings';
  const DEFAULTS = {
    theme: 'light',         // auto | dark | light (light matches the Weka console)
    scale: '100',           // UI zoom percent
    scanlines: true,        // CRT scanline overlay
    pixelGrid: true,        // faint pixel grid background
    showInfo: true,         // emit info-level findings
    flagUnknown: true,      // flag segments/elements not in the profile
    flagMaxLen: true,       // flag values exceeding max length
    checkStructure: true,   // flag missing mandatory segments
    rawLineNumbers: true,   // line numbers in Raw view
    rememberProfile: true,  // restore last selected profile on start
    lastProfile: 'auto'
  };

  let state = load();
  let onChange = function () {};

  function load() {
    try {
      const raw = global.localStorage && global.localStorage.getItem(KEY);
      return Object.assign({}, DEFAULTS, raw ? JSON.parse(raw) : {});
    } catch (e) { return Object.assign({}, DEFAULTS); }
  }
  function persist() {
    try { global.localStorage && global.localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {}
  }

  function get(k) { return state[k]; }
  function set(k, v) { state[k] = v; persist(); }

  function validationOptions() {
    return {
      showInfo: state.showInfo,
      flagUnknown: state.flagUnknown,
      flagMaxLen: state.flagMaxLen,
      checkStructure: state.checkStructure
    };
  }

  // Apply appearance-affecting settings to the document.
  function apply() {
    const rootEl = document.documentElement;
    if (state.theme === 'auto') rootEl.removeAttribute('data-theme');
    else rootEl.setAttribute('data-theme', state.theme);

    const appEl = document.getElementById('app');
    if (appEl) appEl.style.zoom = (parseInt(state.scale, 10) / 100) || 1;

    document.body.classList.toggle('no-scanlines', !state.scanlines);
    document.body.classList.toggle('no-grid', !state.pixelGrid);
    document.body.classList.toggle('hide-lineno', !state.rawLineNumbers);
  }

  // ---- Settings modal --------------------------------------------------------
  function h(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

  function buildModal() {
    const overlay = h('div', 'modal-overlay hidden');
    overlay.id = 'settingsOverlay';
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });

    const modal = h('div', 'modal');
    const head = h('div', 'modal-head');
    head.appendChild(h('h2', null, '⚙  Settings'));
    const x = h('button', 'modal-x', '✕'); x.title = 'Close'; x.addEventListener('click', close);
    head.appendChild(x);
    modal.appendChild(head);

    const bodyEl = h('div', 'modal-body');

    bodyEl.appendChild(section('Appearance', [
      selectRow('Theme', 'theme', [['auto', 'Auto (system)'], ['dark', 'Dark'], ['light', 'Light']]),
      selectRow('UI scale', 'scale', [['90', '90%'], ['100', '100%'], ['110', '110%'], ['125', '125%']]),
      toggleRow('Scanline overlay', 'scanlines', 'CRT-style scanlines over the interface'),
      toggleRow('Pixel grid', 'pixelGrid', 'Faint grid texture in the background')
    ]));

    bodyEl.appendChild(section('Validation', [
      toggleRow('Show info findings', 'showInfo', 'Emit informational (non-error) diagnostics'),
      toggleRow('Flag items not in profile', 'flagUnknown', 'Warn on segments/elements the SEF profile does not define'),
      toggleRow('Flag over-length values', 'flagMaxLen', 'Warn when a value exceeds its maximum length'),
      toggleRow('Check required segments', 'checkStructure', 'Flag mandatory segments missing from the transaction')
    ]));

    bodyEl.appendChild(section('Data view & session', [
      toggleRow('Raw view line numbers', 'rawLineNumbers', 'Show line numbers in the Raw tab'),
      toggleRow('Remember selected profile', 'rememberProfile', 'Restore the last bundled profile on next launch')
    ]));

    modal.appendChild(bodyEl);

    const foot = h('div', 'modal-foot');
    const reset = h('button', 'btn', 'Reset to defaults');
    reset.addEventListener('click', function () {
      const last = state.lastProfile;
      state = Object.assign({}, DEFAULTS, { lastProfile: last });
      persist(); syncInputs(); apply(); onChange('appearance');
    });
    const done = h('button', 'btn primary', 'Done'); done.addEventListener('click', close);
    foot.appendChild(reset); foot.appendChild(done);
    modal.appendChild(foot);

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }

  function section(title, rows) {
    const s = h('div', 'settings-section');
    s.appendChild(h('h3', null, title));
    rows.forEach(function (r) { s.appendChild(r); });
    return s;
  }

  function toggleRow(label, key, hint) {
    const row = h('label', 'setting-row');
    const txt = h('div', 'setting-txt');
    txt.appendChild(h('div', 'setting-label', label));
    if (hint) txt.appendChild(h('div', 'setting-hint', hint));
    row.appendChild(txt);
    const sw = h('span', 'switch');
    const input = document.createElement('input');
    input.type = 'checkbox'; input.dataset.key = key; input.checked = !!state[key];
    input.addEventListener('change', function () {
      set(key, input.checked); sw.classList.toggle('on', input.checked); apply();
      onChange(validationKeys.indexOf(key) >= 0 ? 'validation' : 'appearance');
    });
    sw.classList.toggle('on', !!state[key]);
    const knob = h('span', 'knob');
    sw.appendChild(input); sw.appendChild(knob);
    row.appendChild(sw);
    return row;
  }

  function selectRow(label, key, options) {
    const row = h('div', 'setting-row');
    row.appendChild(h('div', 'setting-label', label));
    const sel = document.createElement('select'); sel.className = 'btn'; sel.dataset.key = key;
    options.forEach(function (o) { const opt = document.createElement('option'); opt.value = o[0]; opt.textContent = o[1]; sel.appendChild(opt); });
    sel.value = state[key];
    sel.addEventListener('change', function () { set(key, sel.value); apply(); onChange('appearance'); });
    row.appendChild(sel);
    return row;
  }

  const validationKeys = ['showInfo', 'flagUnknown', 'flagMaxLen', 'checkStructure'];

  function syncInputs() {
    const overlay = document.getElementById('settingsOverlay');
    if (!overlay) return;
    overlay.querySelectorAll('input[type=checkbox]').forEach(function (i) {
      i.checked = !!state[i.dataset.key];
      const sw = i.closest('.switch'); if (sw) sw.classList.toggle('on', i.checked);
    });
    overlay.querySelectorAll('select[data-key]').forEach(function (s) { s.value = state[s.dataset.key]; });
  }

  function open() { const o = document.getElementById('settingsOverlay'); if (o) { syncInputs(); o.classList.remove('hidden'); } }
  function close() { const o = document.getElementById('settingsOverlay'); if (o) o.classList.add('hidden'); }

  function init(opts) {
    onChange = (opts && opts.onChange) || function () {};
    buildModal();
    apply();
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
  }

  global.Settings = {
    init: init, open: open, close: close, apply: apply,
    get: get, set: set, validationOptions: validationOptions
  };
})(window);
