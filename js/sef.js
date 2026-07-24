/* Signal EDI — SEF (Standard Exchange Format) parser
 *
 * SEF is the de-facto text format for carrying EDI implementation guidelines.
 * This parser targets the widely-interoperable dictionary sections and a clean
 * structure encoding used by the bundled default profiles:
 *
 *   .STD       agency|version|setId|name           (guide identity)
 *   .ELMS      elemNum=type,minLen,maxLen           (data element attributes)
 *   .CODES     elemNum=code,code,...                (permitted code values)
 *   .CODETEXT  elemNum,code=description             (code descriptions)  [extension]
 *   .SEGS      SEGID=elemNum,req,max,...            (segment composition)
 *   .SEGTEXT   SEGID=name                           (segment names)      [extension]
 *   .ELETEXT   elemNum=name                         (element names)      [extension]
 *   .SETS      transaction-set structure (see below)
 *
 * .SETS clean encoding (one directive per line under a "SETID=Name" header):
 *   seg <ID> <req> <max>
 *   loop <loopId> <maxRepeat>
 *   end
 *
 * Third-party SEF files that encode .SETS as a comma stream are parsed
 * best-effort into an ordered expected-segment list for sequence checks.
 */
(function (global) {
  'use strict';

  const REQ = { M: 'Mandatory', O: 'Optional', C: 'Conditional', F: 'Floating', X: 'Relational', A: 'Advised' };
  const TYPE_NAMES = {
    AN: 'String', ID: 'Identifier', DT: 'Date', TM: 'Time', R: 'Decimal', B: 'Binary'
  };

  function splitSections(text) {
    const lines = text.replace(/\r\n?/g, '\n').split('\n');
    const sections = {};
    let cur = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = /^\.([A-Za-z][A-Za-z0-9]*)\s*(.*)$/.exec(line);
      if (m && !/^\.\d/.test(line)) {
        cur = m[1].toUpperCase();
        if (cur === 'SEF') { // ".SEF 1.6" version header
          sections._version = (m[2] || '').trim();
          cur = null;
          continue;
        }
        if (!sections[cur]) sections[cur] = [];
        if (m[2] && m[2].trim() !== '') sections[cur].push(m[2]);
        continue;
      }
      if (cur) sections[cur].push(line);
    }
    return sections;
  }

  function nonEmpty(arr) {
    return (arr || []).map(function (l) { return l.replace(/\s+$/, ''); })
      .filter(function (l) { return l.trim() !== '' && l.trim()[0] !== ';'; });
  }

  function parseStd(lines) {
    const line = (nonEmpty(lines)[0] || '');
    const parts = line.split(/[|,]/).map(function (s) { return s.trim(); });
    return {
      agency: parts[0] || 'X12',
      version: parts[1] || '',
      setId: parts[2] || '',
      name: parts.slice(3).join(', ') || ''
    };
  }

  function parseElms(lines) {
    const elements = {};
    nonEmpty(lines).forEach(function (line) {
      const eq = line.indexOf('=');
      if (eq === -1) return;
      const num = line.slice(0, eq).trim();
      const parts = line.slice(eq + 1).split(',').map(function (s) { return s.trim(); });
      elements[num] = {
        num: num,
        type: (parts[0] || 'AN').toUpperCase(),
        min: parseInt(parts[1], 10) || 0,
        max: parseInt(parts[2], 10) || 0,
        name: '',
        codes: {}
      };
    });
    return elements;
  }

  function parseCodes(lines, elements) {
    nonEmpty(lines).forEach(function (line) {
      const eq = line.indexOf('=');
      if (eq === -1) return;
      const num = line.slice(0, eq).trim();
      let vals = line.slice(eq + 1).split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      // Some SEF writers prefix a numeric "included count/flag"; drop a leading pure-number.
      if (vals.length && /^\d+$/.test(vals[0]) && vals.length > 1 && !/^\d+$/.test(vals[1])) {
        vals = vals.slice(1);
      }
      if (!elements[num]) elements[num] = { num: num, type: 'ID', min: 0, max: 0, name: '', codes: {} };
      vals.forEach(function (code) {
        if (code !== '') elements[num].codes[code] = elements[num].codes[code] || '';
      });
    });
  }

  function parseCodeText(lines, elements) {
    nonEmpty(lines).forEach(function (line) {
      const eq = line.indexOf('=');
      if (eq === -1) return;
      const key = line.slice(0, eq).trim();
      const desc = line.slice(eq + 1).trim();
      const parts = key.split(',');
      const num = parts[0].trim();
      const code = (parts[1] || '').trim();
      if (!elements[num]) elements[num] = { num: num, type: 'ID', min: 0, max: 0, name: '', codes: {} };
      if (code) elements[num].codes[code] = desc;
    });
  }

  function parseSegs(lines, elements) {
    const segments = {};
    nonEmpty(lines).forEach(function (line) {
      const eq = line.indexOf('=');
      if (eq === -1) return;
      const id = line.slice(0, eq).trim().toUpperCase();
      const raw = line.slice(eq + 1);
      // strip user masks like [nn] that some SEFs use for ordinal positions
      const tokens = raw.replace(/\[[^\]]*\]/g, '').split(',').map(function (s) { return s.trim(); });
      const els = [];
      for (let i = 0; i + 0 < tokens.length;) {
        const num = tokens[i];
        if (!num) { i++; continue; }
        let req = 'O', max = 1, consumed = 1;
        if (tokens[i + 1] && /^[MOCFXA]$/i.test(tokens[i + 1])) { req = tokens[i + 1].toUpperCase(); consumed = 2; }
        if (tokens[i + consumed] && /^(>?\d+)$/.test(tokens[i + consumed])) {
          max = tokens[i + consumed] === '>1' ? Infinity : parseInt(tokens[i + consumed], 10);
          consumed++;
        }
        els.push({
          num: num,
          ref: id + (els.length + 1 < 10 ? '0' : '') + (els.length + 1),
          req: req,
          max: max,
          def: elements[num] || null
        });
        i += consumed;
      }
      segments[id] = { id: id, name: '', elements: els };
    });
    return segments;
  }

  function assignNames(lines, target, key) {
    nonEmpty(lines).forEach(function (line) {
      const eq = line.indexOf('=');
      if (eq === -1) return;
      const id = line.slice(0, eq).trim();
      const name = line.slice(eq + 1).trim();
      if (key === 'seg') { if (!target[id.toUpperCase()]) target[id.toUpperCase()] = { id: id.toUpperCase(), name: '', elements: [] }; target[id.toUpperCase()].name = name; }
      else if (key === 'elm') { if (!target[id]) target[id] = { num: id, type: 'AN', min: 0, max: 0, name: '', codes: {} }; target[id].name = name; }
    });
  }

  // ---- .SETS structure -------------------------------------------------------

  function looksClean(firstChunk) {
    return /^\s*$/.test(firstChunk) || /[A-Za-z ]/.test(firstChunk) && !/,/.test(firstChunk);
  }

  function parseSetsSection(lines) {
    const sets = {};
    const src = (lines || []).map(function (l) { return l.replace(/\s+$/, ''); });
    let i = 0;
    while (i < src.length) {
      const line = src[i];
      const hdr = /^([A-Za-z0-9]{1,6})\s*=(.*)$/.exec(line ? line.trim() : '');
      if (!hdr) { i++; continue; }
      const setId = hdr[1];
      const firstChunk = hdr[2];
      // gather following lines until next header
      const body = [];
      let j = i + 1;
      for (; j < src.length; j++) {
        if (/^[A-Za-z0-9]{1,6}\s*=/.test(src[j].trim())) break;
        if (src[j].trim() !== '') body.push(src[j].trim());
      }
      const bodyIsClean = body.length > 0 && /^(seg|loop|end)\b/i.test(body[0]);
      if (bodyIsClean || (looksClean(firstChunk) && body.length === 0)) {
        // firstChunk is the set name; body carries the seg/loop/end directives.
        sets[setId] = { setId: setId, name: firstChunk.trim(), structure: parseCleanStructure(body) };
      } else {
        const stream = [firstChunk].concat(body).join(',');
        sets[setId] = { setId: setId, name: '', structure: parseCommaStructure(stream) };
      }
      i = j;
    }
    return sets;
  }

  function parseCleanStructure(body) {
    const root = [];
    const stack = [{ children: root }];
    body.forEach(function (line) {
      const t = line.split(/\s+/);
      const kw = (t[0] || '').toLowerCase();
      if (kw === 'seg') {
        stack[stack.length - 1].children.push({
          type: 'segment', segId: (t[1] || '').toUpperCase(),
          req: (t[2] || 'O').toUpperCase(), max: t[3] === '>1' ? Infinity : (parseInt(t[3], 10) || 1)
        });
      } else if (kw === 'loop') {
        const node = {
          type: 'loop', loopId: t[1] || '', triggerSeg: '',
          max: t[2] === '>1' ? Infinity : (parseInt(t[2], 10) || 1), children: []
        };
        stack[stack.length - 1].children.push(node);
        stack.push(node);
      } else if (kw === 'end') {
        if (stack.length > 1) stack.pop();
      }
    });
    return root;
  }

  // Best-effort reconstruction from a real-SEF comma stream.
  function parseCommaStructure(stream) {
    const root = [];
    const stack = [{ children: root }];
    const tokens = stream.split(',');
    for (let i = 0; i < tokens.length; i++) {
      let tok = tokens[i].trim();
      // handle bracket loop delimiters possibly attached to tokens
      while (tok[0] === '[') { const node = { type: 'loop', loopId: '', max: Infinity, children: [] }; stack[stack.length - 1].children.push(node); stack.push(node); tok = tok.slice(1); }
      let closes = 0;
      while (tok[tok.length - 1] === ']') { closes++; tok = tok.slice(0, -1); }
      if (/^[A-Z][A-Z0-9]{1,2}$/.test(tok)) {
        let req = 'O', max = 1, consumed = 0;
        if (tokens[i + 1] && /^[MOCFXA]$/i.test(tokens[i + 1].trim())) { req = tokens[i + 1].trim().toUpperCase(); consumed++; }
        if (tokens[i + 1 + consumed] && /^>?\d+$/.test(tokens[i + 1 + consumed].trim())) {
          const mx = tokens[i + 1 + consumed].trim(); max = mx === '>1' ? Infinity : parseInt(mx, 10); consumed++;
        }
        stack[stack.length - 1].children.push({ type: 'segment', segId: tok, req: req, max: max });
        i += consumed;
      }
      while (closes-- > 0 && stack.length > 1) stack.pop();
    }
    return root;
  }

  function parse(text, sourceName) {
    const sections = splitSections(text);
    const elements = {};
    if (sections.ELMS) Object.assign(elements, parseElms(sections.ELMS));
    if (sections.ELETEXT) assignNames(sections.ELETEXT, elements, 'elm');
    if (sections.CODES) parseCodes(sections.CODES, elements);
    if (sections.CODETEXT) parseCodeText(sections.CODETEXT, elements);

    const segments = parseSegs(sections.SEGS || [], elements);
    if (sections.SEGTEXT) assignNames(sections.SEGTEXT, segments, 'seg');

    const sets = parseSetsSection(sections.SETS || []);
    const std = parseStd(sections.STD || []);

    // Attach richer element defs into segment element refs (post name assignment)
    Object.keys(segments).forEach(function (sid) {
      segments[sid].elements.forEach(function (e) { e.def = elements[e.num] || e.def; });
    });

    return {
      source: sourceName || std.name || 'SEF profile',
      version: sections._version || '',
      std: std,
      elements: elements,
      segments: segments,
      sets: sets,
      counts: {
        elements: Object.keys(elements).length,
        segments: Object.keys(segments).length,
        sets: Object.keys(sets).length
      }
    };
  }

  global.SEF = {
    parse: parse,
    REQ: REQ,
    TYPE_NAMES: TYPE_NAMES
  };
})(window);
