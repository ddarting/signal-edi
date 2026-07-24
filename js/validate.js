/* Signal EDI — validation engine
 * Cross-references a parsed X12 model against a SEF profile and produces
 * diagnostics at the interchange, transaction, segment and element level.
 * Annotations are also written back onto the model for inline rendering.
 */
(function (global) {
  'use strict';

  const SEV = { ERROR: 'error', WARNING: 'warning', INFO: 'info' };

  // Validation options (toggled via Settings). Module-scoped for the duration
  // of a validate() call so the per-segment helpers can read them.
  const DEFAULT_OPT = { showInfo: true, flagUnknown: true, flagMaxLen: true, checkStructure: true };
  let OPT = DEFAULT_OPT;

  function loc(seg) { return seg ? (seg.id + ' #' + (seg.index + 1)) : ''; }

  function typeConforms(type, value) {
    if (value === '') return { ok: true };
    const t = (type || 'AN').toUpperCase();
    if (t === 'AN' || t === 'ID') return { ok: true };
    if (t === 'R') return { ok: /^[+-]?\d*\.?\d+$/.test(value), why: 'not a valid decimal (R)' };
    if (t === 'DT') {
      const okLen = value.length === 8 || value.length === 6;
      return { ok: okLen && /^\d+$/.test(value), why: 'not a valid date (expect CCYYMMDD/YYMMDD digits)' };
    }
    if (t === 'TM') return { ok: /^\d{4,8}$/.test(value), why: 'not a valid time (expect HHMM[SS[dd]])' };
    if (t === 'B') return { ok: true };
    if (/^N\d?$/.test(t)) return { ok: /^[+-]?\d+$/.test(value), why: 'not a valid integer/number (' + t + ')' };
    return { ok: true };
  }

  function pushDiag(list, seg, sev, code, message, elementPos, path) {
    const d = { severity: sev, code: code, message: message, segIndex: seg ? seg.index : -1, segId: seg ? seg.id : '', elementPos: elementPos || null, path: path || '' };
    list.push(d);
    if (seg) {
      seg.diagnostics = seg.diagnostics || [];
      seg.diagnostics.push(d);
      if (elementPos && seg.elements[elementPos - 1]) {
        const e = seg.elements[elementPos - 1];
        e.diag = e.diag || [];
        e.diag.push(d);
      }
    }
    return d;
  }

  function validateSegmentElements(seg, sef, diags, path) {
    const def = sef && sef.segments[seg.id];
    if (!def) {
      if (sef && sef.counts.segments > 0 && OPT.flagUnknown) {
        pushDiag(diags, seg, SEV.WARNING, 'SEG_UNKNOWN', 'Segment ' + seg.id + ' is not defined in the active SEF profile.', null, path);
      }
      return;
    }
    seg.def = def;
    def.elements.forEach(function (edef, i) {
      const pos = i + 1;
      const elem = seg.elements[pos - 1];
      const raw = elem ? elem.value : '';
      const value = raw.trim();
      if (elem) elem.def = edef.def;
      if (elem) elem.name = edef.def && edef.def.name;

      if (edef.req === 'M' && value === '') {
        pushDiag(diags, seg, SEV.ERROR, 'ELE_REQUIRED', 'Element ' + edef.ref + (edef.def && edef.def.name ? ' (' + edef.def.name + ')' : '') + ' is mandatory but empty.', pos, path);
        return;
      }
      if (value === '') return;

      const d = edef.def;
      if (d) {
        // Length is measured against the raw value so space-padded fixed-width
        // fields (e.g. the 15-char ISA sender/receiver ids) are not miscounted.
        if (d.max && raw.length > d.max && OPT.flagMaxLen) {
          pushDiag(diags, seg, SEV.WARNING, 'ELE_MAXLEN', 'Element ' + edef.ref + ' length ' + raw.length + ' exceeds max ' + d.max + '.', pos, path);
        }
        if (d.min && raw.length < d.min) {
          pushDiag(diags, seg, SEV.ERROR, 'ELE_MINLEN', 'Element ' + edef.ref + ' length ' + raw.length + ' is below min ' + d.min + '.', pos, path);
        }
        const tc = typeConforms(d.type, value);
        if (!tc.ok) {
          pushDiag(diags, seg, SEV.ERROR, 'ELE_TYPE', 'Element ' + edef.ref + ' value "' + value + '" ' + tc.why + '.', pos, path);
        }
        const codeKeys = Object.keys(d.codes || {});
        if (codeKeys.length > 0 && !(value in d.codes)) {
          // Only the primary (repeat[0]) is checked when repetition present.
          pushDiag(diags, seg, SEV.ERROR, 'ELE_CODE', 'Element ' + edef.ref + ' value "' + value + '" is not an allowed code for this element.', pos, path);
        }
      }
    });
    // Extra elements beyond definition
    if (seg.elements.length > def.elements.length && OPT.flagUnknown) {
      pushDiag(diags, seg, SEV.WARNING, 'SEG_EXTRA', 'Segment ' + seg.id + ' has ' + seg.elements.length + ' elements; profile defines ' + def.elements.length + '.', null, path);
    }
  }

  function flattenExpected(structure, out, loopPath) {
    (structure || []).forEach(function (node) {
      if (node.type === 'segment') {
        out.push({ segId: node.segId, req: node.req, max: node.max, loop: loopPath });
      } else if (node.type === 'loop') {
        flattenExpected(node.children, out, (loopPath ? loopPath + ' > ' : '') + (node.loopId || 'LOOP'));
      }
    });
  }

  function validateTransaction(txn, ich, grp, sef, diags) {
    const path = txn.name + ' [ST ' + txn.controlNumber + ']';

    // ST/SE integrity
    if (txn.trailer) {
      const seCount = parseInt(txn.trailer.elements[0] && txn.trailer.elements[0].value, 10);
      if (!isNaN(seCount) && seCount !== txn.segments.length) {
        pushDiag(diags, txn.trailer, SEV.ERROR, 'SE_COUNT', 'SE01 states ' + seCount + ' segments but transaction contains ' + txn.segments.length + '.', 1, path);
      }
      const seCtl = txn.trailer.elements[1] && txn.trailer.elements[1].value.trim();
      if (seCtl && seCtl !== txn.controlNumber) {
        pushDiag(diags, txn.trailer, SEV.ERROR, 'SE_CTRL', 'SE02 control number "' + seCtl + '" does not match ST02 "' + txn.controlNumber + '".', 2, path);
      }
    } else {
      pushDiag(diags, txn.st, SEV.ERROR, 'SE_MISSING', 'Transaction is missing its SE trailer.', null, path);
    }

    // Implementation reference vs SEF standard version (informational)
    if (OPT.showInfo && sef && sef.std && sef.std.version && txn.implRef && txn.implRef !== sef.std.version) {
      pushDiag(diags, txn.st, SEV.INFO, 'IMPL_REF', 'ST03 implementation reference "' + txn.implRef + '" differs from profile version "' + sef.std.version + '".', 3, path);
    }

    // Per-segment element validation
    txn.segments.forEach(function (seg) {
      if (seg.id === 'ST' || seg.id === 'SE') { validateSegmentElements(seg, sef, diags, path); return; }
      validateSegmentElements(seg, sef, diags, path);
    });

    // Structure: mandatory expected segments present
    const setDef = sef && sef.sets && sef.sets[txn.setId];
    if (OPT.checkStructure && setDef && setDef.structure && setDef.structure.length) {
      const expected = [];
      flattenExpected(setDef.structure, expected, '');
      const present = {};
      txn.segments.forEach(function (s) { present[s.id] = (present[s.id] || 0) + 1; });
      const reported = {};
      expected.forEach(function (ex) {
        if (ex.req === 'M' && !present[ex.segId] && !reported[ex.segId]) {
          reported[ex.segId] = true;
          pushDiag(diags, txn.st, SEV.ERROR, 'STRUCT_MISSING', 'Mandatory segment ' + ex.segId + (ex.loop ? ' (loop ' + ex.loop + ')' : '') + ' is not present in this transaction.', null, path);
        }
      });
    }
  }

  function validateGroup(grp, ich, sef, diags) {
    if (grp.trailer) {
      const geCount = parseInt(grp.trailer.elements[0] && grp.trailer.elements[0].value, 10);
      if (!isNaN(geCount) && geCount !== grp.transactions.length) {
        pushDiag(diags, grp.trailer, SEV.ERROR, 'GE_COUNT', 'GE01 states ' + geCount + ' transaction sets but group contains ' + grp.transactions.length + '.', 1, 'GS ' + grp.controlNumber);
      }
      const geCtl = grp.trailer.elements[1] && grp.trailer.elements[1].value.trim();
      if (geCtl && geCtl !== grp.controlNumber) {
        pushDiag(diags, grp.trailer, SEV.ERROR, 'GE_CTRL', 'GE02 control number "' + geCtl + '" does not match GS06 "' + grp.controlNumber + '".', 2, 'GS ' + grp.controlNumber);
      }
    } else {
      pushDiag(diags, grp.gs, SEV.ERROR, 'GE_MISSING', 'Functional group is missing its GE trailer.', null, 'GS ' + grp.controlNumber);
    }
    grp.transactions.forEach(function (t) { validateTransaction(t, ich, grp, sef, diags); });
  }

  function validateInterchange(ich, sef, diags) {
    if (ich.trailer) {
      const ieaCount = parseInt(ich.trailer.elements[0] && ich.trailer.elements[0].value, 10);
      if (!isNaN(ieaCount) && ieaCount !== ich.groups.length) {
        pushDiag(diags, ich.trailer, SEV.ERROR, 'IEA_COUNT', 'IEA01 states ' + ieaCount + ' functional groups but interchange contains ' + ich.groups.length + '.', 1, 'ISA ' + ich.controlNumber);
      }
      const ieaCtl = ich.trailer.elements[1] && ich.trailer.elements[1].value.trim();
      if (ieaCtl && ieaCtl !== ich.controlNumber) {
        pushDiag(diags, ich.trailer, SEV.ERROR, 'IEA_CTRL', 'IEA02 control number "' + ieaCtl + '" does not match ISA13 "' + ich.controlNumber + '".', 2, 'ISA ' + ich.controlNumber);
      }
    } else {
      pushDiag(diags, ich.isa, SEV.ERROR, 'IEA_MISSING', 'Interchange is missing its IEA trailer.', null, 'ISA ' + ich.controlNumber);
    }
    // Validate envelope segments' elements too
    [ich.isa, ich.trailer].forEach(function (s) { if (s) validateSegmentElements(s, sef, diags, 'ISA ' + ich.controlNumber); });
    ich.groups.forEach(function (g) {
      [g.gs, g.trailer].forEach(function (s) { if (s) validateSegmentElements(s, sef, diags, 'GS ' + g.controlNumber); });
      validateGroup(g, ich, sef, diags);
    });
  }

  function validate(parsed, sef, options) {
    OPT = Object.assign({}, DEFAULT_OPT, options || {});
    const diags = [];
    // reset annotations
    parsed.segments.forEach(function (s) { s.diagnostics = null; s.def = null; s.elements.forEach(function (e) { e.diag = null; }); });
    parsed.interchanges.forEach(function (ich) { validateInterchange(ich, sef, diags); });

    const summary = { error: 0, warning: 0, info: 0 };
    diags.forEach(function (d) { summary[d.severity]++; });
    return { diagnostics: diags, summary: summary };
  }

  global.Validator = { validate: validate, SEV: SEV, typeConforms: typeConforms };
})(window);
