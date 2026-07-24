/* Signal EDI — X12 parser
 * Parses HIPAA/X12 interchanges into a structured model with byte/line offsets.
 * Delimiters are auto-detected from the fixed-length ISA segment.
 * Pure, dependency-free, runs entirely client-side (keeps PHI local).
 */
(function (global) {
  'use strict';

  // Map of ST01 transaction-set id -> friendly HIPAA name (5010 family).
  const SET_NAMES = {
    '270': 'Eligibility, Coverage or Benefit Inquiry (270)',
    '271': 'Eligibility, Coverage or Benefit Response (271)',
    '276': 'Health Care Claim Status Request (276)',
    '277': 'Health Care Claim Status Response (277)',
    '278': 'Health Care Services Review (278)',
    '820': 'Premium Payment / Payroll Deducted (820)',
    '834': 'Benefit Enrollment and Maintenance (834)',
    '835': 'Health Care Claim Payment/Advice (835)',
    '837': 'Health Care Claim (837)',
    '997': 'Functional Acknowledgment (997)',
    '999': 'Implementation Acknowledgment (999)',
    'TA1': 'Interchange Acknowledgment (TA1)'
  };

  // Locate the ISA and derive the delimiter set used by this interchange.
  function detectDelimiters(raw) {
    const isaIdx = raw.indexOf('ISA');
    if (isaIdx === -1) {
      throw new X12Error('No ISA segment found — this does not look like an X12 interchange.');
    }
    // ISA is a fixed 106-char segment. Offsets are counted from the "I" of ISA.
    const element = raw[isaIdx + 3];
    const component = raw[isaIdx + 104];
    const terminator = raw[isaIdx + 105];
    let repetition = raw[isaIdx + 82]; // ISA11 in 5010 is the repetition separator
    // Older guides used ISA11 as a data value ("U"); treat alphanumerics as "none".
    if (/[A-Za-z0-9 ]/.test(repetition)) repetition = null;
    if (!element || !terminator) {
      throw new X12Error('ISA segment is truncated; cannot determine delimiters.');
    }
    return { isaIdx, element, component, terminator, repetition };
  }

  function splitSegments(raw, delims) {
    // Segment terminators are frequently followed by CR/LF for readability — strip those.
    const term = delims.terminator;
    const segments = [];
    let start = delims.isaIdx;
    let offset = start;
    // Walk from the ISA onward so leading junk/BOM before ISA is ignored.
    let buf = '';
    let segStart = start;
    for (let i = start; i < raw.length; i++) {
      const ch = raw[i];
      if (ch === term) {
        if (buf.replace(/[\r\n]/g, '').trim() !== '') {
          segments.push({ text: buf, offset: segStart });
        }
        buf = '';
        segStart = i + 1;
      } else {
        if (buf === '' && (ch === '\r' || ch === '\n')) {
          segStart = i + 1; // skip line breaks between segments
          continue;
        }
        buf += ch;
      }
    }
    if (buf.replace(/[\r\n]/g, '').trim() !== '') {
      segments.push({ text: buf, offset: segStart });
    }
    return segments;
  }

  function parseSegment(rawSeg, delims, index) {
    const text = rawSeg.text.replace(/[\r\n]+/g, '');
    const parts = text.split(delims.element);
    const id = (parts[0] || '').trim().toUpperCase();
    const elements = parts.slice(1).map(function (val, i) {
      const hasComp = delims.component && val.indexOf(delims.component) !== -1;
      const components = hasComp ? val.split(delims.component) : null;
      const hasRep = delims.repetition && val.indexOf(delims.repetition) !== -1;
      const repeats = hasRep ? val.split(delims.repetition) : null;
      return {
        pos: i + 1,          // element position within the segment (1-based)
        ref: id + zeroPad(i + 1),
        value: val,
        components: components,
        repeats: repeats
      };
    });
    return {
      id: id,
      index: index,          // ordinal within the whole interchange
      elements: elements,
      offset: rawSeg.offset,
      raw: text
    };
  }

  function zeroPad(n) { return n < 10 ? '0' + n : '' + n; }

  function el(seg, n) {
    const e = seg.elements[n - 1];
    return e ? e.value : '';
  }

  // Build the ISA/GS/ST hierarchy from a flat segment list.
  function buildHierarchy(segments) {
    const interchanges = [];
    let ich = null, grp = null, txn = null;

    segments.forEach(function (seg) {
      switch (seg.id) {
        case 'ISA':
          ich = {
            type: 'interchange',
            isa: seg,
            senderId: el(seg, 6).trim(),
            senderQual: el(seg, 5).trim(),
            receiverId: el(seg, 8).trim(),
            receiverQual: el(seg, 7).trim(),
            date: el(seg, 9),
            time: el(seg, 10),
            controlNumber: el(seg, 13).trim(),
            usageIndicator: el(seg, 15).trim(), // P=production, T=test
            version: el(seg, 12).trim(),
            groups: [],
            trailer: null,
            segments: [seg]
          };
          interchanges.push(ich);
          grp = txn = null;
          break;
        case 'GS':
          grp = {
            type: 'group',
            gs: seg,
            functionalId: el(seg, 1).trim(),
            senderCode: el(seg, 2).trim(),
            receiverCode: el(seg, 3).trim(),
            date: el(seg, 4),
            time: el(seg, 5),
            controlNumber: el(seg, 6).trim(),
            version: el(seg, 8).trim(),
            transactions: [],
            trailer: null,
            segments: [seg]
          };
          if (ich) { ich.groups.push(grp); ich.segments.push(seg); }
          txn = null;
          break;
        case 'ST':
          txn = {
            type: 'transaction',
            st: seg,
            setId: el(seg, 1).trim(),
            controlNumber: el(seg, 2).trim(),
            implRef: el(seg, 3).trim(), // implementation convention reference (e.g. 005010X222A1)
            name: SET_NAMES[el(seg, 1).trim()] || ('Transaction Set ' + el(seg, 1).trim()),
            segments: [seg],
            trailer: null
          };
          if (grp) { grp.transactions.push(txn); grp.segments.push(seg); }
          if (ich) ich.segments.push(seg);
          break;
        case 'SE':
          if (txn) { txn.trailer = seg; txn.segments.push(seg); }
          if (grp) grp.segments.push(seg);
          if (ich) ich.segments.push(seg);
          txn = null;
          break;
        case 'GE':
          if (grp) { grp.trailer = seg; grp.segments.push(seg); }
          if (ich) ich.segments.push(seg);
          grp = null;
          break;
        case 'IEA':
          if (ich) { ich.trailer = seg; ich.segments.push(seg); }
          ich = null;
          break;
        default:
          if (txn) txn.segments.push(seg);
          else if (grp) grp.segments.push(seg);
          else if (ich) ich.segments.push(seg);
          break;
      }
    });
    return interchanges;
  }

  function parse(raw) {
    if (!raw || typeof raw !== 'string') {
      throw new X12Error('Empty input.');
    }
    const delims = detectDelimiters(raw);
    const rawSegs = splitSegments(raw, delims);
    const segments = rawSegs.map(function (s, i) { return parseSegment(s, delims, i); });
    const interchanges = buildHierarchy(segments);
    return {
      delimiters: delims,
      segments: segments,
      interchanges: interchanges,
      stats: computeStats(segments, interchanges)
    };
  }

  function computeStats(segments, interchanges) {
    const setCounts = {};
    let txnCount = 0, groupCount = 0;
    interchanges.forEach(function (ich) {
      groupCount += ich.groups.length;
      ich.groups.forEach(function (g) {
        g.transactions.forEach(function (t) {
          txnCount++;
          setCounts[t.setId] = (setCounts[t.setId] || 0) + 1;
        });
      });
    });
    const segCounts = {};
    segments.forEach(function (s) { segCounts[s.id] = (segCounts[s.id] || 0) + 1; });
    return {
      segmentTotal: segments.length,
      interchangeCount: interchanges.length,
      groupCount: groupCount,
      transactionCount: txnCount,
      setCounts: setCounts,
      segmentCounts: segCounts
    };
  }

  function X12Error(msg) { this.name = 'X12Error'; this.message = msg; }
  X12Error.prototype = Object.create(Error.prototype);

  global.X12 = {
    parse: parse,
    SET_NAMES: SET_NAMES,
    detectDelimiters: detectDelimiters,
    Error: X12Error
  };
})(window);
