# Signal EDI — HIPAA X12 Diagnostic Console

A visual, **offline** diagnostic tool for HIPAA / ASC X12 EDI files. Open an
interchange and Signal EDI parses the ISA/GS/ST envelope, visualizes the loop
and segment structure, decodes every data element, and validates the file
against a **SEF** (Standard Exchange Format) profile — with bundled reference
profiles for each HIPAA transaction plus the ability to load your own `.sef`
guideline files.

> **PHI stays local.** Everything runs in your browser. No file contents are
> uploaded, fetched, or sent anywhere. There is no server component.

## Running it

Just open **`index.html`** in any modern browser (double-click it, or drag it
onto a browser window). No install, no build, no network.

Then:

1. Click **Open EDI file** (or drag a file onto the window), or click
   **Sample** to load a bundled 837P.
2. Signal EDI auto-detects the delimiters and matches a bundled SEF profile by
   the transaction's implementation reference (e.g. `005010X222A1` → 837P).
3. Explore the tabs; use the **Profile** dropdown or **Load SEF…** to validate
   against a different / your own profile.

## What you get

- **Structure tree** — ISA ▸ GS ▸ ST ▸ loops ▸ segments, with inline severity
  dots. Click any node to inspect it.
- **Overview dashboard** — interchange/group/transaction/segment counts, error
  & warning tallies, transaction-set and segment-frequency charts, a severity
  donut, envelope details (sender/receiver, control numbers, **Prod/Test**
  usage), and the active profile summary.
- **Segment Inspector** — every element with its reference (e.g. `NM103`), name,
  requirement (M/O/C), data type & length, value (composites split out), and the
  **decoded meaning** of coded values.
- **Validation** — filterable list of findings:
  - Envelope integrity: ISA↔IEA, GS↔GE, ST↔SE control-number matches and
    segment/transaction/group counts (`SE01`, `GE01`, `IEA01`).
  - Element checks: mandatory-but-empty, min/max length, data-type conformance
    (`AN/ID/DT/TM/R/N`), and code-value membership against the SEF code lists.
  - Structure: mandatory segments missing from the transaction set.
- **Raw view** — line-numbered segments with delimiters highlighted and rows
  tinted by severity.

## Supported transactions (bundled SEF profiles)

`sef/` contains a reference profile for each of these 5010 transaction sets:

| File | Transaction | Impl. reference |
|------|-------------|-----------------|
| `837P.sef` | Professional Claim | 005010X222A1 |
| `837I.sef` | Institutional Claim | 005010X223A2 |
| `837D.sef` | Dental Claim | 005010X224A2 |
| `835.sef`  | Claim Payment / Remittance | 005010X221A1 |
| `834.sef`  | Benefit Enrollment & Maintenance | 005010X220A1 |
| `270.sef`  | Eligibility Inquiry | 005010X279A1 |
| `271.sef`  | Eligibility Response | 005010X279A1 |
| `276.sef`  | Claim Status Request | 005010X212 |
| `277.sef`  | Claim Status Response | 005010X212 |
| `278.sef`  | Health Care Services Review | 005010X217 |
| `820.sef`  | Premium Payment | 005010X218 |
| `999.sef`  | Implementation Acknowledgment | 005010X231A1 |

> These bundled profiles are **simplified reference guidelines** — they cover the
> envelope and the characteristic segments, elements, and code lists of each
> transaction, which is enough for structural and element-level diagnostics.
> They are **not** exhaustive TR3 implementation guides. For complete,
> certified validation, load the full commercial/authoritative `.sef` for the
> guide (see below).

## Using your own SEF files

Click **Load SEF…** (or drop a `.sef` onto the window) to use any SEF guideline
file. It is added to the **Profile** dropdown for the session.

The parser reads the standard, widely-interoperable SEF dictionary sections:

- `.ELMS` — data element attributes (`elemNum=type,minLen,maxLen`)
- `.CODES` — permitted code values (`elemNum=code,code,…`; a leading count/flag
  is tolerated)
- `.SEGS` — segment composition (`SEGID=elemNum,req,max,…`; `[nn]` masks ignored)
- `.SETS` — transaction-set structure
- Names from `.SEGTEXT` / `.ELETEXT` / `.STD`, code descriptions from `.CODETEXT`

`.SETS` is read in two ways: the clean `seg`/`loop`/`end` encoding used by the
bundled profiles (full loop tree), or a third-party comma stream, which is
parsed best-effort into an ordered expected-segment list with bracketed loops.

## Regenerating the bundled profiles

The bundled `.sef` files and the embedded copy (`js/default-sefs.js`) are
generated from a single source so they never drift:

```
node build-defaults.mjs
```

Edit `build-defaults.mjs` to extend the element/segment dictionaries, add code
lists, or add transaction sets, then re-run it.

## Project layout

```
index.html            App shell
css/styles.css        Theme (light/dark aware)
js/x12.js             X12 parser (delimiter auto-detect, ISA/GS/ST hierarchy)
js/sef.js             SEF parser → validation model
js/validate.js        Validation engine
js/ui.js              Rendering: tree, dashboard, inspector, diagnostics, raw
js/app.js             Controller: file loading, profiles, tabs, drag & drop
js/default-sefs.js    Embedded bundled profiles (generated)
js/sample.js          Embedded sample 837P (generated)
sef/*.sef             Bundled reference SEF profiles (generated, editable)
samples/*.edi         Sample interchange
build-defaults.mjs    Generator for the bundled profiles + sample embed
```
