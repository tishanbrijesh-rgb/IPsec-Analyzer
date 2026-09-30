# Frontend improvement plan

**Created:** 29 September 2026  
**Status:** In progress. Work packages 1, 2, 3 and 5 have implementation
passes checked in the local browser on 29 September 2026. Flow presentation
and the full accessibility review remain open.

**30 September update:** the dashboard now uses separate URL pages for
assessment, threat matrix, IKE sessions, flows, inference, evidence, packets
and reports. The landing page handles capture and optional sanitized
configuration selection. Analysis pages read the same result ID and link to
evidence or packet anchors across pages. A full keyboard and 320 px review of
this navigation remains open.

## Goal

Make the local IPsec dashboard easier to use for repeated capture review. An
analyst should be able to upload a capture, identify the most important
finding or evidence gap, follow it to packet references, and export the right
report without mistaking model estimates for observed facts.

## Starting point

The current frontend is plain HTML, CSS and JavaScript in `dashboard/web/`.
It already has a capture form, analysis status, provenance rail, count summary,
rule-status filter, IKE and flow tables, separate inference table, evidence
links, report downloads, legal pages and a restrained glass/cyber style. A
populated page was checked at 320 px without page-level horizontal overflow.

The next work should improve investigation depth and usability. It should not
repeat the earlier cosmetic redesign.

| Current gap | Why it matters | Planned change |
| --- | --- | --- |
| Evidence values can appear as raw JSON in a narrow table | Analysts must decode transform IDs and long objects themselves | Present known fields as labeled facts with an expandable raw representation |
| Packet references are numbers only | Following a finding stops at a reference, without a compact packet view | Add a packet-reference panel using safe metadata returned by the API; show an unavailable state if the API cannot supply it |
| Reports are six similar links in the side rail | The distinction between full and shared copies is easy to miss | Group full exports and redacted exports with clear format labels and a short sharing explanation |
| Rule status filter is the only investigation control | Larger captures will be difficult to scan | Add a small search for rule ID, SPI or endpoint only when real result sizes justify it; keep filtering client-side |
| Long tables rely on horizontal scrolling | Columns lose context on small screens | Keep accessible table markup and provide a compact row layout at narrow widths where practical |
| Keyboard, focus and contrast checks are incomplete | Users may lose their place when opening details or following evidence links | Run a full keyboard path and measured contrast audit, then fix observed failures |
| Loading and expired states share a general status area | Recovery action is not always obvious | Give each state a concise next action near the upload control |

## Design direction

**Purpose:** an investigation instrument, not a marketing page.  
**Audience:** analysts reviewing IKE, ESP and AH captures.  
**Tone:** precise, calm, technical.  
**Memorable detail:** a compact provenance path from finding to rule, evidence
state and packet reference.  
**Visual system:** dark mineral canvas, mint signal, amber for unknown,
rust for failures. Use glass only for shell and capture context. Keep findings,
tables, disclosures and reports on opaque surfaces. Use a faint grid and small
monospace identifiers as technical cues; avoid glow, decorative charts and
unsubstantiated metrics.

## Work packages

### 1. Clarify the first screen

- Keep file selection and Analyze visible without scrolling at desktop and
  phone widths.
- Explain the 16 MiB limit and supported formats beside the control.
- Show selected filename, size and a clear way to choose another file.
- Distinguish empty, analyzing, complete, malformed, expired and connection
  error states. Each error should state a recovery action.
- Add a no-JavaScript message and ensure it does not falsely promise analysis.

**Done when:** a user can start or retry an analysis without consulting a
separate guide; the page never shows stale results for a failed new upload.

**Implementation note (29 September 2026):** the file control now shows name
and size, selection clears a previous result and URL, errors expose a
reselection action, loading is distinct, and a no-JavaScript message is
present. Browser checks covered actual file selection and successful analysis
plus an expired saved-analysis link. Empty and malformed browser uploads still
need direct browser verification.

### 2. Make the assessment scannable

- Put failed and unknown evaluations first in the default result view, while
  retaining access to all rule evaluations and preserving server order as
  metadata if needed.
- Show status, affected subject, packet references, rationale and remediation
  in a predictable order.
- Keep the current status filter; add a count for each status if it improves
  selection without crowding the toolbar.
- Express rule coverage as evaluated versus applicable counts alongside the
  percentage. Keep the overall security score unavailable while the backend
  withholds it.

**Done when:** an analyst can identify a failure or uncertainty in the first
result viewport and trace it to the relevant rule and evidence.

**Implementation note (29 September 2026):** evaluations now sort failed,
unknown, passed, then not applicable while preserving server order within
each status. The scope rail shows evaluated and applicable counts. A partial
capture was checked in the browser; unknown evaluations appeared first.

### 3. Build an evidence trail

- Replace raw object blobs with labeled observed fields, evidence state,
  reason and source packet indices. Keep a disclosure for exact JSON when
  needed for debugging.
- Add a compact packet-reference view only after confirming the backend's
  metadata contract. Never send raw frame bytes or payloads to the browser.
- Make finding, selected IKE proposal and evidence links land on a visible,
  keyboard-focusable target with a clear highlight.
- Show `UNKNOWN` with its reason; do not render missing values as zero, false
  or a passing result.

**Done when:** a finding can be followed through rule ID, evidence state and
packet index using only keyboard or pointer input.

**Implementation note (29 September 2026):** selected proposal evidence is
summarized with labeled transform IDs and an exact-data disclosure. The
analysis contract supplies up to 5,000 metadata-only summaries for packets
cited by rules or selected IKE responses. Rule and evidence packet links land
on those rows. Browser checks followed packet 2 in the independent IKEv2
fixture and confirmed the target row receives focus. Additional keyboard
audit remains open.

### 4. Improve flows and inference

- Show flow direction, encapsulation, SPI, packet count and captured bytes
  using labels and units taken from the current API contract.
- Keep model estimates in their own section with `INFERRED`, model version,
  confidence qualifier and abstention reason where available.
- Use a short explanation for a capture with no ESP/AH flows or no model
  output. Do not imply traffic was decrypted or an application was identified.

**Done when:** observed flow facts and synthetic pilot estimates cannot be
confused in a quick scan or in screen-reader order.

**Implementation note (29 September 2026):** the flow table now names
direction, encapsulation and captured-frame byte units. The separate model
table shows the model version and reason for every abstention. A populated
modern-tunnel capture rendered both directional ESP flows and two explicit
insufficient-flow abstentions in the browser.

### 5. Organize exports and sharing

- Group full text, HTML, PDF and JSON reports together. Group redacted shared
  copies separately and explain what is removed.
- Give links descriptive accessible names and indicate file format.
- Verify report content against the displayed analysis; retain the current
  API's redaction and download behavior.

**Done when:** the user can choose a full or redacted report without guessing
from link order, and the downloaded report corresponds to the visible capture.

**Implementation note (29 September 2026):** full and shared copies are
separate groups with explicit descriptions and accessible download names.
An API download check confirmed that full and shared JSON retained the DES
finding, while the shared copy omitted the capture hash.

### 6. Accessibility and responsive pass

- Audit the complete keyboard path: skip link, file chooser, submit, status,
  filter, disclosures, evidence links, exports and legal links.
- Measure text and control contrast against WCAG 2.2 AA thresholds. Do not
  rely on color alone for status.
- Check focus after upload, failure, evidence navigation and saved-analysis
  load. Keep focus indicators visible on headings and target rows.
- Check 320, 375, 768 and desktop widths with empty, short and long results.
  Tables may scroll internally, but the page should not overflow horizontally.
- Verify reduced transparency and reduced motion preferences, zoom to 200%,
  and no-JavaScript fallback.

**Done when:** all primary tasks are keyboard operable, text remains readable,
and no essential controls or evidence are clipped at tested sizes.

## Implementation order

1. Record baseline screenshots and a short issue list from actual empty,
   valid, partial and malformed captures.
2. Fix status and upload recovery states in `index.html` and `app.js`.
3. Improve assessment and evidence rendering against the existing API data.
4. Define any additional packet metadata with the backend before adding its
   frontend view; update architecture and API tests if the contract changes.
5. Rework export grouping and flow/inference presentation.
6. Complete keyboard, contrast, responsive and legal-page review.
7. Update `UI_DIRECTION.md`, phase status and screenshots only after checks
   pass.

## Verification matrix

| Scenario | Expected result |
| --- | --- |
| Known IKEv2 capture with selected response | Selection links to observed evidence and its packet index |
| Weak selected transform | Failure is prominent; rationale, baseline and remediation remain visible |
| Request-only or partial capture | Selection and unsupported settings stay unknown with reasons |
| ESP/AH flow without IKE | Flow facts remain visible; IKE rules do not appear to pass |
| Model abstention or unavailable artifact | No definitive application claim; reason is visible |
| Empty, oversized or malformed file | Clear error and recovery path; stale results are hidden |
| Expired saved analysis | Clear re-upload action without broken report links |
| Long identifiers and endpoint strings | No clipped evidence or page-level overflow at tested widths |
| Full versus redacted report | Format and sharing scope are clear; exported facts match the API |

Run `node --check dashboard/web/app.js` and `python -m pytest -q` after code
changes. Browser checks must use a populated analysis and exercise the real
upload and report paths. Add focused frontend tests for behavior that could
regress, especially filtering, evidence navigation and error recovery.

## Boundaries

- Keep the existing plain frontend unless its complexity creates a concrete
  maintenance problem. The self-hosted Motion DOM bundle supplies small state
  transitions; no framework migration is planned.
- Use `textContent` or DOM nodes for capture-derived values; do not inject
  them as HTML.
- Preserve the loopback-only local API model. Authentication, durable jobs and
  multi-user access are separate backend/deployment work.
- Do not invent scores, model accuracy, protocol observations or real-time
  claims in the UI.

The earlier [frontend redesign plan](FRONTEND_REDESIGN_PLAN.md) records the
completed visual pass. This plan starts from the current implementation.
