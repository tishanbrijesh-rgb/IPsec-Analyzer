# Frontend redesign plan

**Status:** core visual and interaction pass implemented 29 September 2026.
The capture workspace, provenance rail, evidence trace, inference separation,
legal copy and 320 px layout were checked in the local browser. Further visual
refinement and a full keyboard audit remain useful before public deployment.
The follow-up pass added a rule-status filter, visible match count, skip link,
empty-file feedback and keyboard focus on loaded results or errors. The filter
was checked in the local browser against a saved analysis.
The selected IKE proposal now links to its response-packet evidence record
when that record exists.
The glass/cyber refinement adds translucent capture and provenance surfaces,
a restrained technical grid, signal mark, stronger table scan lines and
visible target highlighting. Evidence tables remain opaque. The populated
page was checked at desktop and 320 px with no page-level horizontal overflow.

## Direction: a field instrument for IPsec evidence

The interface serves an analyst who uploads a capture, checks what was
observed, follows packet references, and exports a report. Use a calm
technical style with three influences:

- **Glass:** restrained translucent navigation and capture context surfaces.
  Keep tables, findings and legal text on opaque surfaces for readability.
- **Cyber:** precise rules, grid alignment, compact monospace identifiers,
  small status lights and clear technical labels. No decorative neon glow.
- **Natural:** deep pine and mineral ink, stone and fog neutrals, moss green
  for actions, amber for uncertainty and muted rust for failed evaluations.

A fine topographic or circuit-like line pattern may appear at very low
contrast in the background. It must never compete with evidence text. The
distinctive detail is a slim capture provenance rail that connects the file
hash, packet counts, parser scope and analysis state.

## What to change in the current page

| Current issue | Redesign decision |
| --- | --- |
| Generic page heading and card stack | Start with a compact capture workspace and a strong document-style analysis header. |
| Five equal summary blocks | Use a narrow evidence summary row; show actual counts only after analysis. Put unavailable score in a clearly labeled scope note. |
| Repeated rounded panels | Use one principal analysis surface, section dividers and purposeful inset surfaces. Keep corners near square. |
| Dense data and limitations compete for attention | Give rule evaluations first position, then IKE exchanges and flows; keep limits beside evidence. |
| Session and flow tables stop at summary values | Add expandable rows linked to packet indices and evidence IDs already returned by the API. |
| Legal pages use the same generic card styling | Give Privacy Policy and Terms a calm document layout with the same type and color system. Update stale Terms copy about IKEv1 support. |

## Page structure

```text
Product bar: identity | capture review | local status
Capture workspace: file selector | Analyze | format and size guidance
Result header: capture identity | hash | analysis state | report action
Evidence summary: observed packets | IKE sessions | ESP/AH flows | rule outcomes
Main analysis: rule evaluations with status, rationale and packet links
               IKE exchange table with offer/selection/unknown detail
               directional flow table with captured-byte units and ambiguity
Context rail: coverage | unknown settings | parsing limits | source details
Footer: Privacy Policy | Terms and Conditions
```

The empty state shows the upload control and supported formats. It does not
show placeholder metrics. Loading, malformed capture, partial evidence and
API failure each receive a clear state near the control that triggered them.

## Visual rules

- Build on the current plain HTML, CSS and JavaScript files. Use CSS variables
  for color, type, spacing and surface opacity. No design library is needed.
- Use rectangular controls with a small corner radius. No pills, purple
  gradients, emoji icons, decorative blobs, vague hero copy or scroll effects.
- Use a solid color fallback beneath any translucent surface. Limit
  `backdrop-filter` to navigation or capture context; it is enhancement only.
- Use familiar labels, a single compact wordmark, and restrained line icons
  only where they improve recognition. Never use icons as the only label.
- Keep security states legible by text and shape as well as color. Unknown
  values must remain explicit; no fake scores, metrics or classifications.
- Set clear column widths, wrapping and horizontal overflow for tables.
  The 320 px layout must not hide upload, status or legal navigation.
- Avoid animation except a short state transition that explains an actual
  change. Respect reduced motion and reduced transparency preferences.

## Work sequence

1. **Design tokens and shell:** define the palette, type scale, spacing,
   borders, opaque fallback and restrained glass surfaces in `styles.css`.
2. **Workspace hierarchy:** revise `index.html` around capture upload,
   evidence summary, assessment, exchanges, flows and context rail.
3. **Evidence interaction:** update `app.js` to render existing API evidence,
   expandable packet references, unknown reasons, and distinct empty/error
   states. Continue inserting capture-derived text with `textContent`.
4. **Legal pages:** apply the same system to `privacy.html` and `terms.html`,
   and correct copy that no longer matches Phase 1–2 behavior.
5. **Verification:** inspect desktop and narrow layouts, keyboard use, focus,
   file upload, public Wireshark capture, malformed capture, legal navigation,
   report download and no-JavaScript fallback text.

## Acceptance checks

- The first viewport clearly shows what file to analyze and what the tool
  can establish from it.
- Every displayed count, status and claim comes from the current API result.
  A selected proposal links to the response packet; unknown settings explain
  why they are unknown.
- Text contrast meets WCAG 2.2 AA: at least 4.5:1 for normal text and 3:1
  for large text. Interactive boundaries and focus states remain discernible.
- Glass effects can be disabled without losing information or layout.
- At desktop, tablet and 320 px widths, controls remain operable and text
  does not overlap or truncate essential evidence.
- The existing API, CSP, local-only behavior, Privacy Policy and Terms links
  continue to work. The full test suite passes and browser checks cover the
  upload and report path.

Accessibility references: [WCAG 2.2 contrast](https://www.w3.org/TR/wcag/)
and [CSS reduced transparency](https://www.w3.org/TR/mediaqueries-5/).
