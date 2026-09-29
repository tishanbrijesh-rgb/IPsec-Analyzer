# Analyst interface direction

The dashboard is an operational tool for repeated capture review. Its first
screen starts with the upload workflow, then shows real values from the
analyzed capture, rule evidence, sessions and flows. The visual style is dark,
compact and technical: a mineral canvas, restrained mint for actions, amber
for unknown states, and red for failed evaluations. Glass is limited to the
shell and capture context; evidence tables and report controls stay opaque.

## Interface rules

- Show only values returned by a real analysis. Unknown values are labeled.
- Use rectangular controls and compact tables. Avoid pill-shaped buttons.
- Do not use purple gradients, decorative blobs, emoji icons, vague hero copy,
  em dashes or scroll animation.
- Use a text monogram for the product mark and familiar text labels for actions.
- Keep evidence and limitations visible beside findings.
- Use DOM text insertion for capture-derived content. Do not render it as HTML.
- Preserve keyboard focus, contrast, responsive tables and readable legal pages.

The local prototype uses plain HTML, CSS and JavaScript. A small self-hosted
Motion DOM bundle animates entry and status changes without replacing the
accessible HTML. Motion is suppressed by the reduced-motion preference and
on low-core devices. The frontend does not require React.

The visual pass adds `motion` 12.43.0 for its vanilla DOM animation API and
`esbuild` 0.25.12 as a build-only bundler. CSS alone cannot coordinate the
results entrance with the existing JavaScript render event without more
bespoke animation code. The 8.6 KiB local bundle makes no CDN request and
avoids adding a UI framework. Both packages are pinned by `package-lock.json`;
review their licenses and advisories when updating them.

The current visual and interaction pass follows
[FRONTEND_REDESIGN_PLAN.md](FRONTEND_REDESIGN_PLAN.md). It uses a capture
provenance rail, compact assessment tables and separate inference labels while
keeping dense analysis content opaque and readable.
Next work is specified in [FRONTEND_IMPROVEMENT_PLAN.md](FRONTEND_IMPROVEMENT_PLAN.md).
