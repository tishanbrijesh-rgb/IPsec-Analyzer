# Phase 6 local analyst check

**Date:** 30 September 2026. **Scope:** the loopback, single-user prototype. This is not a networked deployment or durable job service.

The automated weak-scenario check uploads a two-packet synthetic IKEv2 capture with a matching sanitized configuration through the API. It checks the analysis resource against sessions, flows, findings and evidence endpoints; checks the full JSON report against the risk score, threat matrix, rule evaluations and inference scope; and checks text, HTML and PDF for the same score and threat details. Under `sih-risk-3`, the weak result has five findings/threat rows and a `42.86/100 MODERATE` risk score. The redacted JSON retains the score and threat rows while hiding the capture hash. The full suite includes missing, malformed, expired and oversized input cases.

The browser was checked against a fresh server running the current workspace code on port 8001. The separate Assessment, Threat matrix, Evidence, Packets, Inference and Reports pages loaded by direct link. Keyboard activation expanded a failed rule and followed its evidence and packet links to focused rows. The disclosure showed rule version, finding ID, evidence state, severity, impact and remediation. The threat page showed affected assets and mapping version. At a 320 px viewport the threat page had no document-level horizontal overflow; its wide table scrolled inside the panel. The Reports page exposed full text/HTML/PDF/JSON and redacted PDF/JSON links. An ESP sample showed its synthetic-profile scope and an explicit `unknown/other` abstention without a confidence claim.

The in-app browser's file chooser did not open during this check, so the generated capture was submitted through the local API before browser page verification. Earlier browser upload checks are recorded in [implementation status](IMPLEMENTATION_STATUS.md). This check does not independently reverify the chooser interaction. The port-8000 process was serving older code during the initial inspection; port 8001 was started from the current workspace and used for the findings above.

The Phase 6 exit checks pass for the **local in-memory analyst slice**. Results expire on restart or eviction after 16 analyses. Durable jobs, persistent storage and authentication/authorization need a deployment requirement before this service can be offered beyond loopback. Packet views expose safe reference metadata, not raw frame bytes or payloads.

An additional accepted synthetic-flow API check confirms that per-flow model
scores match the JSON report, abstained flows have null confidence, and the
text report labels accepted scores as pilot values with unvalidated probability
meaning. The dashboard uses the same language. JavaScript syntax was checked
with `node --check dashboard/web/app.js`.
