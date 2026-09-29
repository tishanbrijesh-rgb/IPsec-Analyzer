# Implementation and Improvement Phases

**Status:** working plan based on the current repository (28 September 2026).  
**Architecture:** [ARCHITECTURE.md](../../ARCHITECTURE.md) defines the system contracts and boundaries.  
**Rule:** a phase is complete only when its exit checks pass and its limitations are documented.

## Current baseline

The current implementation state and verified test count are tracked in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). This document defines phase gates and is not a claim that later phases are complete.

## Dependency path

```text
Phase 0: harden foundation
   ↓
Phase 1: parse IKE and ESP/AH records
   ↓
Phase 2: correlate sessions and preserve evidence
   ↓
Phase 3: security rules, coverage and reports
   ↓
Phase 4: reproducible testbed and labeled dataset
   ↓
Phase 5: AI classification and confidence
   ↓
Phase 6: API, dashboard and report export
   ↓
Phase 7: live input, hardening and final demonstration
```

The first demonstrable vertical slice is Phases 0–3 plus a simple report. The full SIH deliverable set also needs Phases 4–7. Work on the dashboard can start once Phase 3 defines stable result contracts; it need not wait for ML training.

## Phase 0 — Harden the existing foundation

**Goal:** make offline input safe and predictable before parsers consume it.

**Build**

- Add capture-level diagnostics for unsupported PCAPNG packet block types, link types and timestamp resolutions.
- Validate PCAPNG section boundaries, block lengths and packet length versus interface snap length.
- Decide and document supported link types and IPv6 extension behavior; retain an explicit unsupported state.
- Add streaming or bounded-memory reading if realistic demo captures exceed the current 128 MiB whole-file limit.
- Make packet diagnostics visible in CLI summaries without losing the JSON contract.

**Exit checks**

- Valid PCAP/PCAPNG fixtures produce equivalent normalized packet facts.
- Truncated, malformed and unsupported captures return stable diagnostics or a clear capture error.
- The documented maximum capture size is enforced and measured memory use stays within the selected demo target.

**Ownership:** `ingestion/`, `models/`, `tests/`.

## Phase 1 — Protocol dissection

**Goal:** extract directly visible IKE, ESP and AH facts.

**Build**

- IKEv1/IKEv2 header parser with bounded payload-chain walking.
- Visible SA, proposal and transform decoding, including algorithm IDs, key-length attributes and DH groups where present.
- Distinct records for offers and selected responses; parse status for encrypted or missing payloads.
- ESP/AH records with SPI and sequence; native ESP versus NAT-T evidence.
- Tests using generated packets and at least one independently captured, sanitized handshake.

**Exit checks**

- A known IKE exchange yields expected version, exchange type, proposal and transform IDs with packet references.
- A request alone cannot populate a selected transform.
- Invalid payload lengths and unsupported variants produce diagnostics without crashing the run.

**Ownership:** `parsers/`, `models/`, `tests/parser/`.

## Phase 2 — Session correlation and evidence

**Goal:** turn isolated packets into traceable exchanges, SAs and flows.

**Build**

- Correlate IKE request/response/retransmission records by endpoints, SPIs, exchange type and message ID.
- Group directional ESP/AH flows by endpoints, encapsulation, SPI and time.
- Compute packet counts, sizes, timing and sequence observations with units.
- Define `OBSERVED`, `DERIVED`, `INFERRED` and `UNKNOWN` instances with source references.
- Record ambiguous association instead of merging unrelated tunnels.

**Exit checks**

- Concurrent SAs, retransmissions, partial handshakes and SPI reuse remain distinct or explicitly ambiguous.
- Every value shown in a session traces to packet references or a documented derivation.
- Missing PFS, mode, replay configuration and negotiated values remain unknown.

**Ownership:** `models/`, `features/`, `assessment/`, correlation code in `parsers/`.

The current evidence schema supports `INFERRED`, but no inferred record is
emitted until a classifier has passed the Phase 5 validation gate. See
[CORRELATION_AND_EVIDENCE.md](CORRELATION_AND_EVIDENCE.md) for current behavior.

## Phase 3 — Evidence-backed assessment and first report

**Goal:** produce a useful end-to-end security result from an offline capture.

**Build**

- Select a small reviewed baseline and record exact authoritative clauses in `docs/standards/`.
- Implement versioned rules for only fields that Phase 1 can establish reliably.
- Emit `PASS`, `FAIL`, `UNKNOWN` and `NOT_APPLICABLE` rule evaluations.
- Generate findings with severity rationale, evidence, impact and remediation.
- Add coverage-aware scoring policy with documented formula and regression tests.
- Export canonical JSON plus a readable technical report; include limitations and unknowns.

**Exit checks**

- A weak and a compliant test scenario produce expected rule outcomes.
- Partial captures do not receive an unjustified compliant result or full-confidence score.
- Every finding and score contribution can be traced to a rule version and evidence.

**Ownership:** `rules/`, `assessment/`, `reporting/`, `docs/standards/`, `tests/rules/`.

## Phase 4 — Testbed and dataset

**Goal:** generate reproducible, labeled IPsec evidence for verification and ML.

**Build**

- Isolated strongSwan-based lab with tunnel/transport, IPv4/IPv6, selected AES suites, DH groups and PFS configurations.
- Capture IKE plus ESP; add AH where practical and label its coverage explicitly.
- Generate controlled VoIP-like, messaging-like, email, web, ICMP and video traffic.
- Save scenario manifests, configuration versions, capture points, checksums and ground-truth labels.
- Publish a dataset card and split data by run/tunnel/scenario.

**Exit checks**

- Another developer can reproduce at least one strong and one weak configuration and obtain matching packet evidence.
- Labels are derived from the testbed manifest, not predictions.
- Secrets and private keys are absent from committed fixtures and reports.

**Ownership:** `testbed/`, `data/`, `scripts/dataset/`, `tests/integration/`.

## Phase 5 — AI classifier and calibrated uncertainty

**Goal:** estimate traffic class within ESP without claiming to decrypt it.

**Build**

- Freeze a feature schema covering packet length, timing, direction and bursts.
- Train a simple structured-feature baseline before considering sequence models.
- Use scenario/run-level holdout; report per-class metrics and confusion matrix.
- Measure calibration, define abstention threshold and include an unknown/other route.
- Version model artifact, dataset and feature schema; keep inference separate from deterministic rules.

**Exit checks**

- Model reload and schema compatibility tests pass.
- Reported metrics are reproducible on a held-out set.
- Uncertain or out-of-scope flows abstain; model outputs are labeled `INFERRED`.

**Ownership:** `features/`, `ml/`, top-level `models/`, `data/`, `tests/`.

## Phase 6 — Analyst API, dashboard and full reporting

**Goal:** make the assessment usable and reviewable.

**Build**

- Analysis job API with validation, status, sessions, flows, evidence, findings and report endpoints.
- Dashboard views for overview, exchanges, flows, cryptographic observations, findings, coverage and AI confidence.
- Executive summary and technical JSON/HTML/PDF exports from one report model.
- Empty, partial, failed and unknown states; report redaction for sharing.

**Exit checks**

- Uploading a known capture produces the same facts in API, dashboard and export.
- Analyst can reach every finding's packet/rule evidence and remediation.
- UI never displays inferred application type as a directly observed protocol fact.

**Ownership:** `api/`, `dashboard/web/`, `reporting/`, `tests/integration/`.

## Phase 7 — Live capture, hardening and submission

**Goal:** meet the live-stream path and package a defensible demonstration.

**Build**

- Authorized interface capture feeding the same packet contract, with start/stop, dropped-packet accounting and bounded windows.
- Resource limits, input validation, capture/report access control and retention controls.
- Measure throughput and latency on named hardware; state supported limits.
- Record a demo that recreates testbed traffic and traces a report finding back to evidence.
- Freeze technical documentation, dataset card, model evaluation and known limitations.

**Exit checks**

- Live and offline analysis of a controlled run agree on common observable facts.
- Capture can be stopped cleanly and errors are visible.
- Deliverables include prototype, AI engine, dashboard, reports, demo video, documentation and dataset.

**Ownership:** `ingestion/`, `api/`, `testbed/`, `docs/`, validation scripts.

## Change control

Use `PR.md` for parser, rule, scoring, ML and dashboard tests. Update `ARCHITECTURE.md` when a component or contract changes. Update `DIRECTORY_CONSTRAINTS.md` before introducing a new top-level directory. Work proceeds against the remaining checks in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md), with each gate verified before its phase is marked complete.
