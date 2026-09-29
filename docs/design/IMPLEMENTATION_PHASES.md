# Implementation and Improvement Phases

**Status:** SIH26160-aligned working plan, revised 29 September 2026.  
**Architecture:** [ARCHITECTURE.md](../../ARCHITECTURE.md) defines the system contracts and boundaries.  
**Rule:** a phase is complete only when its exit checks pass and its limitations are documented.

## Current baseline

The current implementation state and verified test count are tracked in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). This document defines phase gates and is not a claim that later phases are complete.

## SIH26160 acceptance contract

The problem statement asks for a working IPsec analysis platform, an AI
classification engine, an interactive dashboard, security assessment reports,
a demonstration video, technical documentation, and a training/testing dataset.
The platform must cover offline and live input, varied VPN configurations,
protocol and SA identification, encrypted-traffic estimates, assessment, a
security/risk score, a threat matrix, and executive and technical output.

| Requirement group | Delivery gate | Evidence boundary |
| --- | --- | --- |
| Testbed and dataset | Matrix of tunnel/transport, AES-128/256, GCM/CBC-HMAC, DH/PFS, IPv4/IPv6, and six traffic families, with manifests, hashes and split membership | Synthetic `*-like` profiles are not recordings of WhatsApp, VoIP or other real apps; AH is optional and must be marked covered or absent |
| Capture and protocol identification | Offline PCAP/PCAPNG and bounded live streams identify visible IKE versions, selected algorithms, key exchange groups, SA and ESP/AH facts | Parse directly visible fields deterministically; encrypted Child SA settings and passive mode/PFS/replay/lifetime claims remain `UNKNOWN` without another source |
| Configuration and security assessment | Versioned crypto, compliance, SA, lifetime, replay, PFS, cipher and metadata checks with packet/config provenance and remediation | A lab configuration or authorized configuration import may establish hidden settings; a PCAP alone may not |
| Score and threat matrix | Documented coverage-aware formula, risk bands and evidence-linked threat entries in API, dashboard and both reports | Unknown controls reduce coverage and cannot silently count as pass; inferred traffic class cannot change deterministic crypto findings |
| AI traffic inference | Versioned ESP feature model, per-class holdout metrics, calibration assessment, confidence/abstention, `unknown/other` | State `INFERRED`; report evaluated scope and sample counts; do not claim decryption or real-app identity from synthetic labels |
| Submission | Reproducible demo, video, docs, sanitized dataset card and model evaluation | Every demo claim maps to a run record, test or explicit limitation |

Protocol identification is an automatic hybrid pipeline: deterministic parsing
for visible IKE/ESP/AH facts and ML only for encrypted-traffic estimates where
the model has support. Do not add a model prediction for a protocol fact that
the parser can establish exactly.

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
- Define separate security posture and evidence coverage measures. Publish a
  comprehensive risk score only after a versioned, coverage-aware formula,
  minimum-evidence gate, risk bands and sensitivity tests are reviewed.
- Map each applicable rule to a versioned threat category, affected asset,
  evidence, impact and remediation; generate an explicit threat matrix.
- Export canonical JSON plus a readable technical report; include limitations and unknowns.

**Exit checks**

- A weak and a compliant test scenario produce expected rule outcomes.
- Partial captures do not receive an unjustified compliant result or full-confidence score.
- Every finding and score contribution can be traced to a rule version and evidence.
- Score and threat-matrix rows agree across JSON, dashboard, executive and
  technical reports; insufficient evidence withholds the score.

**Ownership:** `rules/`, `assessment/`, `reporting/`, `docs/standards/`, `tests/rules/`.

## Phase 4 — Testbed and dataset

**Goal:** generate reproducible, labeled IPsec evidence for verification and ML.

**Build**

- Isolated strongSwan-based lab with a published coverage matrix for
  tunnel/transport, IPv4/IPv6, AES-128/256, AES-GCM, AES-CBC plus HMAC,
  multiple DH groups, and PFS on/off. Include positive and contrasting cases.
- Capture IKE plus ESP and a separate normal-communication control trace.
  Add AH when practical and label its coverage explicitly.
- Generate controlled VoIP-like, messaging-like, email-like, web-like, ICMP and
  video-like traffic. Use real application traffic only with authorized capture,
  privacy review and source labels that identify the actual application.
- Save scenario manifests, configuration versions, capture points, checksums and ground-truth labels.
- Publish a dataset card and split data by run/tunnel/scenario.

**Exit checks**

- Another developer can reproduce at least one strong and one weak configuration and obtain matching packet evidence.
- Labels are derived from the testbed manifest, not predictions.
- Secrets and private keys are absent from committed fixtures and reports.
- The coverage matrix explicitly marks each requested configuration and traffic
  family as verified, partial or unavailable; independent-installation checks
  do not substitute for another-developer or physical-host evidence.

**Ownership:** `testbed/`, `data/`, `scripts/dataset/`, `tests/integration/`.

## Phase 5 — AI classifier and calibrated uncertainty

**Goal:** estimate traffic class within ESP without claiming to decrypt it.

**Build**

- Freeze a feature schema covering packet length, timing, direction and bursts.
- Train a simple structured-feature baseline before considering sequence models.
- Use scenario/run-level holdout; report per-class metrics and confusion matrix.
- Measure calibration, define abstention threshold and include an unknown/other route.
- Version model artifact, dataset and feature schema; keep inference separate from deterministic rules.
- Evaluate the frozen model on new complete runs from another host or developer
  and on authorized real traffic before making application-identity claims.

**Exit checks**

- Model reload and schema compatibility tests pass.
- Reported metrics are reproducible on a held-out set.
- Uncertain or out-of-scope flows abstain; model outputs are labeled `INFERRED`.
- Report per-class precision/recall, confusion, coverage, abstentions and
  confidence calibration with denominators for the SIH submission dataset.

**Ownership:** `features/`, `ml/`, top-level `models/`, `data/`, `tests/`.

## Phase 6 — Analyst API, dashboard and full reporting

**Goal:** make the assessment usable and reviewable.

**Build**

- Analysis job API with validation, status, sessions, flows, evidence, findings and report endpoints.
- Dashboard views for overview, exchanges, flows, cryptographic observations, findings, coverage and AI confidence.
- Executive summary and technical JSON/HTML/PDF exports from one report model.
- Render score status and threat matrix with evidence, coverage and explicit
  unknown reasons in the dashboard and both report levels.
- Empty, partial, failed and unknown states; report redaction for sharing.

**Exit checks**

- Uploading a known capture produces the same facts in API, dashboard and export.
- Analyst can reach every finding's packet/rule evidence and remediation.
- UI never displays inferred application type as a directly observed protocol fact.
- Executive and technical exports carry the same score status, threat entries,
  confidence scope and source references as the API.

**Ownership:** `api/`, `dashboard/web/`, `reporting/`, `tests/integration/`.

## Phase 7 — Live capture, hardening and submission

**Goal:** meet the live-stream path and package a defensible demonstration.

**Build**

- Authorized interface capture feeding the same packet contract, with start/stop, dropped-packet accounting and bounded windows.
- Resource limits, input validation, capture/report access control and retention controls.
- Measure throughput and latency on named hardware; state supported limits.
- Record a demo that shows a strong and weak configuration, offline and bounded
  live input, mode/config provenance, score or justified withheld state, threat
  matrix, model prediction and abstention, then executive and technical exports.
- Freeze technical documentation, dataset card, model evaluation and known limitations.

**Exit checks**

- Live and offline analysis of a controlled run agree on common observable facts.
- Capture can be stopped cleanly and errors are visible.
- Deliverables include prototype, AI engine, dashboard, reports, demo video, documentation and dataset.
- A reviewer can follow the runbook, identify which SIH requirements were
  demonstrated, and reproduce the accompanying evidence without accessing keys.

**Ownership:** `ingestion/`, `api/`, `testbed/`, `docs/`, validation scripts.

## Remaining work order for SIH alignment

1. **Assessment contract:** define an authorized configuration input and its
   provenance, then add the missing mode, lifetime, replay and PFS checks with
   `UNKNOWN` for capture-only cases. Add standards sources and positive,
   negative and partial-evidence tests before showing new findings.
2. **Risk and threat output:** define the score denominator, evidence threshold,
   weights and risk bands; implement the threat matrix and keep API, dashboard
   and report outputs identical. Publish score only for cases that pass its
   minimum-evidence gate.
3. **Remediation verification:** compare user-selected before/after runs with
   matched tunnel scope, capture conditions and positive evidence of the new
   state. Emit improved, unchanged, regressed or inconclusive; absence of a
   previously seen packet in a short capture is not proof of a fix. Treat this
   as a candidate differentiator, not a claim of uniqueness.
4. **Dataset and AI:** finish the requested configuration coverage matrix,
   normal-traffic control and dataset card; obtain independent physical-host or
   developer and authorized real-traffic evaluation. Preserve the current
   synthetic pilot label until those results exist.
5. **Product verification:** exercise supported offline and live paths,
   responsive and keyboard dashboard review, score/unknown displays, threat
   drill-down and redacted exports against the same fixtures.
6. **Submission:** freeze the technical docs and limitations, run the written
   demo on the delivery machine, record the video, and assemble every expected
   deliverable with a traceable evidence index.

## Change control

Use `PR.md` for parser, rule, scoring, ML and dashboard tests. Update `ARCHITECTURE.md` when a component or contract changes. Update `DIRECTORY_CONSTRAINTS.md` before introducing a new top-level directory. Work proceeds against the remaining checks in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md), with each gate verified before its phase is marked complete.
