# Project improvement plan

**Baseline:** 29 September 2026; **progress reconciled:** 30 September 2026. This is the prioritized delivery plan for
SIH26160, aligned to the supplied problem statement. [Implementation
status](IMPLEMENTATION_STATUS.md) records what is verified; [implementation
phases](IMPLEMENTATION_PHASES.md) defines the SIH acceptance contract and phase
gates.

## Outcome

Deliver a reproducible IPsec investigation platform with a testbed, offline and
live capture, automatic protocol analysis, ESP traffic estimates, evidence
backed security assessment, a defensible risk score and threat matrix,
dashboard, executive and technical reports, dataset, documentation and demo
video. An analyst must be able to trace each finding to packet or authorized
configuration evidence and distinguish model estimates from observed facts.
Completion is based on the checks below, not on the number of features added.

## Current position

The **P0/P1/P2 labels in the priority table below are delivery priorities**.
The numbered implementation phases are tracked separately in
[IMPLEMENTATION_PHASES.md](IMPLEMENTATION_PHASES.md). Their first three
states are:

| Implementation phase | Current state | Remaining boundary |
| --- | --- | --- |
| Phase 0 — foundation | Complete for documented prototype scope: bounded PCAP/PCAPNG ingestion, diagnostics, supported-input limits and memory checks | Streaming and broader link types are later scope |
| Phase 1 — protocol dissection | Complete for visible-protocol scope: bounded IKEv1/IKEv2 parsing, selected transforms and ESP/AH headers | Other IKEv1 variants and encrypted Child SA settings remain unknown |
| Phase 2 — correlation and evidence | Complete for offline prototype scope: session/flow grouping and packet-linked observed, derived and unknown evidence | Identical concurrent SPI pairs can remain ambiguous; inferred evidence awaits validated modeling |

The detailed checks and limitations are in the [phase status](IMPLEMENTATION_STATUS.md)
and [Phase 0–3 completion audit](PHASE0_3_COMPLETION.md).

## Problem-statement coverage and next proof

`Verified` means the stated bounded behavior has a reviewed local test or run.
`Partial` means the broader wording in the problem statement is not yet
supported. The [phase status](IMPLEMENTATION_STATUS.md) owns detailed evidence.

| Problem-statement capability | Current state | Next proof needed |
| --- | --- | --- |
| Tunnel/transport; AES-128/256; GCM/CBC-HMAC; DH/PFS; IPv4/IPv6 | Verified in the isolated testbed for the published cases | Another-developer or separate-physical-host reproduction; retain configured versus installed-state distinctions |
| VoIP, WhatsApp/messaging, email, web, ICMP and video traffic | Partial: six generator profiles, not those real applications | Privacy-reviewed real application runs with truthful source labels; keep `*-like` labels until then |
| IKE, ESP, optional AH and normal communication captures | Verified IKE/ESP and a separate unprotected ICMP control; AH absent | Keep AH explicitly unavailable or add a reviewed optional AH capture |
| Offline and live capture | Partial: offline paths and one controlled bounded WSL live/offline parity run | Repeated named-hardware live-load and failure/cleanup measurements |
| IPsec/IKE version and visible SA characteristics | Verified within parser scope | Expand unsupported IKE variants only with captured fixtures and parser diagnostics |
| Tunnel/transport mode and ESP Child SA algorithms | Partial: matched configuration and selected IKE transforms are distinguishable; passive encrypted settings remain unknown | Reviewed installed-SA state or other authorized evidence; never infer ESP cipher or mode from IKE selection alone |
| Authentication and key exchange | Partial: visible proposal/transform IDs and selected IKE DH are parsed; comprehensive strength assessment is absent | Versioned reviewed authentication, DH and cipher-suite rules with exact evidence boundaries |
| Traffic type inside ESP and AI confidence | Partial: versioned synthetic pilot, held-out metrics and abstention | Independent complete runs and authorized real-app challenge; assess calibration with meaningful denominators |
| Cryptography, compliance, SA parameters, lifetime, replay, PFS, metadata exposure | Partial: five packet rules and four configured-control rules, with coverage-gated risk | Broader reviewed rules and installed-state verification; explicit metadata-exposure findings where packet evidence supports them |
| Risk score, threat matrix, executive and technical reports | Verified for bounded project policy across local API, separate dashboard pages and exports | Independent policy review and broader control coverage before calling the score comprehensive |
| Working prototype, dashboard, docs and training/testing dataset | Verified local prototype and synthetic dataset with run-level splits | Package a frozen requirement-to-evidence index for submission |
| Demonstration video | Missing | Execute the written strong/weak, offline/live, inference/abstention and export sequence, then record and verify the video |

## Verified prototype baseline

- Offline parsing and correlation work within their documented scope. Five
  packet rules and four matched-configuration rules now feed a versioned,
  coverage-gated project risk score and evidence-linked threat matrix. Passive
  captures cannot reveal every Child SA setting, and configured intent does
  not prove installed state. Independent policy review remains open.
- The strongSwan dataset and encrypted-flow classifier are synthetic pilots.
  The scenarios were reproduced on WSL and a Kali VM; seven Kali runs covered
  all six profiles, with five accepted predictions and two abstentions. This
  does not establish real application identity or independent physical-host
  accuracy. The 44-capture IPsec index and a separate six-packet non-VPN
  control are pinned; the shareable model evaluation now reports coverage,
  abstentions and accepted-only calibration with denominators. See the
  [Phase 4 matrix](PHASE4_COVERAGE_MATRIX.md) and [Phase 5 audit](PHASE5_EVALUATION.md).
- The local API and dashboard support upload, evidence review and report
  exports. Results are synchronous and held in memory, and the API has no
  deployment authentication.
- A bounded Linux/WSL live command passes simulated process and offline-parity
  checks, including empty and byte-limit cleanup. One controlled WSL namespace
  interface run passed live/offline parity with zero kernel drops. Repeated
  live-load measurements remain open.

## Prototype work already verified (29 September 2026)

- The earlier P0 analyst evidence trail now includes priority-sorted rules, readable
  selected-proposal evidence, packet-reference metadata, flow encapsulation,
  explicit model abstention reasons, and grouped full/shared exports. The
  [demo runbook](DEMO_RUNBOOK.md) reproduces a weak DES finding from a tiny
  synthetic capture. Full keyboard/contrast checks and final video remain.
- The earlier P0 real-interface validation passed once on the isolated `sih4c` testbed
  interface: 86 packets in both live and offline captures, matching selected
  IKE transforms and two ESP directions, zero kernel drops and no leftover
  namespace or tcpdump process. See [phase status](IMPLEMENTATION_STATUS.md).
- The earlier P1 [local hardening](P1_LOCAL_HARDENING.md) covers capture failure
  reporting, simulated stop escalation, temporary cleanup, the actual API
  upload byte boundary and result eviction/restart behavior. Offline
  measurements include a 10,000-packet synthetic stress case. Independent-host
  model validation and representative live-load capacity remain open.
- The frontend improvement plan is underway; its first upload/recovery work
  package is implemented.

## Priority order

| Priority | Improvement | Deliverable | Gate |
| --- | --- | --- | --- |
| P0 | Configuration-aware assessment — bounded v1 implemented | Authorized config input with provenance; mode, lifetime, replay and PFS checks | Capture-only results stay unknown; config-backed checks cite source and have positive, negative and partial-evidence tests; independent policy review remains |
| P0 | Risk score and threat matrix — bounded v1 implemented | Versioned formula, per-session coverage gate, risk bands and evidence-linked threat categories | Score is shown only with sufficient evidence; JSON, dashboard and both reports agree; installed-state verification remains |
| P0 | Assessment breadth required by SIH | Reviewed authentication, SA-parameter, cipher-suite and metadata-exposure rules where evidence supports them; selected IKE integrity MD5 rule added locally | Weak/strong/partial tests and independent policy review; unsupported encrypted or installed settings stay unknown |
| P0 | SIH demo and submission | Strong/weak, offline/live, inference/abstention, score or withheld state, threat matrix, exports and video | Another person can follow the guide and reproduce every shown claim |
| P1 | Evidence-backed remediation verification | Paired before/after analyses with comparable scope, finding transition and evidence links | A changed finding is verified only by positive after-evidence; otherwise the result is inconclusive |
| P1 | Testbed and dataset coverage — local checks implemented | [Configuration matrix](PHASE4_COVERAGE_MATRIX.md), reviewed separate normal-traffic control, explicit AH gap and revised dataset card | Each SIH configuration and traffic family has a verified or explicit gap status; independent developer or physical-host reproduction remains |
| P1 | AI credibility — local pilot checks implemented | Shareable frozen model and [held-out evaluation](PHASE5_EVALUATION.md); future complete-run evaluation on another host or by another developer plus authorized real traffic | Per-class errors, abstentions and accepted-only calibration reported with sample counts; external validity remains unverified |
| P1 | Product and live validation | Local keyboard/mobile and API/export checks pass; representative bounded live measurements remain | Repeat named-hardware live-load runs; stop/error cleanup and measured limits are reproducible |
| P2 | Deployment durability and access | Storage and authentication only for the chosen hosting mode | Access, retention and restart behavior meet a written deployment requirement |

The bounded configuration and score P0 items close the local output gaps.
Assessment breadth, independent policy review, installed-state verification,
and the demo/submission P0 items remain open.

## Workstreams

### A. Analyst product and reports

Follow [FRONTEND_IMPROVEMENT_PLAN.md](FRONTEND_IMPROVEMENT_PLAN.md), beginning
with finding priority, explicit unknown reasons and labeled evidence values.
Add a packet-reference view only from safe metadata in a documented API
contract. Group full and redacted exports and verify that both reflect the
same analysis. Add the backend risk-score state, evidence coverage and threat
  matrix. The risk/threat contract and dedicated analysis pages are now
  implemented; finish the remaining browser keyboard review. Keep raw payloads
  out of the browser.

**Exit check:** a weak capture exposes a failed rule, rationale, remediation,
rule version, evidence state and packet number. A partial capture explains
unknown results. A model abstention stays visibly separate from observed
protocol facts. Every threat and score contribution links to evidence;
upload, export, keyboard and 320 px paths work.

### A1. Configuration-aware assessment and risk

The bounded v1 contract accepts sanitized, authorized configuration evidence
with source, collection time, capture hash and an unambiguous peer/session
match. Mode, lifetime, replay and PFS checks stay unknown for capture-only,
unmatched or stale input. The reviewed [project policy](../standards/RISK_AND_CONFIG_POLICY.md)
records thresholds and their source limits; independent policy review and
installed-state checks remain.

The versioned risk score is separate from the narrow observed-rule pass rate.
It defines weights, denominator, unknown/not-applicable treatment, minimum
coverage, bands and a withholding gate. Threat rows include category,
severity, affected asset and control, evidence IDs, impact and remediation.
ESP traffic inference does not change cryptographic risk findings.

**Exit check:** strong and weak lab configs produce distinct, explainable
findings and threat rows; capture-only analysis does not invent hidden
settings. A scored case has adequate coverage, while an insufficient-evidence
case withholds its score. API, dashboard, executive and technical exports match.

### A2. Remediation verification (candidate differentiator)

After the single-run assessment is stable, support a user-selected before/after
pair. Require the same tunnel or a documented replacement, comparable capture
scope, timestamps and configuration provenance. Compare rule outcomes,
underlying observations, coverage and score eligibility; show the old and new
evidence side by side. A remediation is `VERIFIED_IMPROVED` only when the after
run positively establishes the desired state and the relevant finding is
resolved. Use `UNCHANGED`, `REGRESSED` or `INCONCLUSIVE` for the other cases.
Failure to observe an old weak exchange in a short after-capture is not proof
that the weak configuration was removed.

**Exit check:** a controlled weak-to-strong lab change produces linked before
and after records and a reproducible improvement verdict. An incomplete,
unmatched or lower-coverage after-run is inconclusive rather than a false pass.
This is a candidate product distinction, not a claim of unique prior art:
public projects such as [TunnelScope](https://github.com/7-Bala/TunnelScope)
already report overlapping evidence and posture features, and repository
descriptions require implementation-level verification before comparison.

### B. Live ingestion and resource safety

Run the existing bounded capture command on a named, authorized WSL interface
against controlled testbed traffic. Record OS, CPU, memory, tcpdump version,
interface, capture duration, packet count, kernel drop count, capture size and
analysis time. Preserve a sanitized controlled PCAP only for parity checking;
the ordinary live command deletes its temporary raw capture. Exercise a
no-packet window, early stop, permission error and byte/packet limits.

**Exit check:** the live result and an offline read of the same controlled
capture agree on common packet, IKE and flow facts. No tcpdump process or raw
temporary file remains after success or failure. Throughput claims cite the
named machine and test conditions.

### C. Dataset and AI credibility

Keep the current model labeled as a synthetic pilot. The
[coverage matrix](PHASE4_COVERAGE_MATRIX.md) records
tunnel/transport, AES-128/256, GCM/CBC-HMAC, DH/PFS, IPv4/IPv6 and the six
traffic families. A separate normal-communication control capture is reviewed;
AH is explicitly unavailable. The Kali VM runs show
cross-installation behavior, including a `web-like` abstention, but do not
replace another-developer or separate physical-host validation. Add complete
runs from that source to a new evaluation split without moving related tunnels
between training and test. Use authorized real application traffic only with
privacy review and truthful source labels. Report per-class precision/recall,
confusion, coverage, abstention and calibration with sample counts. Compare
with the frozen pilot artifact before changing the model or threshold.

**Exit check:** hashes and manifests reproduce the independent runs; labels
come from the testbed; evaluation can be regenerated; unsupported traffic
abstains. If performance is weak, keep the model in pilot mode and report the
failure rather than relaxing the threshold to create a better-looking demo.

### D. API and deployment boundary

Document whether the demo is single-user and loopback-only or will be served
to other analysts. For a local demo, keep the existing bound and result cap,
and document restart/expiry behavior. For a networked deployment, define
authentication, authorization, report access, retention and cleanup before
opening the service beyond loopback. Add durable jobs only after specifying
the required lifetime and concurrency.

**Exit check:** capture and report access match the declared deployment mode;
resource limits and retention are tested. No unauthenticated network exposure
is presented as production-ready.

### E. Scope, documentation and submission

Reconcile architecture text with implemented behavior, especially live input,
redacted export and result persistence. Keep the dataset card, model
evaluation, supported-input guide and known limitations synchronized. Prepare
a deterministic demo order: generate strong and weak lab configurations,
analyze offline and bounded live traffic, inspect the selected IKE response,
show a weak finding, score or justified withheld state, threat matrix,
remediation and an abstained ESP estimate, then export executive and technical
reports. Record a short video only after the run succeeds from the written
guide. Provide a requirement-to-evidence index for the submitted artifacts.

**Exit check:** the prototype, classifier artifact, dashboard, reports,
dataset card, technical documentation and demo video are present. Each major
SIH claim maps to a test, run record or explicit limitation.

## Execution sequence

1. Authorized configuration evidence, score/threat contracts and strong,
   weak, partial and capture-only fixtures are implemented for bounded v1.
2. Configuration-backed rules, coverage-aware score and threat matrix are
   implemented with evidence links and unknown handling; keep their policy
   scope explicit.
3. The new contract is present in the local API, separate dashboard pages and
   report formats; keep the [Phase 6 local check](PHASE6_LOCAL_CHECK.md) as the
   bounded verification and finish broader contrast/hosting checks.
4. Add reviewed authentication, SA-parameter, cipher-suite and metadata
   exposure checks where packet or authorized configuration evidence supports
   them. Independently review the risk policy before broader claims.
5. Add the paired before/after verification path and its inconclusive cases,
   then show a controlled improvement in the demo.
6. The SIH testbed coverage matrix, normal-traffic control and dataset card
   are updated. Keep optional AH explicitly scoped and the external reproduction
   gate open.
7. Evaluate the frozen classifier on independent physical-host or
   another-developer runs and authorized real traffic when available. Report
   abstentions and calibration limits without changing the pilot gate to fit
   the challenge set.
8. Repeat bounded live-load measurements on named demo hardware, reconcile
   architecture/status docs, execute the runbook and record the submission
   video and evidence index.
9. Decide whether durable jobs or deployment authentication are needed for the
   actual delivery environment; implement against that decision.

## Decisions and dependencies

| Decision or input | Needed for | Default until decided |
| --- | --- | --- |
| Authorized configuration source and tunnel matching | Mode, lifetime, replay and PFS rules | Sanitized v1 match contract implemented; capture-only results remain unknown |
| Risk policy and minimum evidence coverage | Project risk score and threat matrix | Versioned v1 formula and gate implemented; independent policy review remains |
| Authorized controlled interface and traffic window | Representative live validation | One WSL namespace parity run is verified; broader live-load measurements remain open |
| Separate physical host or independent developer | Phase 4 attestation and Phase 5 external validity | WSL and Kali VM checks remain synthetic pilot evidence |
| Authorized real application captures and labels | Application identity validation | Use only synthetic `*-like` claims |
| Demo hosting mode: local or networked | Authentication, persistence and retention design | Loopback-only, single-user prototype |
| Required capture size, concurrency and job lifetime | Streaming or durable job design | Existing 16 MiB API upload and 16 in-memory results |

The current Kali VM provides a second Linux installation, but apparently runs
on the same physical machine and was operated by the same person. It advances
reproducibility without closing independent physical-host or developer
validation. That external dependency does not block the score, threat,
configuration or submission work.

## Change rules

- Do not broaden or present the v1 project risk score as installed-state proof
  without reviewed evidence, formula and coverage tests.
- Do not let inferred traffic class alter deterministic crypto findings.
- Do not add a rule for a hidden setting unless packet or matched authorized
  configuration evidence can support its status; otherwise return unknown.
- Run relevant focused tests and `python -m pytest -q` for implementation
  changes. Browser-check the actual upload, finding trace and export paths for
  UI changes. Update [PR.md](../../PR.md) and architecture documentation when
  contracts change.
