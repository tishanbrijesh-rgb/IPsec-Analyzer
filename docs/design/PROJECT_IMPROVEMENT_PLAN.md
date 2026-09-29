# Project improvement plan

**Baseline:** 29 September 2026. This is the prioritized delivery plan for
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

- Offline parsing, correlation and three narrow security rules work within
  their documented scope. A comprehensive risk score and threat matrix are
  still missing. Passive captures cannot reveal every Child SA setting.
- The strongSwan dataset and encrypted-flow classifier are synthetic pilots.
  The scenarios were reproduced on WSL and a Kali VM; seven Kali runs covered
  all six profiles, with five accepted predictions and two abstentions. This
  does not establish real application identity or independent physical-host
  accuracy.
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
| P0 | Configuration-aware assessment | Authorized config input with provenance; mode, lifetime, replay, PFS and compliance checks | Capture-only results stay unknown; config-backed checks cite source and have positive, negative and partial-evidence tests |
| P0 | Risk score and threat matrix | Versioned formula, coverage gate, risk bands and evidence-linked threat categories | Score is shown only with sufficient evidence; JSON, dashboard and both reports agree |
| P0 | SIH demo and submission | Strong/weak, offline/live, inference/abstention, score or withheld state, threat matrix, exports and video | Another person can follow the guide and reproduce every shown claim |
| P1 | Testbed and dataset coverage | Requested configuration matrix, normal-traffic control, optional AH decision and revised dataset card | Each SIH configuration and traffic family has a verified or explicit gap status; no secrets enter shared artifacts |
| P1 | AI credibility | Complete-run evaluation on another host or by another developer plus authorized real traffic | Per-class errors, abstentions and calibration reported with sample counts; unsupported flows abstain |
| P1 | Product and live validation | Keyboard/mobile review and representative bounded live measurements | API, dashboard and exports agree; stop/error cleanup and measured limits are reproducible |
| P2 | Deployment durability and access | Storage and authentication only for the chosen hosting mode | Access, retention and restart behavior meet a written deployment requirement |

The P0 items close explicit SIH output gaps. Work already verified for the
prototype stays available, but does not count as completion of the broader SIH
score, threat or submission gates.

## Workstreams

### A. Analyst product and reports

Follow [FRONTEND_IMPROVEMENT_PLAN.md](FRONTEND_IMPROVEMENT_PLAN.md), beginning
with finding priority, explicit unknown reasons and labeled evidence values.
Add a packet-reference view only from safe metadata in a documented API
contract. Group full and redacted exports and verify that both reflect the
same analysis. Add the backend risk-score state, evidence coverage and threat
matrix. Keep raw payloads out of the browser.

**Exit check:** a weak capture exposes a failed rule, rationale, remediation,
rule version, evidence state and packet number. A partial capture explains
unknown results. A model abstention stays visibly separate from observed
protocol facts. Every threat and score contribution links to evidence;
upload, export, keyboard and 320 px paths work.

### A1. Configuration-aware assessment and risk

Define a versioned input contract for authorized strongSwan or equivalent
configuration evidence. The source, collection time, configuration scope and
match to the captured tunnel must be explicit. Add mode, key lifetime, replay
protection, PFS and Child SA policy checks only where that evidence can support
them. Keep unknown for capture-only analysis and for unmatched or stale
configuration. Review standards and positive, negative and partial tests for
each check.

Define a risk score independently from the existing narrow observed-rule pass
rate. Specify rule weights, denominator, treatment of unknown/not applicable,
minimum coverage, risk bands and sensitivity to missing evidence before
implementing it. Build a threat matrix whose rows contain category, severity,
affected control, evidence IDs, impact and remediation. Do not let the ESP
traffic classifier change cryptographic risk findings.

**Exit check:** strong and weak lab configs produce distinct, explainable
findings and threat rows; capture-only analysis does not invent hidden
settings. A scored case has adequate coverage, while an insufficient-evidence
case withholds its score. API, dashboard, executive and technical exports match.

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

Keep the current model labeled as a synthetic pilot. Maintain a matrix for
tunnel/transport, AES-128/256, GCM/CBC-HMAC, DH/PFS, IPv4/IPv6 and the six
traffic families. Add a normal-communication control capture; decide and
record whether optional AH is included. The Kali VM runs show
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

1. Specify authorized configuration evidence and the score/threat contracts;
   write acceptance fixtures for strong, weak, partial and capture-only cases.
2. Implement configuration-backed rules, coverage-aware score and threat
   matrix, with evidence links and unknown handling.
3. Surface the new contract in API, dashboard and both report levels; finish
   keyboard and responsive checks on real browser flows.
4. Fill the SIH testbed coverage matrix and normal-traffic control; update the
   dataset card. Keep optional AH explicitly scoped.
5. Evaluate the frozen classifier on independent physical-host or
   another-developer runs and authorized real traffic when available. Report
   abstentions and calibration limits without changing the pilot gate to fit
   the challenge set.
6. Repeat bounded live-load measurements on named demo hardware, reconcile
   architecture/status docs, execute the runbook and record the submission
   video and evidence index.
7. Decide whether durable jobs or deployment authentication are needed for the
   actual delivery environment; implement against that decision.

## Decisions and dependencies

| Decision or input | Needed for | Default until decided |
| --- | --- | --- |
| Authorized configuration source and tunnel matching | Mode, lifetime, replay, PFS and compliance rules | Capture-only results remain unknown |
| Risk policy and minimum evidence coverage | Comprehensive score and threat matrix | Withhold overall score while its formula and gate are unapproved |
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

- Do not add a security score until its formula and evidence coverage are
  defensible and tested.
- Do not let inferred traffic class alter deterministic crypto findings.
- Do not add a rule for a hidden setting unless packet or matched authorized
  configuration evidence can support its status; otherwise return unknown.
- Run relevant focused tests and `python -m pytest -q` for implementation
  changes. Browser-check the actual upload, finding trace and export paths for
  UI changes. Update [PR.md](../../PR.md) and architecture documentation when
  contracts change.
