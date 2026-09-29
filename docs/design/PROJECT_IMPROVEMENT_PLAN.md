# Project improvement plan

**Baseline:** 29 September 2026. This is a prioritized plan for the current
SIH26160 prototype. [Implementation status](IMPLEMENTATION_STATUS.md) records
what is already verified; [implementation phases](IMPLEMENTATION_PHASES.md)
defines the original phase gates.

## Outcome

Deliver a reproducible IPsec investigation demo in which an analyst can trace
every security finding to visible packet evidence, distinguish model estimates
from observed facts, run bounded offline and live analysis, and explain the
system's measured limits. Completion is based on the checks below, not on the
number of features added.

## Current position

- Offline parsing, correlation and three narrow security rules work within
  their documented scope. Overall security and risk scores are withheld.
- The strongSwan dataset and encrypted-flow classifier are one-host synthetic
  pilots. Their results do not establish real application identity or
  cross-host accuracy.
- The local API and dashboard support upload, evidence review and report
  exports. Results are synchronous and held in memory, and the API has no
  deployment authentication.
- A bounded Linux/WSL live command passes simulated process and offline-parity
  checks, including empty and byte-limit cleanup. One controlled WSL namespace
  interface run passed live/offline parity with zero kernel drops. Repeated
  live-load measurements remain open.

## Progress on priorities (29 September 2026)

- P0 analyst evidence trail now includes priority-sorted rules, readable
  selected-proposal evidence, packet-reference metadata, flow encapsulation,
  explicit model abstention reasons, and grouped full/shared exports. The
  [demo runbook](DEMO_RUNBOOK.md) reproduces a weak DES finding from a tiny
  synthetic capture. Full keyboard/contrast checks and final video remain.
- P0 real-interface validation passed once on the isolated `sih4c` testbed
  interface: 86 packets in both live and offline captures, matching selected
  IKE transforms and two ESP directions, zero kernel drops and no leftover
  namespace or tcpdump process. See [phase status](IMPLEMENTATION_STATUS.md).
- P1 [local hardening](P1_LOCAL_HARDENING.md) covers capture failure
  reporting, simulated stop escalation, temporary cleanup, the actual API
  upload byte boundary and result eviction/restart behavior. Offline
  measurements include a 10,000-packet synthetic stress case. Independent-host
  model validation and representative live-load capacity remain open.
- The frontend improvement plan is underway; its first upload/recovery work
  package is implemented.

## Priority order

| Priority | Improvement | Deliverable | Gate |
| --- | --- | --- | --- |
| P0 | Finish analyst evidence workflow | Scannable findings, readable evidence, clear report sharing and keyboard support | Valid, partial and failed captures can be reviewed end to end in the browser |
| P0 | Prove live capture on an authorized WSL interface | Run record with interface, host, duration, packet/drop counts and matching offline facts | Controlled live and offline analysis agree; stop and error paths are visible |
| P0 | Freeze an honest demo path | Reproducible script, sample capture, report and short video | Another person can follow the guide and trace one finding to a packet |
| P1 | Harden local processing | Resource measurements, timeout behavior and bounded result lifecycle | Limits are measured and failure does not leave raw captures or a child process behind |
| P1 | Improve API durability only if needed for demo | A defined job/result lifecycle, then storage if the demo needs restart survival | Repeated uploads and restart behavior meet a written requirement |
| P1 | External dataset and model validation | Independent-host run set, revised evaluation and dataset card | Whole-run holdout on new host; per-class errors and abstentions reported |
| P2 | Extend protocol and assessment scope | Additional independently evidenced fields and rules | Every new rule has a standards source, positive/negative tests and packet provenance |

P0 work comes first because it closes the visible demo path without requiring
an unvalidated model or a larger architecture. P1 and P2 items are conditional
on evidence and the intended deployment.

## Workstreams

### A. Analyst product and reports

Follow [FRONTEND_IMPROVEMENT_PLAN.md](FRONTEND_IMPROVEMENT_PLAN.md), beginning
with finding priority, explicit unknown reasons and labeled evidence values.
Add a packet-reference view only from safe metadata in a documented API
contract. Group full and redacted exports and verify that both reflect the
same analysis. Keep raw payloads out of the browser.

**Exit check:** a weak capture exposes a failed rule, rationale, remediation,
rule version, evidence state and packet number. A partial capture explains
unknown results. A model abstention stays visibly separate from observed
protocol facts. Upload, export, keyboard and 320 px paths work.

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

Keep the present one-host model labeled as a synthetic pilot. Reproduce strong
and weak scenarios on a second host when available, then add complete runs to
a new evaluation split without moving related tunnels between training and
test. Report per-class precision/recall, confusion, coverage, abstention and
calibration with sample counts. Compare with the frozen pilot artifact before
changing the model or threshold.

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
a deterministic demo order: generate or select a controlled capture, analyze
it, inspect the selected IKE response, show a weak finding and remediation,
show an abstained ESP estimate, then export a redacted report. Record a short
video only after the run succeeds from the written guide.

**Exit check:** the prototype, classifier artifact, dashboard, reports,
dataset card, technical documentation and demo video are present. Each major
claim can be mapped to a test, run record or explicit limitation.

## Execution sequence

1. Finish frontend packages 2, 3 and 5, then run its accessibility and
   responsive checks. This can proceed on the current machine.
2. Prepare a controlled live parity fixture and automated stop/error checks.
   Run a real interface test when the authorized WSL interface is available.
3. Measure bounded offline and live processing on the named demo hardware.
4. Reconcile architecture and status docs and prepare the repeatable demo.
5. Perform independent-host reproduction and model evaluation when another
   host becomes available. Keep this gate open until then.
6. Decide whether durable jobs or deployment authentication are needed for the
   actual delivery environment; implement only against that decision.

## Decisions and dependencies

| Decision or input | Needed for | Default until decided |
| --- | --- | --- |
| Authorized WSL interface and controlled traffic window | Real live validation | Simulated capture remains the only verified live-path test |
| Second Linux host or independent developer | Phase 4 reproduction and Phase 5 external validity | Keep one-host synthetic pilot label |
| Demo hosting mode: local or networked | Authentication, persistence and retention design | Loopback-only, single-user prototype |
| Required capture size, concurrency and job lifetime | Streaming or durable job design | Existing 16 MiB API upload and 16 in-memory results |

The current user's inability to use another system does not block frontend,
local hardening or demo preparation. It does prevent an independent-host
validation claim.

## Change rules

- Do not add a security score until its formula and evidence coverage are
  defensible and tested.
- Do not let inferred traffic class alter deterministic crypto findings.
- Do not add a rule for a hidden setting unless capture evidence can support
  its status; otherwise return unknown.
- Run relevant focused tests and `python -m pytest -q` for implementation
  changes. Browser-check the actual upload, finding trace and export paths for
  UI changes. Update [PR.md](../../PR.md) and architecture documentation when
  contracts change.
