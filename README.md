# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

**Smart India Hackathon 2026**\
**Problem Statement:** SIH26160\
**Organization:** National Technical Research Organisation (NTRO)\
**Category:** Software\
**Theme:** Blockchain & Cybersecurity

**Current status:** offline prototype Phases 0–3 are complete within their
documented scopes. Phases 4–5 have a one-host synthetic pilot and remain open
for independent validation. Phase 6 has a local analyst dashboard, evidence
drill-down and text/HTML/PDF/JSON reports; durable jobs and multi-user access
remain future work. Phase 7 has a bounded Linux/WSL capture command, verified
on one controlled namespace interface run with live/offline parity. See
[Phase status](docs/design/IMPLEMENTATION_STATUS.md).

The current priorities and delivery gates are in the
[project improvement plan](docs/design/PROJECT_IMPROVEMENT_PLAN.md).

For a repeatable local dashboard demonstration, follow the
[demo runbook](docs/design/DEMO_RUNBOOK.md).
Local resource limits and result expiry behavior are documented in
[P1 local hardening](docs/design/P1_LOCAL_HARDENING.md).

## Python setup on Linux

Use Python 3.11 or newer. For the API and test suite, install the dependencies
from the root `requirements.txt` in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

The isolated Phase 4 lab also requires system packages for `ip`, `swanctl`,
`charon-systemd` and `tcpdump`; see the
[reproduction guide](docs/design/PHASE4_REPRODUCTION.md).

## Bounded live capture (Phase 7 pilot)

In WSL, from the repository directory, choose a network interface you are
authorized to monitor. Check its name with `ip -br link`, then run:

```bash
sudo env PYTHONPATH=src python3 -m ipsec_analyzer.ingestion.live --interface eth0 --seconds 10 --max-packets 1000 > live-result.json
```

Replace `eth0` with the actual interface. The command requires `tcpdump`,
captures IKE/ESP/AH traffic for at most 60 seconds and 10,000 packets, and
stops if the temporary PCAP exceeds 16 MiB. It prints the offline analyzer's
result plus elapsed time and the kernel drop count reported by `tcpdump`.
The raw capture is deleted after analysis. A `null` drop count means tcpdump
did not report it. One controlled namespace-interface run passed parity on
29 September 2026; throughput under representative live load remains unmeasured.

## 1. Project Purpose

This project proposes an intelligent IPsec VPN analysis and
security-assessment platform.

The system is intended to analyze IPsec VPN traffic from offline packet
captures and, as the implementation matures, live traffic sources. It
separates observable IPsec control-plane information from encrypted
data-plane traffic, extracts protocol and security characteristics,
evaluates security configuration against defined baselines, performs
statistical/AI-based inference where direct observation is not possible,
and produces actionable security findings.

The central objective is not merely to identify IPsec traffic. The
objective is to turn VPN traffic into an understandable security
assessment:

``` text
IPsec Traffic / PCAP
        |
        v
Traffic Ingestion
        |
        +----------------------+
        |                      |
        v                      v
   IKE Analysis            ESP/AH Analysis
        |                      |
        +----------+-----------+
                   |
                   v
          Feature / Metadata Layer
                   |
          +--------+--------+
          |                 |
          v                 v
   Deterministic       AI / Statistical
      Analysis             Inference
          |                 |
          +--------+--------+
                   |
                   v
        Security Assessment Engine
                   |
                   v
        Risk + Threat + Confidence
                   |
          +--------+--------+
          |                 |
          v                 v
      Dashboard          Reports
```

## 2. Problem Being Addressed

Traditional packet-analysis utilities can expose packet-level
information, but security analysts still need to manually correlate
protocol exchanges, cryptographic parameters, security-association
properties, encrypted-flow characteristics, and applicable security
requirements.

The proposed platform addresses this analysis gap by combining:

-   IPsec/IKE protocol dissection
-   ESP/AH traffic analysis
-   deterministic security rules
-   statistical feature extraction
-   AI-assisted encrypted traffic classification
-   cryptographic and configuration assessment
-   risk scoring
-   threat mapping
-   confidence-aware findings
-   technical and executive reporting

## 3. Core Analysis Principle

The platform must distinguish between **what can be directly observed**
and **what must be inferred**.

### Directly observable / deterministically parsed

Examples include:

-   IPsec protocol presence
-   IKE traffic
-   IKE version when available in the captured exchange
-   exchange characteristics
-   Security Association and Transform information available in the
    exchange
-   encryption/integrity/PRF/DH identifiers when exposed by the captured
    negotiation
-   SPI and sequence information from ESP headers
-   packet lengths and timestamps
-   source/destination and flow relationships

### Inferred

Examples include:

-   application traffic class inside encrypted ESP flows
-   some operational characteristics when the relevant handshake is
    absent
-   statistical characteristics of encrypted sessions

Every inferred result must preserve uncertainty. The system must not
represent an inference as directly observed evidence.

## 4. Major Functional Areas

### 4.1 Traffic Ingestion

Inputs:

-   `.pcap`
-   `.pcapng`
-   later, live network interfaces

Responsibilities:

-   read packet streams
-   identify relevant IPsec traffic
-   separate IKE from ESP/AH
-   preserve timestamps and packet metadata
-   create normalized internal records

### 4.2 IKE Dissection

Support targets:

-   IKEv1
-   IKEv2
-   UDP/500
-   UDP/4500 / NAT-T

The parser should reconstruct relevant exchanges and extract available:

-   Security Association information
-   proposals
-   transforms
-   encryption algorithms
-   integrity algorithms
-   PRF information
-   Diffie-Hellman groups
-   authentication information where observable
-   lifetime/rekey information where observable
-   vendor identifiers where useful

### 4.3 ESP/AH Analysis

The analyzer should identify:

-   ESP
-   AH
-   native ESP
-   NAT-T encapsulated ESP
-   SPI
-   sequence numbers
-   flow direction
-   packet-size characteristics
-   inter-arrival timing
-   burst characteristics
-   directional ratios
-   flow-level statistics

### 4.4 AI / Statistical Analysis

The AI layer is not a replacement for protocol parsing.

Use deterministic parsing when protocol fields are available.

Use ML/statistical inference for problems such as:

-   encrypted traffic classification
-   traffic-pattern classification
-   anomaly/uncertainty-aware inference
-   cases where the handshake is unavailable

The research proposes XGBoost as a practical structured-feature
classifier and deeper sequence models as an optional advanced layer.

### 4.5 Security Assessment

Assessment dimensions include:

-   cryptographic strength
-   algorithm/configuration compliance
-   Security Association parameters
-   key lifetime/rekey characteristics
-   replay protection
-   PFS status where determinable
-   metadata exposure
-   obsolete or weak cryptographic choices

The assessment engine must produce evidence-backed findings.

### 4.6 Risk and Threat Analysis

Each finding should contain, where applicable:

-   finding ID
-   observed parameter
-   evidence
-   severity
-   affected component
-   security implication
-   applicable baseline/rule
-   remediation
-   confidence/observability status

Threat mappings may use MITRE ATT&CK where a defensible mapping exists.

### 4.7 Dashboard

The dashboard should provide:

-   scan/session overview
-   detected IPsec sessions
-   IKE details
-   cryptographic parameters
-   ESP flow statistics
-   AI classifications
-   security findings
-   compliance view
-   risk posture
-   remediation guidance
-   confidence/uncertainty
-   report export

### 4.8 Reporting

Two report views are planned:

1.  **Executive Security Posture Report**
2.  **Technical Engineering Report**

The technical report should preserve sufficient evidence for an analyst
to reproduce or investigate a finding.

## 5. Testbed and Dataset Strategy

A controlled IPsec testbed is required for reproducible validation and
labeled data generation.

The research proposes:

-   Linux network namespaces
-   virtual Ethernet pairs
-   isolated client/WAN/server domains
-   strongSwan and/or Libreswan
-   Linux XFRM IPsec
-   configurable cryptographic parameters
-   packet capture
-   controlled application traffic generation

Candidate configuration dimensions include:

-   tunnel vs transport
-   IKEv1 vs IKEv2
-   AES-CBC / AES-GCM
-   legacy vs modern integrity algorithms
-   DH groups
-   PFS enabled/disabled
-   native ESP / NAT-T
-   replay-protection variants
-   IPv4/IPv6 scenarios

The dataset must retain ground-truth labels from the testbed
configuration.

## 6. Technology Status

| Area | Implemented now | Later candidate, subject to validation |
| --- | --- | --- |
| Packet parsing | Bounded Python PCAP/PCAPNG and visible IKE/ESP/AH parser | Dedicated capture/decoder tooling if coverage requires it |
| Backend | Python and local FastAPI API | Durable jobs and storage when needed |
| ML | One-host synthetic structured classifier with abstention and held-out pilot evaluation | Independent-host and broader traffic validation |
| Testbed | Isolated Linux namespaces, strongSwan peers, capture orchestration and pinned pilot dataset | Independent reproduction and broader scenario coverage |
| Dashboard | Local HTML, CSS and JavaScript analyst views with rule evidence and inference separation | Durable jobs and deployment access control |
| Reports | Full analysis JSON plus executive/technical report JSON, text, HTML and text-only PDF with shared-copy redaction | Richer report layout and deployment-specific sharing controls |

The proposed library and infrastructure choices are not dependencies or
implemented capabilities. Add them only after a concrete need is verified.

## 7. Security Assessment Baselines

The research identifies the following standards as candidate assessment
references:

-   NIST SP 800-77 Rev. 1
-   RFC 8221
-   RFC 8247
-   RFC 9395
-   CNSA-related requirements where applicable

The implementation must preserve the distinction between:

-   a protocol fact
-   a security rule
-   a standard requirement
-   a project-specific scoring decision

Standards claims must be traceable to their source.

## 8. Important Non-Goals

The initial implementation must not claim capabilities that cannot be
supported by observable traffic or validated experiments.

In particular:

-   Do not claim decryption of ESP payloads without keys.
-   Do not claim direct visibility into hidden configuration.
-   Do not present statistical inference as deterministic parsing.
-   Do not manufacture AI accuracy figures.
-   Do not claim enterprise-scale throughput without measurement.
-   Do not claim live-capture support unless it is implemented and
    tested.
-   Do not claim a classifier is reliable merely because it produces a
    confidence value.

## 9. Evidence and Confidence Model

Every analysis result should have an evidence state:

-   `OBSERVED`: directly extracted from protocol or packet information.
-   `DERIVED`: calculated from observed fields.
-   `INFERRED`: estimated using statistical or ML analysis.
-   `UNKNOWN`: required evidence was not available.

AI results should additionally expose confidence and, where possible,
model/calibration information.

## 10. Example Finding Format

The following is a format example, not an assessment produced by the
current rule set:

``` text
Finding ID: IPSEC-CRYPTO-001
Component: IKE
Observation: Deprecated/weak cryptographic parameter detected
Evidence: Parsed IKE proposal / transform
Severity: High
Assessment: Non-compliant with selected baseline
Impact: Reduced cryptographic security
Recommendation: Replace with an approved modern configuration
Evidence State: OBSERVED
```

The exact severity and rule must come from the project's versioned rule
set.

## 11. Development Philosophy

The implementation should follow this order:

1.  deterministic packet parsing
2.  normalized data model
3.  rule-based security assessment
4.  reproducible testbed
5.  labeled dataset
6.  ML/AI inference
7.  confidence handling
8.  dashboard
9.  reporting
10. live/advanced capabilities

This prevents the project from becoming an AI demo without a trustworthy
protocol-analysis foundation.

## 12. Current Scope

The project documentation is intentionally divided into:

-   **Required:** directly aligned with SIH26160 requirements
-   **Core prototype:** feasible and demonstrable implementation
-   **Advanced:** additional capability that can be developed after the
    core pipeline works

The distinction must remain explicit in all project documentation and
presentations.

## 13. Project Status

This repository is being developed as an SIH26160 proposal/prototype.

Implementation decisions prioritize a defensible, demonstrable end-to-end
core. Add infrastructure only when a verified requirement calls for it.

### Implemented foundation

The repository now contains offline PCAP/PCAPNG ingestion, bounded visible
IKEv1 and IKEv2 SA proposal parsing, IKE exchange correlation, packet-linked
evidence, and directional ESP/AH flow summaries. It also contains three
RFC-backed IKE rules, packet-linked findings, a synchronous local API, a plain-text technical report
and an analyst dashboard. Phases 0–3 are complete for their documented
prototype scopes. The assessment withholds a comprehensive security score.
IKEv1 decoding is limited to IPsec DOI 1 with identity-only situation;
Passive Child SA configuration inference, validated encrypted application
classification and live capture are not yet available. The working WSL testbed
and pilot captures are documented in [testbed/README.md](testbed/README.md).

The dashboard includes [Privacy Policy](dashboard/web/privacy.html) and
[Terms and Conditions](dashboard/web/terms.html) pages. Its design constraints
are recorded in [UI_DIRECTION.md](docs/design/UI_DIRECTION.md).

Use Python 3.11 or later:

```text
python -m pip install -e ".[test]"
python -m pytest -q
ipsec-analyzer tests/fixtures/synthetic_ipsec.pcap
ipsec-analyzer tests/fixtures/synthetic_ipsec.pcap --analyze text
uvicorn ipsec_analyzer.api.app:app --host 127.0.0.1 --port 8000
```

The tiny synthetic PCAP and PCAPNG fixtures can be rebuilt with
`python tests/fixtures/build_fixtures.py`. A separate 1,448-byte public
Wireshark capture verifies an independently produced IKEv2 handshake; its
source and hash are recorded in
[PUBLIC_CAPTURE_SOURCE.md](tests/fixtures/PUBLIC_CAPTURE_SOURCE.md). The CLI
emits the versioned normalized capture contract as JSON. Current input limits
are 128 MiB per capture, 4 MiB per packet and 250,000 packets; analysis also
caps IKE messages at 10,000 and evidence subjects at 5,000. See
[INGESTION_SUPPORT.md](docs/design/INGESTION_SUPPORT.md) and
[CORRELATION_AND_EVIDENCE.md](docs/design/CORRELATION_AND_EVIDENCE.md). The
local dashboard is at `http://127.0.0.1:8000/` and accepts captures up to
16 MiB. It has no user authentication and must stay bound to loopback.
The charcoal and violet editorial frontend serves its Motion animation bundle locally.
After changing `dashboard/web/motion-src.js`, run `npm ci` and
`npm run build:motion`; the generated bundle is served by the Python app.

## 14. Documentation

-   `README.md` --- project overview and operating principles
-   `ARCHITECTURE.md` --- system architecture and data flow
-   `DIRECTORY_CONSTRAINTS.md` --- repository structure and file
    ownership rules
-   `PR.md` --- pull-request/change requirements
-   `docs/design/IMPLEMENTATION_PHASES.md` --- phased implementation and acceptance plan
-   `docs/design/IMPLEMENTATION_STATUS.md` --- verified phase status and remaining work
-   `docs/design/CORRELATION_AND_EVIDENCE.md` --- current Phase 2 association and evidence rules
-   `docs/design/FRONTEND_REDESIGN_PLAN.md` --- planned glass, cyber and natural analyst UI refresh
-   `docs/design/UI_DIRECTION.md` --- analyst interface design rules
