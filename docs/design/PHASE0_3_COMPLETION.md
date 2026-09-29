# Phase 0–3 completion gate

**Checked:** 29 September 2026. **Decision:** all exit checks in
[`IMPLEMENTATION_PHASES.md`](IMPLEMENTATION_PHASES.md) pass for the documented
offline, visible-evidence prototype. This is a bounded completion claim, not
support for every capture format, IPsec mode, cipher or deployment policy.

| Phase | Exit evidence | Result |
| --- | --- | --- |
| 0 — Foundation | PCAP/PCAPNG normalized equivalence; malformed/truncated/unsupported diagnostics; 128 MiB file and 4 MiB packet bounds; 8 MiB and 10,000-record memory checks in [`INGESTION_SUPPORT.md`](INGESTION_SUPPORT.md) | Pass |
| 1 — Dissection | Bounded IKEv1/IKEv2 parsing, SA offer versus selected response, invalid payload diagnostics, ESP/AH SPI and sequence, NAT-T evidence, independent sanitized Wireshark handshake | Pass |
| 2 — Correlation | Concurrent and partial SAs, retransmission candidates, ambiguous zero-responder associations, idle SPI reuse, packet-linked observed/derived/unknown evidence | Pass |
| 3 — Assessment | Strong and DES-weak captures, four rule statuses, source-backed versioned rules, packet and evidence links, coverage-aware pass rate, withheld overall score, technical report | Pass |

The focused Phase 0–3 suite (`test_ingestion.py`, `test_ike_parser.py`,
`test_sessions.py`, `test_assessment.py`, `test_public_capture.py`) passed
**44 tests**. The full suite passed **90 tests** after the Phase 4 index integrity check was added. A direct CLI run on
`data/sample/modern-tunnel.pcap` normalized 10 packets (4 IKE, 6 ESP) with
no diagnostics and produced a report with one IKE session, two directional
ESP flows, three traceable rule evaluations and a withheld overall score.

## Explicit limits

- The reader has a 128 MiB whole-file bound. Streaming is a later capability
  if representative captures require it; current controlled demo captures do
  not exceed the bound.
- Other link types, unhandled IKEv1 DOI/situations, encrypted Child SA
  settings and indistinguishable concurrent SPI pairs cannot be reported as
  confidently decoded facts. The result records unknown or ambiguous states.
- Three visible rules do not justify a comprehensive security or risk score.
  Expanding the risk model requires broader rules, capture evidence and
  validation; a perfect score for the current narrow rule set would mislead.
- Executive and PDF/HTML/JSON exports were subsequently delivered with Phase
  6. They extend the Phase 3 technical report and do not change its evidence
  boundary.

The next backend work should concentrate on Phase 4 independent reproduction,
Phase 5 external validation, and Phase 6 durability and access control. Broader
Phase 0–3 protocol support should start from a named capture and acceptance
case rather than an unbounded claim of full IPsec visibility.
