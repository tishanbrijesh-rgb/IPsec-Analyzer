# Offline correlation and evidence contract

Phase 2 groups IKE messages by sorted outer endpoints, IKE version, initiator
SPI and responder SPI. A request with a zero responder SPI joins a completed
SA only when exactly one candidate exists. Otherwise it stays in an ambiguous
session. Exchanges within a session use exchange type and message ID, and
record request, response and partial status. IKEv1 direction remains unknown
because the current parser does not infer a response bit for IKEv1.
Byte-identical IKE messages are
listed as `retransmission_candidates`; this is an observation, not proof of
why the packet appeared again.

Conflicting selected response proposals remove the selected value and mark
selection ambiguous. A gap over 30 minutes between packets with the same IKE
SPI pair marks SA continuity ambiguous and withholds the selected value.
This threshold is a conservative prototype heuristic, not an IKE lifetime
claim. Indistinguishable concurrent exchanges sharing both SPIs and endpoints
cannot be separated from passive capture alone.

ESP/AH flows are directional. The key includes source, destination, kind,
SPI, encapsulation and link type. A gap over five minutes starts a new flow
episode and marks both episodes `TIME_SPLIT_UNCERTAIN`; it does not prove a
new SA or SPI reuse. Sequence regressions are counted as observations, not
interpreted as packet loss or disabled replay protection. Nonmonotonic
timestamps withhold mean interarrival time.

Each session and flow has a stable ID within the capture result and
`evidence_ids` pointing to evidence records. Evidence states are `OBSERVED`,
`DERIVED`, `INFERRED` and `UNKNOWN`. Observed and derived records include
packet indices; derived records name a method. Unknown records contain a
reason and null value. No inferred record is emitted until a validated model
is available. PFS, mode and replay configuration remain unknown from the
current passive data. Flow byte totals are captured frame bytes and are not
decrypted payload sizes.

The offline pipeline caps IKE messages at 10,000 and session plus flow
evidence subjects at 5,000 to bound result expansion. Exceeding either limit
returns a capture error rather than a partial success.
