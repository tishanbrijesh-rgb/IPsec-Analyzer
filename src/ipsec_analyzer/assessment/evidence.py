"""Build bounded, packet-linked evidence for sessions and flows."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ipsec_analyzer.assessment.sessions import Session
from ipsec_analyzer.features.flows import Flow
from ipsec_analyzer.models.evidence import Evidence
from ipsec_analyzer.models.packets import EvidenceState


def describe_evidence(
    capture_id: str, sessions: list[Session], flows: list[Flow],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    session_records: list[dict[str, Any]] = []
    flow_records: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    def add(subject_id: str, field: str, state: EvidenceState, value: Any,
            packets: tuple[int, ...], method: str | None = None,
            reason: str | None = None) -> str:
        entry = Evidence(f"{subject_id}:{field}", subject_id, field, state, value, packets, method, reason)
        evidence.append(entry.to_dict())
        return entry.id

    for index, session in enumerate(sessions, 1):
        subject_id = f"{capture_id}:ike:{index}"
        record = session.to_dict()
        record["id"] = subject_id
        packet_refs = tuple(dict.fromkeys(session.request_packets + session.response_packets))
        refs = [
            add(subject_id, "endpoints", EvidenceState.OBSERVED, session.endpoints, packet_refs),
            add(subject_id, "initiator_spi", EvidenceState.OBSERVED, session.initiator_spi, packet_refs),
            add(subject_id, "responder_spi", EvidenceState.OBSERVED, session.responder_spi, packet_refs),
            add(subject_id, "version_major", EvidenceState.OBSERVED, session.version_major, packet_refs),
            add(subject_id, "association_state", EvidenceState.DERIVED, session.association_state,
                packet_refs, method="ike-correlation-1"),
        ]
        if session.offered:
            refs.append(add(subject_id, "offered", EvidenceState.OBSERVED,
                            [asdict(proposal) for proposal in session.offered],
                            tuple(session.offer_evidence_packets)))
        if session.selected is not None and session.selected_evidence_packet is not None:
            refs.append(add(subject_id, "selected", EvidenceState.OBSERVED,
                            asdict(session.selected), (session.selected_evidence_packet,)))
        else:
            reason = "Conflicting response proposals" if session.selection_state == "AMBIGUOUS" else "No unambiguous selected response was captured"
            refs.append(add(subject_id, "selected", EvidenceState.UNKNOWN, None, (), reason=reason))
        for field, reason in (
            ("pfs", "Encrypted Child SA settings are not visible"),
            ("mode", "Outer packets do not establish tunnel or transport mode"),
            ("replay_configuration", "Observed sequence numbers do not reveal gateway replay policy"),
        ):
            refs.append(add(subject_id, field, EvidenceState.UNKNOWN, None, (), reason=reason))
        record["evidence_ids"] = refs
        session_records.append(record)

    for index, flow in enumerate(flows, 1):
        subject_id = f"{capture_id}:flow:{index}"
        record = flow.to_dict()
        record["id"] = subject_id
        packet_refs = tuple(flow.packet_indices)
        refs = [
            add(subject_id, "source", EvidenceState.OBSERVED, flow.source, packet_refs),
            add(subject_id, "destination", EvidenceState.OBSERVED, flow.destination, packet_refs),
            add(subject_id, "kind", EvidenceState.OBSERVED, flow.kind, packet_refs),
            add(subject_id, "spi", EvidenceState.OBSERVED, flow.spi, packet_refs),
            add(subject_id, "encapsulation", EvidenceState.OBSERVED, flow.encapsulation, packet_refs),
            add(subject_id, "link_type", EvidenceState.OBSERVED, flow.link_type, packet_refs),
        ]
        for field in ("packet_count", "byte_count", "mean_length", "mean_interarrival_ns"):
            value = record[field]
            if value is None:
                refs.append(add(subject_id, field, EvidenceState.UNKNOWN, None, (),
                                reason="Insufficient or nonmonotonic timestamps"))
            else:
                refs.append(add(subject_id, field, EvidenceState.DERIVED, value, packet_refs,
                                method="flow-summary-1"))
        record["evidence_ids"] = refs
        flow_records.append(record)
    return session_records, flow_records, evidence
