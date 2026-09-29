"""Correlate IKE messages without upgrading offers into negotiated values."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ipsec_analyzer.parsers.ike import IkeMessage, Proposal

IKE_IDLE_AMBIGUITY_NS = 30 * 60 * 1_000_000_000


@dataclass
class Exchange:
    exchange_type: int
    message_id: int
    request_packets: list[int] = field(default_factory=list)
    response_packets: list[int] = field(default_factory=list)
    retransmission_candidates: list[int] = field(default_factory=list)
    status: str = "UNKNOWN"


@dataclass
class Session:
    endpoints: tuple[str, str]
    initiator_spi: str
    responder_spi: str
    version_major: int
    request_packets: list[int] = field(default_factory=list)
    response_packets: list[int] = field(default_factory=list)
    offered: list[Proposal] = field(default_factory=list)
    offer_evidence_packets: list[int] = field(default_factory=list)
    selected: Proposal | None = None
    selected_evidence_packet: int | None = None
    selection_state: str = "UNKNOWN"
    association_state: str = "UNAMBIGUOUS"
    retransmission_candidates: list[int] = field(default_factory=list)
    exchanges: list[Exchange] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def correlate_messages(messages: list[IkeMessage]) -> list[Session]:
    sessions: dict[tuple[tuple[str, str], int, str, str], Session] = {}
    completed_by_base: dict[tuple[tuple[str, str], int, str], set[tuple[tuple[str, str], int, str, str]]] = {}
    seen_wire_hashes: dict[int, set[str]] = {}
    last_seen_ns: dict[int, int] = {}
    exchanges_by_session: dict[int, dict[tuple[int, int], Exchange]] = {}
    for message in messages:
        endpoints = tuple(sorted((message.source or "", message.destination or "")))
        # Keep IKE versions separate; a zero responder SPI may match a single completed SA.
        base = (endpoints, message.version_major, message.initiator_spi)
        key = (*base, message.responder_spi)
        ambiguous_match = False
        if message.responder_spi == "0000000000000000":
            matches = list(completed_by_base.get(base, ()))
            if len(matches) == 1:
                key = matches[0]
            elif len(matches) > 1:
                ambiguous_match = True
        elif key not in sessions:
            pending = (*base, "0000000000000000")
            competing = bool(completed_by_base.get(base))
            if pending in sessions and not competing and sessions[pending].association_state == "UNAMBIGUOUS":
                sessions[key] = sessions.pop(pending)
                sessions[key].responder_spi = message.responder_spi
            elif pending in sessions:
                sessions[pending].association_state = "AMBIGUOUS"
                if "Zero-responder messages match multiple candidate SAs" not in sessions[pending].diagnostics:
                    sessions[pending].diagnostics.append("Zero-responder messages match multiple candidate SAs")
        session = sessions.setdefault(key, Session(endpoints, message.initiator_spi, key[3], message.version_major))
        if key[3] != "0000000000000000":
            completed_by_base.setdefault(base, set()).add(key)
        if ambiguous_match:
            session.association_state = "AMBIGUOUS"
            if "Zero-responder messages match multiple candidate SAs" not in session.diagnostics:
                session.diagnostics.append("Zero-responder messages match multiple candidate SAs")
        if message.timestamp_ns is not None:
            prior_ns = last_seen_ns.get(id(session))
            if prior_ns is not None and message.timestamp_ns - prior_ns > IKE_IDLE_AMBIGUITY_NS:
                session.association_state = "AMBIGUOUS"
                session.selection_state = "AMBIGUOUS"
                session.selected = None
                session.selected_evidence_packet = None
                if "Long idle gap; IKE SPI continuity is unknown" not in session.diagnostics:
                    session.diagnostics.append("Long idle gap; IKE SPI continuity is unknown")
            last_seen_ns[id(session)] = message.timestamp_ns
        if message.is_response:
            if message.packet_index not in session.response_packets:
                session.response_packets.append(message.packet_index)
        elif message.packet_index not in session.request_packets:
            session.request_packets.append(message.packet_index)
        exchange_key = (message.exchange_type, message.message_id)
        exchange_map = exchanges_by_session.setdefault(id(session), {})
        exchange = exchange_map.get(exchange_key)
        if exchange is None:
            exchange = Exchange(*exchange_key)
            exchange_map[exchange_key] = exchange
            session.exchanges.append(exchange)
        if message.is_response:
            exchange.response_packets.append(message.packet_index)
        else:
            exchange.request_packets.append(message.packet_index)
        if message.version_major == 1:
            exchange.status = "DIRECTION_UNKNOWN"
        elif exchange.request_packets and exchange.response_packets:
            exchange.status = "PAIRED"
        elif exchange.request_packets:
            exchange.status = "REQUEST_ONLY"
        else:
            exchange.status = "RESPONSE_ONLY"
        fingerprints = seen_wire_hashes.setdefault(id(session), set())
        if message.wire_hash and message.wire_hash in fingerprints:
            session.retransmission_candidates.append(message.packet_index)
            exchange.retransmission_candidates.append(message.packet_index)
            continue
        if message.wire_hash:
            fingerprints.add(message.wire_hash)
        if message.is_response:
            if message.exchange_type == 34 and message.message_id == 0 and message.proposals and not message.diagnostics:
                if len(message.proposals) == 1 and session.selection_state != "AMBIGUOUS":
                    candidate = message.proposals[0]
                    if session.selected is None or session.selected == candidate:
                        session.selected = candidate
                        session.selected_evidence_packet = message.packet_index
                        session.selection_state = "OBSERVED"
                    else:
                        session.selected = None
                        session.selected_evidence_packet = None
                        session.selection_state = "AMBIGUOUS"
                        session.diagnostics.append("Conflicting response proposals; selected transform unknown")
                elif len(message.proposals) != 1:
                    session.selection_state = "AMBIGUOUS"
                    session.selected = None
                    session.selected_evidence_packet = None
                    if "Multiple response proposals; selected transform unknown" not in session.diagnostics:
                        session.diagnostics.append("Multiple response proposals; selected transform unknown")
        else:
            if message.exchange_type == 34 and message.message_id == 0 and message.proposals and not message.diagnostics:
                session.offered.extend(message.proposals)
                session.offer_evidence_packets.append(message.packet_index)
    return list(sessions.values())
