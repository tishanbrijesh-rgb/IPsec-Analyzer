from dataclasses import replace

from ipsec_analyzer.assessment.sessions import correlate_messages
from ipsec_analyzer.features.flows import build_flows
from ipsec_analyzer.ingestion.capture import read_capture
from ipsec_analyzer.parsers.ike import parse_ike
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
import struct
from tests.test_ike_parser import ike_sa_message


def test_offer_and_selection_are_distinct(tmp_path):
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = ipv4_packet(17, udp(500, 500, ike_sa_message(True)))
    capture = read_capture(write_pcap(tmp_path / "exchange.pcap", [request, response]))
    only_request = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert only_request is not None
    pending = correlate_messages([only_request])[0]
    assert pending.offered and pending.selected is None
    reply = parse_ike(capture.packets[1], capture.raw_frames[1])
    assert reply is not None
    session = correlate_messages([only_request, reply])[0]
    assert session.selected is not None
    assert session.selected_evidence_packet == 2
    assert [(exchange.exchange_type, exchange.message_id, exchange.status) for exchange in session.exchanges] == [(34, 0, "PAIRED")]


def test_directional_flows(tmp_path):
    capture = read_capture(write_pcap(tmp_path / "flows.pcap"))
    flows = build_flows(capture.packets)
    assert len(flows) == 2
    assert {flow.spi for flow in flows} == {0x12345678, 0x87654321}
    assert all(flow.to_dict()["evidence_state"] == "DERIVED" for flow in flows)


def test_native_and_udp_encapsulated_esp_remain_distinct(tmp_path):
    esp = struct.pack("!II", 0x12345678, 7) + b"ciphertext"
    capture = read_capture(write_pcap(tmp_path / "encapsulation.pcap", [
        ipv4_packet(50, esp),
        ipv4_packet(17, udp(4500, 4500, esp)),
    ]))
    flows = build_flows(capture.packets)
    assert len(flows) == 2
    assert {flow.encapsulation for flow in flows} == {"NATIVE_IP", "UDP_4500"}


def test_retransmission_does_not_duplicate_offer_and_conflict_withholds_selection(tmp_path):
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = ipv4_packet(17, udp(500, 500, ike_sa_message(True)))
    capture = read_capture(write_pcap(tmp_path / "retransmit.pcap", [request, request, response]))
    messages = [parse_ike(event, frame) for event, frame in zip(capture.packets, capture.raw_frames)]
    assert all(message is not None for message in messages)
    session = correlate_messages(messages)[0]
    assert len(session.offered) == 1
    assert session.offer_evidence_packets == [1]
    assert session.retransmission_candidates == [2]
    assert session.exchanges[0].retransmission_candidates == [2]
    assert session.selected_evidence_packet == 3

    selected = messages[2].proposals[0]
    conflicting = replace(messages[2], packet_index=4, wire_hash="different", proposals=[
        replace(selected, transforms=(replace(selected.transforms[0], transform_id=99), *selected.transforms[1:]))
    ])
    session = correlate_messages([*messages, conflicting])[0]
    assert session.selected is None
    assert session.selection_state == "AMBIGUOUS"
    assert session.selected_evidence_packet is None


def test_partial_ike_exchange_remains_partial(tmp_path):
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    capture = read_capture(write_pcap(tmp_path / "partial-exchange.pcap", [request]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    session = correlate_messages([message])[0]
    assert session.exchanges[0].status == "REQUEST_ONLY"
    assert session.exchanges[0].response_packets == []
    assert session.selection_state == "UNKNOWN"
    assert session.selected_evidence_packet is None


def test_zero_responder_cookie_is_ambiguous_with_concurrent_sas(tmp_path):
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = ipv4_packet(17, udp(500, 500, ike_sa_message(True)))
    capture = read_capture(write_pcap(tmp_path / "concurrent.pcap", [request, response]))
    initial, first_reply = [parse_ike(event, frame) for event, frame in zip(capture.packets, capture.raw_frames)]
    assert initial is not None and first_reply is not None
    second_reply = replace(first_reply, packet_index=3, responder_spi="03" * 8, wire_hash="second")
    late_request = replace(initial, packet_index=4)
    sessions = correlate_messages([initial, first_reply, second_reply, late_request])
    assert len(sessions) == 3
    ambiguous = next(session for session in sessions if session.responder_spi == "00" * 8)
    assert ambiguous.association_state == "AMBIGUOUS"
    assert ambiguous.selected is None


def test_long_idle_gap_with_same_ike_spis_withholds_selection(tmp_path):
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = ipv4_packet(17, udp(500, 500, ike_sa_message(True)))
    capture = read_capture(write_pcap(tmp_path / "ike-idle.pcap", [request, response]))
    initial, reply = [parse_ike(event, frame) for event, frame in zip(capture.packets, capture.raw_frames)]
    assert initial is not None and reply is not None
    late_reply = replace(reply, packet_index=3, timestamp_ns=2_000_000_000_000)
    session = correlate_messages([initial, reply, late_reply])[0]
    assert session.association_state == "AMBIGUOUS"
    assert session.selection_state == "AMBIGUOUS"
    assert session.selected is None


def test_idle_spi_reuse_is_split_with_uncertainty(tmp_path):
    frame = ipv4_packet(50, struct.pack("!II", 55, 1) + b"ciphertext")
    capture = read_capture(write_pcap(tmp_path / "reuse.pcap", [frame, frame, frame]))
    packets = [
        replace(capture.packets[0], timestamp_ns=0, sequence=1),
        replace(capture.packets[1], timestamp_ns=1_000_000_000, sequence=2),
        replace(capture.packets[2], timestamp_ns=360_000_000_000, sequence=1),
    ]
    flows = build_flows(packets)
    assert len(flows) == 2
    assert [flow.episode for flow in flows] == [1, 2]
    assert all(flow.association_state == "TIME_SPLIT_UNCERTAIN" for flow in flows)
    assert [flow.packet_indices for flow in flows] == [[1, 2], [3]]


def test_nonmonotonic_timestamps_withhold_interarrival(tmp_path):
    frame = ipv4_packet(50, struct.pack("!II", 55, 1) + b"ciphertext")
    capture = read_capture(write_pcap(tmp_path / "timestamps.pcap", [frame, frame]))
    packets = [
        replace(capture.packets[0], timestamp_ns=2_000_000_000),
        replace(capture.packets[1], timestamp_ns=1_000_000_000),
    ]
    summary = build_flows(packets)[0].to_dict()
    assert summary["mean_interarrival_ns"] is None
    assert "Nonmonotonic timestamps; interarrival unavailable" in summary["diagnostics"]


def test_mixed_link_types_do_not_share_captured_byte_total(tmp_path):
    frame = ipv4_packet(50, struct.pack("!II", 55, 1) + b"ciphertext")
    capture = read_capture(write_pcap(tmp_path / "link-types.pcap", [frame]))
    ethernet = capture.packets[0]
    raw_ip = replace(ethernet, index=2, link_type=101, captured_length=ethernet.captured_length - 14)
    summaries = [flow.to_dict() for flow in build_flows([ethernet, raw_ip])]
    assert len(summaries) == 2
    assert {summary["byte_count"] for summary in summaries} == {ethernet.captured_length, raw_ip.captured_length}
    assert all(summary["byte_count_unit"] == "captured_frame_bytes" for summary in summaries)
