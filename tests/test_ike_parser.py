import struct

from ipsec_analyzer.ingestion.capture import read_capture
from ipsec_analyzer.parsers.ike import parse_ike
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap


def ike_sa_message(response: bool = False) -> bytes:
    transform = struct.pack("!BBHBBH", 0, 0, 12, 1, 0, 12) + struct.pack("!HH", 0x800E, 256)
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    header = (
        b"\x01" * 8 + (b"\x02" * 8 if response else b"\0" * 8)
        + bytes([33, 0x20, 34, 0x20 if response else 0x08])
        + struct.pack("!II", 0, 28 + len(sa))
    )
    return header + sa


def test_v2_sa_proposal_and_response(tmp_path):
    frames = [
        ipv4_packet(17, udp(500, 500, ike_sa_message())),
        ipv4_packet(17, udp(500, 500, ike_sa_message(True))),
    ]
    capture = read_capture(write_pcap(tmp_path / "sa.pcap", frames))
    request, response = [
        parse_ike(event, frame)
        for event, frame in zip(capture.packets, capture.raw_frames)
    ]
    assert request is not None and response is not None
    assert request.version_major == 2
    assert request.is_response is False
    assert response.is_response is True
    assert request.proposals[0].transforms[0].key_length_bits == 256
    assert request.proposals[0].transforms[0].transform_id == 12
    assert not request.diagnostics


def test_bad_proposal_reports_diagnostic(tmp_path):
    raw = bytearray(ike_sa_message())
    raw[28 + 4 + 2:28 + 4 + 4] = b"\0\x02"
    capture = read_capture(write_pcap(tmp_path / "bad-sa.pcap", [ipv4_packet(17, udp(500, 500, bytes(raw)))]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    assert message.diagnostics[0].code == "INVALID_PROPOSAL_LENGTH"


def test_v2_malformed_attribute_never_returns_partial_proposal(tmp_path):
    raw = bytearray(ike_sa_message())
    raw[28 + 4 + 8 + 8:28 + 4 + 8 + 12] = struct.pack("!HH", 14, 100)
    capture = read_capture(write_pcap(tmp_path / "bad-v2-attr.pcap", [ipv4_packet(17, udp(500, 500, bytes(raw)))]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    assert message.proposals == []
    assert message.diagnostics[0].code == "INVALID_TRANSFORM_ATTRIBUTE"


def ike_v1_sa_message(attribute: bytes | None = None, encrypted: bool = False) -> bytes:
    attributes = attribute if attribute is not None else struct.pack("!HHHH", 0x8001, 7, 0x8004, 14)
    transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attributes), 1, 1, 0) + attributes
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack("!BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    header = b"\x01" * 8 + b"\0" * 8 + bytes([1, 0x10, 2, 1 if encrypted else 0])
    return header + struct.pack("!II", 0, 28 + len(sa)) + sa


def test_v1_sa_attributes_are_visible_without_claiming_selection(tmp_path):
    raw = ike_v1_sa_message()
    capture = read_capture(write_pcap(tmp_path / "v1.pcap", [ipv4_packet(17, udp(500, 500, raw))]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    assert message.version_major == 1
    assert message.proposals == []
    assert message.v1_proposals[0].transforms[0].attributes[0].attribute_type == 1
    assert message.v1_proposals[0].transforms[0].attributes[0].value == 7
    assert message.v1_proposals[0].transforms[0].attributes[1].value == 14
    assert not message.diagnostics


def test_v1_invalid_attribute_and_encrypted_payload_are_diagnostic(tmp_path):
    invalid = ike_v1_sa_message(struct.pack("!HH", 1, 100))
    encrypted = ike_v1_sa_message(encrypted=True)
    capture = read_capture(write_pcap(tmp_path / "v1-invalid.pcap", [
        ipv4_packet(17, udp(500, 500, invalid)),
        ipv4_packet(17, udp(500, 500, encrypted)),
    ]))
    messages = [parse_ike(event, frame) for event, frame in zip(capture.packets, capture.raw_frames)]
    assert messages[0] is not None and messages[1] is not None
    assert messages[0].v1_proposals == []
    assert messages[0].diagnostics[0].code == "INVALID_TRANSFORM_ATTRIBUTE"
    assert messages[1].v1_proposals == []
    assert messages[1].diagnostics[0].code == "ENCRYPTED_IKE_PAYLOAD"


def test_v1_empty_sa_is_not_a_valid_proposal(tmp_path):
    raw = bytearray(ike_v1_sa_message())
    raw[30:32] = struct.pack("!H", 12)
    raw[24:28] = struct.pack("!I", 40)
    capture = read_capture(write_pcap(tmp_path / "v1-empty.pcap", [ipv4_packet(17, udp(500, 500, bytes(raw[:40])))]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    assert message.v1_proposals == []
    assert message.diagnostics[0].code == "EMPTY_V1_SA"


def test_v1_opaque_attribute_bytes_are_not_exported(tmp_path):
    raw = ike_v1_sa_message(struct.pack("!HH", 100, 8) + b"secret!!")
    capture = read_capture(write_pcap(tmp_path / "v1-opaque.pcap", [ipv4_packet(17, udp(500, 500, raw))]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    attribute = message.v1_proposals[0].transforms[0].attributes[0]
    assert attribute.value is None
    assert attribute.value_length_bytes == 8
    assert "secret" not in str(message.to_dict())


def test_v1_attribute_count_is_bounded(tmp_path):
    raw = ike_v1_sa_message(struct.pack("!HH", 0x8001, 7) * 129)
    capture = read_capture(write_pcap(tmp_path / "v1-many-attributes.pcap", [ipv4_packet(17, udp(500, 500, raw))]))
    message = parse_ike(capture.packets[0], capture.raw_frames[0])
    assert message is not None
    assert message.v1_proposals == []
    assert message.diagnostics[0].code == "ATTRIBUTE_LIMIT"
