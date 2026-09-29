"""Regression against a small capture maintained by the Wireshark project."""

from hashlib import sha256
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import read_capture
from ipsec_analyzer.models.packets import PacketKind
from ipsec_analyzer.parsers.ike import parse_ike


CAPTURE = Path(__file__).parent / "fixtures" / "wireshark_ikev2_aes256gcm16.pcap"
SHA256 = "86505314cc2cbe68b1c4af270d099cab234e64595277bb572f18dfaab2654179"


def test_wireshark_ikev2_handshake():
    assert sha256(CAPTURE.read_bytes()).hexdigest() == SHA256
    capture = read_capture(CAPTURE)
    assert len(capture.packets) == 6
    assert not capture.diagnostics
    assert all(packet.kind == PacketKind.IKE for packet in capture.packets)

    messages = [parse_ike(event, frame) for event, frame in zip(capture.packets, capture.raw_frames)]
    assert all(message is not None for message in messages)
    request, response = messages[:2]
    assert request.exchange_type == response.exchange_type == 34
    assert request.is_response is False and response.is_response is True
    expected = [(1, 20, 256), (2, 5, None), (4, 19, None)]
    for message in (request, response):
        assert not message.diagnostics
        assert [(t.transform_type, t.transform_id, t.key_length_bits) for t in message.proposals[0].transforms] == expected
    assert all(message.proposals == [] for message in messages[2:])
    assert all(message.diagnostics[0].code == "ENCRYPTED_IKE_PAYLOAD" for message in messages[2:])

    result = analyze_capture(CAPTURE).to_dict()
    assert len(result["sessions"]) == 1
    assert result["sessions"][0]["selected_evidence_packet"] == 2
