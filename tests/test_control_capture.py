"""The negative control accepts only isolated, bidirectional plain ICMP."""

import ipaddress
import json
import struct
from pathlib import Path

import pytest

from testbed.scripts.register_control import register
from tests.fixtures.build_fixtures import write_pcap

CONTROL = Path(__file__).resolve().parents[1] / "data" / "control"


def frame(source: str, destination: str, protocol: int = 1) -> bytes:
    payload = b"\x08\x00\x00\x00\x00\x01\x00\x01" if protocol == 1 else b"\x00" * 8
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64,
                         protocol, 0, ipaddress.IPv4Address(source).packed,
                         ipaddress.IPv4Address(destination).packed)
    return b"\x00" * 12 + b"\x08\x00" + header + payload


def test_bidirectional_control_record(tmp_path):
    path = write_pcap(tmp_path / "control.pcap", [
        frame("198.51.100.2", "203.0.113.2"),
        frame("203.0.113.2", "198.51.100.2"),
    ])
    record = register(path, tmp_path / "control.json")
    assert record["label"] == "unprotected-icmp-control"
    assert record["packet_count"] == 2
    assert record["traffic_directions"] == 2
    assert "excluded" in record["dataset_role"]


@pytest.mark.parametrize("packets", [
    [frame("198.51.100.2", "203.0.113.2")],
    [frame("198.51.100.2", "203.0.113.2"), frame("203.0.113.2", "198.51.100.2", 50)],
    [frame("198.51.100.2", "203.0.113.2"), frame("203.0.113.9", "198.51.100.2")],
])
def test_control_rejects_one_way_ipsec_or_wrong_peer(tmp_path, packets):
    path = write_pcap(tmp_path / "bad.pcap", packets)
    with pytest.raises(ValueError):
        register(path, tmp_path / "control.json")


def test_reviewed_control_capture_is_pinned_and_has_no_ipsec():
    from ipsec_analyzer.ingestion.capture import read_capture

    capture = read_capture(CONTROL / "plain-icmp-01.pcap")
    record = json.loads((CONTROL / "plain-icmp-01.json").read_text(encoding="utf-8"))
    assert capture.sha256 == record["capture_sha256"] == (
        "02f02a863fcd81e8bd96039f36cee491f6a723a16d03d88fb8710c440e3173b0")
    assert len(capture.packets) == record["packet_count"] == 6
    assert not capture.diagnostics
    assert all(packet.kind == "OTHER" and packet.transport == "ICMP" and not packet.diagnostics
               for packet in capture.packets)
    assert {(packet.source, packet.destination) for packet in capture.packets} == {
        ("198.51.100.2", "203.0.113.2"), ("203.0.113.2", "198.51.100.2")}
