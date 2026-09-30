from __future__ import annotations

import json
import os
import subprocess
import sys
import struct
import ipaddress
from pathlib import Path

import pytest

from ipsec_analyzer.ingestion.capture import CaptureError, read_capture
from ipsec_analyzer.models.packets import PacketKind
from ipsec_analyzer.parsers.ike import parse_ike
from tests.fixtures.build_fixtures import frames, ipv4_packet, write_pcap, write_pcapng


@pytest.mark.parametrize("writer", [write_pcap, write_pcapng])
def test_valid_capture(writer, tmp_path):
    path = writer(tmp_path / ("test.pcapng" if writer is write_pcapng else "test.pcap"))
    result = read_capture(path)
    assert [packet.kind for packet in result.packets] == [
        PacketKind.IKE, PacketKind.ESP, PacketKind.ESP, PacketKind.IKE,
        PacketKind.NAT_KEEPALIVE,
    ]
    assert result.packets[1].spi == 0x12345678
    assert result.packets[1].sequence == 7
    assert result.packets[2].spi == 0x87654321
    assert result.packets[0].source == "192.0.2.1"
    assert result.packets[0].timestamp_ns == 1_000_100_000
    assert result.packets[1].encapsulation == "NATIVE_IP"
    assert result.packets[2].encapsulation == "UDP_4500"
    assert not result.diagnostics


def test_pcap_and_pcapng_normalize_the_same_facts(tmp_path):
    classic = read_capture(write_pcap(tmp_path / "same.pcap"))
    next_generation = read_capture(write_pcapng(tmp_path / "same.pcapng"))
    fields = ("kind", "ip_version", "source", "destination", "source_port", "destination_port", "spi", "sequence", "timestamp_ns")
    assert [
        tuple(getattr(packet, field) for field in fields) for packet in classic.packets
    ] == [
        tuple(getattr(packet, field) for field in fields) for packet in next_generation.packets
    ]


@pytest.mark.parametrize("link_type", [113, 276])
@pytest.mark.parametrize("writer", [write_pcap, write_pcapng])
def test_linux_cooked_capture_preserves_ike_and_esp(link_type, writer, tmp_path):
    ethernet = frames()
    prefix = (b"\0" * 14 + b"\x08\x00") if link_type == 113 else (b"\x08\x00" + b"\0" * 18)
    cooked = [prefix + frame[14:] for frame in ethernet]
    path = writer(tmp_path / ("cooked.pcap" if writer is write_pcap else "cooked.pcapng"), cooked)
    raw = bytearray(path.read_bytes())
    if writer is write_pcap:
        raw[20:24] = struct.pack("<I", link_type)
    else:
        raw[36:38] = struct.pack("<H", link_type)
    path.write_bytes(raw)
    result = read_capture(path)
    assert [packet.kind for packet in result.packets] == [
        PacketKind.IKE, PacketKind.ESP, PacketKind.ESP, PacketKind.IKE, PacketKind.NAT_KEEPALIVE,
    ]
    assert result.packets[1].spi == 0x12345678
    assert parse_ike(result.packets[0], result.raw_frames[0]) is not None
    assert not result.diagnostics


@pytest.mark.parametrize("link_type,code", [(113, "TRUNCATED_SLL"), (276, "TRUNCATED_SLL2")])
def test_truncated_linux_cooked_header_is_diagnostic(link_type, code, tmp_path):
    path = write_pcap(tmp_path / "short-cooked.pcap", [b"\0" * 8])
    raw = bytearray(path.read_bytes())
    raw[20:24] = struct.pack("<I", link_type)
    path.write_bytes(raw)
    result = read_capture(path)
    assert result.packets[0].diagnostics[0].code == code


def test_truncated_record_is_diagnostic(tmp_path):
    path = write_pcap(tmp_path / "partial.pcap")
    path.write_bytes(path.read_bytes()[:-3])
    result = read_capture(path)
    assert len(result.packets) == 4
    assert result.diagnostics[-1].code == "TRUNCATED_PACKET"


def test_malformed_packet_does_not_stop_capture(tmp_path):
    packets = [b"\0", *frames()]
    path = write_pcap(tmp_path / "malformed.pcap", packets)
    result = read_capture(path)
    assert result.packets[0].diagnostics[0].code == "TRUNCATED_ETHERNET"
    assert result.packets[1].kind == PacketKind.IKE


def test_unsupported_capture(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a capture")
    with pytest.raises(CaptureError):
        read_capture(path)


def test_ah_and_ipv6_esp(tmp_path):
    ah = ipv4_packet(51, b"\x00\x02\x00\x00" + struct.pack("!II", 44, 5))
    ipv6_header = (
        struct.pack("!IHBB", 6 << 28, 8, 50, 64)
        + ipaddress.IPv6Address("2001:db8::1").packed
        + ipaddress.IPv6Address("2001:db8::2").packed
    )
    ipv6_esp = b"\0" * 12 + b"\x86\xdd" + ipv6_header + struct.pack("!II", 55, 6)
    result = read_capture(write_pcap(tmp_path / "ipv6-ah.pcap", [ah, ipv6_esp]))
    assert result.packets[0].kind == PacketKind.AH
    assert result.packets[0].spi == 44
    assert result.packets[1].kind == PacketKind.ESP
    assert result.packets[1].ip_version == 6
    assert result.packets[1].destination == "2001:db8::2"


def test_cli_json(tmp_path):
    path = write_pcap(tmp_path / "cli.pcap")
    process = subprocess.run(
        [sys.executable, "-m", "ipsec_analyzer.ingestion.cli", str(path)],
        capture_output=True, text=True, check=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    data = json.loads(process.stdout)
    assert data["packets"][0]["kind"] == "IKE"


def test_summary_and_pcapng_validation(tmp_path):
    path = write_pcapng(tmp_path / "summary.pcapng")
    process = subprocess.run(
        [sys.executable, "-m", "ipsec_analyzer.ingestion.cli", str(path), "--summary"],
        capture_output=True, text=True, check=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    summary = json.loads(process.stdout)
    assert summary["packet_count"] == 5
    assert summary["kinds"]["ESP"] == 2
    raw = bytearray(path.read_bytes())
    raw[4:8] = struct.pack("<I", 8)
    path.write_bytes(raw)
    result = read_capture(path)
    assert result.diagnostics[0].code == "INVALID_BLOCK_LENGTH"


def test_pcapng_timestamp_resolution_and_section_length(tmp_path):
    def block(kind, body):
        size = len(body) + 12
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    packet = frames()[0]
    options = (
        struct.pack("<HHB3x", 9, 1, 12)
        + struct.pack("<HHq", 14, 8, 2)
        + struct.pack("<HH", 0, 0)
    )
    interface = block(1, struct.pack("<HHI", 1, 0, 65535) + options)
    enhanced = block(
        6,
        struct.pack("<IIIII", 0, 1_000_000_000_000 >> 32, 1_000_000_000_000 & 0xFFFFFFFF, len(packet), len(packet))
        + packet + b"\0" * ((-len(packet)) % 4),
    )
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, len(interface) + len(enhanced)))
    path = tmp_path / "precision.pcapng"
    path.write_bytes(section + interface + enhanced)
    result = read_capture(path)
    assert result.packets[0].timestamp_ns == 3_000_000_000
    assert any(item.code == "SUBNANOSECOND_TIMESTAMP" for item in result.diagnostics)
    assert not any(item.code == "SECTION_BOUNDARY" for item in result.diagnostics)

    path.write_bytes(section + interface + enhanced + block(4, b""))
    assert read_capture(path).diagnostics[-1].code == "SECTION_BOUNDARY"


def test_capture_size_and_unsupported_link(tmp_path, monkeypatch):
    import ipsec_analyzer.ingestion.capture as capture_module

    path = write_pcap(tmp_path / "unsupported.pcap")
    raw = bytearray(path.read_bytes())
    raw[20:24] = struct.pack("<I", 999)
    path.write_bytes(raw)
    result = read_capture(path)
    assert result.packets[0].diagnostics[0].code == "UNSUPPORTED_LINK_TYPE"
    monkeypatch.setattr(capture_module, "MAX_CAPTURE_BYTES", len(raw) - 1)
    with pytest.raises(CaptureError):
        read_capture(path)


def test_incomplete_or_fragmented_ike_is_not_treated_as_evidence(tmp_path):
    valid = frames()[0]
    truncated_ip = bytearray(valid)
    truncated_ip[16:18] = struct.pack("!H", 200)
    invalid_udp = bytearray(valid)
    invalid_udp[38:40] = struct.pack("!H", 200)
    fragmented_ip = bytearray(valid)
    fragmented_ip[20:22] = struct.pack("!H", 0x2000)
    path = write_pcap(tmp_path / "partial-ike.pcap", [bytes(truncated_ip), bytes(invalid_udp), bytes(fragmented_ip)])
    result = read_capture(path)
    assert [packet.kind for packet in result.packets] == [PacketKind.UNKNOWN] * 3
    assert [packet.diagnostics[0].code for packet in result.packets] == [
        "TRUNCATED_IPV4", "INVALID_UDP_LENGTH", "IP_FRAGMENT",
    ]
    assert all(parse_ike(packet, frame) is None for packet, frame in zip(result.packets, result.raw_frames))


def test_ipv6_jumbogram_is_explicitly_unsupported(tmp_path):
    ipv6 = (
        struct.pack("!IHBB", 6 << 28, 0, 50, 64)
        + ipaddress.IPv6Address("2001:db8::1").packed
        + ipaddress.IPv6Address("2001:db8::2").packed
        + struct.pack("!II", 3, 4)
    )
    frame = b"\0" * 12 + b"\x86\xdd" + ipv6
    result = read_capture(write_pcap(tmp_path / "jumbo.pcap", [frame]))
    assert result.packets[0].kind == PacketKind.UNKNOWN
    assert result.packets[0].diagnostics[0].code == "UNSUPPORTED_IPV6_JUMBOGRAM"


def test_incomplete_security_headers_are_unknown(tmp_path):
    ike = bytearray(frames()[0])
    invalid_ike = bytearray(ike)
    invalid_ike[66:70] = struct.pack("!I", 10_000)
    short_ike = bytearray(ike[:50])
    short_ike[16:18] = struct.pack("!H", len(short_ike) - 14)
    short_ike[38:40] = struct.pack("!H", len(short_ike) - 34)
    short_esp = ipv4_packet(50, b"\0" * 4)
    short_ah = ipv4_packet(51, b"\0" * 8)
    result = read_capture(write_pcap(tmp_path / "short-security.pcap", [bytes(invalid_ike), bytes(short_ike), short_esp, short_ah]))
    assert [packet.kind for packet in result.packets] == [PacketKind.UNKNOWN] * 4
    assert [packet.diagnostics[0].code for packet in result.packets] == [
        "INVALID_IKE_LENGTH", "TRUNCATED_IKE", "TRUNCATED_ESP", "TRUNCATED_AH",
    ]
    assert all(parse_ike(packet, frame) is None for packet, frame in zip(result.packets, result.raw_frames))
