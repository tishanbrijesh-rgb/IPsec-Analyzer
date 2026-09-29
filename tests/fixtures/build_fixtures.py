"""Generate tiny synthetic PCAP/PCAPNG fixtures; no captured user traffic."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


def ipv4_packet(protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0,
        ipaddress.IPv4Address("192.0.2.1").packed,
        ipaddress.IPv4Address("198.51.100.2").packed,
    )
    return b"\0" * 12 + b"\x08\x00" + header + payload


def udp(source: int, destination: int, body: bytes) -> bytes:
    return struct.pack("!HHHH", source, destination, 8 + len(body), 0) + body


def frames() -> list[bytes]:
    ike = b"\x01" * 8 + b"\0" * 8 + bytes([0, 0x20, 34, 8]) + b"\0" * 4 + struct.pack("!I", 28)
    return [
        ipv4_packet(17, udp(500, 500, ike)),
        ipv4_packet(50, struct.pack("!II", 0x12345678, 7) + b"ciphertext"),
        ipv4_packet(17, udp(4500, 4500, struct.pack("!II", 0x87654321, 9) + b"ciphertext")),
        ipv4_packet(17, udp(4500, 4500, b"\0" * 4 + ike)),
        ipv4_packet(17, udp(4500, 4500, b"\xff")),
    ]


def write_pcap(path: Path, packets: list[bytes] | None = None) -> Path:
    packets = frames() if packets is None else packets
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHiiII", 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            stream.write(struct.pack("<IIII", 1 + index, 100, len(packet), len(packet)))
            stream.write(packet)
    return path


def write_pcapng(path: Path, packets: list[bytes] | None = None) -> Path:
    packets = frames() if packets is None else packets

    def block(kind: int, body: bytes) -> bytes:
        length = len(body) + 12
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    with path.open("wb") as stream:
        stream.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        stream.write(block(1, struct.pack("<HHI", 1, 0, 65535)))
        for index, packet in enumerate(packets):
            pad = b"\0" * ((-len(packet)) % 4)
            body = struct.pack("<IIIII", 0, 0, (1 + index) * 1_000_000 + 100, len(packet), len(packet))
            stream.write(block(6, body + packet + pad))
    return path


if __name__ == "__main__":
    directory = Path(__file__).parent
    write_pcap(directory / "synthetic_ipsec.pcap")
    write_pcapng(directory / "synthetic_ipsec.pcapng")
