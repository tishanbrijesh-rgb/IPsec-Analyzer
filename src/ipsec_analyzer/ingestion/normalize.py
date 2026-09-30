"""Normalize visible packet metadata without making security conclusions."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import replace

from ipsec_analyzer.models.packets import Diagnostic, PacketEvent, PacketKind


def normalize_packet(
    capture_id: str, index: int, timestamp_ns: int, frame: bytes,
    original_length: int, link_type: int,
) -> PacketEvent:
    event = PacketEvent(capture_id, index, timestamp_ns, len(frame), original_length, link_type)
    try:
        if link_type == 1:  # Ethernet
            if len(frame) < 14:
                return _warning(event, "TRUNCATED_ETHERNET", "Ethernet header is incomplete")
            ethertype = int.from_bytes(frame[12:14], "big")
            offset = 14
            for _ in range(2):
                if ethertype not in (0x8100, 0x88A8):
                    break
                if len(frame) < offset + 4:
                    return _warning(event, "TRUNCATED_VLAN", "VLAN header is incomplete")
                ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
                offset += 4
            if ethertype not in (0x0800, 0x86DD):
                return event
            ip_bytes = frame[offset:]
        elif link_type == 101:  # Raw IP
            ip_bytes = frame
        elif link_type == 113:  # Linux cooked capture v1
            if len(frame) < 16:
                return _warning(event, "TRUNCATED_SLL", "Linux cooked v1 header is incomplete")
            if int.from_bytes(frame[14:16], "big") not in (0x0800, 0x86DD):
                return event
            ip_bytes = frame[16:]
        elif link_type == 276:  # Linux cooked capture v2
            if len(frame) < 20:
                return _warning(event, "TRUNCATED_SLL2", "Linux cooked v2 header is incomplete")
            if int.from_bytes(frame[0:2], "big") not in (0x0800, 0x86DD):
                return event
            ip_bytes = frame[20:]
        else:
            return _warning(event, "UNSUPPORTED_LINK_TYPE", f"Link type {link_type} is unsupported")
        if not ip_bytes:
            return _warning(event, "TRUNCATED_IP", "IP header is missing")
        version = ip_bytes[0] >> 4
        if version == 4:
            return _ipv4(event, ip_bytes)
        if version == 6:
            return _ipv6(event, ip_bytes)
        return _warning(event, "UNKNOWN_IP_VERSION", f"IP version {version} is unsupported")
    except (ValueError, struct.error) as exc:
        return _warning(event, "MALFORMED_PACKET", str(exc))


def _ipv4(event: PacketEvent, packet: bytes) -> PacketEvent:
    if len(packet) < 20:
        return _warning(event, "TRUNCATED_IPV4", "IPv4 header is incomplete")
    ihl = (packet[0] & 0x0F) * 4
    total = int.from_bytes(packet[2:4], "big")
    if ihl < 20 or total < ihl:
        return _warning(event, "INVALID_IPV4_LENGTH", "IPv4 header or total length is invalid")
    source = str(ipaddress.IPv4Address(bytes(packet[12:16])))
    destination = str(ipaddress.IPv4Address(bytes(packet[16:20])))
    event = replace(event, ip_version=4, source=source, destination=destination)
    if len(packet) < ihl or len(packet) < total:
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "TRUNCATED_IPV4", "IPv4 payload is shorter than declared")
    fragments = int.from_bytes(packet[6:8], "big")
    if fragments & 0x3FFF:
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "IP_FRAGMENT", "Fragmented IPv4 datagram is not reassembled")
    return _payload(event, packet[9], packet[ihl:total])


def _ipv6(event: PacketEvent, packet: bytes) -> PacketEvent:
    if len(packet) < 40:
        return _warning(event, "TRUNCATED_IPV6", "IPv6 header is incomplete")
    payload_length = int.from_bytes(packet[4:6], "big")
    event = replace(
        event, ip_version=6,
        source=str(ipaddress.IPv6Address(bytes(packet[8:24]))),
        destination=str(ipaddress.IPv6Address(bytes(packet[24:40]))),
    )
    if payload_length == 0 and len(packet) > 40:
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "UNSUPPORTED_IPV6_JUMBOGRAM", "IPv6 jumbogram is not decoded")
    if len(packet) < 40 + payload_length:
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "TRUNCATED_IPV6", "IPv6 payload is shorter than declared")
    next_header = packet[6]
    offset = 40
    end = min(len(packet), 40 + payload_length)
    for _ in range(8):
        if next_header not in (0, 43, 44, 60):
            break
        if offset + 2 > end:
            return _warning(event, "TRUNCATED_IPV6_EXTENSION", "IPv6 extension is incomplete")
        next_value = packet[offset]
        if next_header == 44:
            if offset + 8 > end:
                return _warning(event, "TRUNCATED_IPV6_EXTENSION", "Fragment header is incomplete")
            fragment_field = int.from_bytes(packet[offset + 2:offset + 4], "big")
            if fragment_field & 0xFFF9:
                return _warning(replace(event, kind=PacketKind.UNKNOWN), "IP_FRAGMENT", "Fragmented IPv6 datagram is not reassembled")
            length = 8
        else:
            length = (packet[offset + 1] + 1) * 8
        if offset + length > end:
            return _warning(event, "TRUNCATED_IPV6_EXTENSION", "IPv6 extension exceeds packet")
        offset += length
        next_header = next_value
    else:
        return _warning(event, "IPV6_EXTENSION_LIMIT", "Too many IPv6 extensions")
    return _payload(event, next_header, packet[offset:end])


def _payload(event: PacketEvent, protocol: int, payload: bytes) -> PacketEvent:
    if protocol == 50:
        if len(payload) < 8:
            return _warning(replace(event, transport="ESP", kind=PacketKind.UNKNOWN), "TRUNCATED_ESP", "ESP header is incomplete")
        spi, sequence = struct.unpack_from("!II", payload)
        return replace(event, transport="ESP", kind=PacketKind.ESP, encapsulation="NATIVE_IP", spi=spi, sequence=sequence)
    if protocol == 51:
        if len(payload) < 12:
            return _warning(replace(event, transport="AH", kind=PacketKind.UNKNOWN), "TRUNCATED_AH", "AH header is incomplete")
        spi, sequence = struct.unpack_from("!II", payload, 4)
        return replace(event, transport="AH", kind=PacketKind.AH, encapsulation="NATIVE_IP", spi=spi, sequence=sequence)
    if protocol != 17:
        return replace(event, transport={6: "TCP", 1: "ICMP", 58: "ICMPv6"}.get(protocol, f"IP-{protocol}"))
    event = replace(event, transport="UDP")
    if len(payload) < 8:
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "TRUNCATED_UDP", "UDP header is incomplete")
    source_port, destination_port, udp_length, _ = struct.unpack_from("!HHHH", payload)
    event = replace(event, source_port=source_port, destination_port=destination_port)
    if udp_length < 8 or udp_length > len(payload):
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "INVALID_UDP_LENGTH", "UDP length is invalid or truncated")
    body = payload[8:min(len(payload), max(udp_length, 8))]
    if 4500 in (source_port, destination_port):
        if body == b"\xff":
            return replace(event, kind=PacketKind.NAT_KEEPALIVE)
        if len(body) < 4:
            return _warning(replace(event, kind=PacketKind.UNKNOWN), "TRUNCATED_NATT", "NAT-T marker or SPI is incomplete")
        if body[:4] == b"\0\0\0\0":
            return _ike(replace(event, kind=PacketKind.IKE), body[4:])
        if len(body) < 8:
            return _warning(replace(event, kind=PacketKind.UNKNOWN), "TRUNCATED_ESP", "NAT-T ESP header is incomplete")
        spi, sequence = struct.unpack_from("!II", body)
        return replace(event, kind=PacketKind.ESP, encapsulation="UDP_4500", spi=spi, sequence=sequence)
    if 500 in (source_port, destination_port):
        return _ike(replace(event, kind=PacketKind.IKE), body)
    return event


def _ike(event: PacketEvent, body: bytes) -> PacketEvent:
    if len(body) < 28:
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "TRUNCATED_IKE", "IKE header is incomplete")
    declared = int.from_bytes(body[24:28], "big")
    if declared < 28 or declared > len(body):
        return _warning(replace(event, kind=PacketKind.UNKNOWN), "INVALID_IKE_LENGTH", "IKE length is invalid or truncated")
    return event


def _warning(event: PacketEvent, code: str, message: str) -> PacketEvent:
    return replace(event, diagnostics=event.diagnostics + (Diagnostic(code, message, event.index),))
