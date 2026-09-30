"""Bounded IKE header and visible IKEv1/IKEv2 SA parsing."""

from __future__ import annotations

import struct
from hashlib import sha256
from dataclasses import asdict, dataclass, field
from typing import Any

from ipsec_analyzer.models.packets import Diagnostic, PacketEvent, PacketKind


@dataclass(frozen=True)
class Transform:
    transform_type: int
    transform_id: int
    key_length_bits: int | None = None


@dataclass(frozen=True)
class Proposal:
    number: int
    protocol_id: int
    spi: str
    transforms: tuple[Transform, ...]


@dataclass(frozen=True)
class V1Attribute:
    attribute_type: int
    value: int | None
    value_length_bytes: int | None = None


@dataclass(frozen=True)
class V1Transform:
    number: int
    transform_id: int
    attributes: tuple[V1Attribute, ...]


@dataclass(frozen=True)
class V1Proposal:
    number: int
    protocol_id: int
    spi: str
    transforms: tuple[V1Transform, ...]


@dataclass
class IkeMessage:
    packet_index: int
    source: str | None
    destination: str | None
    version_major: int
    version_minor: int
    exchange_type: int
    message_id: int
    initiator_spi: str
    responder_spi: str
    is_response: bool
    timestamp_ns: int | None = None
    wire_hash: str | None = field(default=None, repr=False)
    proposals: list[Proposal] = field(default_factory=list)
    v1_proposals: list[V1Proposal] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("wire_hash")
        return result


def extract_ike_body(frame: bytes, event: PacketEvent) -> bytes | None:
    """Locate UDP body for an already-normalized IKE packet."""
    if event.kind != PacketKind.IKE:
        return None
    if event.link_type == 1:
        if len(frame) < 14:
            return None
        ethertype = int.from_bytes(frame[12:14], "big")
        offset = 14
        for _ in range(2):
            if ethertype not in (0x8100, 0x88A8):
                break
            if len(frame) < offset + 4:
                return None
            ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
    elif event.link_type == 101:
        offset = 0
    elif event.link_type == 113:
        offset = 16
    elif event.link_type == 276:
        offset = 20
    else:
        return None
    if event.ip_version == 4:
        if len(frame) < offset + 20:
            return None
        ip_length = (frame[offset] & 15) * 4
        ip_end = offset + min(int.from_bytes(frame[offset + 2:offset + 4], "big"), len(frame) - offset)
        offset += ip_length
    elif event.ip_version == 6:
        if len(frame) < offset + 40:
            return None
        ip_end = min(len(frame), offset + 40 + int.from_bytes(frame[offset + 4:offset + 6], "big"))
        next_header = frame[offset + 6]
        offset += 40
        for _ in range(8):
            if next_header not in (0, 43, 44, 60):
                break
            if offset + 2 > ip_end:
                return None
            current = next_header
            next_header = frame[offset]
            length = 8 if current == 44 else (frame[offset + 1] + 1) * 8
            offset += length
            if offset > ip_end:
                return None
        if next_header != 17:
            return None
    else:
        return None
    if offset + 8 > ip_end:
        return None
    udp_length = int.from_bytes(frame[offset + 4:offset + 6], "big")
    body = frame[offset + 8:min(ip_end, offset + udp_length)]
    if 4500 in (event.source_port, event.destination_port):
        if body[:4] != b"\0\0\0\0":
            return None
        body = body[4:]
    return body


def parse_ike(event: PacketEvent, frame: bytes) -> IkeMessage | None:
    body = extract_ike_body(frame, event)
    if body is None or len(body) < 28:
        return None
    major, minor = body[17] >> 4, body[17] & 15
    result = IkeMessage(
        event.index, event.source, event.destination, major, minor, body[18],
        int.from_bytes(body[20:24], "big"), body[:8].hex(), body[8:16].hex(),
        bool(body[19] & 0x20) if major == 2 else False,
    )
    if body[:8] == b"\0" * 8:
        result.diagnostics.append(Diagnostic("INVALID_IKE_SPI", "Initiator SPI is zero", event.index))
        return result
    declared = int.from_bytes(body[24:28], "big")
    if declared < 28 or declared > len(body):
        result.diagnostics.append(Diagnostic("INVALID_IKE_LENGTH", "IKE length exceeds available bytes", event.index))
        return result
    result.timestamp_ns = event.timestamp_ns
    result.wire_hash = sha256(body[:declared]).hexdigest()
    if major not in (1, 2):
        result.diagnostics.append(Diagnostic("UNSUPPORTED_IKE_VERSION", f"IKE major version {major}", event.index))
        return result
    if major == 1 and body[19] & 0x01:
        result.diagnostics.append(Diagnostic("ENCRYPTED_IKE_PAYLOAD", "IKEv1 payload is encrypted and cannot be decoded", event.index))
        return result
    payload_type = body[16]
    offset = 28
    payload_count = 0
    while payload_type and offset < declared:
        payload_count += 1
        if payload_count > 256:
            result.diagnostics.append(Diagnostic("IKE_PAYLOAD_LIMIT", "IKE payload chain exceeds limit", event.index))
            break
        if offset + 4 > declared:
            result.diagnostics.append(Diagnostic("TRUNCATED_IKE_PAYLOAD", "Payload header is incomplete", event.index))
            break
        next_type, _, length = struct.unpack_from("!BBH", body, offset)
        if length < 4 or offset + length > declared:
            result.diagnostics.append(Diagnostic("INVALID_IKE_PAYLOAD_LENGTH", "Payload length is invalid", event.index))
            break
        if major == 2 and payload_type == 33:
            proposals, errors = _parse_v2_sa(body[offset + 4:offset + length], event.index)
            result.proposals.extend(proposals)
            result.diagnostics.extend(errors)
        elif major == 1 and payload_type == 1:
            proposals, errors = _parse_v1_sa(body[offset + 4:offset + length], event.index)
            result.v1_proposals.extend(proposals)
            result.diagnostics.extend(errors)
        elif major == 2 and payload_type == 46:
            result.diagnostics.append(Diagnostic("ENCRYPTED_IKE_PAYLOAD", "IKEv2 encrypted payload cannot be decoded", event.index))
            break
        payload_type = next_type
        offset += length
    if payload_type and offset == declared:
        result.diagnostics.append(Diagnostic("MISSING_IKE_PAYLOAD", "Payload chain ends before expected payload", event.index))
    return result


def _parse_v1_sa(data: bytes, packet_index: int) -> tuple[list[V1Proposal], list[Diagnostic]]:
    errors: list[Diagnostic] = []
    proposals: list[V1Proposal] = []
    if len(data) < 8:
        return proposals, [Diagnostic("TRUNCATED_V1_SA", "IKEv1 SA DOI and situation are incomplete", packet_index)]
    doi, situation = struct.unpack_from("!II", data)
    if doi != 1 or situation != 1:
        return proposals, [Diagnostic("UNSUPPORTED_V1_SA", "IKEv1 SA DOI or situation is unsupported", packet_index)]
    if len(data) == 8:
        return proposals, [Diagnostic("EMPTY_V1_SA", "IKEv1 SA has no proposal", packet_index)]
    offset = 8
    proposal_count = 0
    while offset < len(data):
        proposal_count += 1
        if proposal_count > 64:
            errors.append(Diagnostic("PROPOSAL_LIMIT", "IKEv1 SA exceeds proposal limit", packet_index))
            break
        if offset + 8 > len(data):
            errors.append(Diagnostic("TRUNCATED_PROPOSAL", "IKEv1 proposal header is incomplete", packet_index))
            break
        next_payload, _, length, number, protocol_id, spi_size, count = struct.unpack_from("!BBHBBBB", data, offset)
        if length < 8 + spi_size or offset + length > len(data):
            errors.append(Diagnostic("INVALID_PROPOSAL_LENGTH", "IKEv1 proposal length is invalid", packet_index))
            break
        if count == 0:
            errors.append(Diagnostic("EMPTY_V1_PROPOSAL", "IKEv1 proposal has no transforms", packet_index))
            break
        end = offset + length
        position = offset + 8 + spi_size
        transforms: list[V1Transform] = []
        valid = True
        while position < end:
            if len(transforms) >= 64:
                errors.append(Diagnostic("TRANSFORM_LIMIT", "IKEv1 proposal exceeds transform limit", packet_index))
                valid = False
                break
            if position + 8 > end:
                errors.append(Diagnostic("TRUNCATED_TRANSFORM", "IKEv1 transform header is incomplete", packet_index))
                valid = False
                break
            next_transform, _, transform_length, transform_number, transform_id, _ = struct.unpack_from("!BBHBBH", data, position)
            if transform_length < 8 or position + transform_length > end:
                errors.append(Diagnostic("INVALID_TRANSFORM_LENGTH", "IKEv1 transform length is invalid", packet_index))
                valid = False
                break
            attributes: list[V1Attribute] = []
            attribute_end = position + transform_length
            attribute_offset = position + 8
            while attribute_offset < attribute_end:
                if len(attributes) >= 128:
                    errors.append(Diagnostic("ATTRIBUTE_LIMIT", "IKEv1 transform exceeds attribute limit", packet_index))
                    valid = False
                    break
                if attribute_offset + 4 > attribute_end:
                    errors.append(Diagnostic("TRUNCATED_TRANSFORM_ATTRIBUTE", "IKEv1 attribute header is incomplete", packet_index))
                    valid = False
                    break
                type_field, value_field = struct.unpack_from("!HH", data, attribute_offset)
                attribute_offset += 4
                if type_field & 0x8000:
                    value: int | None = value_field
                    value_length_bytes = None
                else:
                    if attribute_offset + value_field > attribute_end:
                        errors.append(Diagnostic("INVALID_TRANSFORM_ATTRIBUTE", "IKEv1 attribute exceeds transform", packet_index))
                        valid = False
                        break
                    value = (
                        int.from_bytes(data[attribute_offset:attribute_offset + value_field], "big")
                        if type_field in (12, 14) and 0 < value_field <= 4 else None
                    )
                    value_length_bytes = value_field
                    attribute_offset += value_field
                attributes.append(V1Attribute(type_field & 0x7FFF, value, value_length_bytes))
            if not valid:
                break
            transforms.append(V1Transform(transform_number, transform_id, tuple(attributes)))
            position = attribute_end
            if next_transform not in (0, 3) or (next_transform == 0) != (position == end):
                errors.append(Diagnostic("TRANSFORM_CHAIN_MISMATCH", "IKEv1 transform chain marker is inconsistent", packet_index))
                valid = False
                break
        if valid and len(transforms) != count:
            errors.append(Diagnostic("TRANSFORM_COUNT_MISMATCH", "IKEv1 transform count differs from header", packet_index))
            valid = False
        if valid:
            proposals.append(V1Proposal(number, protocol_id, data[offset + 8:offset + 8 + spi_size].hex(), tuple(transforms)))
        offset = end
        if next_payload not in (0, 2) or (next_payload == 0) != (offset == len(data)):
            errors.append(Diagnostic("PROPOSAL_CHAIN_MISMATCH", "IKEv1 proposal chain marker is inconsistent", packet_index))
            break
    return proposals, errors


def _parse_v2_sa(data: bytes, packet_index: int) -> tuple[list[Proposal], list[Diagnostic]]:
    proposals: list[Proposal] = []
    errors: list[Diagnostic] = []
    offset = 0
    proposal_count = 0
    while offset < len(data):
        proposal_count += 1
        if proposal_count > 64:
            errors.append(Diagnostic("PROPOSAL_LIMIT", "IKEv2 SA exceeds proposal limit", packet_index))
            break
        if offset + 8 > len(data):
            errors.append(Diagnostic("TRUNCATED_PROPOSAL", "IKEv2 proposal header is incomplete", packet_index))
            break
        last, _, length, number, protocol_id, spi_size, transform_count = struct.unpack_from("!BBHBBBB", data, offset)
        if length < 8 + spi_size or offset + length > len(data):
            errors.append(Diagnostic("INVALID_PROPOSAL_LENGTH", "IKEv2 proposal length is invalid", packet_index))
            break
        if transform_count == 0:
            errors.append(Diagnostic("EMPTY_V2_PROPOSAL", "IKEv2 proposal has no transforms", packet_index))
            break
        end = offset + length
        spi = data[offset + 8:offset + 8 + spi_size].hex()
        transforms: list[Transform] = []
        position = offset + 8 + spi_size
        valid = True
        while position < end:
            if len(transforms) >= 64:
                errors.append(Diagnostic("TRANSFORM_LIMIT", "IKEv2 proposal exceeds transform limit", packet_index))
                valid = False
                break
            if position + 8 > end:
                errors.append(Diagnostic("TRUNCATED_TRANSFORM", "IKEv2 transform header is incomplete", packet_index))
                valid = False
                break
            last_transform, _, transform_length, transform_type, _, transform_id = struct.unpack_from("!BBHBBH", data, position)
            if transform_length < 8 or position + transform_length > end:
                errors.append(Diagnostic("INVALID_TRANSFORM_LENGTH", "IKEv2 transform length is invalid", packet_index))
                valid = False
                break
            key_length: int | None = None
            attr_offset = position + 8
            attribute_count = 0
            while attr_offset + 4 <= position + transform_length:
                attribute_count += 1
                if attribute_count > 128:
                    errors.append(Diagnostic("ATTRIBUTE_LIMIT", "IKEv2 transform exceeds attribute limit", packet_index))
                    valid = False
                    break
                attr_type, attr_value = struct.unpack_from("!HH", data, attr_offset)
                if attr_type & 0x8000:
                    if attr_type & 0x7FFF == 14:
                        key_length = attr_value
                    attr_offset += 4
                else:
                    if attr_offset + 4 + attr_value > position + transform_length:
                        errors.append(Diagnostic("INVALID_TRANSFORM_ATTRIBUTE", "IKEv2 transform attribute exceeds payload", packet_index))
                        valid = False
                        break
                    if attr_type == 14 and attr_value == 2:
                        key_length = int.from_bytes(data[attr_offset + 4:attr_offset + 6], "big")
                    attr_offset += 4 + attr_value
            if not valid:
                break
            if attr_offset != position + transform_length:
                errors.append(Diagnostic("TRUNCATED_TRANSFORM_ATTRIBUTE", "IKEv2 transform attribute header is incomplete", packet_index))
                valid = False
                break
            transforms.append(Transform(transform_type, transform_id, key_length))
            position += transform_length
            if last_transform not in (0, 3) or (last_transform == 0) != (position == end):
                errors.append(Diagnostic("TRANSFORM_CHAIN_MISMATCH", "IKEv2 transform chain marker is inconsistent", packet_index))
                valid = False
                break
        if len(transforms) != transform_count:
            errors.append(Diagnostic("TRANSFORM_COUNT_MISMATCH", "Declared transform count differs from decoded count", packet_index))
            valid = False
        if valid:
            proposals.append(Proposal(number, protocol_id, spi, tuple(transforms)))
        offset = end
        if last not in (0, 2) or (last == 0) != (offset == len(data)):
            errors.append(Diagnostic("PROPOSAL_CHAIN_MISMATCH", "IKEv2 proposal chain marker is inconsistent", packet_index))
            break
    return proposals, errors
