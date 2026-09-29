"""Dependency-free offline PCAP/PCAPNG reader with bounded input."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from ipsec_analyzer.ingestion.normalize import normalize_packet
from ipsec_analyzer.models.packets import CaptureResult, Diagnostic

MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_PACKET_BYTES = 4 * 1024 * 1024
MAX_PACKETS = 250_000


class CaptureError(ValueError):
    """A capture cannot be safely or meaningfully read."""


def read_capture(path: str | Path) -> CaptureResult:
    capture_path = Path(path)
    if not capture_path.is_file():
        raise CaptureError(f"Capture is not a file: {capture_path}")
    size = capture_path.stat().st_size
    if size > MAX_CAPTURE_BYTES:
        raise CaptureError(f"Capture exceeds {MAX_CAPTURE_BYTES} byte limit")
    data = capture_path.read_bytes()
    if len(data) != size:
        raise CaptureError("Capture changed while being read")
    digest = hashlib.sha256(data).hexdigest()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        result = CaptureResult(digest[:16], "pcapng", digest)
        _read_pcapng(data, result)
    elif data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                      b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        result = CaptureResult(digest[:16], "pcap", digest)
        _read_pcap(data, result)
    else:
        raise CaptureError("Unsupported capture format or missing magic bytes")
    return result


def _read_pcap(data: bytes, result: CaptureResult) -> None:
    if len(data) < 24:
        raise CaptureError("Truncated PCAP global header")
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nanoseconds = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHiiII", data, 4)
    if (major, minor) != (2, 4):
        raise CaptureError(f"Unsupported PCAP version {major}.{minor}")
    if snaplen == 0 or snaplen > MAX_PACKET_BYTES:
        raise CaptureError("Invalid PCAP snapshot length")
    link_type = network & 0xFFFF
    offset = 24
    while offset < len(data):
        if len(result.packets) >= MAX_PACKETS:
            raise CaptureError("Packet count limit exceeded")
        if len(data) - offset < 16:
            result.diagnostics.append(Diagnostic("TRUNCATED_RECORD", "Incomplete PCAP packet header", offset=offset))
            break
        sec, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > snaplen or captured > MAX_PACKET_BYTES:
            raise CaptureError(f"Invalid packet length at byte {offset - 16}")
        if original < captured:
            result.diagnostics.append(Diagnostic("INVALID_ORIGINAL_LENGTH", "Original length is smaller than captured length", len(result.packets) + 1, offset - 16))
        if captured > len(data) - offset:
            result.diagnostics.append(Diagnostic("TRUNCATED_PACKET", "Packet bytes end before declared length", len(result.packets) + 1, offset))
            break
        if fraction >= (1_000_000_000 if nanoseconds else 1_000_000):
            result.diagnostics.append(Diagnostic("INVALID_TIMESTAMP_FRACTION", "Timestamp fraction is out of range", len(result.packets) + 1, offset - 16))
        timestamp_ns = sec * 1_000_000_000 + fraction * (1 if nanoseconds else 1_000)
        frame = memoryview(data)[offset:offset + captured]
        result.packets.append(normalize_packet(result.capture_id, len(result.packets) + 1, timestamp_ns, frame, original, link_type))
        result.raw_frames.append(frame)
        offset += captured


def _read_pcapng(data: bytes, result: CaptureResult) -> None:
    offset = 0
    endian: str | None = None
    interfaces: list[tuple[int, int, int, int]] = []  # link type, ticks per second, snaplen, offset seconds
    section_end: int | None = None
    while offset < len(data):
        if len(result.packets) >= MAX_PACKETS:
            raise CaptureError("Packet count limit exceeded")
        if len(data) - offset < 12:
            result.diagnostics.append(Diagnostic("TRUNCATED_BLOCK", "Incomplete PCAPNG block", offset=offset))
            break
        section_header = data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a"
        if section_end is not None:
            if offset == section_end and not section_header:
                result.diagnostics.append(Diagnostic("SECTION_BOUNDARY", "Expected a new section header", offset=offset))
                break
            if offset < section_end and section_header:
                result.diagnostics.append(Diagnostic("SECTION_BOUNDARY", "New section starts before declared boundary", offset=offset))
                break
            if offset > section_end:
                result.diagnostics.append(Diagnostic("SECTION_BOUNDARY", "Block begins past declared section boundary", offset=offset))
                break
        if section_header:
            marker = data[offset + 8:offset + 12]
            if marker == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif marker == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureError(f"Invalid PCAPNG byte-order magic at byte {offset}")
            interfaces = []
        if endian is None:
            raise CaptureError("PCAPNG section header is missing")
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or block_len % 4 or block_len > len(data) - offset:
            result.diagnostics.append(Diagnostic("INVALID_BLOCK_LENGTH", "Invalid or truncated PCAPNG block", offset=offset))
            break
        if not section_header and section_end is not None and offset + block_len > section_end:
            result.diagnostics.append(Diagnostic("SECTION_BOUNDARY", "Block exceeds declared section boundary", offset=offset))
            break
        if struct.unpack_from(endian + "I", data, offset + block_len - 4)[0] != block_len:
            result.diagnostics.append(Diagnostic("BLOCK_LENGTH_MISMATCH", "PCAPNG trailing length mismatch", offset=offset))
            break
        body = data[offset + 8:offset + block_len - 4]
        if section_header:
            if block_len < 28 or len(body) < 16:
                raise CaptureError(f"Incomplete PCAPNG section header at byte {offset}")
            major, minor = struct.unpack_from(endian + "HH", body, 4)
            if (major, minor) != (1, 0):
                raise CaptureError(f"Unsupported PCAPNG version {major}.{minor}")
            section_length = struct.unpack_from(endian + "q", body, 8)[0]
            if section_length < -1 or (section_length >= 0 and section_length % 4):
                raise CaptureError(f"Invalid PCAPNG section length at byte {offset}")
            section_end = None if section_length == -1 else offset + block_len + section_length
            if section_end is not None and section_end > len(data):
                result.diagnostics.append(Diagnostic("TRUNCATED_SECTION", "Declared section exceeds file length", offset=offset))
                break
        elif block_type == 1:
            if len(body) < 8:
                result.diagnostics.append(Diagnostic("TRUNCATED_INTERFACE", "Incomplete interface description", offset=offset))
            else:
                link_type, _, snaplen = struct.unpack_from(endian + "HHI", body)
                if snaplen == 0 or snaplen > MAX_PACKET_BYTES:
                    raise CaptureError("PCAPNG snapshot length exceeds limit")
                ticks_per_second = 1_000_000  # default timestamp resolution: microseconds
                offset_seconds = 0
                pos = 8
                while pos + 4 <= len(body):
                    option, length = struct.unpack_from(endian + "HH", body, pos)
                    pos += 4
                    if option == 0:
                        break
                    if pos + length > len(body):
                        result.diagnostics.append(Diagnostic("TRUNCATED_OPTION", "Incomplete interface option", offset=offset))
                        break
                    if option == 9 and length == 1:
                        resolution = body[pos]
                        ticks_per_second = (2 ** (resolution & 0x7F)) if resolution & 0x80 else (10 ** resolution)
                        if ticks_per_second > 1_000_000_000:
                            result.diagnostics.append(Diagnostic("SUBNANOSECOND_TIMESTAMP", "Timestamp is truncated to nanoseconds", offset=offset))
                    elif option == 9:
                        result.diagnostics.append(Diagnostic("INVALID_TIMESTAMP_RESOLUTION", "Timestamp resolution option has invalid length", offset=offset))
                    elif option == 14 and length == 8:
                        offset_seconds = struct.unpack_from(endian + "q", body, pos)[0]
                    elif option == 14:
                        result.diagnostics.append(Diagnostic("INVALID_TIMESTAMP_OFFSET", "Timestamp offset option has invalid length", offset=offset))
                    pos += (length + 3) & ~3
                interfaces.append((link_type, ticks_per_second, snaplen, offset_seconds))
        elif block_type == 6:
            if len(body) < 20:
                result.diagnostics.append(Diagnostic("TRUNCATED_PACKET", "Incomplete enhanced packet block", offset=offset))
            else:
                interface_id, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
                if interface_id >= len(interfaces):
                    result.diagnostics.append(Diagnostic("UNKNOWN_INTERFACE", "Packet references missing interface", offset=offset))
                elif captured > MAX_PACKET_BYTES or captured > interfaces[interface_id][2] or captured > len(body) - 20:
                    result.diagnostics.append(Diagnostic("TRUNCATED_PACKET", "Invalid enhanced packet length", offset=offset))
                else:
                    link_type, ticks_per_second, _, offset_seconds = interfaces[interface_id]
                    if original < captured:
                        result.diagnostics.append(Diagnostic("INVALID_ORIGINAL_LENGTH", "Original length is smaller than captured length", len(result.packets) + 1, offset))
                    timestamp_ns = (((high << 32) | low) * 1_000_000_000) // ticks_per_second + offset_seconds * 1_000_000_000
                    frame = memoryview(data)[offset + 28:offset + 28 + captured]
                    result.packets.append(normalize_packet(result.capture_id, len(result.packets) + 1, timestamp_ns, frame, original, link_type))
                    result.raw_frames.append(frame)
        elif block_type in (2, 3):
            result.diagnostics.append(Diagnostic("UNSUPPORTED_PACKET_BLOCK", f"PCAPNG packet block type {block_type} is not decoded", offset=offset))
        elif block_type not in (4, 5):
            result.diagnostics.append(Diagnostic("SKIPPED_BLOCK", f"Unsupported PCAPNG block type {block_type}", offset=offset))
        offset += block_len
    if section_end is not None and offset != section_end and offset == len(data):
        result.diagnostics.append(Diagnostic("SECTION_BOUNDARY", "Section ends at a different byte offset than declared", offset=offset))
