"""Capture and packet contracts shared by ingestion and later analysis layers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.1"


class EvidenceState(StrEnum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class PacketKind(StrEnum):
    IKE = "IKE"
    ESP = "ESP"
    AH = "AH"
    NAT_KEEPALIVE = "NAT_KEEPALIVE"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    packet_index: int | None = None
    offset: int | None = None
    severity: str = "warning"


@dataclass(frozen=True)
class PacketEvent:
    capture_id: str
    index: int
    timestamp_ns: int
    captured_length: int
    original_length: int
    link_type: int
    ip_version: int | None = None
    source: str | None = None
    destination: str | None = None
    transport: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    kind: PacketKind = PacketKind.OTHER
    encapsulation: str | None = None
    spi: int | None = None
    sequence: int | None = None
    diagnostics: tuple[Diagnostic, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaptureResult:
    capture_id: str
    source_format: str
    sha256: str
    packets: list[PacketEvent] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    raw_frames: list[memoryview] = field(default_factory=list, repr=False)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "source_format": self.source_format,
            "sha256": self.sha256,
            "packets": [packet.to_dict() for packet in self.packets],
            "diagnostics": [asdict(diagnostic) for diagnostic in self.diagnostics],
            "schema_version": self.schema_version,
        }
