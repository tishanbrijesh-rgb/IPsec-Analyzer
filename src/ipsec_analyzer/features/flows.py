"""Build directional ESP/AH flows from normalized packet observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Any

from ipsec_analyzer.models.packets import PacketEvent, PacketKind

FLOW_IDLE_SPLIT_NS = 5 * 60 * 1_000_000_000


@dataclass
class Flow:
    source: str
    destination: str
    kind: str
    spi: int
    encapsulation: str | None = None
    link_type: int | None = None
    episode: int = 1
    association_state: str = "UNAMBIGUOUS"
    packet_indices: list[int] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    timestamps_ns: list[int] = field(default_factory=list)
    sequences: list[int] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        intervals = [later - earlier for earlier, later in zip(self.timestamps_ns, self.timestamps_ns[1:])]
        ordered_timestamps = all(interval >= 0 for interval in intervals)
        average_length = mean(self.lengths)
        return {
            "source": self.source,
            "destination": self.destination,
            "kind": self.kind,
            "spi": self.spi,
            "encapsulation": self.encapsulation,
            "link_type": self.link_type,
            "episode": self.episode,
            "association_state": self.association_state,
            "packet_indices": self.packet_indices,
            "first_timestamp_ns": min(self.timestamps_ns),
            "last_timestamp_ns": max(self.timestamps_ns),
            "packet_count": len(self.packet_indices),
            "byte_count": sum(self.lengths),
            "byte_count_unit": "captured_frame_bytes",
            "min_length": min(self.lengths),
            "max_length": max(self.lengths),
            "mean_length": average_length,
            "std_length": (sum((length - average_length) ** 2 for length in self.lengths) / len(self.lengths)) ** 0.5,
            "mean_interarrival_ns": mean(intervals) if intervals and ordered_timestamps else None,
            "burst_count": 1 + sum(interval > 200_000_000 for interval in intervals) if ordered_timestamps else None,
            "sequence_min": min(self.sequences) if self.sequences else None,
            "sequence_max": max(self.sequences) if self.sequences else None,
            "nonincreasing_sequence_count": sum(later <= earlier for earlier, later in zip(self.sequences, self.sequences[1:])),
            "diagnostics": self.diagnostics,
            "evidence_state": "DERIVED",
        }


def build_flows(packets: list[PacketEvent]) -> list[Flow]:
    flows: dict[tuple[str, str, str, int, str | None, int], list[Flow]] = {}
    for packet in packets:
        if packet.kind not in (PacketKind.ESP, PacketKind.AH):
            continue
        if packet.source is None or packet.destination is None or packet.spi is None:
            continue
        key = (packet.source, packet.destination, packet.kind.value, packet.spi, packet.encapsulation, packet.link_type)
        episodes = flows.setdefault(key, [])
        flow = episodes[-1] if episodes else None
        if flow is not None and packet.timestamp_ns - flow.timestamps_ns[-1] > FLOW_IDLE_SPLIT_NS:
            flow.association_state = "TIME_SPLIT_UNCERTAIN"
            if "Long idle gap; SPI continuity is unknown" not in flow.diagnostics:
                flow.diagnostics.append("Long idle gap; SPI continuity is unknown")
            flow = None
        if flow is None:
            flow = Flow(*key, episode=len(episodes) + 1)
            if episodes:
                flow.association_state = "TIME_SPLIT_UNCERTAIN"
                flow.diagnostics.append("Long idle gap; SPI continuity is unknown")
            episodes.append(flow)
        elif packet.timestamp_ns < flow.timestamps_ns[-1] and "Nonmonotonic timestamps; interarrival unavailable" not in flow.diagnostics:
            flow.diagnostics.append("Nonmonotonic timestamps; interarrival unavailable")
        flow.packet_indices.append(packet.index)
        flow.lengths.append(packet.captured_length)
        flow.timestamps_ns.append(packet.timestamp_ns)
        if packet.sequence is not None:
            flow.sequences.append(packet.sequence)
    return [flow for episodes in flows.values() for flow in episodes]
