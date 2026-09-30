"""Validate and label an isolated, unprotected ICMP control capture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ipsec_analyzer.ingestion.capture import read_capture
from ipsec_analyzer.models.packets import PacketKind

PEERS = {"198.51.100.2", "203.0.113.2"}


def register(capture_path: Path, record_path: Path) -> dict:
    if record_path.exists():
        raise ValueError("Control record already exists")
    capture = read_capture(capture_path)
    if not capture.packets or capture.diagnostics:
        raise ValueError("Control capture is empty or has capture diagnostics")
    directions = set()
    for packet in capture.packets:
        if (packet.ip_version != 4 or packet.transport != "ICMP" or packet.kind != PacketKind.OTHER
                or packet.diagnostics or {packet.source, packet.destination} != PEERS):
            raise ValueError(f"Packet {packet.index} is not isolated outer-link ICMP control traffic")
        directions.add((packet.source, packet.destination))
    if len(directions) != 2:
        raise ValueError("Control capture needs ICMP in both directions")
    record = {
        "schema_version": "1.0",
        "label": "unprotected-icmp-control",
        "label_source": "isolated lab command; no VPN daemon started",
        "capture_point": "outer client interface",
        "capture_sha256": capture.sha256,
        "capture_format": capture.source_format,
        "packet_count": len(capture.packets),
        "traffic_directions": 2,
        "dataset_role": "negative control; excluded from IPsec training index",
    }
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    print(json.dumps(register(args.capture, args.record)))


if __name__ == "__main__":
    main()
