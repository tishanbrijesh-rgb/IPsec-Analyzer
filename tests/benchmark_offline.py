"""Measure bounded offline analysis on named local capture files.

Run from the repository root with PYTHONPATH=src. Results describe this machine
and these captures only; tracemalloc excludes native allocations.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import struct
import tempfile
import time
import tracemalloc
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import read_capture


def synthetic_capture(path: Path, packet_count: int) -> None:
    """Repeat one controlled ESP frame with increasing PCAP timestamps."""
    source = read_capture("data/sample/modern-tunnel.pcap")
    frame = next(bytes(raw) for packet, raw in zip(source.packets, source.raw_frames)
                 if packet.kind.value == "ESP")
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiII", 2, 4, 0, 0, 65535, 1))
        for index in range(packet_count):
            stream.write(struct.pack("<IIII", 1 + index // 1000, index % 1000,
                                     len(frame), len(frame)))
            stream.write(frame)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="*", type=Path)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--synthetic-packets", type=int, default=0,
                        help="Add a temporary repeated-ESP capture; 1–10000 packets")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 30:
        parser.error("--repeats must be between 1 and 30")
    if args.synthetic_packets and not 1 <= args.synthetic_packets <= 10_000:
        parser.error("--synthetic-packets must be between 1 and 10000")
    if not args.captures and not args.synthetic_packets:
        parser.error("Provide a capture path or --synthetic-packets")
    machine = {"os": platform.platform(), "cpu": platform.processor(),
               "logical_cpus": os.cpu_count(), "python": platform.python_version()}
    results = []
    with tempfile.TemporaryDirectory(prefix="ipsec-benchmark-") as directory:
        captures = list(args.captures)
        if args.synthetic_packets:
            generated = Path(directory) / f"repeated-esp-{args.synthetic_packets}.pcap"
            synthetic_capture(generated, args.synthetic_packets)
            captures.append(generated)
        for path in captures:
            results.append(measure(path, args.repeats,
                                   synthetic=path.parent == Path(directory)))
    print(json.dumps({"machine": machine, "results": results}, indent=2))


def measure(path: Path, repeats: int, *, synthetic: bool = False) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Capture does not exist: {path}")
    durations = []
    peaks = []
    packet_count = None
    for _ in range(repeats):
        tracemalloc.start()
        started = time.perf_counter()
        try:
            result = analyze_capture(path).to_dict()
            durations.append(time.perf_counter() - started)
            peaks.append(tracemalloc.get_traced_memory()[1])
            packet_count = result["capture"]["packet_count"]
        finally:
            tracemalloc.stop()
    return {"capture": f"repeated ESP synthetic ({packet_count} packets)" if synthetic else str(path),
            "capture_bytes": path.stat().st_size, "packets": packet_count,
            "repeats": repeats,
            "median_wall_seconds_with_tracemalloc": statistics.median(durations),
            "max_tracemalloc_peak_bytes": max(peaks)}


if __name__ == "__main__":
    main()
