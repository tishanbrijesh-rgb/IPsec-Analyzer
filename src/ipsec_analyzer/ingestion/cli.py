"""Inspect an offline capture and emit normalized metadata as JSON."""

from __future__ import annotations

import argparse
import json
import sys

from ipsec_analyzer.ingestion.capture import CaptureError, read_capture


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize an IPsec PCAP or PCAPNG capture")
    parser.add_argument("capture", help="Path to a PCAP or PCAPNG file")
    parser.add_argument("--summary", action="store_true", help="Print counts and diagnostics instead of packet records")
    parser.add_argument("--analyze", choices=("json", "text"), help="Run the current evidence-backed assessment")
    args = parser.parse_args(argv)
    try:
        if args.analyze:
            from ipsec_analyzer.assessment.analyze import analyze_capture
            analysis = analyze_capture(args.capture)
            if args.analyze == "text":
                from ipsec_analyzer.reporting.technical import render_technical
                print(render_technical(analysis), end="")
            else:
                print(json.dumps(analysis.to_dict(), indent=2))
            return 0
        result = read_capture(args.capture)
    except (CaptureError, OSError) as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return 2
    if args.summary:
        counts: dict[str, int] = {}
        for packet in result.packets:
            counts[packet.kind.value] = counts.get(packet.kind.value, 0) + 1
        payload = {
            "capture_id": result.capture_id,
            "source_format": result.source_format,
            "packet_count": len(result.packets),
            "kinds": counts,
            "diagnostics": [diagnostic.__dict__ for diagnostic in result.diagnostics],
            "packet_diagnostics": [
                {"packet_index": packet.index, "diagnostics": [diagnostic.__dict__ for diagnostic in packet.diagnostics]}
                for packet in result.packets if packet.diagnostics
            ],
        }
    else:
        payload = result.to_dict()
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
