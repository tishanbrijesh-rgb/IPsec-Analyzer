"""Compare a bounded namespace live window with its controlled offline run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture


def _selection(analysis: dict) -> set[tuple]:
    return {
        (session["version_major"],
         tuple(sorted((item["transform_type"], item["transform_id"],
                       item["key_length_bits"])
                      for item in session["selected"]["transforms"])))
        for session in analysis["sessions"] if session["selected"] is not None
    }


def _flows(analysis: dict) -> set[tuple]:
    return {(flow["source"], flow["destination"], flow["kind"],
             flow["spi"], flow["encapsulation"])
            for flow in analysis["flows"]}


def compare(live_result: dict, offline: dict) -> dict:
    metadata = live_result["live_capture"]
    live = live_result["analysis"]
    live_selections = _selection(live)
    offline_selections = _selection(offline)
    live_flows = _flows(live)
    offline_flows = _flows(offline)
    checks = {
        "interface_is_sih4c": metadata["interface"] == "sih4c",
        "raw_capture_deleted": metadata["raw_capture_retained"] is False,
        "live_has_packets": live["capture"]["packet_count"] > 0,
        "selected_ike_matches": bool(live_selections) and live_selections == offline_selections,
        "esp_directions_match": len(live_flows) >= 2 and live_flows == offline_flows,
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "live_packet_count": live["capture"]["packet_count"],
        "offline_packet_count": offline["capture"]["packet_count"],
        "live_capture_bytes": metadata["capture_bytes"],
        "stop_reason": metadata["stop_reason"],
        "elapsed_seconds": metadata["elapsed_seconds"],
        "analysis_seconds": metadata["analysis_seconds"],
        "packets_dropped_by_kernel": metadata["packets_dropped_by_kernel"],
        "live_ike_selections": len(live_selections),
        "live_esp_directions": len(live_flows),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("live_result", type=Path)
    parser.add_argument("offline_capture", type=Path)
    args = parser.parse_args()
    live_result = json.loads(args.live_result.read_text(encoding="utf-8"))
    offline = analyze_capture(args.offline_capture).to_dict()
    report = compare(live_result, offline)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
