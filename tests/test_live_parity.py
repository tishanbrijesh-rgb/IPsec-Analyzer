"""Controlled live/offline comparison checks without using a real interface."""

from ipsec_analyzer.assessment.analyze import analyze_capture
from testbed.scripts.verify_live_parity import compare


def test_matching_controlled_results_pass():
    offline = analyze_capture("data/sample/modern-tunnel.pcap").to_dict()
    live = {"live_capture": {"interface": "sih4c", "raw_capture_retained": False,
                             "capture_bytes": 2407, "stop_reason": "duration",
                             "elapsed_seconds": 20.0, "analysis_seconds": 0.01,
                             "packets_dropped_by_kernel": 0},
            "analysis": offline}
    report = compare(live, offline)
    assert report["passed"]
    assert report["live_esp_directions"] == 2


def test_missing_live_direction_fails():
    offline = analyze_capture("data/sample/modern-tunnel.pcap").to_dict()
    live_analysis = dict(offline, flows=offline["flows"][:1])
    live = {"live_capture": {"interface": "sih4c", "raw_capture_retained": False,
                             "capture_bytes": 2407, "stop_reason": "duration",
                             "elapsed_seconds": 20.0, "analysis_seconds": 0.01,
                             "packets_dropped_by_kernel": 0},
            "analysis": live_analysis}
    report = compare(live, offline)
    assert not report["passed"]
    assert not report["checks"]["esp_directions_match"]
