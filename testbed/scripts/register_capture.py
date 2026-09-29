"""Record a verified outer-interface capture without copying packet data."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import read_capture
from ipsec_analyzer.models.packets import PacketKind
from testbed.scripts.generate_scenario import SCENARIOS
from testbed.traffic.generate import PROFILES, pattern

OUTER_ADDRESSES = {"198.51.100.2", "203.0.113.2"}
OUTER_V6_ADDRESSES = {"2001:db8:1::2", "2001:db8:2::2"}
ALLOWED_KINDS = {PacketKind.IKE, PacketKind.ESP, PacketKind.AH, PacketKind.NAT_KEEPALIVE}


def register(run_directory: Path, capture_path: Path, capture_point: str) -> Path:
    manifest_path = run_directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "configuration_generated_not_executed":
        raise ValueError("Expected an unregistered generated scenario")
    if manifest.get("ground_truth") != SCENARIOS.get(manifest.get("scenario")):
        raise ValueError("Scenario ground truth does not match the generator")
    for name in ("client.conf", "server.conf", "client.strongswan.conf", "server.strongswan.conf"):
        digest = hashlib.sha256((run_directory / name).read_bytes()).hexdigest()
        if digest != manifest.get("config_sha256", {}).get(name):
            raise ValueError(f"Generated config changed: {name}")
    if capture_point not in ("outer client interface", "outer server interface"):
        raise ValueError("Unknown capture point")
    capture = read_capture(capture_path)
    addresses = OUTER_V6_ADDRESSES if manifest["scenario"] == "modern-v6-tunnel" else OUTER_ADDRESSES
    if not capture.packets or capture.diagnostics:
        raise ValueError("Capture is empty or has capture-level diagnostics")
    for packet in capture.packets:
        if (packet.source not in addresses or packet.destination not in addresses
                or packet.kind not in ALLOWED_KINDS or packet.diagnostics):
            raise ValueError(f"Packet {packet.index} is not verified outer IKE/ESP/AH traffic")
    result = analyze_capture(capture_path).to_dict()
    if not any(session["selected"] is not None for session in result["sessions"]):
        raise ValueError("No selected IKE SA response is visible")
    if not any(flow["kind"] == "ESP" for flow in result["flows"]):
        raise ValueError("No ESP flow is visible")
    record = {
        "schema_version": "1.0",
        "scenario": manifest["scenario"],
        "scenario_version": manifest["scenario_version"],
        "label_source": "generated scenario configuration; not model output",
        "ground_truth": manifest["ground_truth"],
        "capture_point": capture_point,
        "capture_sha256": capture.sha256,
        "capture_format": capture.source_format,
        "packet_count": len(capture.packets),
        "ike_session_count": len(result["sessions"]),
        "esp_flow_count": sum(flow["kind"] == "ESP" for flow in result["flows"]),
        "split_group": run_directory.name,
        "verification": "outer packets and selected IKE/ESP observed; daemon configuration not independently attested",
    }
    traffic_path = run_directory / "traffic_record.json"
    if traffic_path.exists():
        traffic = json.loads(traffic_path.read_text(encoding="utf-8"))
        profile = PROFILES.get(traffic.get("profile"))
        if (not profile or traffic.get("role") != "sender"
                or traffic.get("messages") != profile["count"]
                or traffic.get("label_source") != "synthetic generator command"):
            raise ValueError("Invalid synthetic traffic record")
        seed = traffic.get("seed", 0)
        if type(seed) is not int:
            raise ValueError("Invalid synthetic traffic seed")
        sizes, _ = pattern(traffic["profile"], seed)
        if traffic.get("payload_bytes") != (None if traffic["profile"] == "icmp" else sum(sizes)):
            raise ValueError("Synthetic traffic byte count does not match seed")
        record["traffic_profile"] = traffic["profile"]
        record["traffic_seed"] = seed
        record["traffic_label_source"] = "synthetic generator command; packet window requires run verification"
    destination = run_directory / "dataset_record.json"
    if destination.exists():
        raise ValueError("Dataset record already exists")
    destination.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--capture-point", required=True,
                        choices=("outer client interface", "outer server interface"))
    args = parser.parse_args()
    print(register(args.run_directory, args.capture, args.capture_point))


if __name__ == "__main__":
    main()
