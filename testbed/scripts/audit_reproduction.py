"""Read-only audit of the Phase 4 strong/contrast reproduction bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from testbed.scripts.generate_scenario import SCENARIOS

EXPECTED = {
    "modern-tunnel": (20, 256, "AES_GCM_16-256"),
    "cbc-no-pfs": (12, 128, "AES_CBC-128/HMAC_SHA2_256_128"),
}


def audit(run_directory: Path) -> dict:
    record = json.loads((run_directory / "dataset_record.json").read_text(encoding="utf-8"))
    scenario = record.get("scenario")
    if scenario not in EXPECTED:
        raise ValueError("Expected modern-tunnel or cbc-no-pfs scenario")
    if record.get("ground_truth") != SCENARIOS[scenario]:
        raise ValueError("Dataset ground truth differs from the generator scenario")
    if record.get("label_source") != "generated scenario configuration; not model output":
        raise ValueError("Ground-truth source is not the generated configuration")
    result = analyze_capture(run_directory / "outer.pcap").to_dict()
    if result["capture"]["sha256"] != record.get("capture_sha256"):
        raise ValueError("Capture SHA-256 differs from dataset record")
    if result["capture"]["packet_count"] != record.get("packet_count"):
        raise ValueError("Packet count differs from dataset record")
    if result["diagnostics"]:
        raise ValueError("Capture has diagnostics")
    if len(result["sessions"]) != record.get("ike_session_count"):
        raise ValueError("IKE session count differs from dataset record")
    esp_flows = [flow for flow in result["flows"] if flow["kind"] == "ESP"]
    if len(esp_flows) != record.get("esp_flow_count") or len(esp_flows) < 2:
        raise ValueError("Expected recorded bidirectional ESP flows")
    expected_id, expected_bits, expected_esp = EXPECTED[scenario]
    selected = [session["selected"] for session in result["sessions"] if session["selected"]]
    if len(selected) != 1:
        raise ValueError("Expected one selected IKE SA response")
    encryption = [transform for transform in selected[0]["transforms"] if transform["transform_type"] == 1]
    if len(encryption) != 1 or (encryption[0]["transform_id"], encryption[0]["key_length_bits"]) != (expected_id, expected_bits):
        raise ValueError("Selected IKE encryption differs from expected scenario")
    status = (run_directory / "sa-status.log").read_text(encoding="utf-8")
    sections = {}
    peer = None
    for line in status.splitlines():
        if line.strip() in ("client:", "server:"):
            peer = line.strip()[:-1]
            sections[peer] = []
        elif peer and "INSTALLED" in line and "ESP:" in line:
            sections[peer].append(line.strip())
    if set(sections) != {"client", "server"} or any(
        len(lines) != 1 or expected_esp not in lines[0] for lines in sections.values()
    ):
        raise ValueError("Expected installed Child SAs on both peers")
    return {
        "scenario": scenario,
        "capture_sha256": result["capture"]["sha256"],
        "packet_count": result["capture"]["packet_count"],
        "ike_sessions": len(selected),
        "selected_ike_encryption_id": expected_id,
        "selected_ike_key_bits": expected_bits,
        "esp_flows": len(esp_flows),
        "installed_child_sa_lines": sum(map(len, sections.values())),
        "note": "Local consistency check only; reviewer identity and host independence require separate attestation.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("modern_run", type=Path)
    parser.add_argument("cbc_run", type=Path)
    args = parser.parse_args()
    records = [audit(args.modern_run), audit(args.cbc_run)]
    if {item["scenario"] for item in records} != set(EXPECTED):
        raise ValueError("Provide one modern and one CBC scenario")
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
