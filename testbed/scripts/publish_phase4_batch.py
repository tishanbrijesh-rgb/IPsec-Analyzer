"""Copy only verified, secret-free Phase 4 records and outer captures."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import read_capture
from testbed.scripts.generate_scenario import SCENARIOS
from testbed.traffic.generate import PROFILES, pattern


def publish(project: Path) -> int:
    source_root = project / "testbed" / "generated"
    destination = project / "data" / "sample"
    runs = sorted(path for path in source_root.glob("phase4-*/dataset_record.json")
                  if re.fullmatch(r"phase4-(voip|video|messaging|email|web|icmp)-0[1-5]", path.parent.name))
    if len(runs) != 30:
        raise ValueError(f"Expected 30 registered runs, got {len(runs)}")
    staged = []
    for record_path in runs:
        run = record_path.parent
        capture_path = run / "outer.pcap"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        traffic = json.loads((run / "traffic_record.json").read_text(encoding="utf-8"))
        if record.get("split_group") != run.name or record.get("scenario") not in SCENARIOS:
            raise ValueError(f"Invalid run label: {run.name}")
        if record.get("ground_truth") != SCENARIOS[record["scenario"]]:
            raise ValueError(f"Invalid scenario ground truth: {run.name}")
        if traffic.get("profile") not in PROFILES or record.get("traffic_profile") != traffic["profile"]:
            raise ValueError(f"Invalid traffic label: {run.name}")
        seed = traffic.get("seed")
        if type(seed) is not int or record.get("traffic_seed") != seed:
            raise ValueError(f"Invalid seed: {run.name}")
        sizes, _ = pattern(traffic["profile"], seed)
        expected = None if traffic["profile"] == "icmp" else sum(sizes)
        if traffic.get("payload_bytes") != expected:
            raise ValueError(f"Invalid traffic byte count: {run.name}")
        capture = read_capture(capture_path)
        result = analyze_capture(capture_path).to_dict()
        if (capture.sha256 != record.get("capture_sha256")
                or len(capture.packets) != record.get("packet_count")
                or capture.diagnostics or not result["sessions"] or not result["flows"]
                or not any(session["selected"] for session in result["sessions"])
                or not all(flow["kind"] == "ESP" for flow in result["flows"])):
            raise ValueError(f"Capture verification failed: {run.name}")
        output_capture = destination / f"{run.name}.pcap"
        output_record = destination / f"{run.name}.json"
        if output_capture.exists() or output_record.exists():
            raise ValueError(f"Destination already exists: {run.name}")
        staged.append((capture_path, record_path, output_capture, output_record))
    for capture_path, record_path, output_capture, output_record in staged:
        shutil.copyfile(capture_path, output_capture)
        shutil.copyfile(record_path, output_record)
    return len(staged)


if __name__ == "__main__":
    print(f"published {publish(Path(__file__).resolve().parents[2])} reviewed runs")
