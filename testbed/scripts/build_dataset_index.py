"""Validate shared lab fixtures and record run-level pilot partitions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from testbed.scripts.generate_scenario import SCENARIOS
from testbed.traffic.generate import PROFILES


def build(sample_dir: Path) -> dict[str, object]:
    records: list[dict[str, object]] = []
    hashes: set[str] = set()
    groups: set[str] = set()
    classes: dict[str, list[dict[str, object]]] = defaultdict(list)
    for path in sorted(sample_dir.glob("*.json")):
        if path.name.endswith("-verification.json"):
            continue
        pcap = path.with_suffix(".pcap")
        if not pcap.is_file():
            raise ValueError(f"Missing PCAP: {path.name}")
        record = json.loads(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
        if digest != record.get("capture_sha256") or digest in hashes:
            raise ValueError(f"Missing, changed, or duplicate capture hash: {path.name}")
        analysis = analyze_capture(pcap).to_dict()
        if (analysis["capture"]["packet_count"] != record.get("packet_count")
                or analysis["capture"]["format"] != record.get("capture_format")
                or len(analysis["sessions"]) != record.get("ike_session_count")
                or len(analysis["flows"]) != record.get("esp_flow_count")
                or analysis["diagnostics"]
                or not any(session["selected"] for session in analysis["sessions"])
                or not analysis["flows"]
                or not all(flow["kind"] == "ESP" for flow in analysis["flows"])):
            raise ValueError(f"Capture metadata or IPsec evidence mismatch: {path.name}")
        group = record.get("split_group")
        if not isinstance(group, str) or not group or group in groups:
            raise ValueError(f"Invalid or duplicate split group: {path.name}")
        if record.get("ground_truth") != SCENARIOS.get(record.get("scenario")):
            raise ValueError(f"Scenario label mismatch: {path.name}")
        if record.get("label_source") != "generated scenario configuration; not model output":
            raise ValueError(f"Unverified label source: {path.name}")
        profile = record.get("traffic_profile")
        if profile is not None and profile not in PROFILES:
            raise ValueError(f"Unknown traffic profile: {path.name}")
        if profile is not None:
            if not str(record.get("traffic_label_source", "")).startswith("synthetic generator command"):
                raise ValueError(f"Unverified traffic label: {path.name}")
            seed = record.get("traffic_seed", 0)
            if type(seed) is not int or not 0 <= seed <= 1000000:
                raise ValueError(f"Invalid traffic seed: {path.name}")
        item = {"capture": pcap.name, "record": path.name, "sha256": digest,
                "split_group": group, "scenario": record["scenario"],
                "traffic_profile": profile, "partition": "reference"}
        if re.fullmatch(r"phase4-(voip|video|messaging|email|web|icmp)-0[1-5]", path.stem) and profile is not None:
            classes[profile].append(item)
        records.append(item)
        hashes.add(digest)
        groups.add(group)
    if not records:
        raise ValueError("No dataset records")
    for profile in PROFILES:
        examples = sorted(classes[profile], key=lambda item: item["split_group"])
        if examples and len(examples) != 5:
            raise ValueError(f"Expected five reviewed batch runs for {profile}")
        if examples:
            # A rotating order avoids assigning one scenario to every held-out class.
            offset = sorted(PROFILES).index(profile) % 5
            for rank, item in enumerate(examples):
                slot = (rank + offset) % 5
                item["partition"] = "train" if slot < 3 else ("validation" if slot == 3 else "test")
    counts = Counter(item["partition"] for item in records)
    return {"schema_version": "1.0", "purpose": "controlled lab pilot; not a validated ML benchmark",
            "split_unit": "complete run", "host_scope": "one WSL2 host",
            "counts": dict(sorted(counts.items())), "records": records}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sample_dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="Validate captures and records without writing an index")
    args = parser.parse_args()
    if not args.check and args.output is None:
        parser.error("--output is required unless --check is used")
    result = build(args.sample_dir)
    if not args.check:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"]))


if __name__ == "__main__":
    main()
