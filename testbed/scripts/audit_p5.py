"""Read-only second-pass audit of pinned Phase 5 holdout claims."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ml.classifier import load_model, predict


def audit(root: Path) -> dict:
    index_bytes = (root / "data/dataset-index.json").read_bytes()
    index = json.loads(index_bytes)
    saved = json.loads((root / "models/artifacts/traffic-classifier/evaluation.json").read_text(encoding="utf-8"))
    model = load_model(root / "models/artifacts/traffic-classifier/model.json")
    digest = hashlib.sha256(index_bytes).hexdigest()
    if digest != model["dataset_version"] or digest != saved["dataset_version"]:
        raise ValueError("Model or evaluation uses a different dataset index")

    groups: dict[str, str] = {}
    outcomes: dict[str, list[tuple[str, str, bool]]] = defaultdict(list)
    for item in index["records"]:
        partition = item["partition"]
        group = item["split_group"]
        if group in groups:
            raise ValueError(f"Repeated split group: {group}")
        groups[group] = partition
        if partition not in ("validation", "test"):
            continue
        capture_path = root / "data/sample" / item["capture"]
        record = json.loads((root / "data/sample" / item["record"]).read_text(encoding="utf-8"))
        if (hashlib.sha256(capture_path.read_bytes()).hexdigest() != item["sha256"]
                or record["capture_sha256"] != item["sha256"]
                or record["split_group"] != group
                or record["traffic_profile"] != item["traffic_profile"]
                or not record["traffic_label_source"].startswith("synthetic generator command")):
            raise ValueError(f"Hash, group or label provenance mismatch: {group}")
        analysis = analyze_capture(capture_path).to_dict()
        flows = [flow for flow in analysis["flows"] if flow["kind"] == "ESP"]
        if analysis["diagnostics"] or not flows:
            raise ValueError(f"Invalid held-out capture: {group}")
        sender = max(flows, key=lambda flow: (flow["packet_count"], flow["byte_count"]))
        result = predict(sender, model)
        outcomes[partition].append((item["traffic_profile"], result["prediction"], result["abstained"]))

    summary = {"dataset_version": digest, "model_version": model["model_version"], "partitions": {}}
    for partition in ("validation", "test"):
        rows = outcomes[partition]
        actual = Counter(label for label, _, _ in rows)
        confusion = defaultdict(Counter)
        for label, prediction, _ in rows:
            confusion[label][prediction] += 1
        expected = saved[partition]
        if (len(rows) != expected["run_count"]
                or sum(not abstained for _, _, abstained in rows) != expected["accepted_count"]
                or sum(abstained for _, _, abstained in rows) != expected["abstained_count"]
                or any(dict(confusion[label]) != {key: value for key, value in expected["confusion"][label].items() if value}
                       for label in actual)
                or any(actual[label] != expected["per_class"][label]["support"] for label in actual)):
            raise ValueError(f"Published {partition} metrics disagree with independent recount")
        summary["partitions"][partition] = {
            "runs": len(rows), "accepted": expected["accepted_count"],
            "abstained": expected["abstained_count"],
            "correct_accepted": sum(label == prediction for label, prediction, abstained in rows if not abstained),
            "classes": dict(sorted(actual.items())),
        }
    return summary


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[2]
    print(json.dumps(audit(repo), indent=2))
