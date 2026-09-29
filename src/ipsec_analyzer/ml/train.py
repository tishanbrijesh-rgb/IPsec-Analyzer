"""Rebuild the one-host synthetic pilot artifact from pinned complete runs."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ml.classifier import MODEL_VERSION, _scores, predict
from ipsec_analyzer.ml.contract import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, flow_features


def build(root: Path) -> tuple[dict, dict]:
    index_path = root / "data/dataset-index.json"
    raw = index_path.read_bytes()
    index = json.loads(raw)
    samples = {part: [] for part in ("train", "validation", "test")}
    groups = set()
    for item in index["records"]:
        part = item["partition"]
        if part not in samples:
            continue
        group = item["split_group"]
        if group in groups:
            raise ValueError("Split group repeated")
        groups.add(group)
        capture = root / "data/sample" / item["capture"]
        if hashlib.sha256(capture.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Capture hash mismatch")
        flows = [f for f in analyze_capture(capture).to_dict()["flows"] if f["kind"] == "ESP"]
        if not flows or not item["traffic_profile"]:
            raise ValueError("Training record lacks ESP or label")
        # One example per whole run: the busiest direction is the generated sender.
        flow = max(flows, key=lambda f: (f["packet_count"], f["byte_count"]))
        samples[part].append((item["traffic_profile"], flow, group))
    classes = sorted({label for label, _, _ in samples["train"]})
    if any({label for label, _, _ in samples[part]} != set(classes) for part in samples):
        raise ValueError("Each partition must cover every class")
    matrix = [list(flow_features(flow).values()) for _, flow, _ in samples["train"]]
    center = [sum(row[i] for row in matrix) / len(matrix) for i in range(len(FEATURE_NAMES))]
    scale = [max((sum((row[i] - center[i]) ** 2 for row in matrix) / len(matrix)) ** 0.5, 1.0) for i in range(len(FEATURE_NAMES))]
    normalized = [[(value - center[i]) / scale[i] for i, value in enumerate(row)] for row in matrix]
    centroids = {}
    for label in classes:
        rows = [v for v, sample in zip(normalized, samples["train"]) if sample[0] == label]
        centroids[label] = [sum(row[i] for row in rows) / len(rows) for i in range(len(FEATURE_NAMES))]
    model = {"model_version": MODEL_VERSION, "feature_schema_version": FEATURE_SCHEMA_VERSION,
             "feature_names": list(FEATURE_NAMES), "dataset_version": hashlib.sha256(raw).hexdigest(),
             "classes": classes, "center": center, "scale": scale, "centroids": centroids,
             "temperature": 1.0, "threshold": 0.5, "minimum_packets": 10, "max_distance": 100.0}
    # Temperature is fitted only on validation log loss. Test runs are untouched.
    def loss(t):
        model["temperature"] = t
        return sum(-math.log(max(_scores(flow, model)[0][label], 1e-12))
                   for label, flow, _ in samples["validation"])
    model["temperature"] = min((0.25, 0.5, 1, 2, 4, 8, 16), key=loss)
    train_distances = []
    for label, flow, _ in samples["train"]:
        vec = [(flow_features(flow)[name] - mid) / s for name, mid, s in zip(FEATURE_NAMES, center, scale)]
        train_distances.append(sum((a-b)**2 for a, b in zip(vec, centroids[label])))
    model["max_distance"] = max(train_distances) * 1.5 + 0.01
    # Select a conservative confidence cutoff from validation: accepted predictions
    # must all be correct. A coarse fixed grid makes the selection reproducible.
    for threshold in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99):
        model["threshold"] = threshold
        results = [(label, predict(flow, model)) for label, flow, _ in samples["validation"]]
        if all(result["abstained"] or result["prediction"] == label for label, result in results):
            break
    report = {"scope": "single-host synthetic pilot; no real-application generalization claim",
              "model_version": MODEL_VERSION, "dataset_version": model["dataset_version"],
              "feature_schema_version": FEATURE_SCHEMA_VERSION, "temperature": model["temperature"],
              "threshold": model["threshold"], "partitions": {part: [group for _, _, group in rows] for part, rows in samples.items()}}
    for part in ("validation", "test"):
        rows = [(label, predict(flow, model)) for label, flow, _ in samples[part]]
        confusion = {label: {pred: 0 for pred in classes + ["unknown/other"]} for label in classes}
        for label, result in rows:
            confusion[label][result["prediction"]] += 1
        scored = [(label, result) for label, result in rows if result["probabilities"] is not None]
        report[part] = {"confusion": confusion, "per_class": {},
                        "coverage": sum(not result["abstained"] for _, result in rows) / len(rows),
                        "accuracy_all_runs": sum(result["prediction"] == label for label, result in rows) / len(rows),
                        "brier_accepted_only": (sum(sum((result["probabilities"][c] - (c == label)) ** 2 for c in classes)
                                                       for label, result in scored) / len(scored)) if scored else None,
                        "calibration_sample_count": len(scored)}
        for label in classes:
            tp = confusion[label][label]
            fp = sum(confusion[other][label] for other in classes if other != label)
            fn = sum(confusion[label][other] for other in classes + ["unknown/other"] if other != label)
            report[part]["per_class"][label] = {"precision": tp / (tp + fp) if tp + fp else 0,
                                                 "recall": tp / (tp + fn) if tp + fn else 0,
                                                 "support": sum(confusion[label].values())}
    return model, report


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[3]
    artifact, evaluation = build(repo)
    target = repo / "models/artifacts/traffic-classifier"
    target.mkdir(parents=True, exist_ok=True)
    (target / "model.json").write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    (target / "evaluation.json").write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n")
