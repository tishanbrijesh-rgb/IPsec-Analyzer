"""Bounded, data-only prototype classifier for synthetic ESP profiles."""

from __future__ import annotations

import json
import math
from pathlib import Path

from ipsec_analyzer.ml.contract import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, MAX_ARTIFACT_BYTES, ModelUnavailable, flow_features

MODEL_VERSION = "synthetic-centroid-2"


def load_model(path: str | Path) -> dict:
    source = Path(path)
    if not source.is_file() or source.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ModelUnavailable("Classifier artifact is absent or too large")
    try:
        model = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(model, dict) or model["model_version"] != MODEL_VERSION or model["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise ValueError("Incompatible classifier")
        names = model["feature_names"]
        classes = model["classes"]
        if names != list(FEATURE_NAMES) or not isinstance(classes, list) or len(classes) < 2 or len(set(classes)) != len(classes):
            raise ValueError("Invalid model dimensions")
        if not all(isinstance(c, str) and c for c in classes):
            raise ValueError("Invalid classes")
        if set(model["centroids"]) != set(classes):
            raise ValueError("Invalid centroids")
        vectors = [model["center"], model["scale"], *model["centroids"].values()]
        if any(not isinstance(v, list) or len(v) != len(names)
               or any(type(x) not in (int, float) or not math.isfinite(x) for x in v)
               for v in vectors):
            raise ValueError("Invalid numeric parameters")
        if any(x <= 0 for x in model["scale"]):
            raise ValueError("Invalid scale")
        if (type(model["temperature"]) not in (int, float)
                or type(model["threshold"]) not in (int, float)
                or not math.isfinite(model["temperature"])
                or not math.isfinite(model["threshold"])
                or not 0 < model["temperature"] <= 100
                or not 0 < model["threshold"] <= 1):
            raise ValueError("Invalid calibration")
        if type(model["minimum_packets"]) is not int or model["minimum_packets"] < 2:
            raise ValueError("Invalid support bound")
        if type(model["max_distance"]) not in (int, float) or not math.isfinite(model["max_distance"]) or model["max_distance"] <= 0:
            raise ValueError("Invalid support distance")
        return model
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ModelUnavailable("Classifier artifact is invalid or incompatible") from exc


def _scores(flow: dict, model: dict) -> tuple[dict[str, float], dict[str, float]]:
    features = flow_features(flow)
    vector = [(features[name] - mid) / scale for name, mid, scale in zip(FEATURE_NAMES, model["center"], model["scale"])]
    distances = {name: sum((a - b) ** 2 for a, b in zip(vector, model["centroids"][name])) for name in model["classes"]}
    if any(not math.isfinite(distance) for distance in distances.values()):
        raise ValueError("Flow lies outside finite model support")
    logits = {name: -distance / model["temperature"] for name, distance in distances.items()}
    peak = max(logits.values())
    weights = {name: math.exp(value - peak) for name, value in logits.items()}
    total = sum(weights.values())
    if not math.isfinite(total) or total <= 0:
        raise ValueError("Invalid model probability normalization")
    probabilities = {name: value / total for name, value in weights.items()}
    if any(not math.isfinite(value) for value in probabilities.values()):
        raise ValueError("Non-finite model probability")
    return probabilities, distances


def predict(flow: dict, model: dict) -> dict:
    base = {"state": "UNKNOWN", "prediction": "unknown/other", "abstained": True,
            "model_version": model["model_version"], "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "evidence_refs": flow.get("packet_indices", []), "probabilities": None, "confidence": None}
    if flow.get("kind") != "ESP" or flow.get("packet_count", 0) < model["minimum_packets"] or flow.get("association_state") != "UNAMBIGUOUS":
        return dict(base, reason="Unsupported or insufficient ESP flow")
    try:
        probabilities, distances = _scores(flow, model)
    except (ValueError, TypeError, OverflowError):
        return dict(base, reason="Incompatible flow features")
    label = max(probabilities, key=probabilities.get)
    confidence = probabilities[label]
    if confidence < model["threshold"] or distances[label] > model["max_distance"]:
        return dict(base, reason="Low confidence or outside training support")
    return dict(base, state="INFERRED", prediction=label, abstained=False,
                probabilities=probabilities, confidence=confidence, reason="Synthetic profile estimate")
