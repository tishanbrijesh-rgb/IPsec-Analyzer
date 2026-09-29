"""Safe model-artifact contract; no executable pickle loading."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

FEATURE_SCHEMA_VERSION = "esp-flow-2"
FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "mean_length",
    "std_length",
    "min_length",
    "max_length",
    "mean_interarrival_ns",
    "length_range",
    "bytes_per_packet",
    "burst_count",
)
MAX_ARTIFACT_BYTES = 1_000_000


class ModelUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class ModelMetadata:
    name: str
    version: str
    dataset_version: str
    feature_schema_version: str
    classes: tuple[str, ...]
    evaluation: dict
    calibrated: bool


def load_metadata(path: str | Path) -> ModelMetadata:
    artifact = Path(path)
    if not artifact.is_file() or artifact.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ModelUnavailable("Model metadata is absent or exceeds size limit")
    try:
        data = json.loads(artifact.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ModelUnavailable("Model metadata is invalid JSON") from exc
    required = ("name", "version", "dataset_version", "feature_schema_version", "classes", "evaluation", "calibrated")
    if not isinstance(data, dict) or any(key not in data for key in required):
        raise ModelUnavailable("Model metadata is incomplete")
    if data["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
        raise ModelUnavailable("Model feature schema is incompatible")
    if not isinstance(data["classes"], list) or not data["classes"] or not all(isinstance(value, str) for value in data["classes"]):
        raise ModelUnavailable("Model classes are invalid")
    if not isinstance(data["evaluation"], dict) or not isinstance(data["calibrated"], bool):
        raise ModelUnavailable("Model evaluation or calibration metadata is invalid")
    if not all(isinstance(data[key], str) and data[key] for key in ("name", "version", "dataset_version")):
        raise ModelUnavailable("Model identity is invalid")
    return ModelMetadata(
        data["name"], data["version"], data["dataset_version"],
        data["feature_schema_version"], tuple(data["classes"]),
        data["evaluation"], data["calibrated"],
    )


def flow_features(flow: dict) -> dict[str, float]:
    if any(name not in flow for name in FEATURE_NAMES[:-3]):
        raise ValueError("Flow does not match the feature schema")
    values = {name: float(flow[name] or 0) for name in FEATURE_NAMES[:-3]}
    values["length_range"] = values["max_length"] - values["min_length"]
    values["bytes_per_packet"] = values["byte_count"] / max(values["packet_count"], 1)
    if "burst_count" not in flow:
        raise ValueError("Flow does not match the feature schema")
    values["burst_count"] = float(flow["burst_count"] or 0)
    if any(not math.isfinite(value) or value < 0 for value in values.values()):
        raise ValueError("Flow feature contains a negative or non-finite value")
    return values
