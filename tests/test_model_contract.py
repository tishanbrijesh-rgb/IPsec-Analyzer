import json

import pytest

from ipsec_analyzer.ml.contract import ModelUnavailable, flow_features, load_metadata


def test_model_metadata_requires_matching_schema(tmp_path):
    path = tmp_path / "metadata.json"
    data = {
        "name": "example", "version": "1", "dataset_version": "demo-1",
        "feature_schema_version": "other", "classes": ["web"],
        "evaluation": {}, "calibrated": False,
    }
    path.write_text(json.dumps(data))
    with pytest.raises(ModelUnavailable):
        load_metadata(path)
    data["feature_schema_version"] = "esp-flow-2"
    path.write_text(json.dumps(data))
    assert load_metadata(path).calibrated is False


def test_flow_schema_is_explicit():
    with pytest.raises(ValueError):
        flow_features({"packet_count": 1})
    from ipsec_analyzer.ml.contract import FEATURE_NAMES
    with pytest.raises(ValueError):
        flow_features({name: float("inf") for name in FEATURE_NAMES})
