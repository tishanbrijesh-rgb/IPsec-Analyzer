import json
from pathlib import Path

import pytest

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ml.classifier import load_model, predict
from ipsec_analyzer.ml.contract import ModelUnavailable
from ipsec_analyzer.ml.train import build


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "models/artifacts/traffic-classifier"


def test_rebuild_matches_pinned_artifact_and_holdout():
    model, evaluation = build(ROOT)
    assert model == json.loads((ARTIFACT / "model.json").read_text())
    assert evaluation == json.loads((ARTIFACT / "evaluation.json").read_text())
    assert set(evaluation["partitions"]["train"]).isdisjoint(evaluation["partitions"]["test"])
    for part in ("validation", "test"):
        metrics = evaluation[part]
        assert metrics["run_count"] == metrics["accepted_count"] + metrics["abstained_count"] == 6
        assert sum(bin_["count"] for bin_ in metrics["confidence_bins_accepted_only"]) == metrics["accepted_count"]
        assert metrics["calibration_sample_count"] == metrics["accepted_count"]


def test_reload_abstention_and_rule_separation(tmp_path):
    model = load_model(ARTIFACT / "model.json")
    result = analyze_capture(ROOT / "data/sample/voip-like.pcap").to_dict()
    assert result["ai_inference"]["model_version"] == model["model_version"]
    assert all(item["state"] in ("INFERRED", "UNKNOWN") for item in result["ai_inference"]["flows"])
    assert all("prediction" not in item for item in result["rule_evaluations"])
    short = dict(result["flows"][0], packet_count=1)
    assert predict(short, model)["prediction"] == "unknown/other"
    assert predict(short, model)["confidence"] is None
    assert predict(short, model)["probabilities"] is None
    out_of_support = dict(result["flows"][0], byte_count=1_000_000_000)
    rejected = predict(out_of_support, model)
    assert rejected["abstained"]
    assert rejected["confidence"] is None
    assert rejected["probabilities"] is None
    overflow = predict(dict(result["flows"][0], byte_count=1e308), model)
    assert overflow["abstained"] and overflow["confidence"] is None
    assert overflow["probabilities"] is None
    wrong = dict(model, feature_schema_version="future")
    path = tmp_path / "model.json"
    path.write_text(json.dumps(wrong))
    with pytest.raises(ModelUnavailable):
        load_model(path)
    invalid_temperature = dict(model, temperature=float("nan"))
    path.write_text(json.dumps(invalid_temperature))
    with pytest.raises(ModelUnavailable):
        load_model(path)
    invalid_minimum = dict(model, minimum_packets=True)
    path.write_text(json.dumps(invalid_minimum))
    with pytest.raises(ModelUnavailable):
        load_model(path)
    old = dict(model, model_version="synthetic-centroid-1")
    path.write_text(json.dumps(old))
    with pytest.raises(ModelUnavailable):
        load_model(path)


def test_normal_control_has_no_inferred_traffic_class():
    result = analyze_capture(ROOT / "data/control/plain-icmp-01.pcap").to_dict()
    assert result["flows"] == []
    assert result["ai_inference"]["flows"] == []
    assert result["rule_evaluations"] == []
