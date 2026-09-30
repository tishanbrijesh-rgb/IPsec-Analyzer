"""Offline analysis pipeline with explicit scope and coverage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ipsec_analyzer.assessment.sessions import correlate_messages
from ipsec_analyzer.assessment.evidence import describe_evidence
from ipsec_analyzer.assessment.configuration import FIELDS, validate_configuration
from ipsec_analyzer.assessment.risk import assess_risk
from ipsec_analyzer.features.flows import build_flows
from ipsec_analyzer.ingestion.capture import CaptureError, read_capture
from ipsec_analyzer.parsers.ike import parse_ike
from ipsec_analyzer.rules.ikev1 import evaluate_ike_version
from ipsec_analyzer.rules.ikev2_selected import evaluate_selected_transform
from ipsec_analyzer.rules.configured import evaluate_configuration
from ipsec_analyzer.ml.classifier import load_model, predict
from ipsec_analyzer.ml.contract import ModelUnavailable

ANALYSIS_VERSION = "0.4"
MAX_IKE_MESSAGES = 10_000
MAX_EVIDENCE_SUBJECTS = 5_000
MAX_PACKET_SUMMARIES = 5_000


@dataclass
class Analysis:
    result: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.result


def analyze_capture(path: str | Path, configuration: dict | None = None) -> Analysis:
    capture = read_capture(path)
    messages = []
    for event, frame in zip(capture.packets, capture.raw_frames):
        message = parse_ike(event, frame)
        if message is not None:
            if len(messages) >= MAX_IKE_MESSAGES:
                raise CaptureError("Capture exceeds IKE analysis message limit")
            messages.append(message)
    fatal_codes = {"INVALID_IKE_LENGTH", "INVALID_IKE_SPI", "UNSUPPORTED_IKE_VERSION"}
    sessions = correlate_messages([
        message for message in messages
        if not any(diagnostic.code in fatal_codes for diagnostic in message.diagnostics)
    ])
    flows = build_flows(capture.packets)
    if len(sessions) + len(flows) > MAX_EVIDENCE_SUBJECTS:
        raise CaptureError("Capture exceeds evidence subject limit")
    session_records, flow_records, evidence = describe_evidence(capture.capture_id, sessions, flows)
    capture_end_ns = max((p.timestamp_ns for p in capture.packets if p.timestamp_ns is not None), default=None)
    config_status = validate_configuration(configuration, capture.sha256, session_records, capture_end_ns)
    for record in session_records:
        values = config_status["matches"].get(record["id"], {})
        for field in FIELDS:
            evidence_id = f"{record['id']}:config:{field}"
            evidence.append({
                "id": evidence_id, "subject_id": record["id"], "field": field,
                "state": "CONFIGURED" if field in values else "UNKNOWN",
                "value": values.get(field), "packet_indices": (),
                "method": "authorized-config-v1" if field in values else None,
                "reason": None if field in values else
                    ("Field absent from matched configuration." if values else config_status["reason"]),
                "source_id": config_status["source_id"] if field in values else None,
                "collected_at": config_status["collected_at"] if field in values else None,
            })
            record["evidence_ids"].append(evidence_id)
    model_path = Path(__file__).resolve().parents[3] / "models/artifacts/traffic-classifier/model.json"
    try:
        model = load_model(model_path)
        inferences = [dict(predict(flow, model), flow_id=flow["id"]) for flow in flow_records]
        ai_status = "AVAILABLE"
        ai_reason = "Synthetic one-host pilot only; unknown/other means abstention."
        model_version = model["model_version"]
    except ModelUnavailable:
        inferences = []
        ai_status = "UNKNOWN"
        ai_reason = "No compatible classifier artifact is available."
        model_version = None
    evaluations = []
    for session, record in zip(sessions, session_records):
        for item in (evaluate_ike_version(session),
                     evaluate_selected_transform(session, 1),
                     evaluate_selected_transform(session, 2),
                     evaluate_selected_transform(session, 4)):
            entry = item.to_dict()
            entry["subject_id"] = record["id"]
            field = "version_major" if item.rule_id == "IPSEC-IKE-LEGACY-001" else "selected"
            entry["evidence_ids"] = [record["id"] + ":" + field] if item.evidence_packets else []
            evaluations.append(entry)
        values = config_status["matches"].get(record["id"], {})
        for item in evaluate_configuration(record["id"], values, config_status["reason"]):
            entry = item.to_dict()
            entry["subject_id"] = record["id"]
            entry["evidence_ids"] = list(item.evidence_ids)
            evaluations.append(entry)
    evaluated = sum(item["status"] in ("PASS", "FAIL") for item in evaluations)
    failed = sum(item["status"] == "FAIL" for item in evaluations)
    applicable = sum(item["status"] != "NOT_APPLICABLE" for item in evaluations)
    packet_evaluations = [item for item in evaluations if not item["rule_id"].startswith("IPSEC-CONFIG-")]
    packet_applicable = [item for item in packet_evaluations if item["status"] != "NOT_APPLICABLE"]
    packet_assessed = [item for item in packet_applicable if item["status"] in ("PASS", "FAIL")]
    packet_passed = sum(item["status"] == "PASS" for item in packet_assessed)
    findings = [dict(item, finding_id=f"{item['subject_id']}:{item['rule_id']}:{item['rule_version']}")
                for item in evaluations if item["status"] == "FAIL"]
    risk_score, threat_matrix = assess_risk(evaluations, config_status["status"])
    referenced_packets = sorted({index for item in evaluations for index in item["evidence_packets"]}
                                | {session["selected_evidence_packet"] for session in session_records
                                   if session["selected_evidence_packet"] is not None})
    packet_summaries = []
    for index in referenced_packets[:MAX_PACKET_SUMMARIES]:
        if not 1 <= index <= len(capture.packets):
            continue
        packet = capture.packets[index - 1]
        packet_summaries.append({
            "index": packet.index,
            "timestamp_ns": packet.timestamp_ns,
            "kind": packet.kind,
            "source": packet.source,
            "destination": packet.destination,
            "captured_length": packet.captured_length,
            "encapsulation": packet.encapsulation,
            "diagnostics": [diagnostic.code for diagnostic in packet.diagnostics],
        })
    rule_coverage = evaluated / applicable if applicable else 0.0
    result = {
        "analysis_version": ANALYSIS_VERSION,
        "capture": {
            "id": capture.capture_id,
            "sha256": capture.sha256,
            "format": capture.source_format,
            "packet_count": len(capture.packets),
        },
        "sessions": session_records,
        "ike_messages": [message.to_dict() for message in messages],
        "flows": flow_records,
        "evidence": evidence,
        "configuration": config_status,
        "packet_summaries": packet_summaries,
        "packet_summaries_truncated": len(referenced_packets) > MAX_PACKET_SUMMARIES,
        "rule_evaluations": evaluations,
        "findings": findings,
        "threat_matrix": threat_matrix,
        "rule_set_version": "configuration-2",
        "coverage": {
            "implemented_rules": 8,
            "evaluated_session_rules": evaluated,
            "total_session_rules": applicable,
            "not_applicable_session_rules": len(evaluations) - applicable,
            "evaluated_ratio": rule_coverage,
        },
        "assessed_rule_pass_percent": (round(100 * packet_passed / len(packet_assessed), 2)
                                        if packet_assessed and len(packet_assessed) == len(packet_applicable) else None),
        "score_policy_version": risk_score["policy_version"],
        "security_score": round(100 - risk_score["value"], 2) if risk_score["value"] is not None else None,
        "risk_score": risk_score,
        "ai_inference": {
            "status": ai_status,
            "confidence": None,
            "model_version": model_version,
            "reason": ai_reason,
            "flows": inferences,
        },
        "score_reason": risk_score["withheld_reason"],
        "finding_count": failed,
        "diagnostics": [d.__dict__ for d in capture.diagnostics],
        "limitations": [
            "Visible IKEv1 DOI 1, identity-only SA attributes are decoded; other DOI/situations and encrypted payloads remain unknown.",
            "Configuration-backed Child SA settings describe configured intent, not installed state; capture-only values remain unknown.",
            "The risk score uses a project policy and limited controls; it is not a deployment certification. Application estimates are synthetic-profile inferences only.",
        ],
    }
    return Analysis(result)
