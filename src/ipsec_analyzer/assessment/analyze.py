"""Offline analysis pipeline with explicit scope and coverage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ipsec_analyzer.assessment.sessions import correlate_messages
from ipsec_analyzer.assessment.evidence import describe_evidence
from ipsec_analyzer.features.flows import build_flows
from ipsec_analyzer.ingestion.capture import CaptureError, read_capture
from ipsec_analyzer.parsers.ike import parse_ike
from ipsec_analyzer.rules.ikev1 import evaluate_ike_version
from ipsec_analyzer.rules.ikev2_selected import evaluate_selected_transform
from ipsec_analyzer.ml.classifier import load_model, predict
from ipsec_analyzer.ml.contract import ModelUnavailable

ANALYSIS_VERSION = "0.3"
MAX_IKE_MESSAGES = 10_000
MAX_EVIDENCE_SUBJECTS = 5_000
MAX_PACKET_SUMMARIES = 5_000


@dataclass
class Analysis:
    result: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.result


def analyze_capture(path: str | Path) -> Analysis:
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
                     evaluate_selected_transform(session, 4)):
            entry = item.to_dict()
            entry["subject_id"] = record["id"]
            field = "version_major" if item.rule_id == "IPSEC-IKE-LEGACY-001" else "selected"
            entry["evidence_ids"] = [record["id"] + ":" + field] if item.evidence_packets else []
            evaluations.append(entry)
    evaluated = sum(item["status"] in ("PASS", "FAIL") for item in evaluations)
    failed = sum(item["status"] == "FAIL" for item in evaluations)
    applicable = sum(item["status"] != "NOT_APPLICABLE" for item in evaluations)
    passed = sum(item["status"] == "PASS" for item in evaluations)
    findings = [dict(item, finding_id=f"{item['subject_id']}:{item['rule_id']}:{item['rule_version']}")
                for item in evaluations if item["status"] == "FAIL"]
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
        "packet_summaries": packet_summaries,
        "packet_summaries_truncated": len(referenced_packets) > MAX_PACKET_SUMMARIES,
        "rule_evaluations": evaluations,
        "findings": findings,
        "rule_set_version": "prototype-2",
        "coverage": {
            "implemented_rules": 3,
            "evaluated_session_rules": evaluated,
            "total_session_rules": applicable,
            "not_applicable_session_rules": len(evaluations) - applicable,
            "evaluated_ratio": rule_coverage,
        },
        "assessed_rule_pass_percent": round(100 * passed / evaluated, 2) if evaluated and evaluated == applicable else None,
        "score_policy_version": "observed-rule-pass-1",
        "security_score": None,
        "risk_score": None,
        "ai_inference": {
            "status": ai_status,
            "confidence": None,
            "model_version": model_version,
            "reason": ai_reason,
            "flows": inferences,
        },
        "score_reason": "A comprehensive score is withheld until more assessment dimensions are implemented.",
        "finding_count": failed,
        "diagnostics": [d.__dict__ for d in capture.diagnostics],
        "limitations": [
            "Visible IKEv1 DOI 1, identity-only SA attributes are decoded; other DOI/situations and encrypted payloads remain unknown.",
            "Child SA, PFS, lifetime, replay setting and mode are not determined. Application estimates are synthetic-profile inferences only.",
            "No comprehensive security score is available from the current rule coverage.",
        ],
    }
    return Analysis(result)
