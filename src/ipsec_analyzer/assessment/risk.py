"""Versioned, coverage-gated project risk and evidence-linked threats."""

from __future__ import annotations

from typing import Any

POLICY_VERSION = "sih-risk-3"
THREAT_VERSION = "sih-threat-1"
MIN_WEIGHTED_COVERAGE = 0.8
WEIGHTS = {
    "IPSEC-IKE-LEGACY-001": 3,
    "IPSEC-IKEV2-DES-001": 3,
    "IPSEC-IKEV2-PRF-MD5-001": 3,
    "IPSEC-IKEV2-INTEG-MD5-001": 3,
    "IPSEC-IKEV2-MODP1-001": 3,
    "IPSEC-CONFIG-MODE-001": 1,
    "IPSEC-CONFIG-LIFETIME-001": 1,
    "IPSEC-CONFIG-REPLAY-001": 2,
    "IPSEC-CONFIG-PFS-001": 2,
}
THREATS = {
    "IPSEC-IKE-LEGACY-001": ("Legacy key exchange", "IKE protocol version", "IKE SA"),
    "IPSEC-IKEV2-DES-001": ("Weak confidentiality", "Selected IKE encryption", "IKE SA"),
    "IPSEC-IKEV2-PRF-MD5-001": ("Weak key derivation", "Selected IKE PRF", "IKE SA"),
    "IPSEC-IKEV2-INTEG-MD5-001": ("Weak authentication", "Selected IKE integrity", "IKE SA"),
    "IPSEC-IKEV2-MODP1-001": ("Weak key exchange", "Selected IKE DH group", "IKE SA"),
    "IPSEC-CONFIG-MODE-001": ("Policy scope", "Configured Child SA mode", "Protected traffic"),
    "IPSEC-CONFIG-LIFETIME-001": ("Key exposure duration", "Configured Child SA lifetime", "Child SA"),
    "IPSEC-CONFIG-REPLAY-001": ("Replay exposure", "Configured ESP anti-replay", "Receiving IPsec gateway"),
    "IPSEC-CONFIG-PFS-001": ("Forward secrecy", "Configured Child SA rekey DH", "Rekeyed Child SA"),
}


def assess_risk(evaluations: list[dict[str, Any]], configuration_status: str) -> tuple[dict, list[dict]]:
    applicable = [e for e in evaluations if e["status"] != "NOT_APPLICABLE"]
    denominator = sum(WEIGHTS[e["rule_id"]] for e in applicable)
    assessed = [e for e in applicable if e["status"] in ("PASS", "FAIL")]
    assessed_weight = sum(WEIGHTS[e["rule_id"]] for e in assessed)
    failed_weight = sum(WEIGHTS[e["rule_id"]] for e in assessed if e["status"] == "FAIL")
    raw_coverage = assessed_weight / denominator if denominator else 0.0
    coverage = round(raw_coverage, 4)
    has_packet = any(e["evidence_state"] == "OBSERVED" for e in assessed)
    subjects = {e["subject_id"] for e in applicable}
    critical_ids = {"IPSEC-CONFIG-REPLAY-001", "IPSEC-CONFIG-PFS-001"}
    config_complete = all(
        sum(e["evidence_state"] == "CONFIGURED" for e in assessed if e["subject_id"] == subject) >= 3
        and critical_ids <= {e["rule_id"] for e in assessed
                             if e["subject_id"] == subject and e["evidence_state"] == "CONFIGURED"}
        for subject in subjects
    )
    eligible = (configuration_status == "MATCHED" and raw_coverage >= MIN_WEIGHTED_COVERAGE
                and has_packet and bool(subjects) and config_complete)
    if eligible:
        value = round(100 * failed_weight / assessed_weight, 2)
        band = "LOW" if value < 25 else "MODERATE" if value < 50 else "HIGH" if value < 75 else "CRITICAL"
        reason = None
    else:
        value = band = None
        reason = ("Requires a matched configuration, at least one packet-observed rule, three configuration "
                  "controls including replay and PFS, and 80% weighted applicable-rule coverage.")
    contributions = [
        {"rule_id": e["rule_id"], "rule_version": e["rule_version"], "subject_id": e["subject_id"],
         "status": e["status"], "weight": WEIGHTS[e["rule_id"]],
         "evidence_ids": e["evidence_ids"], "evidence_packets": e["evidence_packets"]}
        for e in applicable
    ]
    score = {"status": "SCORED" if eligible else "WITHHELD", "value": value, "band": band,
             "policy_version": POLICY_VERSION, "coverage": coverage,
             "assessed_weight": assessed_weight, "applicable_weight": denominator,
             "failed_weight": failed_weight, "minimum_coverage": MIN_WEIGHTED_COVERAGE,
             "contributions": contributions, "withheld_reason": reason}
    threats = []
    for e in evaluations:
        if e["status"] != "FAIL":
            continue
        category, control, asset = THREATS[e["rule_id"]]
        threats.append({"id": f"{e['subject_id']}:{e['rule_id']}:threat",
                        "category": category, "affected_control": control, "affected_asset": asset,
                        "severity": e["severity"], "finding_id": f"{e['subject_id']}:{e['rule_id']}:{e['rule_version']}",
                        "evidence_ids": e["evidence_ids"], "evidence_packets": e["evidence_packets"],
                        "impact": e["impact"], "remediation": e["remediation"],
                        "mapping_version": THREAT_VERSION})
    return score, threats
