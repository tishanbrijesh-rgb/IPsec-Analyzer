"""Authorized configuration must never silently become packet evidence."""

from datetime import datetime, timezone

import pytest

from ipsec_analyzer.assessment.analyze import analyze_capture
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
from tests.test_ike_parser import ike_sa_message, ike_sa_message_with_dh


def snapshot(path, **changes):
    base = analyze_capture(path).to_dict()
    document = {
        "schema_version": "1", "source_id": "lab-sanitized-1",
        "collected_at": datetime.fromtimestamp(1, timezone.utc).isoformat(),
        "capture_sha256": base["capture"]["sha256"],
        "peers": ["192.0.2.1", "198.51.100.2"],
        "values": {"mode": "tunnel", "child_sa_lifetime_seconds": 3600,
                   "replay_window": 32, "pfs_group": 14},
    }
    document.update(changes)
    return document


def capture(tmp_path):
    packet = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    return write_pcap(tmp_path / "config.pcap", [packet])


def selected_capture(tmp_path, weak=False):
    def with_prf_and_integrity(message):
        raw = bytearray(message)
        raw[-8] = 3
        raw[39] = 4
        raw[24:28] = (int.from_bytes(raw[24:28], "big") + 16).to_bytes(4, "big")
        for start in (30, 34):
            raw[start:start + 2] = (int.from_bytes(raw[start:start + 2], "big") + 16).to_bytes(2, "big")
        raw.extend(b"\x03\0\0\x08\x02\0\0\x05")
        raw.extend(b"\0\0\0\x08\x03\0\0\x0c")
        return bytes(raw)

    packets = [ipv4_packet(17, udp(500, 500, with_prf_and_integrity(ike_sa_message_with_dh()))),
               ipv4_packet(17, udp(500, 500, with_prf_and_integrity(ike_sa_message_with_dh(True, 2 if weak else 12))))]
    return write_pcap(tmp_path / "selected.pcap", packets)


def test_selected_md5_prf_is_traceable_and_request_alone_is_unknown(tmp_path):
    from ipsec_analyzer.rules.ikev2_selected import evaluate_selected_transform
    from ipsec_analyzer.assessment.sessions import Session
    from ipsec_analyzer.parsers.ike import Proposal, Transform

    session = Session(("192.0.2.1", "198.51.100.2"), "01" * 8, "02" * 8, 2)
    assert evaluate_selected_transform(session, 2).status == "UNKNOWN"
    session.selected = Proposal(1, 1, "", (Transform(2, 1),))
    session.selected_evidence_packet = 9
    finding = evaluate_selected_transform(session, 2)
    assert finding.status == "FAIL"
    assert finding.evidence_packets == (9,)
    assert finding.baseline == "RFC 8247 section 2.2"
    session.selected = Proposal(1, 1, "", (Transform(2, 5),))
    assert evaluate_selected_transform(session, 2).status == "PASS"


def test_selected_md5_integrity_is_traceable_without_grading_aead():
    from ipsec_analyzer.rules.ikev2_selected import evaluate_selected_integrity
    from ipsec_analyzer.assessment.sessions import Session
    from ipsec_analyzer.parsers.ike import Proposal, Transform

    session = Session(("192.0.2.1", "198.51.100.2"), "01" * 8, "02" * 8, 2)
    assert evaluate_selected_integrity(session).status == "UNKNOWN"
    session.selected_evidence_packet = 9
    session.selected = Proposal(1, 1, "", (Transform(1, 12), Transform(3, 1)))
    finding = evaluate_selected_integrity(session)
    assert finding.status == "FAIL"
    assert finding.evidence_packets == (9,)
    assert finding.baseline == "RFC 8247 section 2.3"
    session.selected = Proposal(1, 1, "", (Transform(1, 12), Transform(3, 12)))
    assert evaluate_selected_integrity(session).status == "PASS"
    session.selected = Proposal(1, 1, "", (Transform(1, 20),))
    assert evaluate_selected_integrity(session).status == "NOT_APPLICABLE"
    session.selected = Proposal(1, 1, "", (Transform(1, 12),))
    assert evaluate_selected_integrity(session).status == "UNKNOWN"


def test_matched_configuration_has_explicit_source_and_no_packet_claim(tmp_path):
    path = capture(tmp_path)
    data = analyze_capture(path, snapshot(path)).to_dict()
    assert data["configuration"]["status"] == "MATCHED"
    item = next(e for e in data["evidence"] if e["id"].endswith(":config:mode"))
    assert item["state"] == "CONFIGURED"
    assert item["value"] == "tunnel"
    assert item["source_id"] == "lab-sanitized-1"
    assert item["packet_indices"] == ()


@pytest.mark.parametrize("changes,status", [
    ({"capture_sha256": "0" * 64}, "UNMATCHED"),
    ({"peers": ["192.0.2.1", "203.0.113.9"]}, "UNMATCHED"),
    ({"collected_at": "2026-09-29T00:00:00Z"}, "STALE"),
])
def test_unmatched_or_stale_stays_unknown(tmp_path, changes, status):
    path = capture(tmp_path)
    data = analyze_capture(path, snapshot(path, **changes)).to_dict()
    assert data["configuration"]["status"] == status
    assert all(e["state"] == "UNKNOWN" for e in data["evidence"] if ":config:" in e["id"])


def test_partial_fields_and_secret_keys(tmp_path):
    path = capture(tmp_path)
    data = analyze_capture(path, snapshot(path, values={"mode": "transport"})).to_dict()
    configured = {e["field"] for e in data["evidence"] if e["state"] == "CONFIGURED"}
    assert configured == {"mode"}
    with pytest.raises(ValueError, match="unsupported fields"):
        analyze_capture(path, snapshot(path, values={"psk": "secret"}))


def test_shared_report_redacts_configuration_source(tmp_path):
    from ipsec_analyzer.reporting.exports import report_document

    path = capture(tmp_path)
    analysis = analyze_capture(path, snapshot(path))
    full = report_document(analysis)
    shared = report_document(analysis, redacted=True)
    assert full["configuration"]["source_id"] == "lab-sanitized-1"
    assert shared["configuration"]["source_id"] == "[redacted configuration source]"
    assert all(e.get("source_id") != "lab-sanitized-1" for e in shared["evidence"])


def test_strong_configuration_scores_and_weak_configuration_has_traceable_threats(tmp_path):
    path = selected_capture(tmp_path)
    strong = analyze_capture(path, snapshot(path, values={
        "deployment_type": "site_to_site", "mode": "tunnel",
        "child_sa_lifetime_seconds": 3600, "replay_window": 64, "pfs_group": 20,
    })).to_dict()
    assert strong["risk_score"]["status"] == "SCORED"
    assert strong["risk_score"]["value"] == 0
    assert strong["threat_matrix"] == []
    weak = analyze_capture(path, snapshot(path, values={
        "deployment_type": "site_to_site", "mode": "transport",
        "child_sa_lifetime_seconds": 172800, "replay_window": 0, "pfs_group": 0,
    })).to_dict()
    assert weak["risk_score"]["status"] == "SCORED"
    assert weak["risk_score"]["value"] > strong["risk_score"]["value"]
    assert len(weak["threat_matrix"]) == 4
    evidence = {item["id"] for item in weak["evidence"]}
    findings = {item["finding_id"] for item in weak["findings"]}
    for threat in weak["threat_matrix"]:
        assert threat["finding_id"] in findings
        assert set(threat["evidence_ids"]) <= evidence
        assert threat["affected_asset"] and threat["impact"] and threat["remediation"]
    for contribution in weak["risk_score"]["contributions"]:
        assert contribution["rule_version"]
        assert set(contribution["evidence_ids"]) <= evidence


def test_capture_only_and_partial_configuration_withhold_score(tmp_path):
    path = selected_capture(tmp_path)
    blind = analyze_capture(path).to_dict()
    partial = analyze_capture(path, snapshot(path, values={"pfs_group": 0})).to_dict()
    assert blind["risk_score"]["status"] == partial["risk_score"]["status"] == "WITHHELD"
    assert blind["security_score"] is None
    assert partial["risk_score"]["coverage"] > blind["risk_score"]["coverage"]
    assert partial["risk_score"]["value"] is None
    assert len(partial["threat_matrix"]) == 1


def test_missing_replay_withholds_even_at_high_numeric_coverage(tmp_path):
    path = selected_capture(tmp_path)
    values = {"deployment_type": "site_to_site", "mode": "tunnel",
              "child_sa_lifetime_seconds": 3600, "pfs_group": 20}
    data = analyze_capture(path, snapshot(path, values=values)).to_dict()
    assert data["risk_score"]["coverage"] >= 0.8
    assert data["risk_score"]["status"] == "WITHHELD"
    assert "replay and PFS" in data["risk_score"]["withheld_reason"]


def test_host_to_host_mode_is_not_applicable(tmp_path):
    path = selected_capture(tmp_path)
    values = {"deployment_type": "host_to_host", "mode": "transport",
              "child_sa_lifetime_seconds": 3600, "replay_window": 64, "pfs_group": 20}
    data = analyze_capture(path, snapshot(path, values=values)).to_dict()
    mode = next(e for e in data["rule_evaluations"] if e["rule_id"] == "IPSEC-CONFIG-MODE-001")
    assert mode["status"] == "NOT_APPLICABLE"
    assert data["risk_score"]["status"] == "SCORED"
    assert all(c["rule_id"] != mode["rule_id"] for c in data["risk_score"]["contributions"])


def test_score_and_threats_agree_across_report_formats(tmp_path):
    from ipsec_analyzer.reporting.exports import report_document, report_html, report_pdf, report_text

    path = selected_capture(tmp_path, weak=True)
    values = {"deployment_type": "site_to_site", "mode": "transport",
              "child_sa_lifetime_seconds": 172800, "replay_window": 0, "pfs_group": 0}
    analysis = analyze_capture(path, snapshot(path, values=values))
    data = analysis.to_dict()
    document = report_document(analysis)
    assert document["risk_score"] == data["risk_score"]
    assert document["threat_matrix"] == data["threat_matrix"]
    assert document["summary"]["score_status"] == "SCORED"
    for rendered in (report_text(analysis), report_html(analysis)):
        assert "42.86/100 (MODERATE)" in rendered
        assert "Replay exposure" in rendered
        assert "Receiving IPsec gateway" in rendered
        assert "IPSEC-CONFIG-REPLAY-001" in rendered
    pdf = report_pdf(analysis)
    assert b"42.86/100" in pdf and b"Replay exposure" in pdf


def test_score_cannot_borrow_configured_controls_from_another_session(tmp_path):
    from ipsec_analyzer.assessment.risk import assess_risk

    path = selected_capture(tmp_path)
    data = analyze_capture(path, snapshot(path, values={
        "deployment_type": "site_to_site", "mode": "tunnel",
        "child_sa_lifetime_seconds": 3600, "replay_window": 64, "pfs_group": 20,
    })).to_dict()
    first = data["rule_evaluations"]
    second = []
    for item in first:
        copy = dict(item, subject_id="unmatched-session")
        if item["rule_id"].startswith("IPSEC-CONFIG-"):
            copy.update(status="UNKNOWN", evidence_state="UNKNOWN")
        second.append(copy)
    score, _ = assess_risk(first + second, "MATCHED")
    assert score["coverage"] >= 0.8
    assert score["status"] == "WITHHELD"
