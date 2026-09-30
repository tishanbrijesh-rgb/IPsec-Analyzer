import pytest

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import CaptureError
from ipsec_analyzer.reporting.technical import render_technical
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
from tests.test_ike_parser import ike_sa_message


def test_ikev2_rule_and_score_coverage(tmp_path):
    packet = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    analysis = analyze_capture(write_pcap(tmp_path / "v2.pcap", [packet]))
    data = analysis.to_dict()
    assert data["rule_evaluations"][0]["status"] == "PASS"
    assert data["rule_evaluations"][0]["evidence_state"] == "OBSERVED"
    assert data["security_score"] is None
    assert "Packets:" in render_technical(analysis)


def test_ikev1_failure(tmp_path):
    raw = bytearray(ike_sa_message())
    raw[16] = 0
    raw[17] = 0x10
    packet = ipv4_packet(17, udp(500, 500, bytes(raw)))
    data = analyze_capture(write_pcap(tmp_path / "v1.pcap", [packet])).to_dict()
    result = data["rule_evaluations"][0]
    assert result["status"] == "FAIL"
    assert result["severity"] == "HIGH"
    assert result["evidence_packets"] == (1,)


def test_no_handshake_has_no_score_or_compliance_claim(tmp_path):
    data = analyze_capture(write_pcap(tmp_path / "empty.pcap", [])).to_dict()
    assert data["rule_evaluations"] == []
    assert data["security_score"] is None
    assert data["coverage"]["evaluated_ratio"] == 0


def test_invalid_ike_header_cannot_create_rule_pass(tmp_path):
    raw = bytearray(ike_sa_message())
    raw[:8] = b"\0" * 8
    packet = ipv4_packet(17, udp(500, 500, bytes(raw)))
    data = analyze_capture(write_pcap(tmp_path / "invalid-ike.pcap", [packet])).to_dict()
    assert data["ike_messages"][0]["diagnostics"][0]["code"] == "INVALID_IKE_SPI"
    assert data["rule_evaluations"] == []


def test_session_and_flow_evidence_has_packet_provenance(tmp_path):
    from tests.fixtures.build_fixtures import frames

    data = analyze_capture(write_pcap(tmp_path / "evidence.pcap", frames())).to_dict()
    assert data["evidence"]
    subjects = {item["id"] for item in data["sessions"] + data["flows"]}
    evidence_by_id = {item["id"]: item for item in data["evidence"]}
    for record in data["sessions"] + data["flows"]:
        assert record["evidence_ids"]
        assert all(reference in evidence_by_id for reference in record["evidence_ids"])
    for item in data["evidence"]:
        assert item["subject_id"] in subjects
        if item["state"] in ("OBSERVED", "DERIVED"):
            assert item["packet_indices"]
        else:
            assert item["value"] is None and item["reason"]
    session = data["sessions"][0]
    selected = evidence_by_id[session["id"] + ":selected"]
    assert selected["state"] == "UNKNOWN"
    assert session["selected"] is None


def test_analysis_rejects_subject_amplification(tmp_path, monkeypatch):
    import ipsec_analyzer.assessment.analyze as analysis_module

    packet = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    path = write_pcap(tmp_path / "bounded.pcap", [packet])
    monkeypatch.setattr(analysis_module, "MAX_IKE_MESSAGES", 0)
    with pytest.raises(CaptureError, match="IKE analysis message limit"):
        analyze_capture(path)
    monkeypatch.setattr(analysis_module, "MAX_IKE_MESSAGES", 10_000)
    monkeypatch.setattr(analysis_module, "MAX_EVIDENCE_SUBJECTS", 0)
    with pytest.raises(CaptureError, match="evidence subject limit"):
        analyze_capture(path)


def test_selected_des_creates_traceable_finding(tmp_path):
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = bytearray(ike_sa_message(True))
    response[46:48] = b"\x00\x02"  # Selected ENCR_DES transform ID.
    selected = ipv4_packet(17, udp(500, 500, bytes(response)))
    analysis = analyze_capture(write_pcap(tmp_path / "des.pcap", [request, selected]))
    data = analysis.to_dict()
    finding = next(item for item in data["findings"] if item["rule_id"] == "IPSEC-IKEV2-DES-001")
    assert finding["status"] == "FAIL"
    assert finding["evidence_packets"] == (2,)
    assert finding["evidence_ids"] == [data["sessions"][0]["id"] + ":selected"]
    assert finding["impact"] and finding["severity_rationale"] and finding["remediation"]
    assert data["security_score"] is None
    assert "Impact:" in render_technical(analysis)
    summaries = {item["index"]: item for item in data["packet_summaries"]}
    assert set(summaries) == {1, 2}
    assert summaries[2]["kind"] == "IKE"
    assert summaries[2]["captured_length"] == len(selected)
    assert not {"payload", "raw_frames", "spi", "sequence"} & summaries[2].keys()


def test_packet_summary_cap_is_reported(tmp_path, monkeypatch):
    import ipsec_analyzer.assessment.analyze as analysis_module

    packet = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    path = write_pcap(tmp_path / "summary-cap.pcap", [packet, packet])
    monkeypatch.setattr(analysis_module, "MAX_PACKET_SUMMARIES", 1)
    data = analyze_capture(path).to_dict()
    assert len(data["packet_summaries"]) == 1
    assert data["packet_summaries_truncated"] is True


def test_request_only_does_not_pass_selected_rules(tmp_path):
    packet = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    data = analyze_capture(write_pcap(tmp_path / "request.pcap", [packet])).to_dict()
    selected = [item for item in data["rule_evaluations"] if item["rule_id"].startswith("IPSEC-IKEV2-")]
    assert [item["status"] for item in selected] == ["UNKNOWN"] * 4
    assert data["coverage"]["evaluated_ratio"] == 1 / 9
    assert data["assessed_rule_pass_percent"] is None


def test_ikev1_selected_rules_not_applicable(tmp_path):
    raw = bytearray(ike_sa_message())
    raw[16:18] = b"\x00\x10"
    packet = ipv4_packet(17, udp(500, 500, bytes(raw)))
    data = analyze_capture(write_pcap(tmp_path / "v1-na.pcap", [packet])).to_dict()
    assert [item["status"] for item in data["rule_evaluations"][:5]] == ["FAIL"] + ["NOT_APPLICABLE"] * 4
    assert data["coverage"]["evaluated_ratio"] == 1 / 5
    assert data["assessed_rule_pass_percent"] == 0


def test_selected_modp_group_one_rule():
    from ipsec_analyzer.assessment.sessions import Session
    from ipsec_analyzer.parsers.ike import Proposal, Transform
    from ipsec_analyzer.rules.ikev2_selected import evaluate_selected_transform

    session = Session(("192.0.2.1", "192.0.2.2"), "01" * 8, "02" * 8, 2)
    session.selected = Proposal(1, 1, "", (Transform(4, 1),))
    session.selected_evidence_packet = 7
    result = evaluate_selected_transform(session, 4)
    assert result.status == "FAIL"
    assert result.evidence_packets == (7,)
