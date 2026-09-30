"""Regression checks for controlled, outer-link strongSwan WSL captures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ipsec_analyzer.assessment.analyze import analyze_capture

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "sample"


@pytest.mark.parametrize("name,sha256,encryption_id", [
    ("modern-tunnel", "af30fd79d36d123293953f6cc33580c2bd41ccafb1941ca163cc519da445b61d", 20),
    ("modern-transport", "ba0e1dce71cd90800e273f500c610367715f6f67a38de74c7ca39e3a297b6c4f", 20),
    ("cbc-no-pfs", "80873fec17e7d44dd869ecd179e9b9b8a64d9a94dd71c293b6371e40f4c9e4e8", 12),
])
def test_controlled_capture_and_label_provenance(name: str, sha256: str, encryption_id: int):
    data = analyze_capture(SAMPLES / f"{name}.pcap").to_dict()
    record = json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    assert data["capture"]["sha256"] == record["capture_sha256"] == sha256
    assert len(data["sessions"]) == 1
    assert len(data["flows"]) == 2
    assert {flow["kind"] for flow in data["flows"]} == {"ESP"}
    selected = data["sessions"][0]["selected"]
    assert selected is not None
    assert next(item["transform_id"] for item in selected["transforms"]
                if item["transform_type"] == 1) == encryption_id
    assert record["label_source"].startswith("generated scenario configuration")
    assert data["security_score"] is None


@pytest.mark.parametrize("name,sha256,packet_count", [
    ("voip-like", "c0d14c683882b1af04e7cf46212b0bc63f033f3340e8e74a6bcfca95045876d5", 84),
    ("video-like", "ad0e027259339a31535c1c234eb1e83d6a5dbf62dfa99ddc0293059a2cdffe65", 84),
    ("messaging-like", "2506330fec3a1a0b2e5076b89d91391efa8c27b97665d6dcf768d5998c9ff7ec", 48),
    ("email-like", "83bcee139ad8c098491226f599706eef742188206d3f3d5f6bf1ff42ec9952a5", 59),
    ("web-like", "db67cdf07ee9128370d1808d629940d99b44113f07ce39e2aa2b10299f237ff9", 54),
    ("icmp", "8257ac1f30410e0cd0b274ad6ac52d163d4008ce4e265dc21eb043a7275f300e", 10),
])
def test_synthetic_profile_capture(name: str, sha256: str, packet_count: int):
    data = analyze_capture(SAMPLES / f"{name}.pcap").to_dict()
    record = json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    assert data["capture"]["sha256"] == record["capture_sha256"] == sha256
    assert data["capture"]["packet_count"] == packet_count
    assert record["traffic_profile"] == name
    assert record["traffic_label_source"].startswith("synthetic generator command")
    assert len(data["sessions"]) == 1
    assert len(data["flows"]) == 2
    assert all(flow["kind"] == "ESP" for flow in data["flows"])
    assert all(item["status"] in ("PASS", "NOT_APPLICABLE") for item in data["rule_evaluations"] if not item["rule_id"].startswith("IPSEC-CONFIG-"))
    assert all(item["status"] == "UNKNOWN" for item in data["rule_evaluations"] if item["rule_id"].startswith("IPSEC-CONFIG-"))


@pytest.mark.parametrize("name,sha256,dh_group", [
    ("modern-rekey", "6ceae2a713d5bdddecb116b4216f83796c5b800185beb0aa6a792718681ede50", "ECP_384"),
    ("cbc-rekey", "2e5f7ae9799fb9035e6f9961cc1851e5bc19897c64ee8cf8fff7f81e39092c94", None),
])
def test_rekey_sidecar_does_not_upgrade_passive_pfs(name: str, sha256: str, dh_group: str | None):
    data = analyze_capture(SAMPLES / f"{name}.pcap").to_dict()
    record = json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    rekey = json.loads((SAMPLES / f"{name}-verification.json").read_text(encoding="utf-8"))
    assert data["capture"]["sha256"] == record["capture_sha256"] == rekey["capture_sha256"] == sha256
    assert rekey["rekey_status"] == "completed successfully"
    assert rekey["both_peers_installed"]
    assert rekey["child_sa_dh_group"] == dh_group
    assert len(data["flows"]) == 2
    pfs_evidence = next(item for item in data["evidence"] if item["field"] == "pfs")
    assert pfs_evidence["state"] == "UNKNOWN"


@pytest.mark.parametrize("name,sha256,packets,profile", [
    ("phase4-ipv6-01", "aa44d37aee6a1af60f1b3d4491ece4a4a553f80dd633ef769cc9d6a270cc1f92", 12, "icmp"),
    ("phase4-ipv6-02", "3cae9f68daab2634d048bdc6d4821df37f826dbc018b738348e07eecdc6cd691", 84, "voip-like"),
])
def test_ipv6_tunnel_capture(name: str, sha256: str, packets: int, profile: str) -> None:
    data = analyze_capture(SAMPLES / f"{name}.pcap").to_dict()
    record = json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    assert data["capture"]["sha256"] == record["capture_sha256"] == sha256
    assert record["ground_truth"]["ip_version"] == 6
    assert record["packet_count"] == packets
    assert record["traffic_profile"] == profile
    assert len(data["sessions"]) == 1
    assert len(data["flows"]) == 2
    assert all(flow["kind"] == "ESP" for flow in data["flows"])


def test_forced_udp_encapsulation_capture() -> None:
    name = "phase4-udp-encap-01"
    data = analyze_capture(SAMPLES / f"{name}.pcap").to_dict()
    record = json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    assert data["capture"]["sha256"] == record["capture_sha256"] == (
        "b39acfd775d13bacb7796a574d521ed40c4afd5c4e10b9b96119c4d5f001b36f")
    assert record["ground_truth"]["forced_udp_encapsulation"] is True
    assert len(data["flows"]) == 2
    assert {flow["encapsulation"] for flow in data["flows"]} == {"UDP_4500"}
