import json
import ipaddress
import struct

import pytest

from testbed.scripts.generate_scenario import generate
from testbed.scripts.register_capture import register
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
from tests.test_ike_parser import ike_sa_message


def test_manifest_excludes_generated_secret(tmp_path):
    output = generate("modern-tunnel", tmp_path / "scenario")
    manifest = (output / "manifest.json").read_text()
    client = (output / "client.conf").read_text()
    server = (output / "server.conf").read_text()
    secret = client.split('secret = "')[1].split('"')[0]
    assert secret in server
    assert secret not in manifest
    assert json.loads(manifest)["status"] == "configuration_generated_not_executed"
    with pytest.raises(ValueError):
        generate("modern-tunnel", output)


def _outer(frame: bytes) -> bytes:
    packet = bytearray(frame)
    packet[26:30] = ipaddress.IPv4Address("198.51.100.2").packed
    packet[30:34] = ipaddress.IPv4Address("203.0.113.2").packed
    return bytes(packet)


def test_register_capture_requires_selected_ike_and_esp(tmp_path):
    output = generate("modern-tunnel", tmp_path / "run-001")
    request = _outer(ipv4_packet(17, udp(500, 500, ike_sa_message())))
    response = _outer(ipv4_packet(17, udp(500, 500, ike_sa_message(True))))
    esp = _outer(ipv4_packet(50, struct.pack("!II", 0x12345678, 1) + b"ciphertext"))
    incomplete = write_pcap(tmp_path / "incomplete.pcap", [request, esp])
    with pytest.raises(ValueError, match="selected IKE"):
        register(output, incomplete, "outer client interface")
    capture = write_pcap(tmp_path / "outer.pcap", [request, response, esp])
    record_path = register(output, capture, "outer client interface")
    record = json.loads(record_path.read_text())
    assert record["esp_flow_count"] == 1
    assert record["ground_truth"]["mode"] == "tunnel"
    assert "secret" not in record_path.read_text()
    with pytest.raises(ValueError, match="already exists"):
        register(output, capture, "outer client interface")


def test_register_rejects_changed_config(tmp_path):
    output = generate("modern-transport", tmp_path / "run-002")
    (output / "client.conf").write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="config changed"):
        register(output, tmp_path / "missing.pcap", "outer client interface")
