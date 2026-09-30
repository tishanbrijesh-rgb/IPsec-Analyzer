import asyncio
import base64
import json
from collections import OrderedDict
from pathlib import Path

from ipsec_analyzer.api.app import app
import ipsec_analyzer.api.app as api_module
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
from tests.test_ike_parser import ike_sa_message


def request(method: str, path: str, body: bytes = b"", headers=None, client="127.0.0.1", return_headers=False):
    route, _, query = path.partition("?")
    async def run():
        sent = []
        received = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "method": method,
            "path": route, "raw_path": route.encode(), "query_string": query.encode(),
            "headers": [(key.lower().encode(), value.encode()) for key, value in {"host": "127.0.0.1:8000", **(headers or {})}.items()],
            "client": (client, 1), "server": ("127.0.0.1", 8000), "scheme": "http",
            "http_version": "1.1",
        }
        await app(scope, receive, send)
        start = next(message for message in sent if message["type"] == "http.response.start")
        status = start["status"]
        content = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
        if return_headers:
            return status, content, {key.decode(): value.decode() for key, value in start["headers"]}
        return status, content

    return asyncio.run(run())


def test_public_demo_is_read_only_and_serves_reviewed_captures(monkeypatch):
    monkeypatch.setattr(api_module, "PUBLIC_DEMO", True)
    monkeypatch.setattr(api_module, "_results", OrderedDict())
    monkeypatch.setattr(api_module, "_demo_ids", {})
    external = {"host": "ipsec-analyzer-lab-demo.onrender.com"}
    status, home = request("GET", "/", headers=external, client="203.0.113.6")
    assert status == 200
    assert b"PUBLIC READ-ONLY DEMO" in home
    assert b"/demo/modern-tunnel" in home
    modern_id = api_module._demo_ids["modern-tunnel"]
    status, body = request("GET", f"/api/analyses/{modern_id}", headers=external,
                           client="203.0.113.6")
    assert status == 200
    assert json.loads(body)["capture"]["packet_count"] == 10
    status, _ = request("POST", "/api/analyses", b"unsafe", external,
                        client="203.0.113.6")
    assert status == 405
    status, page = request("GET", f"/analyses/{modern_id}/assessment", headers=external,
                           client="203.0.113.6")
    assert status == 200
    assert b"PUBLIC LAB DEMO" in page
    assert b'<body class="public-demo">' in page
    assert b"All lab cases</a>" in page


def test_health_and_home_accept_head_requests():
    assert request("HEAD", "/api/health") == (200, b"")
    assert request("HEAD", "/") == (200, b"")


def test_protected_hosted_workspace_requires_password_for_upload_and_results(monkeypatch, tmp_path):
    monkeypatch.setattr(api_module, "PROTECTED_UPLOAD", True)
    monkeypatch.setattr(api_module, "HOSTED_UPLOAD", True)
    monkeypatch.setattr(api_module, "UPLOAD_USER", "analyst")
    monkeypatch.setattr(api_module, "UPLOAD_PASSWORD", "test-secret")
    external = {"host": "ipsec-analyzer-workspace.onrender.com"}
    assert request("GET", "/", headers=external, client="203.0.113.6")[0] == 303
    assert request("GET", "/login", headers=external, client="203.0.113.6")[0] == 200
    assert request("GET", "/assets/login.css", headers=external, client="203.0.113.6")[0] == 200
    assert request("POST", "/api/analyses", b"capture", external, client="203.0.113.6")[0] == 401
    assert request("GET", "/api/health", headers=external, client="203.0.113.6")[0] == 200
    form_headers = {**external, "content-type": "application/x-www-form-urlencoded"}
    assert request("POST", "/login", b"username=analyst&password=wrong", form_headers,
                   client="203.0.113.6")[0] == 401
    status, _, response_headers = request("POST", "/login", b"username=analyst&password=test-secret",
                                          form_headers, client="203.0.113.6", return_headers=True)
    assert status == 303
    assert "secure" in response_headers["set-cookie"].lower()
    assert "httponly" in response_headers["set-cookie"].lower()
    cookie = response_headers["set-cookie"].split(";", 1)[0]
    assert request("GET", "/", headers={**external, "cookie": cookie}, client="203.0.113.6")[0] == 200
    external["authorization"] = "Basic " + base64.b64encode(b"analyst:test-secret").decode()
    status, home = request("GET", "/", headers=external, client="203.0.113.6")
    assert status == 200
    assert b"PROTECTED WORKSPACE" in home
    status, body = request("POST", "/api/analyses", write_pcap(tmp_path / "hosted.pcap").read_bytes(),
                           {**external, "content-type": "application/octet-stream"}, client="203.0.113.6")
    assert status == 201
    analysis_id = json.loads(body)["id"]
    assert request("GET", f"/api/analyses/{analysis_id}", headers={"host": external["host"]},
                   client="203.0.113.6")[0] == 401
    assert request("GET", f"/api/analyses/{analysis_id}", headers=external,
                   client="203.0.113.6")[0] == 200


def test_public_upload_workspace_opens_without_login(monkeypatch, tmp_path):
    monkeypatch.setattr(api_module, "PUBLIC_UPLOAD", True)
    monkeypatch.setattr(api_module, "HOSTED_UPLOAD", True)
    external = {"host": "ipsec-analyzer-workspace.onrender.com"}
    status, home = request("GET", "/", headers=external, client="203.0.113.6")
    assert status == 200
    assert b"PUBLIC UPLOAD WORKSPACE" in home
    assert request("GET", "/api/health", headers=external, client="203.0.113.6")[1] == b'{"status":"ready","version":"0.1.0","mode":"public-upload"}'
    assert request("GET", "/login", headers=external, client="203.0.113.6")[0] == 404
    assert b"without a password" in request("GET", "/privacy", headers=external, client="203.0.113.6")[1]
    capture = write_pcap(tmp_path / "public.pcap").read_bytes()
    status, body = request("POST", "/api/analyses", capture,
                           {**external, "content-type": "application/octet-stream"}, client="203.0.113.6")
    assert status == 201
    analysis_id = json.loads(body)["id"]
    assert request("GET", f"/analyses/{analysis_id}/assessment", headers=external,
                   client="203.0.113.6")[0] == 200


def test_upload_and_get(tmp_path):
    capture = write_pcap(tmp_path / "api.pcap").read_bytes()
    status, body = request("POST", "/api/analyses", capture, {"content-type": "application/octet-stream"})
    assert status == 201
    payload = json.loads(body)
    assert payload["result"]["capture"]["packet_count"] == 5
    assert "raw_frames" not in body.decode()
    assert "wire_hash" not in body.decode()
    assert payload["result"]["evidence"]
    status, body = request("GET", "/api/analyses/" + payload["id"])
    assert status == 200
    assert json.loads(body)["capture"]["sha256"]


def test_inference_score_scope_matches_api_and_report():
    capture = Path(__file__).resolve().parents[1] / "data/sample/phase4-voip-01.pcap"
    status, body = request("POST", "/api/analyses", capture.read_bytes(),
                           {"content-type": "application/octet-stream"})
    assert status == 201
    created = json.loads(body)
    flows = created["result"]["ai_inference"]["flows"]
    assert any(item["state"] == "INFERRED" and item["confidence"] is not None for item in flows)
    assert all(item["confidence"] is None for item in flows if item["abstained"])
    base = f"/api/analyses/{created['id']}"
    status, body = request("GET", base + "/report?format=json")
    assert status == 200
    assert json.loads(body)["ai_inference"]["flows"] == flows
    status, body = request("GET", base + "/report?format=text")
    assert status == 200
    assert b"pilot model score" in body
    assert b"probability unvalidated" in body


def test_multipart_configuration_produces_same_scored_report(tmp_path):
    from tests.test_configuration import selected_capture, snapshot

    path = selected_capture(tmp_path)
    config = json.dumps(snapshot(path, values={
        "deployment_type": "site_to_site", "mode": "tunnel",
        "child_sa_lifetime_seconds": 3600, "replay_window": 64, "pfs_group": 20,
    })).encode()
    boundary = b"sih-config-test"
    body = (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"capture\"; filename=\"capture.pcap\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n" + path.read_bytes() + b"\r\n"
            b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"configuration\"; filename=\"config.json\"\r\n"
            b"Content-Type: application/json\r\n\r\n" + config + b"\r\n--" + boundary + b"--\r\n")
    status, response = request("POST", "/api/analyses", body,
                               {"content-type": "multipart/form-data; boundary=sih-config-test"})
    assert status == 201
    payload = json.loads(response)
    assert payload["result"]["risk_score"]["status"] == "SCORED"
    status, response = request("GET", f"/api/analyses/{payload['id']}/report?format=json")
    assert status == 200
    report = json.loads(response)
    assert report["risk_score"] == payload["result"]["risk_score"]
    for view in ("assessment", "threats", "sessions", "flows", "inference", "evidence", "packets", "reports"):
        status, page = request("GET", f"/analyses/{payload['id']}/{view}")
        assert status == 200
        assert b'data-page-link="reports"' in page


def test_weak_assessment_agrees_across_api_and_all_exports(tmp_path):
    from tests.test_configuration import selected_capture, snapshot

    path = selected_capture(tmp_path, weak=True)
    config = json.dumps(snapshot(path, values={
        "deployment_type": "site_to_site", "mode": "transport",
        "child_sa_lifetime_seconds": 172800, "replay_window": 0, "pfs_group": 0,
    })).encode()
    boundary = b"phase6-review"
    body = (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"capture\"; filename=\"weak.pcap\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n" + path.read_bytes() + b"\r\n"
            b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"configuration\"; filename=\"config.json\"\r\n"
            b"Content-Type: application/json\r\n\r\n" + config + b"\r\n--" + boundary + b"--\r\n")
    status, response = request("POST", "/api/analyses", body,
                               {"content-type": "multipart/form-data; boundary=phase6-review"})
    assert status == 201
    created = json.loads(response)
    result = created["result"]
    assert result["risk_score"]["value"] == 42.86
    assert len(result["threat_matrix"]) == result["finding_count"] == 5
    base = f"/api/analyses/{created['id']}"
    for route, key in (("/sessions", "sessions"), ("/flows", "flows"),
                       ("/findings", "findings"), ("/evidence", "evidence")):
        status, response = request("GET", base + route)
        assert status == 200
        assert json.loads(response) == json.loads(json.dumps(result[key]))
    status, response = request("GET", base + "/report?format=json")
    assert status == 200
    exported = json.loads(response)
    for key in ("risk_score", "threat_matrix", "ai_inference", "rule_evaluations", "findings"):
        assert exported[key] == result[key]
    assert exported["summary"]["score_status"] == "SCORED"
    for format in ("text", "html", "pdf"):
        status, response = request("GET", base + f"/report?format={format}")
        assert status == 200
        assert b"42.86/100" in response
        assert b"sih-threat-1" in response
        assert b"Receiving IPsec gateway" in response
        if format != "pdf":
            assert b"42.86/100 (MODERATE)" in response
            assert b"INFERRED synthetic-profile" in response
    status, response = request("GET", base + "/report?format=json&redacted=true")
    assert status == 200
    shared = json.loads(response)
    assert shared["capture"]["sha256"] == "[redacted]"
    assert shared["risk_score"]["status"] == "SCORED"
    assert len(shared["threat_matrix"]) == 5


def test_result_eviction_and_restart_lifecycle(tmp_path, monkeypatch):
    original = api_module._results.copy()
    api_module._results.clear()
    monkeypatch.setattr(api_module, "MAX_RESULTS", 2)
    try:
        capture = write_pcap(tmp_path / "bounded-results.pcap").read_bytes()
        ids = []
        for _ in range(3):
            status, body = request("POST", "/api/analyses", capture,
                                   {"content-type": "application/octet-stream"})
            assert status == 201
            ids.append(json.loads(body)["id"])
        assert len(api_module._results) == 2
        for suffix in ("", "/status", "/report?format=json"):
            status, _ = request("GET", "/api/analyses/" + ids[0] + suffix)
            assert status == 404
        status, _ = request("GET", "/api/analyses/" + ids[-1])
        assert status == 200
        api_module._results.clear()  # In-memory results vanish on restart.
        status, _ = request("GET", "/api/analyses/" + ids[-1])
        assert status == 404
    finally:
        api_module._results.clear()
        api_module._results.update(original)


def test_upload_rejects_bad_input_and_remote_client():
    status, _ = request("POST", "/api/analyses", b"bad", {"content-type": "application/octet-stream"})
    assert status == 422
    status, _ = request("POST", "/api/analyses", b"bad", {"content-type": "text/plain"})
    assert status == 415
    status, _ = request("GET", "/api/health", client="203.0.113.7")
    assert status == 403


def test_invalid_upload_removes_temporary_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(api_module.tempfile, "tempdir", str(tmp_path))
    status, _ = request("POST", "/api/analyses", b"not a capture",
                        {"content-type": "application/octet-stream"})
    assert status == 422
    assert not list(tmp_path.glob("ipsec-analysis-*"))


def test_upload_over_16_mib_rejected_without_retaining_raw_file(tmp_path, monkeypatch):
    monkeypatch.setattr(api_module.tempfile, "tempdir", str(tmp_path))
    status, _ = request("POST", "/api/analyses",
                        b"x" * (api_module.MAX_UPLOAD_BYTES + 1),
                        {"content-type": "application/octet-stream"})
    assert status == 413
    assert not list(tmp_path.glob("ipsec-analysis-*"))


def test_dashboard_and_security_headers():
    status, body = request("GET", "/")
    assert status == 200
    assert b"Decode the <em>unseen.</em>" in body
    assert b'/assets/editorial.css' in body
    assert b'href="/privacy"' in body
    assert b'href="/terms"' in body
    assert b"\xe2\x80\x94" not in body
    for path, heading in (("/privacy", b"Privacy Policy"), ("/terms", b"Terms and Conditions")):
        status, page = request("GET", path)
        assert status == 200
        assert heading in page
        assert b'href="/"' in page
        assert b"\xe2\x80\x94" not in page
    status, _ = request("GET", "/api/health", headers={"host": "attacker.example"})
    assert status == 403
    status, _ = request(
        "POST", "/api/analyses", b"bad",
        {"content-type": "application/octet-stream", "origin": "https://other.example", "host": "127.0.0.1:8000"},
    )
    assert status == 403


def test_phase6_resources_and_exports(tmp_path):
    capture = write_pcap(tmp_path / "report.pcap").read_bytes()
    status, body = request("POST", "/api/analyses", capture, {"content-type": "application/octet-stream"})
    assert status == 201
    created = json.loads(body)
    analysis_id = created["id"]
    result = created["result"]
    assert created["status"] == "complete"
    base = "/api/analyses/" + analysis_id
    for suffix, key in (("/sessions", "sessions"), ("/flows", "flows"),
                        ("/evidence", "evidence"), ("/findings", "findings")):
        status, body = request("GET", base + suffix)
        assert status == 200
        assert json.loads(body) == json.loads(json.dumps(result[key]))
    status, body = request("GET", base + "/status")
    assert status == 200 and json.loads(body)["status"] == "complete"
    evidence_id = result["rule_evaluations"][0]["evidence_ids"][0]
    status, body = request("GET", base + "/evidence/" + evidence_id)
    assert status == 200 and json.loads(body)["id"] == evidence_id
    status, body = request("GET", base + "/evidence/missing")
    assert status == 404
    for format, marker in (("text", b"Executive summary"), ("html", b"<html"),
                           ("pdf", b"%PDF-1.4"), ("json", b'"capture"')):
        status, body = request("GET", base + "/report?format=" + format)
        assert status == 200 and marker in body
    status, body = request("GET", base + "/report?format=html&redacted=true")
    assert status == 200
    assert result["capture"]["sha256"].encode() not in body
    assert result["capture"]["id"].encode() not in body
    assert b"192.0.2.1" not in body
    status, redacted_json = request("GET", base + "/report?format=json&redacted=true")
    assert status == 200
    assert result["capture"]["sha256"].encode() not in redacted_json
    assert result["capture"]["id"].encode() not in redacted_json
    assert b"192.0.2.1" not in redacted_json
    shared = json.loads(redacted_json)
    assert shared["summary"]["packet_count"] == result["capture"]["packet_count"]
    assert all(flow["spi"] is None for flow in shared["flows"])


def test_failed_finding_traces_to_api_evidence_and_report(tmp_path):
    request_packet = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = bytearray(ike_sa_message(True))
    response[46:48] = b"\x00\x02"
    capture = write_pcap(tmp_path / "weak.pcap", [request_packet, ipv4_packet(17, udp(500, 500, bytes(response)))]).read_bytes()
    status, body = request("POST", "/api/analyses", capture, {"content-type": "application/octet-stream"})
    assert status == 201
    payload = json.loads(body)
    base = "/api/analyses/" + payload["id"]
    status, body = request("GET", base + "/findings")
    assert status == 200
    finding = next(item for item in json.loads(body) if item["rule_id"] == "IPSEC-IKEV2-DES-001")
    assert finding["remediation"] and finding["evidence_packets"] == [2]
    status, body = request("GET", base + "/evidence/" + finding["evidence_ids"][0])
    assert status == 200 and json.loads(body)["packet_indices"] == [2]
    status, report = request("GET", base + "/report?format=html")
    assert status == 200
    assert finding["rule_id"].encode() in report
    assert finding["remediation"].encode() in report
    status, report_json = request("GET", base + "/report?format=json")
    assert status == 200
    exported = json.loads(report_json)
    assert exported["summary"]["failed_rule_finding_count"] == 1
    assert any(item["rule_id"] == finding["rule_id"] and item["remediation"] == finding["remediation"]
               for item in exported["rule_evaluations"])
