from pathlib import Path

import pytest

from testbed.scripts.audit_reproduction import audit


SAMPLES = Path(__file__).resolve().parents[1] / "data" / "sample"


@pytest.mark.parametrize("name,esp", [
    ("modern-tunnel", "AES_GCM_16-256"),
    ("cbc-no-pfs", "AES_CBC-128/HMAC_SHA2_256_128"),
])
def test_reproduction_audit_checks_record_capture_and_installed_state(name, esp, tmp_path):
    run = tmp_path / name
    run.mkdir()
    (run / "dataset_record.json").write_bytes((SAMPLES / f"{name}.json").read_bytes())
    (run / "outer.pcap").write_bytes((SAMPLES / f"{name}.pcap").read_bytes())
    status = "".join(f"{peer}:\n  protected: #1, reqid 1, INSTALLED, TUNNEL, ESP:{esp}\n"
                     for peer in ("client", "server"))
    (run / "sa-status.log").write_text(status, encoding="utf-8")
    result = audit(run)
    assert result["esp_flows"] == 2
    assert result["installed_child_sa_lines"] == 2
    (run / "outer.pcap").write_bytes((SAMPLES / ("cbc-no-pfs" if name == "modern-tunnel" else "modern-tunnel")).with_suffix(".pcap").read_bytes())
    with pytest.raises(ValueError, match="SHA-256"):
        audit(run)
