"""Record Child SA rekey evidence from the two lab peers' swanctl output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

EXPECTED_DH = {"modern-tunnel": "ECP_384", "cbc-no-pfs": None}


def verify(run_directory: Path) -> Path:
    manifest = json.loads((run_directory / "manifest.json").read_text(encoding="utf-8"))
    scenario = manifest["scenario"]
    if scenario not in EXPECTED_DH:
        raise ValueError("No rekey expectation for this scenario")
    rekey_text = (run_directory / "rekey.log").read_text(encoding="utf-8")
    if "rekey completed successfully" not in rekey_text:
        raise ValueError("Child SA rekey did not complete successfully")
    status_text = (run_directory / "sa-after-rekey.log").read_text(encoding="utf-8")
    child_lines = [line.strip() for line in status_text.splitlines() if line.strip().startswith("protected:")]
    if len(child_lines) != 2:
        raise ValueError("Expected rekeyed Child SA on both peers")
    expected_dh = EXPECTED_DH[scenario]
    for line in child_lines:
        if "#2" not in line or "INSTALLED" not in line or "ESP:" not in line:
            raise ValueError("Expected installed second Child SA on both peers")
        esp = line.split("ESP:", 1)[1]
        if expected_dh is None and ("ECP_" in esp or "MODP_" in esp):
            raise ValueError("Unexpected Child SA DH group")
        if expected_dh is not None and expected_dh not in esp:
            raise ValueError("Expected Child SA DH group is absent")
    capture_record = json.loads((run_directory / "dataset_record.json").read_text(encoding="utf-8"))
    if capture_record["scenario"] != scenario:
        raise ValueError("Capture and rekey scenario differ")
    output = run_directory / "rekey_verification.json"
    if output.exists():
        raise ValueError("Rekey verification already exists")
    record = {
        "schema_version": "1.0",
        "scenario": scenario,
        "capture_sha256": capture_record["capture_sha256"],
        "rekey_command": "swanctl --rekey --child protected",
        "rekey_status": "completed successfully",
        "child_sa_instance": 2,
        "both_peers_installed": True,
        "selected_child_esp": [line.split("ESP:", 1)[1].strip() for line in child_lines],
        "child_sa_dh_group": expected_dh,
        "verification_source": "swanctl --list-sas after Child SA rekey; not passive PCAP inference",
    }
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    print(verify(args.run_directory))


if __name__ == "__main__":
    main()
