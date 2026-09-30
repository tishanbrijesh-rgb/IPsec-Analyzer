"""Create a tiny synthetic IKEv2 capture with an observed weak selection."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from ipsec_analyzer.ingestion.capture import read_capture
from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
from tests.test_ike_parser import ike_sa_message_with_dh


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Output PCAP path")
    parser.add_argument("--profile", choices=("strong", "weak"), default="weak")
    parser.add_argument("--configuration-output", type=Path, help="Write a sanitized matching lab snapshot")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    request = ipv4_packet(17, udp(500, 500, ike_sa_message_with_dh()))
    response = ike_sa_message_with_dh(True, 2 if args.profile == "weak" else 12)
    reply = ipv4_packet(17, udp(500, 500, response))
    print(write_pcap(args.output, [request, reply]))
    if args.configuration_output:
        capture = read_capture(args.output)
        snapshot = {
            "schema_version": "1", "source_id": f"synthetic-demo-{args.profile}",
            "collected_at": datetime.fromtimestamp(capture.packets[-1].timestamp_ns / 1_000_000_000,
                                                   timezone.utc).isoformat(),
            "capture_sha256": capture.sha256,
            "peers": ["192.0.2.1", "198.51.100.2"],
            "values": ({"deployment_type": "site_to_site", "mode": "tunnel",
                        "child_sa_lifetime_seconds": 3600, "replay_window": 64, "pfs_group": 20}
                       if args.profile == "strong" else
                       {"deployment_type": "site_to_site", "mode": "transport",
                        "child_sa_lifetime_seconds": 172800, "replay_window": 0, "pfs_group": 0}),
        }
        args.configuration_output.parent.mkdir(parents=True, exist_ok=True)
        args.configuration_output.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
        print(args.configuration_output)


if __name__ == "__main__":
    main()
