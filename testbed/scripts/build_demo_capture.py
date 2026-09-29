"""Create a tiny synthetic IKEv2 capture with an observed weak selection."""

from __future__ import annotations

import argparse
from pathlib import Path

from tests.fixtures.build_fixtures import ipv4_packet, udp, write_pcap
from tests.test_ike_parser import ike_sa_message


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Output PCAP path")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    request = ipv4_packet(17, udp(500, 500, ike_sa_message()))
    response = bytearray(ike_sa_message(True))
    response[46:48] = b"\x00\x02"  # Selected IKEv2 ENCR_DES transform ID.
    reply = ipv4_packet(17, udp(500, 500, bytes(response)))
    print(write_pcap(args.output, [request, reply]))


if __name__ == "__main__":
    main()
