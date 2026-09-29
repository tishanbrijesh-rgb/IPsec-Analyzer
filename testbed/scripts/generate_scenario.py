"""Generate isolated strongSwan peer configs and a secret-free run manifest.

This prepares a scenario; Linux namespaces, daemons and packet capture must be
set up separately on an authorized Linux host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

SCENARIOS = {
    "modern-tunnel": {
        "mode": "tunnel",
        "ike_proposal": "aes256gcm16-prfsha384-ecp384",
        "esp_proposal": "aes256gcm16-ecp384",
        "pfs_on_rekey": True,
    },
    "modern-transport": {
        "mode": "transport",
        "ike_proposal": "aes256gcm16-prfsha384-ecp384",
        "esp_proposal": "aes256gcm16-ecp384",
        "pfs_on_rekey": True,
    },
    "modern-v6-tunnel": {
        "mode": "tunnel",
        "ike_proposal": "aes256gcm16-prfsha384-ecp384",
        "esp_proposal": "aes256gcm16-ecp384",
        "pfs_on_rekey": True,
        "ip_version": 6,
    },
    "modern-udp-encap": {
        "mode": "tunnel",
        "ike_proposal": "aes256gcm16-prfsha384-ecp384",
        "esp_proposal": "aes256gcm16-ecp384",
        "pfs_on_rekey": True,
        "forced_udp_encapsulation": True,
    },
    "cbc-no-pfs": {
        "mode": "tunnel",
        "ike_proposal": "aes128-sha256-prfsha256-modp2048",
        "esp_proposal": "aes128-sha256",
        "pfs_on_rekey": False,
    },
}
PEERS = (
    ("client", "198.51.100.2", "203.0.113.2", "client.test", "server.test", "10.1.0.0/24", "10.2.0.0/24"),
    ("server", "203.0.113.2", "198.51.100.2", "server.test", "client.test", "10.2.0.0/24", "10.1.0.0/24"),
)


def generate(name: str, output: Path) -> Path:
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    scenario = SCENARIOS[name]
    peers = PEERS
    if scenario.get("ip_version") == 6:
        peers = (
            ("client", "2001:db8:1::2", "2001:db8:2::2", "client.test", "server.test",
             "2001:db8:10:1::/64", "2001:db8:10:2::/64"),
            ("server", "2001:db8:2::2", "2001:db8:1::2", "server.test", "client.test",
             "2001:db8:10:2::/64", "2001:db8:10:1::/64"),
        )
    secret = secrets.token_urlsafe(48)
    config_hashes = {}
    for peer, local_ip, remote_ip, local_id, remote_id, local_ts, remote_ts in peers:
        if scenario["mode"] == "transport":
            local_ts, remote_ts = f"{local_ip}/32", f"{remote_ip}/32"
        encap_line = "    encap = yes\n" if scenario.get("forced_udp_encapsulation") else ""
        config = f"""connections {{
  lab {{
    version = 2
{encap_line}    local_addrs = {local_ip}
    remote_addrs = {remote_ip}
    proposals = {scenario['ike_proposal']}
    local {{
      auth = psk
      id = {local_id}
    }}
    remote {{
      auth = psk
      id = {remote_id}
    }}
    children {{
      protected {{
        mode = {scenario['mode']}
        local_ts = {local_ts}
        remote_ts = {remote_ts}
        esp_proposals = {scenario['esp_proposal']}
      }}
    }}
  }}
}}
secrets {{
  ike-lab {{
    id-1 = client.test
    id-2 = server.test
    secret = "{secret}"
  }}
}}
"""
        path = output / f"{peer}.conf"
        path.write_text(config, encoding="utf-8")
        path.chmod(0o600)
        config_hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        namespace = f"sih4-{peer}"
        daemon_config = output / f"{peer}.strongswan.conf"
        daemon_config.write_text(
            "include /etc/strongswan.conf\n"
            "charon-systemd {\n"
            "  plugins {\n"
            "    vici {\n"
            f"      socket = unix:///run/{namespace}/charon.vici\n"
            "    }\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        daemon_config.chmod(0o600)
        config_hashes[daemon_config.name] = hashlib.sha256(daemon_config.read_bytes()).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "scenario_version": "1.2",
        "scenario": name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "topology": "two peers; documentation IPv4 addresses; isolated Linux testbed required",
        "ground_truth": scenario,
        "generated_configs": ["client.conf", "server.conf", "client.strongswan.conf", "server.strongswan.conf"],
        "config_sha256": config_hashes,
        "status": "configuration_generated_not_executed",
        "capture_points": ["outer client interface", "outer server interface"],
        "label_source": "scenario configuration",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(generate(args.scenario, args.output))


if __name__ == "__main__":
    main()
