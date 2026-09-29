# Controlled testbed status

`scripts/generate_scenario.py` prepares strongSwan peer configurations and a
secret-free ground-truth manifest. Supported scenarios are modern IPv4 tunnel,
modern IPv4 transport, modern IPv6 tunnel, forced UDP encapsulation, and CBC
without PFS on rekey. For example:

```text
python testbed/scripts/generate_scenario.py modern-tunnel --output testbed/generated/run-001
```

The output directory is ignored by Git because the peer configurations contain
a randomly generated PSK. Do not copy the config or PSK into committed fixtures.
Run manifests contain config hashes, not the PSK. The generated addresses are
documentation ranges and must be used only inside an isolated lab.

## Linux topology and capture procedure

On a Linux test host with `iproute2`, strongSwan, `swanctl`, `tcpdump`, and
permission to create network namespaces:

In WSL, keep one Ubuntu shell open through topology setup, daemon startup,
capture and cleanup. When Ubuntu stops, it loses its network namespaces and
`/run` sockets. The following steps were exercised on Ubuntu 26.04 WSL2.

1. Run `sudo bash testbed/scripts/topology.sh up`. This creates two namespaces,
   `sih4-client` and `sih4-server`, a veth link, and protected dummy subnets.
   Run `status` to inspect them and `down` after stopping daemons and capture.
2. Run `sudo bash testbed/scripts/peers.sh start <run-dir>`. The generated
   `*.strongswan.conf` files set distinct VICI sockets under `/run/sih4-*`,
   and `peers.sh` starts the two daemons inside their namespaces and loads
   the matching peer configs. The [strongSwan namespace guide](https://docs.strongswan.org/docs/6.0/howtos/nameSpaces.html)
   explains why independent daemon sockets are needed.
3. Start the **outer-link capture before initiating** so the IKE negotiation
   is recorded. Inside the client namespace, run
   `tcpdump -i sih4c -s 0 -w <run-dir>/outer.pcap 'ip and (udp port 500 or udp port 4500 or proto 50 or proto 51)'`.
4. Initiate from the client with `ip netns exec sih4-client swanctl --initiate
   --uri unix:///run/sih4-client/charon.vici --child protected`. Run
   `sudo bash testbed/scripts/peers.sh status <run-dir>` and confirm SAs on
   both peers. See the [swanctl reference](https://docs.strongswan.org/docs/latest/swanctl/swanctl.html).
   For tunnel mode, ping from `10.1.0.1` to `10.2.0.1` after the SA is up.
   For transport mode, use the two outer peer addresses. Stop capture cleanly.
   Then run `sudo bash testbed/scripts/peers.sh stop <run-dir>`.
5. Run `python -m testbed.scripts.register_capture <run-dir> <run-dir>/outer.pcap
   --capture-point 'outer client interface'` after installing the project or
   setting `PYTHONPATH=src`. It writes a secret-free `dataset_record.json` only
   if a selected IKE response and ESP flow are visible, packets stay within
   the lab outer endpoints, and the configs match their hashes.

Capture registration does not attest that the daemons loaded those exact
configs. Record daemon version, command outputs, kernel version and capture
point in a separate run log before using a capture as training ground truth.
Keep raw captures and logs in the ignored run directory and review them before
sharing. The topology script passed `bash -n` and created both namespaces on
Ubuntu 26.04 WSL2. A client-to-server outer-link ping succeeded. strongSwan
6.0.4 and tcpdump were installed. The installed service runs in the default
namespace and is not the two-peer lab. The three scenarios in `data/sample/`
were run with separate lab daemons. Both peers reported installed Child SAs;
each scenario carried a 3/3 protected ping. The three filtered outer captures
contain IKE negotiation and ESP in both directions and have passed capture
registration. Run-specific PCAP hashes and label limits are in
[`data/README.md`](../data/README.md). The synthetic traffic samples described
below are additional runs; independent host reproduction remains outstanding.

## Synthetic traffic profiles

`testbed/traffic/generate.py` provides bounded `icmp`, `voip-like`,
`video-like`, `messaging-like`, `email-like`, and `web-like` profiles. The names
describe packet size, interval and transport patterns emitted by the generator;
they do not claim an actual VoIP, email or web application ran.

On the same Linux host, run one profile and capture through the isolated VPN:

```text
sudo bash testbed/scripts/run_profile.sh voip-like example-voip-01
```

The script creates a fresh ignored run directory, starts the peers, captures
from before IKE initiation through the profile, verifies IKE selection and
ESP, writes a sender record, and tears down the namespaces. Its run ID must be
unique. A failed run remains in the ignored directory for diagnosis and must
not be copied into `data/sample/`. Six initial profile samples plus thirty
reviewed batch runs are included in `data/sample/`. The batch uses seeds 101
through 105 and alternates three configuration scenarios. The ICMP sender
retains a fixed three-ping pattern; its repeated runs vary configuration and
independently negotiate each SA. The shared index is generated with
`PYTHONPATH=src python -m testbed.scripts.build_dataset_index data/sample
--output data/dataset-index.json`. Host diversity and independent reproduction
are still required before model quality claims.

An IPv6 tunnel is available as `modern-v6-tunnel`; its two reviewed reference
captures include ICMP and UDP. `modern-udp-encap` forces ESP-in-UDP on port
4500 for a controlled encapsulation check. It does not contain an actual NAT
device. The strongSwan [`encap` setting](https://docs.strongswan.org/docs/latest/features/natTraversal.html)
is used to force this behavior. Both scenarios are exercised through the same
run script with a unique ID, seed and scenario argument.

## Child SA rekey verification

For a fresh `modern-tunnel` or `cbc-no-pfs` run, follow the manual topology,
peer and capture steps above. After initiation, run `ip netns exec sih4-client
swanctl --rekey --uri unix:///run/sih4-client/charon.vici --child protected`
and save its output as `<run-dir>/rekey.log`. Save `bash
testbed/scripts/peers.sh status <run-dir>` as
`<run-dir>/sa-after-rekey.log` while both peers are running. Send a protected
ping, stop capture, and register it. Then run `python -m
testbed.scripts.verify_rekey <run-dir>`. This checks that both peers installed
Child SA #2, and records the selected Child SA DH group from live daemon
state. The `modern-rekey` and `cbc-rekey` samples include the resulting
secret-free verification sidecars. The passive analyzer still reports PFS as
`UNKNOWN` for those encrypted rekey captures.

The proposal syntax follows the [strongSwan swanctl configuration
reference](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html).
PFS here refers to Child SA rekeying; an initial IKEv2 Child SA does not gain
a separate DH exchange merely because the ESP proposal contains a DH group.
