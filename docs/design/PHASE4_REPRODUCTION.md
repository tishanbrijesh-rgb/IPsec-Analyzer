# Phase 4 independent reproduction

The current captures were made on one Ubuntu 26.04 WSL2 host with strongSwan
6.0.4 and tcpdump. A second developer should run this checklist on an
independent Linux installation and record the results. New capture hashes will
differ because IKE nonces, keys, timing, and packet ordering differ. Matching
evidence means equivalent negotiated IKE transforms, installed Child SAs, and
protected ESP packets, not byte-identical PCAPs.

## Prerequisites

- An isolated Linux host with root access, network namespaces (`iproute2`),
  strongSwan `charon-systemd` and `swanctl`, tcpdump, Python 3, and this
  repository. Do not run against a real VPN or an external interface.
- Execute from the repository root. The scripts reserve `sih4-client` and
  `sih4-server` namespaces and use only documentation addresses.
- Use unique run IDs; generated peer configs contain fresh PSKs and are
  confined to ignored `testbed/generated/`.

## Strong and contrasting configuration

Run each command separately, waiting for it to finish:

```sh
sudo bash testbed/scripts/run_profile.sh voip-like repro-modern-01 201 modern-tunnel
sudo bash testbed/scripts/run_profile.sh voip-like repro-cbc-01 201 cbc-no-pfs
```

For each run, keep `outer.pcap`, `manifest.json`, `dataset_record.json`,
`traffic_record.json`, `initiate.log`, and `sa-status.log` privately. Record
`uname -a`, `swanctl --version`, `tcpdump --version`, the date, and the host
type. Verify:

1. `dataset_record.json` names the intended scenario, has a nonempty capture
   SHA-256, records `voip-like`, seed 201, a selected IKE response, and ESP
   flows. Its `ground_truth` must match the generated manifest.
2. `sa-status.log` shows installed Child SAs at both peers. The modern run
   should select AES-GCM-16 with 256-bit IKE encryption and configure ECP-384
   for Child SA rekey. The CBC run should select AES-CBC with 128-bit IKE
   encryption and configure no Child SA DH group.
3. The capture analyzer reports ESP in both directions and no capture-level
   diagnostics. It must leave PFS `UNKNOWN` from passive packet evidence.
4. Only lab outer endpoints appear in `outer.pcap`. Never publish generated
   peer configs, PSKs, daemon logs, or unreviewed captures.

Run `PYTHONPATH=src python -m testbed.scripts.register_capture` only when
making a fresh capture manually; `run_profile.sh` already registers its own.
The two runs above establish reproducibility of the configured strong and
contrasting CBC cases. They do not establish live PFS-on-rekey unless the
separate rekey procedure in `testbed/README.md` is also performed.

## Evidence to return

The reviewer can share the host/tool versions, both secret-free
`dataset_record.json` files, the selected IKE transform IDs, ESP flow counts,
and whether both Child SAs installed. Capture files may be shared only after
checking their contents and local policy. Record the reviewer and host in the
Phase 4 status before calling independent reproduction complete.

Before accepting new records into the shared dataset, run
`PYTHONPATH=src python -m testbed.scripts.build_dataset_index <staging-dir> --check`
on a reviewed staging directory containing only the candidate `.pcap` and
`.json` pairs. It checks hashes, labels, run groups, packet counts, IKE
selection and ESP flow metadata against the captures without writing an index.
It does not verify daemon execution; the host and `swanctl` evidence above
remain necessary.

## Local self-reproduction on 29 September 2026

The two commands above were rerun with fresh namespaces, configs and PSKs on
the same Ubuntu WSL2 host. Both peers reported installed Child SAs in each
run. `repro-modern-01` selected IKE encryption transform 20 (AES-GCM-16),
had 84 outer packets and two native ESP flows; its capture SHA-256 was
`f6d84589bdb0e37fa262ee65ba8ccf959e6e1ebd89153285b0f598af54e343e6`.
`repro-cbc-01` selected transform 12 (AES-CBC), had 86 outer packets and two
native ESP flows; its SHA-256 was
`b0f5d8b585e714ff4d360ee0826a125dc30aa1a7e49d78ec467f7ffd4ad36042`.
These fresh runs verify the instructions on the original host. They are not
independent-host or another-developer evidence and stay in ignored generated
directories rather than the shared dataset.
