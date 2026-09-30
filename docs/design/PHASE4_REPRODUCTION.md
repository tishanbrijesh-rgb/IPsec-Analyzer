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

### Ubuntu AppArmor access to lab VICI sockets

Some Ubuntu installations confine `/usr/sbin/swanctl` to the default VICI
socket. If the kernel log reports `apparmor="DENIED"` for a connection to
`/run/sih4-client/charon.vici` or `/run/sih4-server/charon.vici`, first confirm
that `/etc/apparmor.d/usr.sbin.swanctl` includes
`local/usr.sbin.swanctl`. Then add only these two lab paths to that local
include and reload the `swanctl` profile:

```sh
sudo grep -n 'local/usr.sbin.swanctl' /etc/apparmor.d/usr.sbin.swanctl
printf '%s\n' '/run/sih4-client/charon.vici rw,' '/run/sih4-server/charon.vici rw,' | sudo tee -a /etc/apparmor.d/local/usr.sbin.swanctl
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.swanctl
```

Stop if the include is absent or the reload fails; inspect the installed
profile before retrying. This changes only the `swanctl` profile on the lab
host and leaves AppArmor enforcement enabled. Use new run IDs after a failed
run. The generated config directories are root-owned and should not be
published.

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

Run the read-only consistency audit from the repository root after both runs:

```sh
sudo env PYTHONPATH=src python3 -m testbed.scripts.audit_reproduction testbed/generated/repro-modern-01 testbed/generated/repro-cbc-01
```

It checks each secret-free record against its PCAP, selected IKE transform,
bidirectional ESP flows and the installed Child SA line under each peer heading.
It prints a compact JSON summary and does not publish or modify the captures.
`run_profile.sh` creates the run directories as root, so the audit needs `sudo`
to read them. `env PYTHONPATH=src` keeps the project modules importable under
`sudo`.
The audit does not establish who operated the host, physical host independence,
or whether the installed state was captured at the same instant as every packet.

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

## Kali VM reproduction on 29 September 2026

The user repeated the modern and contrasting CBC `voip-like` runs on a separate
Kali Linux installation in VMware. The host reported kernel
`6.19.14+kali-amd64` (`x86_64`), strongSwan `6.1.0`, tcpdump `4.99.6`, and
Python `3.14.7`. The environment check was recorded at 15:46:52 UTC. The
`swanctl --version` command printed its version, then could not connect to
`charon` after the run had torn down the daemon; this is not evidence of a
failed tunnel during either run.

The completed runs are `kali-modern-02` and `kali-cbc-02`; earlier `-01` run
directories were incomplete and are excluded. Both completed runs have a
`dataset_record.json`, nonempty `outer.pcap`, and `sa-status.log` showing
installed Child SAs at both peers. An independent analyzer read of each PCAP
matched the recorded SHA-256 and packet count, found zero capture diagnostics,
one IKE session, and two ESP directions. The modern run had 86 packets and
selected IKE encryption transform 20 (AES-GCM-16); the CBC run had 88 packets
and selected transform 12 (AES-CBC). Both records remain in the ignored Kali
`testbed/generated/` directory and have not entered the shared dataset or
model evaluation.

This verifies reproduction on a second Linux installation. The Kali VM appears
to run on the user's original Windows machine, and the same operator performed
the checks. Independent physical-host or another-developer attestation and
external model validation remain open.

## Additional Kali VM run on 30 September 2026

The user reran the guide's `voip-like` seed-201 modern and CBC scenarios as
`repro-modern-01` and `repro-cbc-01` in Kali. The displayed secret-free records
showed 88 packets, one IKE session and two ESP flows for each run, with distinct
capture hashes and the expected scenario labels. The user supplied the
`sa-status.log` installed-SA lines for both peers in each run:

- Modern: two `INSTALLED, TUNNEL, ESP:AES_GCM_16-256` lines.
- CBC: two `INSTALLED, TUNNEL, ESP:AES_CBC-128/HMAC_SHA2_256_128` lines.

This confirms the reported installed ESP selections on both Kali peers. The
provided excerpt does not show the analyzer's selected IKE transform IDs or an
independent reanalysis of these new PCAPs. It is another run on the Kali VM,
not another developer or a separate physical host, and it does not by itself
verify Child SA PFS behavior on rekey.
