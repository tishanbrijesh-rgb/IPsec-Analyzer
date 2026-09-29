# Dataset status and handling

Forty-four small, controlled strongSwan WSL runs are included in `sample/` as
filtered outer-link PCAPs with secret-free JSON records. Three cover configured
tunnel, transport and PFS differences; six use synthetic traffic profiles;
two capture Child SA rekey. A generated scenario
manifest provides configuration labels; live `swanctl --list-sas` checks also
confirmed the intended tunnel or transport mode and installed ESP during each
run. Each protected ping passed 3/3. The full generated configs, PSKs and
daemon logs remain in ignored `testbed/generated/` directories. Capture
registration records a SHA-256 digest, capture point, scenario version and
run-level split group after visible IKE selection and ESP are found.

| Sample | Packets | Config mode | Selected IKE encryption seen in response | SHA-256 |
| --- | ---: | --- | --- | --- |
| `modern-tunnel` | 10 | Tunnel | AES-GCM-16, 256-bit | `af30fd79d36d123293953f6cc33580c2bd41ccafb1941ca163cc519da445b61d` |
| `modern-transport` | 8 | Transport | AES-GCM-16, 256-bit | `ba0e1dce71cd90800e273f500c610367715f6f67a38de74c7ca39e3a297b6c4f` |
| `cbc-no-pfs` | 8 | Tunnel, no PFS on Child SA rekey | AES-CBC, 128-bit | `80873fec17e7d44dd869ecd179e9b9b8a64d9a94dd71c293b6371e40f4c9e4e8` |

Tunnel/transport and PFS labels come from the generated configs and daemon
checks, not a passive packet inference. No Child SA rekey was performed, so
the PFS-on-rekey label has not been validated against a rekey exchange. The
current narrow IKE rules pass for all three samples; they do not assess PFS.

Two additional rekey samples pin the PCAP and carry a separate verification
record sourced from both peers' live `swanctl --list-sas` output:

| Sample | Installed Child SA after rekey | Live DH observation | Capture SHA-256 |
| --- | --- | --- | --- |
| `modern-rekey` | `ESP:AES_GCM_16-256/ECP_384` | ECP-384 on both peers | `6ceae2a713d5bdddecb116b4216f83796c5b800185beb0aa6a792718681ede50` |
| `cbc-rekey` | `ESP:AES_CBC-128/HMAC_SHA2_256_128` | No Child SA DH group on either peer | `2e5f7ae9799fb9035e6f9961cc1851e5bc19897c64ee8cf8fff7f81e39092c94` |

Both rekeys completed successfully and the new SAs carried a protected ping.
The rekey packets are encrypted, so the passive analyzer correctly retains
`UNKNOWN` for PFS even for these samples. The sidecar records are lab ground
truth and must never be presented as packet-derived findings.

| Synthetic profile | Packets | Sender pattern |
| --- | ---: | --- |
| `voip-like` | 84 | 40 UDP messages, 160 bytes each, 20 ms spacing |
| `video-like` | 84 | 40 UDP messages, 1100 bytes each, 30 ms spacing |
| `messaging-like` | 48 | 12 small TCP frames, 100 ms spacing |
| `email-like` | 59 | 16 medium TCP frames, 60 ms spacing |
| `web-like` | 54 | 20 larger TCP frames, 20 ms spacing |
| `icmp` | 10 | 3 ICMP echo requests and responses |

These are generator-profile labels recorded by the sender command. They do
not establish real application identity from encrypted packets. The JSON
records pin capture hashes and keep each run in a distinct split group. TCP
packet counts depend on segmentation and acknowledgements, so they need not
equal the generator's message count.

## Dataset card draft

- **Purpose:** validate IPsec parsing and, later, train and evaluate encrypted
  flow classification under controlled lab conditions.
- **Collection:** isolated Linux namespaces and strongSwan peers; outer-link
  PCAP filtered to IKE, ESP and AH. No real user traffic is intended.
- **Labels:** tunnel/transport mode, IKE and ESP proposal, and PFS-on-rekey
  setting from generated configs. These are configuration ground truth, not
  facts inferred from packets. Synthetic traffic labels come from recorded
  generator commands and are not real application labels.
- **Unit of split:** entire run/tunnel/scenario group. Packets or flows from a
  run must never appear in both training and held-out evaluation.
- **Privacy:** generated PSKs stay in ignored directories. Captures and run
  logs require manual review before sharing. Do not include private keys,
  credentials, or unrelated traffic.
- **Current limits:** six runs per synthetic profile, including five seeded
  variations, on one WSL host. The labels describe generated traffic rather
  than real applications. There are no performance or model quality claims.

## Reviewed Phase 4 batch and pilot split

The Phase 5 synthetic classifier uses the 18/6/6 complete-run partitions below.
It selects the busiest ESP direction as one example per run. `esp-flow-2`
contains packet and captured-byte counts, length summary and range, mean
interarrival time, and a count of bursts separated by over 200 ms. Direction
is represented by separate directional ESP flows, not by decrypted traffic.
The data-only artifact and evaluation are in `models/artifacts/traffic-classifier/`.
Training fits standardized class centroids; validation selects a temperature
and an abstention threshold. The six held-out runs provide one sample per
class, so the resulting precision, recall and accepted-only Brier figures have high
uncertainty. The reported probabilities are pilot calibration outputs and
must not be interpreted as real-application probabilities. Out-of-support,
short, non-ESP and ambiguous flows route to `unknown/other`. Inference does
not change any deterministic security evaluation. Abstentions expose no
confidence or probability distribution; the evaluation reports the number of
accepted runs used for its Brier score.
The version 2 inference gate requires at least ten ESP packets, so short ICMP
flows abstain even when their synthetic template appears easy to classify.

Thirty additional runs use deterministic bounded size and timing variation,
with five runs per synthetic profile across modern tunnel, modern transport,
and CBC tunnel scenarios. Each run has its own fresh strongSwan configuration,
PSK, packet capture, generator record, and secret-free shared label record.
All 30 captures passed hash, packet-count, selected IKE, ESP, scenario-label,
seed, and generated-byte checks before being copied into `sample/`.

[`dataset-index.json`](dataset-index.json) pins all 44 capture hashes and
records 14 reference runs plus 18 train, 6 validation, and 6 test
runs. Partitions contain complete runs and each synthetic class contributes
3/1/1 batch runs. These are **pilot partitions**, not an independently
validated ML benchmark: all captures come from one WSL host, and the scenarios
and profiles are generated from a narrow family of settings. A classifier
trained and tested only here would have uncertain transfer to real traffic.
Rebuilding the index now re-analyzes every PCAP and rejects records whose
packet count, format, IKE session count, ESP flow count, selected IKE evidence
or diagnostics disagree with the capture. The current 44 records pass this
check and rebuild to an identical index. This checks internal consistency;
it cannot attest that another host ran the stated strongSwan configuration.
Run `PYTHONPATH=src python -m testbed.scripts.build_dataset_index data/sample
--check` to validate the shared set without rewriting the index.

Two reference runs exercise an IPv6 tunnel with ICMP and generated UDP
traffic. One reference run exercises forced ESP-in-UDP on port 4500. The latter
is a configuration-driven encapsulation check, not a claim that an actual NAT
device was traversed. AH remains unrepresented because it was optional in the
Phase 4 plan. These additional reference runs do not enter the traffic-class
pilot partitions.
