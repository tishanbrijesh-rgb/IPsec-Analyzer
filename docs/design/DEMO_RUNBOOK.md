# Local analyst demo

This demo uses synthetic packets and the loopback-only dashboard. Run it from
the repository root in WSL, where `python3`, `uvicorn` and project dependencies
are installed. It does not require a live interface or a second host.

## 1. Generate and check the weak capture

```bash
cd "/mnt/c/Users/Tishan Kumar B/Desktop/SIH-2"
PYTHONPATH=src:. python3 -m testbed.scripts.build_demo_capture /tmp/weak-des-demo.pcap
PYTHONPATH=src python3 -m ipsec_analyzer.ingestion.cli /tmp/weak-des-demo.pcap --analyze text
```

The deterministic two-packet capture should show one IKE session,
`IPSEC-IKEV2-DES-001 [FAIL]`, selected response packet 2, and a remediation to
remove DES. `IPSEC-IKEV2-MODP1-001` is `UNKNOWN`; the overall security score is
unavailable. The capture contains documentation-range addresses and no real
user traffic. Its generator reuses the same packet construction as the parser
tests.

## 2. Start the dashboard

Keep this WSL terminal open:

```bash
PYTHONPATH=src uvicorn ipsec_analyzer.api.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` on the same machine. Upload
`/tmp/weak-des-demo.pcap` from WSL, or open `\\wsl.localhost\Ubuntu\tmp` in
the Windows file picker (replace `Ubuntu` with the installed distro name).
If the Windows file picker cannot reach WSL, generate the capture in the
ignored generated-data directory and upload `data/generated/demo-weak-des.pcap`:

```bash
PYTHONPATH=src:. python3 -m testbed.scripts.build_demo_capture data/generated/demo-weak-des.pcap
```

Remove that temporary PCAP after the demo.

## 3. Trace and export

1. Confirm two packets, one IKE session, a failed DES rule and an unknown
   MODP1 rule. The failure is a visible IKE selection, not a model estimate.
2. Expand the DES rule. Read its rationale, impact and remediation. Follow
   packet 2 to the metadata-only `Referenced packets` row.
3. Inspect the selected-proposal evidence and its `OBSERVED` state. The exact
   JSON is available in the disclosure if needed.
4. Download the full JSON or PDF, then a shared copy. The shared copy removes
   capture identifiers, endpoint addresses and SPI values. Check the packet
   count and DES finding still match the dashboard.
5. Upload `data/sample/modern-tunnel.pcap` to show real controlled ESP flow
   metadata and a separate synthetic pilot estimate or abstention. Explain
   that encrypted payloads were not decrypted and application identity is
   unvalidated outside the one-host testbed.

For a short video, record these five steps and the final limitations. Do not
describe the one-host classifier as externally validated or the overall score
as available. The video itself remains a submission task.

## Optional live check

The live command is separate from the browser. The testbed has a controlled
`sih4c` interface inside the `sih4-client` namespace; WSL `eth0` does not
carry this isolated traffic. From the repository root in WSL, run:

```bash
sudo bash testbed/scripts/run_profile.sh voip-like phase7-live-01 401 modern-tunnel --live-check
```

Use a new run ID if `phase7-live-01` already exists. This creates fresh lab
namespaces and temporary strongSwan keys, starts the bounded live analyzer
on `sih4c` for at most 20 seconds and 1,000 packets, sends only synthetic
lab traffic, and compares selected IKE transforms and both directional ESP
flows with the simultaneous offline PCAP. It waits for the live process and
tears down the namespaces when finished. The live analyzer deletes its own
temporary raw capture; the testbed's separate `outer.pcap` remains in the
ignored run directory for parity review.

The command prints a JSON parity result. Check `"passed": true` and keep
`testbed/generated/phase7-live-01/live-parity.json`, `live-result.json`,
`live-host.txt` and `dataset_record.json` private. The parity record includes
duration, packet/drop counts, capture bytes and analysis time. Share the
JSON parity result and any error text for review, but do not post generated
peer configs, PSKs or unreviewed PCAPs. The first controlled run on 29 September
2026 passed with 86 matching packets, one selected IKE response, two ESP
directions and zero kernel drops; use a fresh run ID when repeating it.
