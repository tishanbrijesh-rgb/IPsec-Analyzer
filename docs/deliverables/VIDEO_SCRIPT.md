# Demonstration video script

**Project:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**Target length:** 8–10 minutes  
**Recording date:** 30 September 2026  
**Evidence rule:** Show actual reviewed strongSwan lab captures. Do not present a withheld score as a number, a generated traffic profile as a real application, or selected IKE transforms as proof of the installed ESP cipher.

## Before recording

1. Start the local dashboard from the repository root: `PYTHONPATH=src python -m uvicorn ipsec_analyzer.api.app:app --host 127.0.0.1 --port 8047` (use `python3` on Linux). Keep that terminal open. If the existing server is running, use it.
2. Open the links below. Analysis IDs live in memory; if the server restarts, upload each linked PCAP again and replace the analysis URLs. Do not record an expired-result screen.
3. Prepare the actual files in `data/sample/` and `data/control/`. Keep private generated configs, PSKs and daemon logs out of the recording. Show the secret-free JSON records only when discussing lab provenance.
4. Record at 1280×720 or higher. Use browser zoom that keeps the page heading, metric strip and navigation legible. Pause after each click so the viewer can read the result.

| Segment | Reviewed input | Current analysis page |
| --- | --- | --- |
| Modern tunnel | [`modern-tunnel.pcap`](../../data/sample/modern-tunnel.pcap), [record](../../data/sample/modern-tunnel.json) | [Assessment](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/assessment) |
| CBC contrast | [`cbc-no-pfs.pcap`](../../data/sample/cbc-no-pfs.pcap), [record](../../data/sample/cbc-no-pfs.json) | [Assessment](http://127.0.0.1:8047/analyses/99fef3024e4946b6bf5cdab6338d4937/assessment) |
| Unprotected control | [`plain-icmp-01.pcap`](../../data/control/plain-icmp-01.pcap), [record](../../data/control/plain-icmp-01.json) | [Assessment](http://127.0.0.1:8047/analyses/178a37590ad3493f86ca58f738d0754c/assessment) |
| AI pilot behavior | [`phase4-voip-01.pcap`](../../data/sample/phase4-voip-01.pcap), [record](../../data/sample/phase4-voip-01.json) | [Inference](http://127.0.0.1:8047/analyses/ef1c89e0cc6f48b6bc15f32454b0952f/inference) |

The VPN exchanges in these PCAPs were captured from a controlled strongSwan lab. The `*-like` traffic was produced by a generator through that VPN; it is not a recording of WhatsApp, a VoIP application, or another real user application. The control PCAP contains normal unprotected ICMP traffic.

## Spoken script and screen directions

### 0:00–0:35 — Title and problem

**Screen:** Show the dashboard's New capture page and title. Put the project name in the video title card.

**Say:** “This is the AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework. IPsec protects network traffic, but reading an IKE and ESP capture by hand takes expertise. This prototype organizes the visible protocol facts, evaluates selected security controls, and shows where the evidence stops. Its AI component estimates a traffic profile from encrypted-flow metadata and can abstain when the evidence is weak.”

**On-screen caption:** `Protocol facts • evidence-linked rules • bounded AI inference`

### 0:35–1:25 — What went into the system

**Screen:** Show [`data/sample/modern-tunnel.json`](../../data/sample/modern-tunnel.json) briefly. Point to scenario, SHA-256, packet count, IKE session count and ESP flow count. Then open the modern assessment link.

**Say:** “The first input is a reviewed outer-interface PCAP from an isolated strongSwan tunnel. Its secret-free record pins the capture hash and the intended lab scenario. It contains ten captured packets, one IKE session and two directional ESP flows. The lab configuration and daemon checks describe the scenario; the analyzer does not silently promote those labels into packet observations.”

**On-screen caption:** `Reviewed lab capture; configuration labels are separate from packet observations`

### 1:25–2:25 — Automatic protocol identification

**Screen:** On [modern IKE sessions](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/sessions), show the selected response and transforms. Open [modern flows](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/flows), then return to [assessment](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/assessment).

**Say:** “The parser reconstructs the visible IKEv2 exchange, identifies the selected IKE encryption, PRF and Diffie–Hellman transforms, and groups ESP packets by direction. Here the selected IKE response contains AES-GCM-256. The flow page shows ESP traffic in both directions. This is evidence for the IKE negotiation and outer ESP activity; it does not decrypt payloads or reveal every installed Child SA parameter.”

**On-screen caption:** `Selected IKE transform ≠ automatically the installed ESP cipher`

### 2:25–3:25 — Evidence-linked assessment

**Screen:** On the modern assessment, scroll to the observed rule rows. Open “Evidence and remediation” on one PASS row; follow its packet-2 link to [Packet references](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/packets#packet-2). Return to assessment and expand “Why withheld.”

**Say:** “Each rule gives a status and a trace. For example, the selected DES rule passes because the selected IKEv2 response is not DES, and its packet link leads to response packet two. The deployment mode, lifetime, replay and PFS rules are marked unknown in this upload because no matching authorized configuration snapshot was supplied. The risk score is therefore withheld. Unknown is not a pass, and withheld is not zero risk.”

**On-screen caption:** `OBSERVED / CONFIGURED / UNKNOWN are different evidence states`

### 3:25–4:20 — Contrasting real lab configuration

**Screen:** Open [CBC IKE sessions](http://127.0.0.1:8047/analyses/99fef3024e4946b6bf5cdab6338d4937/sessions), [CBC flows](http://127.0.0.1:8047/analyses/99fef3024e4946b6bf5cdab6338d4937/flows), then the [CBC assessment](http://127.0.0.1:8047/analyses/99fef3024e4946b6bf5cdab6338d4937/assessment). Briefly show its [secret-free record](../../data/sample/cbc-no-pfs.json).

**Say:** “A second reviewed strongSwan capture gives a contrast: eight packets, one IKEv2 session and two ESP directions. Its selected IKE response contains AES-CBC-128 with an integrity transform. The lab record names a CBC, no-PFS configuration, but the passive PCAP alone cannot verify Child SA PFS. The dashboard keeps that control unknown rather than manufacturing a verdict.”

**On-screen caption:** `CBC/no-PFS is lab configuration provenance; packet analysis shows selected IKE and ESP activity`

### 4:20–5:00 — Negative control

**Screen:** Open the [unprotected ICMP control assessment](http://127.0.0.1:8047/analyses/178a37590ad3493f86ca58f738d0754c/assessment), then [flows](http://127.0.0.1:8047/analyses/178a37590ad3493f86ca58f738d0754c/flows).

**Say:** “This separate control contains six unprotected ICMP packets from three successful pings. The analyzer finds no IKE session and no ESP flow. It does not force an IPsec classification onto ordinary traffic.”

**On-screen caption:** `Normal communication control: 6 packets, 0 IKE sessions, 0 ESP flows`

### 5:00–6:10 — AI pilot and abstention

**Screen:** Open the [recorded `voip-like` inference page](http://127.0.0.1:8047/analyses/ef1c89e0cc6f48b6bc15f32454b0952f/inference). Show both directional rows: one `INFERRED voip-like` and one `UNKNOWN unknown/other`. Point to the pilot model label and confidence caveat. If possible, show the [evaluation document](../design/PHASE5_EVALUATION.md).

**Say:** “The AI component uses packet counts, captured lengths, timing and bursts from directional ESP flows. In this recorded lab run, it labels one direction `voip-like` and abstains on the other. `Voip-like` names a synthetic sender profile, not a proven VoIP application inside the encrypted tunnel. The held-out pilot test accepted four of six runs and matched all four accepted generator labels; two abstained. That small synthetic test does not validate application identity or real-world confidence.”

**On-screen caption:** `INFERRED synthetic profile; abstention is an intended result`

### 6:10–7:05 — Reports and traceability

**Screen:** Open [modern Evidence ledger](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/evidence) and [Reports](http://127.0.0.1:8047/analyses/fdd4bec0cd0249699477b972ab27d2d2/reports). Show the technical, executive, JSON and redacted report choices. If downloading on camera, open a report and confirm it matches the dashboard's withheld-score status.

**Say:** “The evidence ledger records the source and packet references behind each value. Reports are available in human-readable and machine-readable formats, with redacted versions for sharing. The same evidence status and withheld-score decision appear in the dashboard and exports.”

**On-screen caption:** `Trace a conclusion to its packet or authorized source`

### 7:05–8:05 — Reproducibility and current limits

**Screen:** Show [the dataset card](../../data/README.md), [coverage matrix](../design/PHASE4_COVERAGE_MATRIX.md), and [implementation status](../design/IMPLEMENTATION_STATUS.md). Highlight 44 reviewed captures, the independent Kali VM installation, and open items.

**Say:** “The shared dataset contains 44 reviewed lab captures with hashes and secret-free records. The parser and model have automated checks, and modern and CBC VPN cases were reproduced on a separate Kali VM installation. Important work remains: another developer or physical host must validate generalization; real application traffic has not been labeled; AH is not in the reviewed set; and deployment authentication and durable jobs are still open. This is a working prototype with explicit evidence limits.”

### 8:05–8:35 — Close

**Screen:** Return to the modern assessment overview. End with a title card: `Evidence first. Unknown when unproven.`

**Say:** “The result is an analyst workspace that turns captured IPsec traffic into navigable sessions, flows, rule evaluations and reports. Its strongest feature is the boundary between what packets show, what a configuration declares, what the pilot model estimates, and what remains unknown. Thank you.”

## Recording checks

- Keep all four demo URLs on the same running local server; analysis results are in memory and expire on restart or eviction.
- Never substitute the old synthetic strong/weak demo for a captured lab run. No numeric risk score is shown for the four capture-only links above.
- Say **selected IKE encryption** for the packet-derived AES result. Say **configured or installed Child SA encryption** only when citing the separate lab/SA record that supports it.
- Show model confidence as a pilot score, not a validated probability. Do not call a `*-like` label a real application detection.
- If any on-screen count differs after a new upload, read the current dashboard and update the spoken count before recording.
