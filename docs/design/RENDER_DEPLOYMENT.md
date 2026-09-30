# Render public lab demo

The repository root contains `render.yaml` for a free Render Python web service. It builds with `pip install .`, starts Uvicorn on Render's `$PORT`, and checks `/api/health`. The `IPSEC_DEPLOYMENT_MODE=public-demo` setting enables a public **read-only** gallery of four reviewed project captures. The ordinary local mode remains loopback-only and supports authorized capture uploads.

The public gallery loads `modern-tunnel.pcap`, `cbc-no-pfs.pcap`, `phase4-voip-01.pcap`, and the separate `plain-icmp-01.pcap` control from the repository at startup. Their analysis IDs derive from capture hashes, so links survive restarts as long as the files and analyzer version remain unchanged. Visitors can inspect pages and export reports; all methods other than GET/HEAD are rejected. No visitor capture bytes are accepted or retained.

Public examples are captured lab runs with generated test traffic. Their risk scores are withheld because no matched configuration snapshot is uploaded. The synthetic traffic-profile inference is not a real-application identification claim. The source records in `data/sample/` and `data/control/` remain the provenance for the displayed captures.

To deploy, sync the Blueprint from this repository in the Render dashboard. The service should use the repository's `main` branch and the free plan shown in `render.yaml`. Verify `/api/health` returns `mode: public-demo`, `/` lists the four cases, a case opens its analysis, and POST `/api/analyses` returns 405. The Render URL must be checked after deployment; a pushed `render.yaml` alone does not create a service.

Do not change this public service to the upload mode without adding access control, a reviewed privacy notice, retention controls and a hosting decision. The current local upload API deliberately rejects nonlocal clients.
