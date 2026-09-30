# Authorized configuration evidence v1

The first P0 implementation slice accepts an optional **sanitized snapshot**
through `python -m ipsec_analyzer.ingestion.cli CAPTURE --analyze json
--configuration snapshot.json`. It is deliberately separate from blind capture
analysis. The file limit is 16 KiB. No raw strongSwan export, secrets, keys,
certificates or unknown fields are accepted.

```json
{
  "schema_version": "1",
  "source_id": "lab-sanitized-1",
  "collected_at": "2026-09-29T12:00:00+00:00",
  "capture_sha256": "64 lowercase hexadecimal characters from the capture",
  "peers": ["192.0.2.1", "198.51.100.2"],
  "values": {
    "deployment_type": "site_to_site",
    "mode": "tunnel",
    "child_sa_lifetime_seconds": 3600,
    "replay_window": 32,
    "pfs_group": 14
  }
}
```

`source_id` names the authorized, sanitized source; the analyst is responsible
for collecting it under permission. `collected_at` is the collection instant,
not a claim that a configured SA was installed. The snapshot matches only when
its capture SHA-256 is exact, its unordered peer pair matches exactly one
unambiguous IKE session, and collection is within 24 hours of the final packet
timestamp. A missing capture timestamp, stale snapshot or failed match leaves
all configuration fields `UNKNOWN`. The 24-hour bound is a prototype policy:
it requires trustworthy capture clocks and a snapshot taken near the traffic.

Each field has an evidence ID under the matched session, a `CONFIGURED` state,
source ID, collection time and no packet reference. A missing field stays
`UNKNOWN`. Existing passive `UNKNOWN` fields remain as separate packet-only
evidence. The JSON report includes the match state; shared exports redact the
source ID. Configured values establish declared settings only. They do not
prove installed Child SA state. Config-backed rules and the gated score are
defined in [configuration and risk policy](../standards/RISK_AND_CONFIG_POLICY.md).
The local API and dashboard accept the same snapshot as an optional JSON file
alongside the capture. Raw capture-only upload remains supported.
