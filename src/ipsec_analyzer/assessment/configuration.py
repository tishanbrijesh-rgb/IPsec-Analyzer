"""Validate a sanitized, explicitly authorized configuration snapshot.

The capture hash and unordered peer pair bind a snapshot to one analysis. An
unmatched, stale, ambiguous, or incomplete snapshot cannot establish a fact.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import re
from typing import Any


FIELDS = ("deployment_type", "mode", "child_sa_lifetime_seconds", "replay_window", "pfs_group")


def validate_configuration(document: Any, capture_sha256: str,
                           session_records: list[dict], capture_end_ns: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {"schema_version": "1", "status": "UNMATCHED",
                              "reason": "No authorized configuration was supplied.",
                              "source_id": None, "collected_at": None,
                              "matches": {}}
    if document is None:
        return result
    if not isinstance(document, dict) or set(document) != {
        "schema_version", "source_id", "collected_at", "capture_sha256", "peers", "values"
    }:
        raise ValueError("Configuration must use the exact sanitized schema v1")
    if document["schema_version"] != "1":
        raise ValueError("Unsupported configuration schema version")
    source_id = document["source_id"]
    if not isinstance(source_id, str) or not 1 <= len(source_id) <= 100:
        raise ValueError("Configuration source_id must be 1–100 characters")
    result["source_id"] = source_id
    try:
        collected = datetime.fromisoformat(document["collected_at"].replace("Z", "+00:00"))
        if collected.tzinfo is None:
            raise ValueError
        collected = collected.astimezone(timezone.utc)
    except (TypeError, AttributeError, ValueError) as exc:
        raise ValueError("Configuration collected_at must have a timezone") from exc
    result["collected_at"] = collected.isoformat()
    peers = document["peers"]
    if not isinstance(peers, list) or len(peers) != 2 or any(not isinstance(p, str) for p in peers) or peers[0] == peers[1]:
        raise ValueError("Configuration peers must contain two distinct addresses")
    values = document["values"]
    if not isinstance(values, dict) or not set(values) <= set(FIELDS):
        raise ValueError("Configuration values contain unsupported fields")
    for field, value in values.items():
        if field == "deployment_type" and value not in ("site_to_site", "host_to_host"):
            raise ValueError("Invalid deployment_type")
        if field == "mode" and value not in ("tunnel", "transport"):
            raise ValueError("Invalid mode")
        if field not in ("mode", "deployment_type") and (type(value) is not int or value < 0 or value > 86400 * 365):
            raise ValueError(f"Invalid {field}")
    if not isinstance(document["capture_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", document["capture_sha256"]):
        raise ValueError("Configuration capture_sha256 must be lowercase SHA-256")
    if document["capture_sha256"] != capture_sha256:
        result["reason"] = "Capture hash does not match the configuration scope."
        return result
    if capture_end_ns is None or abs(collected - datetime.fromtimestamp(
            capture_end_ns / 1_000_000_000, timezone.utc)) > timedelta(hours=24):
        result["status"] = "STALE"
        result["reason"] = "Snapshot collection is more than 24 hours from the captured traffic."
        return result
    matches = [record for record in session_records if set(record["endpoints"]) == set(peers)]
    if len(matches) != 1 or matches[0]["association_state"] != "UNAMBIGUOUS":
        result["reason"] = "Configuration must match exactly one unambiguous IKE session."
        return result
    result["status"] = "MATCHED"
    result["reason"] = "Capture hash and peer pair match one IKE session."
    result["matches"] = {matches[0]["id"]: dict(values)}
    return result
