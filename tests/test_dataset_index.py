"""Checks that dataset labels and partitions cannot hide changed captures."""

from __future__ import annotations

from pathlib import Path

import pytest
import re

from testbed.scripts.build_dataset_index import build
from testbed.traffic.generate import PROFILES, pattern


SAMPLES = Path(__file__).resolve().parents[1] / "data" / "sample"


def test_seeded_pattern_is_bounded_and_repeatable() -> None:
    for name, profile in PROFILES.items():
        sizes, intervals = pattern(name, 101)
        assert (sizes, intervals) == pattern(name, 101)
        assert len(sizes) == len(intervals) == profile["count"]
        assert all(16 <= size <= 2048 for size in sizes)
        assert all(interval >= 0.005 for interval in intervals)
        assert pattern(name, 0)[0] == [profile["size"]] * profile["count"]
    with pytest.raises(ValueError):
        pattern("web-like", -1)


def test_reviewed_index_has_no_hash_or_group_leakage() -> None:
    index = build(SAMPLES)
    records = index["records"]
    assert len({record["sha256"] for record in records}) == len(records)
    assert len({record["split_group"] for record in records}) == len(records)
    for profile in PROFILES:
        batch = [record for record in records if record["traffic_profile"] == profile
                 and re.fullmatch(r"phase4-(voip|video|messaging|email|web|icmp)-0[1-5]\.pcap", record["capture"])]
        if batch:
            assert len(batch) == 5
            assert {partition: sum(record["partition"] == partition for record in batch)
                    for partition in ("train", "validation", "test")} == {
                        "train": 3, "validation": 1, "test": 1}


def test_index_rejects_modified_capture(tmp_path: Path) -> None:
    source = SAMPLES / "modern-tunnel"
    (tmp_path / "modern-tunnel.json").write_text(
        (source.with_suffix(".json")).read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "modern-tunnel.pcap").write_bytes(source.with_suffix(".pcap").read_bytes() + b"changed")
    with pytest.raises(ValueError, match="changed"):
        build(tmp_path)


def test_index_rejects_fabricated_packet_count_with_valid_capture_hash(tmp_path: Path) -> None:
    import json

    source = SAMPLES / "modern-tunnel"
    record = json.loads(source.with_suffix(".json").read_text(encoding="utf-8"))
    record["packet_count"] += 1
    (tmp_path / "modern-tunnel.json").write_text(json.dumps(record), encoding="utf-8")
    (tmp_path / "modern-tunnel.pcap").write_bytes(source.with_suffix(".pcap").read_bytes())
    with pytest.raises(ValueError, match="metadata or IPsec evidence mismatch"):
        build(tmp_path)
