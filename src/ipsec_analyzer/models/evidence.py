"""Explicit provenance for observed, derived and unavailable facts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ipsec_analyzer.models.packets import EvidenceState


@dataclass(frozen=True)
class Evidence:
    id: str
    subject_id: str
    field: str
    state: EvidenceState
    value: Any
    packet_indices: tuple[int, ...]
    method: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
