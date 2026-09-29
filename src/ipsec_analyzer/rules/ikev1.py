"""Narrow, source-backed IKEv1 deprecation rule."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ipsec_analyzer.assessment.sessions import Session

RULE_ID = "IPSEC-IKE-LEGACY-001"
RULE_VERSION = "1.0"
BASELINE = "RFC 9395 section 3"
BASELINE_URL = "https://www.rfc-editor.org/rfc/rfc9395.html#section-3"


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    rule_version: str
    status: str
    severity: str | None
    subject: str
    evidence_packets: tuple[int, ...]
    rationale: str
    remediation: str | None
    baseline: str
    baseline_url: str
    evidence_state: str
    severity_rationale: str | None = None
    impact: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_ike_version(session: Session) -> RuleResult:
    packets = tuple(session.request_packets + session.response_packets)
    subject = session.initiator_spi
    if not packets or session.version_major not in (1, 2):
        return RuleResult(
            RULE_ID, RULE_VERSION, "UNKNOWN", None, subject, packets,
            "IKE version was not established by captured packets.", None,
            BASELINE, BASELINE_URL, "UNKNOWN",
        )
    if session.version_major == 1:
        return RuleResult(
            RULE_ID, RULE_VERSION, "FAIL", "HIGH", subject, packets,
            "The capture contains IKEv1. RFC 9395 deprecates IKEv1 and recommends migration.",
            "Upgrade and configure both peers for IKEv2.",
            BASELINE, BASELINE_URL, "OBSERVED",
            "Project policy: deprecated key exchange warrants prompt migration.",
            "IKEv1 retains protocol weaknesses and lacks current maintenance.",
        )
    return RuleResult(
        RULE_ID, RULE_VERSION, "PASS", None, subject, packets,
        "The observed exchange uses IKEv2; this rule's IKEv1 condition is absent.",
        None, BASELINE, BASELINE_URL, "OBSERVED",
    )
