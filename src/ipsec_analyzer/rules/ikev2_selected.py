"""Checks limited to an unambiguous, visible IKEv2 SA response."""

from __future__ import annotations

from ipsec_analyzer.assessment.sessions import Session
from ipsec_analyzer.rules.ikev1 import RuleResult

RULE_VERSION = "1.0"


def evaluate_selected_transform(session: Session, transform_type: int) -> RuleResult:
    if transform_type == 1:
        rule_id, weak_id, label = "IPSEC-IKEV2-DES-001", 2, "ENCR_DES"
        baseline, url = "RFC 8247 section 2.1", "https://www.rfc-editor.org/rfc/rfc8247.html#section-2.1"
        impact = "DES provides no meaningful confidentiality for the IKE SA."
        remediation = "Remove DES from IKEv2 proposals and select a supported modern encryption transform."
    elif transform_type == 4:
        rule_id, weak_id, label = "IPSEC-IKEV2-MODP1-001", 1, "768-bit MODP group 1"
        baseline, url = "RFC 8247 section 2.4", "https://www.rfc-editor.org/rfc/rfc8247.html#section-2.4"
        impact = "Group 1 does not provide a meaningful key exchange security margin."
        remediation = "Remove MODP group 1 from IKEv2 proposals and select a supported stronger group."
    else:
        raise ValueError("Unsupported transform rule")

    subject = session.initiator_spi
    if session.version_major != 2:
        return RuleResult(rule_id, RULE_VERSION, "NOT_APPLICABLE", None, subject, (),
                          "This rule applies only to IKEv2.", None, baseline, url, "UNKNOWN")
    if session.selected is None or session.selected_evidence_packet is None or session.association_state != "UNAMBIGUOUS":
        return RuleResult(rule_id, RULE_VERSION, "UNKNOWN", None, subject, (),
                          "No unambiguous selected IKEv2 SA response is visible.", None,
                          baseline, url, "UNKNOWN")
    matches = [item for item in session.selected.transforms if item.transform_type == transform_type]
    packet = (session.selected_evidence_packet,)
    if len(matches) != 1:
        return RuleResult(rule_id, RULE_VERSION, "UNKNOWN", None, subject, packet,
                          "The selected response does not contain exactly one transform of this type.",
                          None, baseline, url, "UNKNOWN")
    if matches[0].transform_id == weak_id:
        return RuleResult(rule_id, RULE_VERSION, "FAIL", "HIGH", subject, packet,
                          f"Selected IKEv2 response uses {label}; {baseline} marks it MUST NOT.",
                          remediation, baseline, url, "OBSERVED",
                          "Project policy: an RFC MUST NOT transform in a selected response is high severity.", impact)
    return RuleResult(rule_id, RULE_VERSION, "PASS", None, subject, packet,
                      f"The selected IKEv2 transform is not {label}; this narrow rule passes.",
                      None, baseline, url, "OBSERVED")
