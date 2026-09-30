"""Narrow project-policy checks on a matched, sanitized configuration.

These results describe configured intent, not installed Child SA state.
"""

from __future__ import annotations

from ipsec_analyzer.rules.ikev1 import RuleResult

RULE_VERSION = "1.0"
POLICY = "SIH project configuration baseline v1"
POLICY_URL = "https://csrc.nist.gov/pubs/sp/800/77/r1/final"
REPLAY_URL = "https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4.3"
PFS_URL = "https://www.rfc-editor.org/rfc/rfc7296.html#section-1.3"


def evaluate_configuration(subject_id: str, values: dict, match_reason: str) -> list[RuleResult]:
    specs = (
        ("IPSEC-CONFIG-MODE-001", "mode", "Expected site-to-site tunnel mode", "MEDIUM",
         "Transport mode in a declared site-to-site deployment can expose inner addressing or miss the intended gateway policy.",
         "Use tunnel mode for this site-to-site policy, then verify the installed Child SA."),
        ("IPSEC-CONFIG-LIFETIME-001", "child_sa_lifetime_seconds", "Child SA lifetime at most 86,400 seconds", "MEDIUM",
         "A long configured Child SA lifetime extends exposure after key compromise.",
         "Set the Child SA lifetime to at most 86,400 seconds and verify rekeying."),
        ("IPSEC-CONFIG-REPLAY-001", "replay_window", "ESP replay window of at least 32 packets", "HIGH",
         "A disabled replay window can permit duplicate ESP packets to be accepted.",
         "Enable ESP anti-replay with a window of at least 32 packets and verify the installed policy."),
        ("IPSEC-CONFIG-PFS-001", "pfs_group", "Child SA rekey PFS enabled", "MEDIUM",
         "Without a separate DH exchange on Child SA rekey, compromise of IKE key material can affect rekeyed Child SAs.",
         "Configure a supported nonzero DH group for Child SA rekey and verify an actual rekey."),
    )
    out: list[RuleResult] = []
    for rule_id, field, target, severity, impact, remediation in specs:
        evidence_fields = ("deployment_type", "mode") if field == "mode" else (field,)
        evidence_ids = tuple(f"{subject_id}:config:{name}" for name in evidence_fields)
        if any(name not in values for name in evidence_fields):
            reason = match_reason if not values else "required configuration field is absent"
            status, rationale = "UNKNOWN", f"{target} cannot be checked: {reason.rstrip('.')}."
        elif field == "mode" and values["deployment_type"] == "host_to_host":
            status, rationale = "NOT_APPLICABLE", "The site-to-site tunnel-mode policy does not apply to declared host-to-host traffic."
        else:
            value = values[field]
            if field == "mode":
                passes = value == "tunnel"
            elif field == "child_sa_lifetime_seconds":
                passes = 0 < value <= 86_400
            elif field == "replay_window":
                passes = value >= 32
            else:
                passes = value > 0
            status = "PASS" if passes else "FAIL"
            rationale = f"Configured {field}={value}; project target: {target}. Configured intent is not installed-state proof."
        out.append(RuleResult(
            rule_id, RULE_VERSION, status, severity if status == "FAIL" else None,
            subject_id, (), rationale, remediation if status == "FAIL" else None,
            POLICY, (REPLAY_URL if field == "replay_window" else PFS_URL if field == "pfs_group" else POLICY_URL),
            "CONFIGURED" if status in ("PASS", "FAIL", "NOT_APPLICABLE") else "UNKNOWN",
            "Project policy severity; the reference does not assign this rating." if status == "FAIL" else None,
            impact if status == "FAIL" else None, evidence_ids,
        ))
    return out
