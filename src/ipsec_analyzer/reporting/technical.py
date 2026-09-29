"""Plain-text technical report with evidence and limitations."""

from __future__ import annotations

from ipsec_analyzer.assessment.analyze import Analysis


def render_technical(analysis: Analysis) -> str:
    data = analysis.to_dict()
    capture = data["capture"]
    lines = [
        "IPsec Capture Analysis: Technical Report",
        f"Capture SHA-256: {capture['sha256']}",
        f"Packets: {capture['packet_count']}",
        f"IKE sessions: {len(data['sessions'])}",
        f"ESP/AH directional flows: {len(data['flows'])}",
        f"Rule set: {data['rule_set_version']}",
        f"Applicable rule coverage: {data['coverage']['evaluated_session_rules']}/{data['coverage']['total_session_rules']}",
        f"Assessed rule pass rate: {str(data['assessed_rule_pass_percent']) + '%' if data['assessed_rule_pass_percent'] is not None else 'unavailable'}",
        "",
        "Rule evaluations",
    ]
    for finding in data["rule_evaluations"]:
        lines.append(
            f"- {finding['rule_id']} v{finding['rule_version']} [{finding['status']}] "
            f"Subject: {finding['subject_id']}. {finding['rationale']} "
            f"Packets: {finding['evidence_packets']}. Evidence: {finding['evidence_ids']}. "
            f"Baseline: {finding['baseline_url']}"
        )
        if finding["severity"]:
            lines.append(f"  Severity: {finding['severity']}. {finding['severity_rationale']}")
            lines.append(f"  Impact: {finding['impact']}")
        if finding["remediation"]:
            lines.append(f"  Remediation: {finding['remediation']}")
    if not data["rule_evaluations"]:
        lines.append("- No IKE session was available for rule evaluation.")
    lines.extend(["", f"Security score: unavailable. {data['score_reason']}", "", "Limitations"])
    lines.extend(f"- {item}" for item in data["limitations"])
    return "\n".join(lines) + "\n"
