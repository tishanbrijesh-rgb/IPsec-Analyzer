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
        f"Configuration match: {data['configuration']['status']}. {data['configuration']['reason']}",
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
    risk = data["risk_score"]
    lines.extend(["", f"Risk policy: {risk['policy_version']}; status: {risk['status']}; weighted coverage: {risk['coverage']:.0%}."])
    if risk["status"] == "SCORED":
        lines.append(f"Risk score: {risk['value']}/100 ({risk['band']}); failed weight {risk['failed_weight']}/{risk['assessed_weight']} assessed weight.")
    else:
        lines.append(f"Risk score withheld: {risk['withheld_reason']}")
    lines.append("Threat matrix")
    for threat in data["threat_matrix"]:
        lines.append(f"- {threat['category']} [{threat['severity']}]; mapping: {threat['mapping_version']}; asset: {threat['affected_asset']}; control: {threat['affected_control']}; finding: {threat['finding_id']}; evidence: {threat['evidence_ids']}; packets: {threat['evidence_packets']}.")
        lines.append(f"  Impact: {threat['impact']}")
        lines.append(f"  Remediation: {threat['remediation']}")
    if not data["threat_matrix"]:
        lines.append("- No failed-rule threat rows; unknown controls remain unassessed.")
    lines.extend(["", "Limitations"])
    lines.extend(f"- {item}" for item in data["limitations"])
    return "\n".join(lines) + "\n"
