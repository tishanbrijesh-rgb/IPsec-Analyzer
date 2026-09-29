"""Shared report text rendered as plain text, HTML, or a small PDF.

The PDF writer emits text only and never embeds capture data or external assets.
"""

from __future__ import annotations

import html
import textwrap
from copy import deepcopy

from ipsec_analyzer.assessment.analyze import Analysis
from ipsec_analyzer.reporting.technical import render_technical


def report_document(analysis: Analysis, redacted: bool = False) -> dict:
    """One structured report contract for every export format."""
    data = analysis.to_dict()
    names = ("capture", "sessions", "flows", "evidence", "rule_evaluations", "findings",
             "coverage", "assessed_rule_pass_percent", "rule_set_version", "security_score",
             "risk_score", "score_reason", "ai_inference", "limitations", "finding_count")
    document = {name: deepcopy(data[name]) for name in names}
    document["report_schema_version"] = "1"
    document["summary"] = {
        "packet_count": data["capture"]["packet_count"],
        "ike_session_count": len(data["sessions"]),
        "directional_flow_count": len(data["flows"]),
        "failed_rule_finding_count": data["finding_count"],
        "score_status": "WITHHELD",
    }
    if not redacted:
        return document
    substitutions = {data["capture"]["sha256"]: "[redacted]", data["capture"]["id"]: "[capture]"}
    for flow in data["flows"]:
        substitutions[flow["source"]] = "[redacted endpoint]"
        substitutions[flow["destination"]] = "[redacted endpoint]"
    for session in data["sessions"]:
        for endpoint in session.get("endpoints", ()):
            substitutions[endpoint] = "[redacted endpoint]"
        for field in ("initiator_spi", "responder_spi"):
            if session.get(field):
                substitutions[session[field]] = "[redacted SPI]"
    for flow in document["flows"]:
        flow["spi"] = None
    for evidence in document["evidence"]:
        if evidence["field"] == "spi":
            evidence["value"] = None
    replacements = sorted(substitutions.items(), key=lambda item: len(item[0]), reverse=True)
    def scrub(value):
        if isinstance(value, str):
            for original, replacement in replacements:
                value = value.replace(original, replacement)
            return value
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [scrub(item) for item in value]
        return value
    return scrub(document)


def report_text(analysis: Analysis, redacted: bool = False) -> str:
    data = report_document(analysis, redacted)
    lines = ["Executive summary",
             f"Capture contains {data['capture']['packet_count']} packets, {len(data['sessions'])} IKE sessions and {len(data['flows'])} directional ESP/AH flows.",
             f"Failed rule findings: {data['finding_count']}.",
             "Overall security score: withheld because implemented coverage is limited.",
             "Traffic labels, when present, are INFERRED synthetic-profile estimates, not observed applications.",
             ""]
    technical = render_technical(Analysis(data))
    lines.append(technical.rstrip())
    lines.extend(["", "Traffic inference"])
    for item in data.get("ai_inference", {}).get("flows", []):
        label = item["prediction"] if not item["abstained"] else "unknown/other (abstained)"
        confidence = f"; pilot confidence {item['confidence']:.3f}" if item["confidence"] is not None else ""
        lines.append(f"- {item['flow_id'].split(':')[-1]}: {item['state']} {label}{confidence}; packets {item['evidence_refs']}")
    if not data.get("ai_inference", {}).get("flows"):
        lines.append("- No compatible classifier result is available.")
    if redacted:
        lines.extend(["", "Shared copy: capture identifiers, endpoints and SPI values are omitted."])
    return "\n".join(lines) + "\n"


def report_html(analysis: Analysis, redacted: bool = False) -> str:
    content = html.escape(report_text(analysis, redacted))
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>IPsec analysis report</title></head>"
            f"<body><main><pre>{content}</pre></main></body></html>")


def report_pdf(analysis: Analysis, redacted: bool = False) -> bytes:
    source = report_text(analysis, redacted)
    lines: list[str] = []
    for line in source.splitlines():
        lines.extend(textwrap.wrap(line, width=95, break_long_words=True, break_on_hyphens=False) or [""])
    if len(lines) > 3000:
        lines = lines[:3000] + ["Report truncated after 3000 lines; use JSON for full detail."]
    pages = [lines[i:i + 48] for i in range(0, max(len(lines), 1), 48)]
    objects: list[bytes] = []
    def add(value: bytes) -> int:
        objects.append(value)
        return len(objects)
    catalog = add(b"")
    page_tree = add(b"")
    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    page_ids = []
    for page_lines in pages:
        stream_lines = [b"BT /F1 9 Tf 36 758 Td 14 TL"]
        for line in page_lines:
            encoded = line.encode("latin-1", "replace").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
            stream_lines.append(b"(" + encoded + b") Tj T*")
        stream_lines.append(b"ET")
        stream = b"\n".join(stream_lines) + b"\n"
        content_id = add(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream")
        page_id = add(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font} 0 R >> >> /Contents {content_id} 0 R >>".encode())
        page_ids.append(page_id)
    objects[catalog - 1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[page_tree - 1] = b"<< /Type /Pages /Count " + str(len(page_ids)).encode() + b" /Kids [" + b" ".join(f"{i} 0 R".encode() for i in page_ids) + b"] >>"
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)
