const fileInput = document.getElementById("capture-file");
const fileName = document.getElementById("file-name");
const form = document.getElementById("upload-form");
const button = document.getElementById("analyze-button");
const status = document.getElementById("status");
const statusMessage = document.getElementById("status-message");
const retrySelect = document.getElementById("retry-select");
const selectedFile = document.getElementById("selected-file");
const results = document.getElementById("results");
const emptyGuide = document.getElementById("empty-guide");
const ruleFilter = document.getElementById("rule-filter");
let currentEvaluations = [];

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  fileName.textContent = file?.name || "Select a PCAP or PCAPNG";
  selectedFile.hidden = !file;
  selectedFile.textContent = file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB selected` : "";
  results.hidden = true;
  emptyGuide.hidden = false;
  if (location.search) history.replaceState(null, "", "/");
  setStatus(file ? "Ready to analyze the selected capture." : "Choose a local capture to begin.");
});

retrySelect.addEventListener("click", () => fileInput.click());

function setStatus(message, kind = "", canRetry = false) {
  statusMessage.textContent = message;
  status.className = "status" + (kind ? " " + kind : "");
  status.setAttribute("role", kind === "error" ? "alert" : "status");
  status.setAttribute("aria-busy", kind === "loading" ? "true" : "false");
  retrySelect.hidden = !canRetry;
  window.dispatchEvent(new CustomEvent("ipsec:status"));
}

function applyRuleFilter() {
  const selected = ruleFilter.value;
  let visible = 0;
  for (const row of document.getElementById("findings-body").rows) {
    if (!row.dataset.ruleStatus) continue;
    row.hidden = selected !== "all" && row.dataset.ruleStatus !== selected;
    if (!row.hidden) visible++;
  }
  const total = currentEvaluations.length;
  document.getElementById("finding-count").textContent =
    selected === "all" ? `${total} ${total === 1 ? "EVALUATION" : "EVALUATIONS"}` : `${visible} OF ${total} SHOWN`;
  const body = document.getElementById("findings-body");
  body.querySelector(".filter-empty")?.remove();
  if (total && !visible) {
    const row = body.insertRow();
    row.className = "filter-empty";
    const item = cell(row, "No evaluations have this status. Choose another status to continue.");
    item.colSpan = 4;
    item.className = "empty";
  }
}

ruleFilter.addEventListener("change", applyRuleFilter);

function cell(row, content, className = "") {
  const item = document.createElement("td");
  item.textContent = String(content ?? "Unknown");
  if (className) item.className = className;
  row.appendChild(item);
  return item;
}

function emptyRow(body, columns, message) {
  const row = body.insertRow();
  const item = cell(row, message);
  item.colSpan = columns;
  item.className = "empty";
}

function detailLine(parent, label, value) {
  const line = document.createElement("p");
  const key = document.createElement("strong");
  key.textContent = label + ": ";
  line.append(key, document.createTextNode(String(value ?? "Unknown")));
  parent.appendChild(line);
}

function formatEvidenceValue(item) {
  if (item.value == null) return item.reason || "Unavailable";
  if (item.field === "selected" && typeof item.value === "object") {
    const proposal = item.value;
    const transforms = (proposal.transforms || []).map(transform =>
      `type ${transform.transform_type}, ID ${transform.transform_id}` +
      (transform.key_length_bits == null ? "" : `, ${transform.key_length_bits} bits`));
    return `Proposal ${proposal.number}; protocol ${proposal.protocol_id}; ` +
      (transforms.length ? transforms.join("; ") : "transforms unavailable");
  }
  if (Array.isArray(item.value)) return item.value.length ? item.value.join(", ") : "None observed";
  if (typeof item.value === "object") return "Structured value";
  return String(item.value);
}

function evidenceValueCell(row, item) {
  const valueCell = row.insertCell();
  valueCell.textContent = formatEvidenceValue(item);
  if (item.value && typeof item.value === "object") {
    const detail = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Exact data";
    const raw = document.createElement("code");
    raw.className = "evidence-raw";
    raw.textContent = JSON.stringify(item.value);
    detail.append(summary, raw);
    valueCell.appendChild(detail);
  }
}

function packetLinks(parent, indices, summariesByIndex) {
  for (const index of indices || []) {
    const link = document.createElement("a");
    link.href = summariesByIndex.has(index) ? "#packet-" + index : "#packets-title";
    link.textContent = "Packet " + index;
    parent.appendChild(link);
  }
}

function render(data, id) {
  results.hidden = false;
  emptyGuide.hidden = true;
  document.getElementById("capture-id").textContent = data.capture.id;
  document.getElementById("rail-format").textContent = data.capture.format.toUpperCase();
  document.getElementById("analysis-version").textContent = data.analysis_version;
  document.getElementById("metric-packets").textContent = data.capture.packet_count;
  document.getElementById("metric-sessions").textContent = data.sessions.length;
  document.getElementById("metric-flows").textContent = data.flows.length;
  document.getElementById("metric-findings").textContent = data.finding_count;
  currentEvaluations = data.rule_evaluations;
  ruleFilter.value = "all";
  document.getElementById("ai-status").textContent = data.ai_inference.status;
  document.getElementById("ai-reason").textContent = data.ai_inference.reason || "";
  document.getElementById("implemented-rules").textContent = data.coverage.implemented_rules;
  document.getElementById("rule-coverage").textContent = Math.round(data.coverage.evaluated_ratio * 100) + "%";
  document.getElementById("rule-coverage-detail").textContent =
    `${data.coverage.evaluated_session_rules} evaluated of ${data.coverage.total_session_rules} applicable session rules`;
  document.getElementById("source-format").textContent = data.capture.format.toUpperCase();
  document.getElementById("source-hash").textContent = data.capture.sha256;
  const reportBase = "/api/analyses/" + encodeURIComponent(id) + "/report";
  document.getElementById("report-link").href = reportBase;
  document.getElementById("html-link").href = reportBase + "?format=html";
  document.getElementById("pdf-link").href = reportBase + "?format=pdf";
  document.getElementById("json-link").href = reportBase + "?format=json";
  document.getElementById("redacted-link").href = reportBase + "?format=pdf&redacted=true";
  document.getElementById("redacted-json-link").href = reportBase + "?format=json&redacted=true";
  document.getElementById("report-actions").hidden = false;
  for (const [linkId, label] of [
    ["report-link", "Download full text report"], ["html-link", "Download full HTML report"],
    ["pdf-link", "Download full PDF report"], ["json-link", "Download full JSON report"],
    ["redacted-link", "Download redacted PDF shared copy"],
    ["redacted-json-link", "Download redacted JSON shared copy"],
  ]) document.getElementById(linkId).setAttribute("aria-label", label);

  const evidenceById = new Map(data.evidence.map((entry, index) => [entry.id, {entry, anchor: "evidence-" + index}]));
  const summariesByIndex = new Map((data.packet_summaries || []).map(packet => [packet.index, packet]));

  const findings = document.getElementById("findings-body");
  findings.replaceChildren();
  const statusOrder = {FAIL: 0, UNKNOWN: 1, PASS: 2, NOT_APPLICABLE: 3};
  const sortedEvaluations = data.rule_evaluations.map((result, index) => ({result, index}))
    .sort((a, b) => (statusOrder[a.result.status] ?? 4) - (statusOrder[b.result.status] ?? 4) || a.index - b.index);
  for (const {result} of sortedEvaluations) {
    const row = findings.insertRow();
    row.dataset.ruleStatus = result.status;
    cell(row, result.rule_id, "mono");
    const badgeCell = row.insertCell();
    const badge = document.createElement("span");
    badge.className = "badge " + result.status.toLowerCase();
    badge.textContent = result.status;
    badgeCell.appendChild(badge);
    const packetCell = row.insertCell();
    if (result.evidence_packets.length) packetLinks(packetCell, result.evidence_packets, summariesByIndex);
    else packetCell.textContent = "Unavailable";
    const detailCell = row.insertCell();
    detailCell.appendChild(document.createTextNode(result.rationale));
    const subject = document.createElement("span");
    subject.className = "rule-subject mono";
    subject.textContent = "Subject " + result.subject_id;
    detailCell.appendChild(subject);
    const detail = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Evidence and remediation";
    detail.appendChild(summary);
    detailLine(detail, "Subject", result.subject_id);
    detailLine(detail, "Severity", result.severity || "Not assigned");
    detailLine(detail, "Impact", result.impact || "No failed-rule impact recorded");
    detailLine(detail, "Remediation", result.remediation || "Not applicable");
    if (result.baseline_url) {
      const baseline = document.createElement("a");
      baseline.href = result.baseline_url;
      baseline.textContent = result.baseline || "Rule baseline";
      baseline.rel = "noopener noreferrer";
      baseline.target = "_blank";
      detail.appendChild(baseline);
    }
    for (const id of result.evidence_ids || []) {
      const target = evidenceById.get(id);
      if (!target) continue;
      const link = document.createElement("a");
      link.href = "#" + target.anchor;
      link.textContent = "Evidence " + id.split(":").at(-1);
      detail.appendChild(link);
    }
    detailCell.appendChild(detail);
  }
  if (!data.rule_evaluations.length) emptyRow(findings, 4, "No IKE session was available for rule evaluation.");
  applyRuleFilter();

  const sessions = document.getElementById("sessions-body");
  sessions.replaceChildren();
  for (const session of data.sessions) {
    const row = sessions.insertRow();
    cell(row, session.initiator_spi, "mono");
    cell(row, "IKEv" + session.version_major);
    cell(row, session.request_packets.length);
    cell(row, session.response_packets.length);
    const selected = row.insertCell();
    selected.textContent = session.selected ? "Proposal " + session.selected.number : "Unknown";
    const exchangeDetail = document.createElement("details");
    const exchangeSummary = document.createElement("summary");
    exchangeSummary.textContent = "Exchange detail";
    exchangeDetail.appendChild(exchangeSummary);
    detailLine(exchangeDetail, "Selection state", session.selection_state);
    detailLine(exchangeDetail, "Selected response packet", session.selected_evidence_packet);
    const selectedEvidenceId = session.id + ":selected";
    const selectedEvidence = evidenceById.get(selectedEvidenceId);
    if (selectedEvidence && session.selected_evidence_packet != null) {
      const link = document.createElement("a");
      link.href = "#" + selectedEvidence.anchor;
      link.textContent = "Trace selected proposal to packet " + session.selected_evidence_packet;
      exchangeDetail.appendChild(link);
    }
    detailLine(exchangeDetail, "Selected transforms", session.selected?.transforms?.length
      ? session.selected.transforms.map(item => "type " + item.transform_type + ", ID " + item.transform_id
        + (item.key_length_bits ? ", " + item.key_length_bits + " bits" : "")).join("; ")
      : "Unknown");
    detailLine(exchangeDetail, "Association", session.association_state);
    for (const exchange of session.exchanges || []) {
      detailLine(exchangeDetail, "Exchange " + exchange.exchange_type + " / message " + exchange.message_id,
        exchange.status + "; requests " + exchange.request_packets.join(", ") + "; responses " + exchange.response_packets.join(", "));
    }
    selected.appendChild(exchangeDetail);
  }
  if (!data.sessions.length) emptyRow(sessions, 5, "No IKE exchange was identified in this capture.");

  const flows = document.getElementById("flows-body");
  flows.replaceChildren();
  for (const flow of data.flows) {
    const row = flows.insertRow();
    cell(row, flow.source + " → " + flow.destination, "mono");
    cell(row, flow.kind);
      cell(row, flow.encapsulation || "Not specified");
    cell(row, "0x" + flow.spi.toString(16).padStart(8, "0"), "mono");
    cell(row, flow.packet_count);
    cell(row, flow.byte_count.toLocaleString());
  }
    if (!data.flows.length) emptyRow(flows, 6, "No ESP or AH flow was identified in this capture.");

  const inference = document.getElementById("inference-body");
  inference.replaceChildren();
  for (const item of data.ai_inference.flows || []) {
    const row = inference.insertRow();
    cell(row, item.flow_id.split(":").at(-1), "mono");
      cell(row, item.abstained ? "Unknown / abstained: " + (item.reason || "Reason unavailable") : "INFERRED: " + item.prediction);
      cell(row, (item.model_version || "Model unavailable") + " · " + (item.confidence == null ? "confidence unavailable" : Math.round(item.confidence * 100) + "% pilot confidence"));
    cell(row, item.evidence_refs.length ? item.evidence_refs.join(", ") : "Unavailable");
  }
  if (!inference.rows.length) emptyRow(inference, 4, "No classifier result is available for this capture.");

  const evidence = document.getElementById("evidence-body");
  evidence.replaceChildren();
  const referenced = new Set(data.rule_evaluations.flatMap(item => item.evidence_ids || []));
  for (const session of data.sessions) {
    if (session.selected_evidence_packet != null) referenced.add(session.id + ":selected");
  }
  for (const id of referenced) {
    const target = evidenceById.get(id);
    if (!target) continue;
    const row = evidence.insertRow();
    row.id = target.anchor;
    row.tabIndex = -1;
    const item = target.entry;
    cell(row, item.id, "mono");
    cell(row, item.state);
    evidenceValueCell(row, item);
    const packetCell = row.insertCell();
    if (item.packet_indices.length) packetLinks(packetCell, item.packet_indices, summariesByIndex);
    else packetCell.textContent = "Unavailable";
  }
  if (!evidence.rows.length) emptyRow(evidence, 4, "No rule evidence is available for this capture.");

  const packets = document.getElementById("packets-body");
  packets.replaceChildren();
  for (const packet of data.packet_summaries || []) {
    const row = packets.insertRow();
    row.id = "packet-" + packet.index;
    row.tabIndex = -1;
    cell(row, packet.index, "mono");
    cell(row, packet.kind);
    cell(row, (packet.source || "Unknown") + " → " + (packet.destination || "Unknown"), "mono");
    cell(row, packet.captured_length + " bytes");
    cell(row, [packet.encapsulation, ...(packet.diagnostics || [])].filter(Boolean).join("; ") || "None");
  }
  if (!packets.rows.length) emptyRow(packets, 5, "No referenced packet metadata is available for this capture.");
  document.getElementById("packets-truncated").hidden = !data.packet_summaries_truncated;

  const limits = document.getElementById("limitations");
  limits.replaceChildren();
  for (const text of data.limitations) {
    const item = document.createElement("li");
    item.textContent = text;
    limits.appendChild(item);
  }
  window.dispatchEvent(new CustomEvent("ipsec:results"));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = fileInput.files[0];
  if (!file) return;
  results.hidden = true;
  emptyGuide.hidden = false;
  if (location.search) history.replaceState(null, "", "/");
  if (!file.size) {
    setStatus("This capture is empty. Choose a PCAP or PCAPNG file with packet data.", "error", true);
    status.focus();
    return;
  }
  if (file.size > 16 * 1024 * 1024) {
    setStatus("This local API accepts captures up to 16 MiB. Choose a smaller file.", "error", true);
    status.focus();
    return;
  }
  button.disabled = true;
  setStatus("Analyzing " + file.name + "…", "loading");
  try {
    const response = await fetch("/api/analyses", {
      method: "POST",
      headers: {"Content-Type": "application/octet-stream"},
      body: file
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(typeof payload.detail === "string" ? payload.detail : "The capture could not be analyzed.");
    render(payload.result, payload.id);
    history.replaceState(null, "", "/?analysis=" + encodeURIComponent(payload.id));
    setStatus("Analysis complete. Results describe the evidence visible in this capture.", "success");
    document.getElementById("findings-title").focus();
  } catch (error) {
    setStatus((error.message || "Analysis failed.") + " Choose another capture or try again.", "error", true);
    status.focus();
  } finally {
    button.disabled = false;
  }
});

const savedId = new URLSearchParams(location.search).get("analysis");
if (savedId && /^[a-f0-9]{32}$/.test(savedId)) {
  setStatus("Loading saved analysis…", "loading");
  fetch("/api/analyses/" + savedId).then(async (response) => {
    if (!response.ok) throw new Error("Analysis expired or unavailable. Upload the capture again.");
    render(await response.json(), savedId);
    setStatus("Analysis loaded from this local session.", "success");
    document.getElementById("findings-title").focus();
  }).catch((error) => {
    results.hidden = true;
    emptyGuide.hidden = false;
    setStatus(error.message || "Analysis unavailable. Upload the capture again.", "error", true);
    status.focus();
  });
}
