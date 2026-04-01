#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   ./generate_assessment_report_blocks2.sh <blocks1_file> <openvas_parsed_json> <output_file>
#
# Esempio:
#./generate_assessment_report_blocks2.sh 
#/opt/zbfox/engagements/CLIENTE/report/assessment_report_draft_phase1.md 
#/opt/zbfox/engagements/CLIENTE/report/openvas_parsed.json  
#/opt/zbfox/engagements/cliente/report/final_report.txt


if [[ $# -lt 3 ]]; then
  echo "Uso: $0 <blocks1_file> <openvas_parsed_json> <output_file>" >&2
  exit 1
fi

BLOCKS1_FILE="$1"
OPENVAS_JSON="$2"
OUTPUT_FILE="$3"

if [[ ! -f "$BLOCKS1_FILE" ]]; then
  echo "[!] File blocks1 non trovato: $BLOCKS1_FILE" >&2
  exit 1
fi

if [[ ! -f "$OPENVAS_JSON" ]]; then
  echo "[!] File JSON OpenVAS non trovato: $OPENVAS_JSON" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

python3 - "$BLOCKS1_FILE" "$OPENVAS_JSON" "$OUTPUT_FILE" <<'PY'
import json
import os
import sys
from collections import defaultdict

blocks1_file = sys.argv[1]
openvas_json = sys.argv[2]
output_file = sys.argv[3]

with open(blocks1_file, "r", encoding="utf-8") as f:
    blocks1_text = f.read().strip()

with open(openvas_json, "r", encoding="utf-8") as f:
    data = json.load(f)

meta = data.get("meta", {})
severity = data.get("severity_summary", {})
host_summary = data.get("host_summary", [])
top_findings = data.get("top_findings_global", [])
host_top_findings = data.get("host_top_findings", {})
errors = data.get("errors", [])

def sev_label(score):
    try:
        s = float(score)
    except Exception:
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "log"

def yesno(v):
    return "Yes" if v else "No"

def safe(v, default="N/A"):
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip() or default
    return v

def fmt_score(v):
    try:
        return f"{float(v):.1f}"
    except Exception:
        return "N/A"

def first_nonempty(*values, default="N/A"):
    for v in values:
        if isinstance(v, str):
            if v.strip():
                return v.strip()
        elif v:
            return v
    return default

def build_scan_status_section():
    lines = []
    lines.append("## 5. Vulnerability Assessment Execution Status")
    lines.append("")
    lines.append(f"- VA engine: Greenbone / OpenVAS")
    lines.append(f"- Task name: {safe(meta.get('task_name'))}")
    lines.append(f"- Target name: {safe(meta.get('target_name'))}")
    lines.append(f"- Report format used for parsing: {safe(meta.get('report_format_name'))}")
    lines.append(f"- Scan status: {safe(meta.get('scan_run_status'))}")
    lines.append(f"- Scan progress at export time: {safe(meta.get('progress'))}%")
    lines.append(f"- Scan start: {safe(meta.get('scan_start'))}")
    lines.append(f"- Scan end: {safe(meta.get('scan_end'))}")
    lines.append(f"- Report complete: {yesno(meta.get('report_is_complete', False))}")
    lines.append("")
    if meta.get("report_is_partial"):
        lines.append(
            "The available OpenVAS report appears to be an intermediate export rather than a fully finalized report. "
            "The XML already contains concrete findings, host-level results and severity information, but the scan "
            "did not reach a clean 'Done' state at export time. For this reason, the results below should be interpreted "
            "as technically meaningful but potentially incomplete."
        )
    else:
        lines.append(
            "The available OpenVAS report appears to be complete and finalized. "
            "The findings below can therefore be treated as the final output of the vulnerability assessment phase."
        )
    lines.append("")
    return "\n".join(lines)

def build_scope_section():
    lines = []
    lines.append("## 6. OpenVAS Quantitative Summary")
    lines.append("")
    lines.append(f"- Hosts identified in the report: {safe(meta.get('hosts_count'), 0)}")
    lines.append(f"- Vulnerability count: {safe(meta.get('vulns_count'), 0)}")
    lines.append(f"- Port count: {safe(meta.get('ports_count'), 0)}")
    lines.append(f"- Result count (full): {safe(meta.get('result_count_full'), 0)}")
    lines.append(f"- Result count (filtered): {safe(meta.get('result_count_filtered'), 0)}")
    lines.append(f"- Maximum severity observed (full): {fmt_score(meta.get('max_cvss_full', 0))}")
    lines.append(f"- Maximum severity observed (filtered): {fmt_score(meta.get('max_cvss_filtered', 0))}")
    lines.append("")
    lines.append("### Severity Breakdown")
    lines.append("")
    lines.append(f"- Critical: {severity.get('critical_filtered', 0)} filtered / {severity.get('critical_full', 0)} full")
    lines.append(f"- High: {severity.get('high_filtered', 0)} filtered / {severity.get('high_full', 0)} full")
    lines.append(f"- Medium: {severity.get('medium_filtered', 0)} filtered / {severity.get('medium_full', 0)} full")
    lines.append(f"- Low: {severity.get('low_filtered', 0)} filtered / {severity.get('low_full', 0)} full")
    lines.append(f"- Log: {severity.get('log_filtered', 0)} filtered / {severity.get('log_full', 0)} full")
    lines.append("")
    return "\n".join(lines)

def build_priority_findings_section():
    lines = []
    lines.append("## 7. Priority Findings")
    lines.append("")
    if not top_findings:
        lines.append("No findings were extracted from the parsed report.")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "The following findings represent the highest-priority evidence extracted from the OpenVAS XML report, "
        "ordered primarily by severity and then by Quality of Detection (QoD)."
    )
    lines.append("")

    for idx, f in enumerate(top_findings[:10], start=1):
        cves = ", ".join(f.get("cves", [])) if f.get("cves") else "No CVE explicitly listed"
        solution = first_nonempty(f.get("solution"), default="No explicit solution text extracted")
        lines.append(f"### 7.{idx} {f.get('name', 'Unnamed finding')}")
        lines.append("")
        lines.append(f"- Host: {safe(f.get('host'))}")
        lines.append(f"- Port / Service reference: {safe(f.get('port'))}")
        lines.append(f"- Severity: {safe(f.get('severity_label')).upper()} ({fmt_score(f.get('severity'))})")
        lines.append(f"- QoD: {fmt_score(f.get('qod'))}")
        lines.append(f"- Family: {safe(f.get('family'))}")
        lines.append(f"- CVE references: {cves}")
        lines.append(f"- Suggested remediation direction: {solution}")
        lines.append("")
    return "\n".join(lines)

def build_host_matrix_section():
    lines = []
    lines.append("## 8. Vulnerability Distribution by IP")
    lines.append("")
    if not host_summary:
        lines.append("No host-level vulnerability distribution could be extracted.")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "The section below reorganizes the OpenVAS findings by host, in order to identify which systems accumulate "
        "the largest number of issues and which severity tiers are concentrated on each IP."
    )
    lines.append("")

    for idx, host in enumerate(host_summary, start=1):
        host_ip = host.get("host", "N/A")
        hostname = host.get("hostname", "")
        host_label = f"{host_ip} ({hostname})" if hostname else host_ip

        lines.append(f"### 8.{idx} Host: {host_label}")
        lines.append("")
        lines.append(f"- Total findings: {host.get('findings_total', 0)}")
        lines.append(f"- Critical: {host.get('critical', 0)}")
        lines.append(f"- High: {host.get('high', 0)}")
        lines.append(f"- Medium: {host.get('medium', 0)}")
        lines.append(f"- Low: {host.get('low', 0)}")
        lines.append(f"- Log / Informational: {host.get('log', 0)}")
        lines.append(f"- Maximum severity observed: {fmt_score(host.get('max_severity', 0))}")

        ports = host.get("ports", [])
        if ports:
            lines.append(f"- Observed ports in findings: {', '.join(ports)}")
        else:
            lines.append("- Observed ports in findings: N/A")
        lines.append("")

        host_findings = host_top_findings.get(host_ip, [])
        if host_findings:
            lines.append("Top host-specific findings:")
            lines.append("")
            for item in host_findings[:8]:
                cves = ", ".join(item.get("cves", [])) if item.get("cves") else "No CVE explicitly listed"
                lines.append(
                    f"- {item.get('name', 'Unnamed finding')} | "
                    f"{safe(item.get('port'))} | "
                    f"{safe(item.get('severity_label')).upper()} ({fmt_score(item.get('severity'))}) | "
                    f"QoD {fmt_score(item.get('qod'))} | CVEs: {cves}"
                )
            lines.append("")
        else:
            lines.append("No detailed host findings available.")
            lines.append("")

    return "\n".join(lines)

def build_operational_readout():
    lines = []
    lines.append("## 9. Operational Interpretation")
    lines.append("")
    observations = []

    crit = severity.get("critical_filtered", 0)
    high = severity.get("high_filtered", 0)
    med = severity.get("medium_filtered", 0)

    if crit > 0:
        observations.append(
            "At least one critical-severity condition is already visible in the parsed dataset. "
            "This means the environment includes at least one exposure that should be treated as a near-term remediation priority."
        )

    if high > 0:
        observations.append(
            "High-severity findings are also present, suggesting that the attack surface is not limited to informational or hygiene-level issues, "
            "but includes weaknesses that may materially increase compromise likelihood if left unaddressed."
        )

    if med > 0:
        observations.append(
            "A broader layer of medium-severity findings is also visible. In operational terms, this often reflects configuration drift, "
            "legacy protocol support, weak cryptographic settings, expired certificates or service hardening gaps."
        )

    noisy_hosts = sorted(host_summary, key=lambda x: x.get("findings_total", 0), reverse=True)[:3]
    if noisy_hosts:
        host_list = ", ".join([f"{h.get('host')} ({h.get('findings_total', 0)} findings)" for h in noisy_hosts])
        observations.append(
            f"The most exposed hosts in the current dataset appear to be: {host_list}. "
            "These systems should be prioritized first for technical validation and remediation sequencing."
        )

    if errors:
        observations.append(
            "The scan also recorded plugin-level errors and/or timeouts. This does not invalidate the findings already collected, "
            "but it does mean that some plugin families may not have completed cleanly across all hosts."
        )

    if meta.get("report_is_partial"):
        observations.append(
            "Because the available report was exported while the task still appeared to be running at 99%, "
            "the present interpretation should be considered a strong preliminary assessment rather than a finalized VA baseline."
        )

    if not observations:
        observations.append(
            "The current OpenVAS dataset does not expose major high-impact patterns, but the result still contributes useful host-level visibility "
            "for technical validation and prioritization."
        )

    for obs in observations:
        lines.append(f"- {obs}")
    lines.append("")
    return "\n".join(lines)

def build_errors_section():
    lines = []
    lines.append("## 10. Scan Errors, Timeouts and Caveats")
    lines.append("")
    if not errors:
        lines.append(
            "No explicit scan errors were extracted from the XML error section. "
            "This does not guarantee the absence of minor plugin-side anomalies, but no structured error entries were parsed."
        )
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "The report contains explicit scan-side errors. These should be read as execution caveats rather than as direct evidence of vulnerability, "
        "but they matter because they may reduce coverage or confidence for specific checks."
    )
    lines.append("")

    for idx, e in enumerate(errors[:20], start=1):
        lines.append(f"- Error {idx}: host={safe(e.get('host'))} | port={safe(e.get('port'))} | detail={safe(e.get('description'))}")

    lines.append("")
    lines.append(
        "Where timeouts or plugin-level errors are present, a later validation pass may be appropriate, especially for the hosts or services "
        "associated with high-severity results."
    )
    lines.append("")
    return "\n".join(lines)

def build_methodological_section():
    lines = []
    lines.append("## 11. Methodological Notes")
    lines.append("")
    lines.append(
        "This VA phase should be interpreted as a non-intrusive remote vulnerability assessment. "
        "Its purpose is to identify known weaknesses, weak defaults, legacy configurations, outdated protocol exposure and other visible risk indicators, "
        "without performing exploitation, destructive testing or brute-force validation as a standard operating principle."
    )
    lines.append("")
    lines.append(
        "As with any automated scanner-based assessment, the findings may include false positives, incomplete detections or partially executed checks. "
        "For this reason, the OpenVAS output should be treated as structured technical evidence requiring validation, prioritization and contextual interpretation."
    )
    lines.append("")
    if meta.get("report_is_partial"):
        lines.append(
            "A further caveat applies here because the XML used for parsing appears to have been exported before the task reached a clean final 'Done' state. "
            "This does not prevent extraction of meaningful findings, but it does reduce certainty that the dataset is exhaustive."
        )
        lines.append("")
    return "\n".join(lines)

sections = [
    blocks1_text,
    "",
    build_scan_status_section(),
    build_scope_section(),
    build_priority_findings_section(),
    build_host_matrix_section(),
    build_operational_readout(),
    build_errors_section(),
    build_methodological_section(),
]

final_text = "\n".join(sections).strip() + "\n"

with open(output_file, "w", encoding="utf-8") as f:
    f.write(final_text)

print(f"[+] Final report draft written to: {output_file}")
PY
