#!/usr/bin/env bash
set -euo pipefail
print_banner() {
  local ORANGE="\033[38;5;208m"
  local BLUE="\033[38;5;39m"
  local WHITE="\033[1;37m"
  local RESET="\033[0m"

  echo -e "${WHITE}==================================================${RESET}"
  echo -e "${ORANGE}███████╗██████╗${RESET} ${BLUE}███████╗ ██████╗ ██╗  ██╗${RESET}"
  echo -e "${ORANGE}╚══███╔╝██╔══██╗${RESET} ${BLUE}██╔════╝██╔═══██╗╚██╗██╔╝${RESET}"
  echo -e "${ORANGE}  ███╔╝ ██████╔╝${RESET} ${BLUE}█████╗  ██║   ██║ ╚███╔╝ ${RESET}"
  echo -e "${ORANGE} ███╔╝  ██╔══██╗${RESET} ${BLUE}██╔══╝  ██║   ██║ ██╔██╗ ${RESET}"
  echo -e "${ORANGE}███████╗██████╔╝${RESET} ${BLUE}██║     ╚██████╔╝██╔╝ ██╗${RESET}"
  echo -e "${ORANGE}╚══════╝╚═════╝ ${RESET} ${BLUE}╚═╝      ╚═════╝ ╚═╝  ╚═╝${RESET}"
  echo
  echo -e "        ${ORANGE}ZB${BLUE}FOX${RESET} ${WHITE}Cyber Operations Kit${RESET}"
  echo -e "${WHITE}==================================================${RESET}"
}

# Uso:
#   ./parse_openvas_report.sh /path/to/openvas_report.xml /path/to/output_dir
#
# Esempio:
#   ./parse_openvas_report.sh \
#       engagements/CSA-001/assessment/openvas/raw/openvas_report.xml \
#       engagements/CSA-001/assessment/openvas/parsed

if [[ $# -lt 2 ]]; then
  echo "Uso: $0 <openvas_report.xml> <output_dir>" >&2
  exit 1
fi

INPUT_XML="$1"
OUTPUT_DIR="$2"

if [[ ! -f "$INPUT_XML" ]]; then
  echo "[!] File XML non trovato: $INPUT_XML" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

python3 - "$INPUT_XML" "$OUTPUT_DIR" <<'PY'
import os
import re
import sys
import json
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter

input_xml = sys.argv[1]
output_dir = sys.argv[2]

tree = ET.parse(input_xml)
root = tree.getroot()

# Nel report OpenVAS esportato, i dati utili sono nel nodo <report> figlio del root
report = root.find("report")
if report is None:
    raise SystemExit("[!] Nodo <report> non trovato nel file XML")

def txt(node, path=None, default=""):
    if node is None:
        return default
    if path is None:
        return (node.text or "").strip()
    child = node.find(path)
    if child is None or child.text is None:
        return default
    return child.text.strip()

def first_text(node, *paths, default=""):
    for p in paths:
        value = txt(node, p, default="")
        if value != "":
            return value
    return default

def to_float(value, default=0.0):
    try:
        return float(str(value).strip())
    except Exception:
        return default

def to_int(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default

def norm_severity_label(threat, severity):
    t = (threat or "").strip().lower()
    sev = to_float(severity, 0.0)

    if t:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "log": "log",
            "info": "info",
            "alarm": "alarm",
            "debug": "debug"
        }
        if t in mapping:
            return mapping[t]

    # fallback su score
    if sev >= 9.0:
        return "critical"
    elif sev >= 7.0:
        return "high"
    elif sev >= 4.0:
        return "medium"
    elif sev > 0.0:
        return "low"
    return "log"

def clean_multiline(s):
    s = (s or "").strip()
    s = re.sub(r'\r', '', s)
    s = re.sub(r'[ \t]+', ' ', s)
    s = re.sub(r'\n{3,}', '\n\n', s)
    return s

def parse_refs(nvt_node):
    refs = []
    refs_node = nvt_node.find("refs") if nvt_node is not None else None
    if refs_node is None:
        return refs

    for ref in refs_node.findall("ref"):
        refs.append({
            "type": ref.attrib.get("type", ""),
            "id": ref.attrib.get("id", "")
        })
    return refs

def parse_tags(tags_raw):
    data = {}
    if not tags_raw:
        return data

    for chunk in tags_raw.split("|"):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            data[k.strip()] = v.strip()
    return data

def extract_cves(refs):
    cves = []
    for r in refs:
        if r.get("type", "").upper() == "CVE" and r.get("id"):
            cves.append(r["id"])
    return sorted(set(cves))

def score_sort_key(item):
    return (
        to_float(item.get("severity", 0.0), 0.0),
        to_float(item.get("qod", 0.0), 0.0)
    )

# -------------------------
# METADATI REPORT
# -------------------------
report_meta = {
    "report_id": root.attrib.get("id", ""),
    "report_format_id": root.attrib.get("format_id", ""),
    "config_id": root.attrib.get("config_id", ""),
    "name": txt(root, "name"),
    "creation_time": txt(root, "creation_time"),
    "modification_time": txt(root, "modification_time"),
    "task_name": txt(root, "task/name"),
    "task_id": root.find("task").attrib.get("id", "") if root.find("task") is not None else "",
    "target_name": txt(report, "task/target/name"),
    "target_id": report.find("task/target").attrib.get("id", "") if report.find("task/target") is not None else "",
    "report_format_name": txt(root, "report_format/name"),
    "scan_run_status": txt(report, "scan_run_status"),
    "scan_start": txt(report, "scan_start"),
    "scan_end": txt(report, "scan_end"),
    "timestamp": txt(report, "timestamp"),
    "timezone": txt(report, "timezone"),
    "timezone_abbrev": txt(report, "timezone_abbrev"),
    "progress": to_int(txt(report, "task/progress", default="0"), 0),
    "hosts_count": to_int(txt(report, "hosts/count", default="0"), 0),
    "vulns_count": to_int(txt(report, "vulns/count", default="0"), 0),
    "ports_count": to_int(txt(report, "ports/count", default="0"), 0),
    "result_count_full": to_int(txt(report, "result_count/full", default="0"), 0),
    "result_count_filtered": to_int(txt(report, "result_count/filtered", default="0"), 0),
    "max_cvss_filtered": to_float(txt(report, "severity/filtered", default="0"), 0.0),
    "max_cvss_full": to_float(txt(report, "severity/full", default="0"), 0.0),
}

report_meta["report_is_complete"] = (report_meta["scan_run_status"].lower() == "done")
report_meta["report_is_partial"] = not report_meta["report_is_complete"]

severity_summary = {
    "critical_full": to_int(txt(report, "result_count/critical/full", default="0"), 0),
    "critical_filtered": to_int(txt(report, "result_count/critical/filtered", default="0"), 0),
    "high_full": to_int(txt(report, "result_count/high/full", default="0"), 0),
    "high_filtered": to_int(txt(report, "result_count/high/filtered", default="0"), 0),
    "medium_full": to_int(txt(report, "result_count/medium/full", default="0"), 0),
    "medium_filtered": to_int(txt(report, "result_count/medium/filtered", default="0"), 0),
    "low_full": to_int(txt(report, "result_count/low/full", default="0"), 0),
    "low_filtered": to_int(txt(report, "result_count/low/filtered", default="0"), 0),
    "log_full": to_int(txt(report, "result_count/log/full", default="0"), 0),
    "log_filtered": to_int(txt(report, "result_count/log/filtered", default="0"), 0),
}

# -------------------------
# RISULTATI DETTAGLIATI
# -------------------------
results_node = report.find("results")
findings = []

if results_node is not None:
    for r in results_node.findall("result"):
        nvt = r.find("nvt")
        host = txt(r, "host")
        port = txt(r, "port")
        name = txt(r, "name")
        threat = txt(r, "threat")
        severity = to_float(txt(r, "severity", default="0"), 0.0)
        qod = to_float(txt(r, "qod/value", default="0"), 0.0)

        tags_raw = txt(nvt, "tags") if nvt is not None else ""
        refs = parse_refs(nvt)
        cves = extract_cves(refs)
        tags = parse_tags(tags_raw)

        finding = {
            "result_id": r.attrib.get("id", ""),
            "host": host,
            "hostname": txt(r, "host/hostname"),
            "port": port,
            "name": name,
            "family": txt(nvt, "family") if nvt is not None else "",
            "vt_oid": nvt.attrib.get("oid", "") if nvt is not None else "",
            "severity": severity,
            "threat": threat,
            "severity_label": norm_severity_label(threat, severity),
            "qod": qod,
            "description": clean_multiline(txt(r, "description")),
            "solution": clean_multiline(txt(nvt, "solution")) if nvt is not None else "",
            "solution_type": nvt.find("solution").attrib.get("type", "") if (nvt is not None and nvt.find("solution") is not None) else "",
            "cvss_base": to_float(txt(nvt, "cvss_base", default="0"), 0.0) if nvt is not None else 0.0,
            "cvss_vector": tags.get("cvss_base_vector", ""),
            "summary_tag": tags.get("summary", ""),
            "impact_tag": tags.get("impact", ""),
            "insight_tag": tags.get("insight", ""),
            "solution_tag": tags.get("solution", ""),
            "refs": refs,
            "cves": cves,
            "raw_tags": tags_raw,
        }
        findings.append(finding)

# Ordino i findings per severity decrescente, poi QoD
findings_sorted = sorted(findings, key=score_sort_key, reverse=True)

# -------------------------
# VULNERABILITÀ PER IP
# -------------------------
by_host = defaultdict(list)
for f in findings_sorted:
    by_host[f["host"]].append(f)

host_summary = []
host_severity_matrix = {}
host_top_findings = {}

for host, items in sorted(by_host.items(), key=lambda kv: kv[0]):
    counter = Counter()
    ports = set()
    max_sev = 0.0

    for item in items:
        counter[item["severity_label"]] += 1
        if item["port"]:
            ports.add(item["port"])
        if item["severity"] > max_sev:
            max_sev = item["severity"]

    host_summary.append({
        "host": host,
        "hostname": next((x["hostname"] for x in items if x["hostname"]), ""),
        "findings_total": len(items),
        "critical": counter.get("critical", 0),
        "high": counter.get("high", 0),
        "medium": counter.get("medium", 0),
        "low": counter.get("low", 0),
        "log": counter.get("log", 0),
        "max_severity": max_sev,
        "ports": sorted(ports),
    })

    host_severity_matrix[host] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "log": [],
    }

    for item in items:
        host_severity_matrix[host][item["severity_label"]].append({
            "name": item["name"],
            "port": item["port"],
            "severity": item["severity"],
            "qod": item["qod"],
            "family": item["family"],
            "cves": item["cves"],
            "solution": item["solution"],
        })

    # Top findings per host: massimo 10, niente duplicati banali host+name+port
    seen = set()
    top = []
    for item in items:
        key = (item["name"], item["port"], item["severity"])
        if key in seen:
            continue
        seen.add(key)
        top.append({
            "name": item["name"],
            "port": item["port"],
            "severity": item["severity"],
            "severity_label": item["severity_label"],
            "qod": item["qod"],
            "family": item["family"],
            "cves": item["cves"],
            "solution": item["solution"],
        })
        if len(top) >= 10:
            break
    host_top_findings[host] = top

# -------------------------
# ERRORI DI SCANSIONE
# -------------------------
errors = []
errors_node = report.find("errors")
if errors_node is not None:
    for e in errors_node.findall("error"):
        errors.append({
            "host": txt(e, "host"),
            "port": txt(e, "port"),
            "nvt_oid": txt(e, "nvt/oid"),
            "description": clean_multiline(txt(e, "description")),
        })

# -------------------------
# TOP FINDINGS GLOBALI
# -------------------------
top_findings_global = []
seen_global = set()
for item in findings_sorted:
    key = (item["host"], item["name"], item["port"], item["severity"])
    if key in seen_global:
        continue
    seen_global.add(key)
    top_findings_global.append({
        "host": item["host"],
        "hostname": item["hostname"],
        "port": item["port"],
        "name": item["name"],
        "severity": item["severity"],
        "severity_label": item["severity_label"],
        "qod": item["qod"],
        "family": item["family"],
        "cves": item["cves"],
        "solution": item["solution"],
    })
    if len(top_findings_global) >= 20:
        break

# -------------------------
# PACCHETTO FINALE JSON
# -------------------------
parsed = {
    "meta": report_meta,
    "severity_summary": severity_summary,
    "host_summary": host_summary,
    "top_findings_global": top_findings_global,
    "host_top_findings": host_top_findings,
    "host_severity_matrix": host_severity_matrix,
    "errors": errors,
    "findings": findings_sorted,
}

json_path = os.path.join(output_dir, "openvas_parsed.json")
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(parsed, f, indent=2, ensure_ascii=False)

# -------------------------
# OUTPUT TESTUALE CONSULENZIALE
# -------------------------
txt_path = os.path.join(output_dir, "openvas_summary.txt")
with open(txt_path, "w", encoding="utf-8") as f:
    f.write("OPENVAS PARSED SUMMARY\n")
    f.write("======================\n\n")

    f.write("[META]\n")
    f.write(f"Task name: {report_meta['task_name']}\n")
    f.write(f"Target name: {report_meta['target_name']}\n")
    f.write(f"Report format: {report_meta['report_format_name']}\n")
    f.write(f"Scan status: {report_meta['scan_run_status']}\n")
    f.write(f"Progress: {report_meta['progress']}%\n")
    f.write(f"Scan start: {report_meta['scan_start']}\n")
    f.write(f"Scan end: {report_meta['scan_end']}\n")
    f.write(f"Hosts count: {report_meta['hosts_count']}\n")
    f.write(f"Vulns count: {report_meta['vulns_count']}\n")
    f.write(f"Ports count: {report_meta['ports_count']}\n")
    f.write(f"Result count (full): {report_meta['result_count_full']}\n")
    f.write(f"Result count (filtered): {report_meta['result_count_filtered']}\n")
    f.write(f"Report complete: {report_meta['report_is_complete']}\n")
    f.write("\n")

    f.write("[SEVERITY SUMMARY]\n")
    for k, v in severity_summary.items():
        f.write(f"{k}: {v}\n")
    f.write("\n")

    f.write("[HOST SUMMARY]\n")
    for h in host_summary:
        f.write(
            f"- {h['host']} | total={h['findings_total']} | "
            f"critical={h['critical']} high={h['high']} medium={h['medium']} "
            f"low={h['low']} log={h['log']} | max_severity={h['max_severity']}\n"
        )
    f.write("\n")

    f.write("[TOP FINDINGS GLOBAL]\n")
    for item in top_findings_global:
        f.write(
            f"- {item['host']} {item['port']} | {item['severity_label'].upper()} "
            f"({item['severity']}) | {item['name']}\n"
        )
    f.write("\n")

    f.write("[ERRORS]\n")
    if errors:
        for e in errors:
            f.write(f"- {e['host']} {e['port']} | {e['description']}\n")
    else:
        f.write("No scan errors found.\n")
    f.write("\n")

# -------------------------
# CSV 1: findings completi
# -------------------------
csv_findings = os.path.join(output_dir, "openvas_findings.csv")
with open(csv_findings, "w", encoding="utf-8") as f:
    headers = [
        "host","hostname","port","severity_label","severity","qod","family",
        "name","vt_oid","cves","solution"
    ]
    f.write(",".join(headers) + "\n")
    for item in findings_sorted:
        row = [
            item["host"],
            item["hostname"].replace(",", " "),
            item["port"],
            item["severity_label"],
            str(item["severity"]),
            str(item["qod"]),
            item["family"].replace(",", " "),
            item["name"].replace(",", " "),
            item["vt_oid"],
            ";".join(item["cves"]),
            item["solution"].replace(",", " ").replace("\n", " "),
        ]
        f.write(",".join(row) + "\n")

# -------------------------
# CSV 2: vulnerabilità per IP e livello
# -------------------------
csv_by_host = os.path.join(output_dir, "openvas_by_ip_and_severity.csv")
with open(csv_by_host, "w", encoding="utf-8") as f:
    headers = ["host", "severity_label", "count", "items"]
    f.write(",".join(headers) + "\n")

    for host in sorted(host_severity_matrix.keys()):
        sev_map = host_severity_matrix[host]
        for level in ["critical", "high", "medium", "low", "log"]:
            items = sev_map[level]
            names = [f"{x['name']} [{x['port']}]" for x in items]
            row = [
                host,
                level,
                str(len(items)),
                " | ".join(names).replace(",", " ")
            ]
            f.write(",".join(row) + "\n")

# -------------------------
# CSV 3: host summary
# -------------------------
csv_hosts = os.path.join(output_dir, "openvas_host_summary.csv")
with open(csv_hosts, "w", encoding="utf-8") as f:
    headers = ["host","hostname","findings_total","critical","high","medium","low","log","max_severity","ports"]
    f.write(",".join(headers) + "\n")
    for h in host_summary:
        row = [
            h["host"],
            h["hostname"].replace(",", " "),
            str(h["findings_total"]),
            str(h["critical"]),
            str(h["high"]),
            str(h["medium"]),
            str(h["low"]),
            str(h["log"]),
            str(h["max_severity"]),
            ";".join(h["ports"])
        ]
        f.write(",".join(row) + "\n")

print(f"[+] JSON: {json_path}")
print(f"[+] TXT:  {txt_path}")
print(f"[+] CSV:  {csv_findings}")
print(f"[+] CSV:  {csv_by_host}")
print(f"[+] CSV:  {csv_hosts}")
PY

