#!/usr/bin/env python3
"""
compare_assessment_delta.py

Confronta due assessment OpenVAS già parsati secondo lo schema reale:
- findings[]
- host_summary[]
- errors[]

Produce:
- delta_hosts.csv
- delta_findings.csv
- delta_summary.json
- manual_review_cases.csv
- delta_log.txt

Uso:
  python3 compare_assessment_delta.py \
    --old-engagement /path/to/ASSESSMENT_OLD \
    --new-engagement /path/to/ASSESSMENT_NEW \
    --old-openvas-json /path/to/old/openvas_parsed.json \
    --new-openvas-json /path/to/new/openvas_parsed.json \
    --output-dir /path/to/output \
    --client-id CLIENTE_X
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "log": 1,
    "info": 1,
    "unknown": 0,
    "": 0,
}


@dataclass
class Finding:
    host: str
    hostname: str
    port: str
    vt_oid: str
    name: str
    name_normalized: str
    family: str
    severity: Optional[float]
    severity_label: str
    cvss_base: Optional[float]
    cves: str
    solution: str


@dataclass
class Host:
    host: str
    hostname: str
    critical: int
    high: int
    medium: int
    low: int
    findings: List[Finding]


@dataclass
class ScanError:
    host: str
    port: str
    description: str


@dataclass
class ManualReviewCase:
    case_type: str
    old_host: str
    new_host: str
    old_hostname: str
    new_hostname: str
    old_port: str
    new_port: str
    old_vt_oid: str
    new_vt_oid: str
    old_name: str
    new_name: str
    reason: str
    recommended_manual_action: str


class DeltaLogger:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def log(self, msg: str) -> None:
        self.lines.append(msg)

    def dump(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


# -----------------------------
# Normalization helpers
# -----------------------------

def normalize_host(value: Any) -> str:
    return str(value or "").strip()


def normalize_hostname(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = s.rstrip(".")
    s = re.sub(r"\s+", " ", s)
    return s


def normalize_port(value: Any) -> str:
    s = str(value or "").strip()
    # lasciare intatti casi tipo 80/tcp se già presenti, altrimenti numero puro
    return s


def normalize_title(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^a-z0-9 ./:_\-]", "", s)
    return s


def normalize_cves(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [str(v).strip().upper() for v in value if str(v).strip()]
    else:
        raw = str(value).strip()
        parts = [p.strip().upper() for p in re.split(r"[,;| ]+", raw) if p.strip()]
    return "|".join(sorted(set(parts)))


def normalize_severity_label(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s in SEVERITY_ORDER:
        return s
    aliases = {
        "alarm": "medium",
        "warning": "medium",
        "error": "high",
        "none": "info",
    }
    return aliases.get(s, "unknown")


def to_float(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def severity_score_from_label(label: str) -> int:
    return SEVERITY_ORDER.get(label, 0)


# -----------------------------
# Loading real schema
# -----------------------------

def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_assessment_schema(payload: Dict[str, Any], logger: DeltaLogger) -> Tuple[List[Host], List[ScanError]]:
    host_summary = payload.get("host_summary", []) or []
    findings_raw = payload.get("findings", []) or []
    errors_raw = payload.get("errors", []) or []

    logger.log(f"host_summary entries: {len(host_summary)}")
    logger.log(f"findings entries: {len(findings_raw)}")
    logger.log(f"errors entries: {len(errors_raw)}")

    hosts_map: Dict[str, Host] = {}

    # Base from host_summary
    for item in host_summary:
        host = normalize_host(item.get("host"))
        hostname = normalize_hostname(item.get("hostname"))
        if not host and not hostname:
            continue
        key = host or hostname
        hosts_map[key] = Host(
            host=host,
            hostname=hostname,
            critical=int(item.get("critical") or 0),
            high=int(item.get("high") or 0),
            medium=int(item.get("medium") or 0),
            low=int(item.get("low") or 0),
            findings=[],
        )

    # Attach findings
    for raw in findings_raw:
        host = normalize_host(raw.get("host"))
        hostname = normalize_hostname(raw.get("hostname"))
        key = host or hostname
        if not key:
            continue
        if key not in hosts_map:
            hosts_map[key] = Host(
                host=host,
                hostname=hostname,
                critical=0,
                high=0,
                medium=0,
                low=0,
                findings=[],
            )
        finding = Finding(
            host=host,
            hostname=hostname,
            port=normalize_port(raw.get("port")),
            vt_oid=str(raw.get("vt_oid") or "").strip(),
            name=str(raw.get("name") or "").strip(),
            name_normalized=normalize_title(raw.get("name") or ""),
            family=str(raw.get("family") or "").strip(),
            severity=to_float(raw.get("severity")),
            severity_label=normalize_severity_label(raw.get("severity_label")),
            cvss_base=to_float(raw.get("cvss_base")),
            cves=normalize_cves(raw.get("cves")),
            solution=str(raw.get("solution") or "").strip(),
        )
        hosts_map[key].findings.append(finding)

    # Backfill counts from findings if needed
    for host in hosts_map.values():
        if host.critical == host.high == host.medium == host.low == 0 and host.findings:
            counts = Counter(f.severity_label for f in host.findings)
            host.critical = counts["critical"]
            host.high = counts["high"]
            host.medium = counts["medium"]
            host.low = counts["low"]

    errors: List[ScanError] = []
    for raw in errors_raw:
        errors.append(
            ScanError(
                host=normalize_host(raw.get("host")),
                port=normalize_port(raw.get("port")),
                description=str(raw.get("error") or raw.get("description") or "").strip(),
            )
        )

    return list(hosts_map.values()), errors


# -----------------------------
# Matching logic
# -----------------------------

def correlate_hosts(
    old_hosts: List[Host],
    new_hosts: List[Host],
    manual_cases: List[ManualReviewCase],
    logger: DeltaLogger,
) -> Tuple[List[Tuple[Host, Host, str, str]], List[Host], List[Host]]:
    matched: List[Tuple[Host, Host, str, str]] = []
    used_old = set()
    used_new = set()

    # Primary match: exact host/IP
    old_by_host = {h.host: h for h in old_hosts if h.host}
    new_by_host = {h.host: h for h in new_hosts if h.host}
    for host, old_h in old_by_host.items():
        if host in new_by_host:
            new_h = new_by_host[host]
            matched.append((old_h, new_h, "HOST", "HIGH"))
            used_old.add(old_h.host or old_h.hostname)
            used_new.add(new_h.host or new_h.hostname)

    # Fallback: hostname if exact and only when not already used
    old_by_hostname: Dict[str, List[Host]] = defaultdict(list)
    new_by_hostname: Dict[str, List[Host]] = defaultdict(list)
    for h in old_hosts:
        key = h.host or h.hostname
        if key not in used_old and h.hostname:
            old_by_hostname[h.hostname].append(h)
    for h in new_hosts:
        key = h.host or h.hostname
        if key not in used_new and h.hostname:
            new_by_hostname[h.hostname].append(h)

    for hostname, old_list in old_by_hostname.items():
        new_list = new_by_hostname.get(hostname, [])
        if len(old_list) == 1 and len(new_list) == 1:
            old_h = old_list[0]
            new_h = new_list[0]
            matched.append((old_h, new_h, "HOSTNAME", "MEDIUM"))
            used_old.add(old_h.host or old_h.hostname)
            used_new.add(new_h.host or new_h.hostname)
        elif old_list and new_list:
            for old_h in old_list:
                for new_h in new_list:
                    manual_cases.append(ManualReviewCase(
                        case_type="HOST_MATCH_PROBABLE",
                        old_host=old_h.host,
                        new_host=new_h.host,
                        old_hostname=old_h.hostname,
                        new_hostname=new_h.hostname,
                        old_port="",
                        new_port="",
                        old_vt_oid="",
                        new_vt_oid="",
                        old_name="",
                        new_name="",
                        reason="Hostname identico ma correlazione non univoca tra host vecchio e nuovo.",
                        recommended_manual_action="Verificare manualmente se gli host rappresentano lo stesso asset.",
                    ))

    old_unmatched = [h for h in old_hosts if (h.host or h.hostname) not in used_old]
    new_unmatched = [h for h in new_hosts if (h.host or h.hostname) not in used_new]

    logger.log(f"hosts_old_total={len(old_hosts)}")
    logger.log(f"hosts_new_total={len(new_hosts)}")
    logger.log(f"hosts_matched={len(matched)}")
    logger.log(f"hosts_old_unmatched={len(old_unmatched)}")
    logger.log(f"hosts_new_unmatched={len(new_unmatched)}")

    return matched, old_unmatched, new_unmatched


def finding_identity_keys(f: Finding) -> List[Tuple[str, str, str]]:
    keys: List[Tuple[str, str, str]] = []
    if f.vt_oid:
        keys.append((f.port, "VT_OID", f.vt_oid))
    if f.cves:
        keys.append((f.port, "CVES", f.cves))
    if f.name_normalized:
        keys.append((f.port, "NAME", f.name_normalized))
    return keys


def probable_finding_match(old_f: Finding, new_f: Finding) -> bool:
    if old_f.port != new_f.port:
        return False
    if old_f.family and new_f.family and old_f.family == new_f.family:
        return True
    old_words = set(old_f.name_normalized.split())
    new_words = set(new_f.name_normalized.split())
    return bool(old_words and new_words and len(old_words & new_words) >= max(2, min(len(old_words), len(new_words)) // 2))


def classify_partial_level(old_f: Finding, new_f: Finding) -> str:
    sev_gap = severity_score_from_label(old_f.severity_label) - severity_score_from_label(new_f.severity_label)
    cvss_gap = None
    if old_f.cvss_base is not None and new_f.cvss_base is not None:
        cvss_gap = old_f.cvss_base - new_f.cvss_base

    if sev_gap >= 3 or (cvss_gap is not None and cvss_gap >= 5):
        return "ALTO"
    if sev_gap >= 1 or (cvss_gap is not None and cvss_gap >= 2):
        return "MEDIO"
    return "BASSO"


def classify_delta(old_f: Finding, new_f: Finding) -> Tuple[str, str, str]:
    old_score = severity_score_from_label(old_f.severity_label)
    new_score = severity_score_from_label(new_f.severity_label)

    if new_score < old_score:
        level = classify_partial_level(old_f, new_f)
        return "PARZIALMENTE_RISOLTA", level, "Vulnerabilità presente in entrambi con severità ridotta."
    if new_score > old_score:
        return "PEGGIORATA", "N/A", "Vulnerabilità presente in entrambi con severità aumentata."

    if old_f.cvss_base is not None and new_f.cvss_base is not None:
        if new_f.cvss_base < old_f.cvss_base:
            level = classify_partial_level(old_f, new_f)
            return "PARZIALMENTE_RISOLTA", level, "Vulnerabilità presente in entrambi con CVSS ridotto."
        if new_f.cvss_base > old_f.cvss_base:
            return "PEGGIORATA", "N/A", "Vulnerabilità presente in entrambi con CVSS aumentato."

    return "PERSISTENTE", "N/A", "Vulnerabilità invariata tra i due assessment."


def build_error_index(errors: List[ScanError]) -> Dict[Tuple[str, str], List[str]]:
    idx: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for e in errors:
        idx[(e.host, e.port)].append(e.description)
    return idx


# -----------------------------
# Row builders
# -----------------------------

def build_finding_row(
    client_id: str,
    engagement_old: str,
    engagement_new: str,
    old_host: Host,
    new_host: Host,
    old_f: Optional[Finding],
    new_f: Optional[Finding],
    delta_status: str,
    remediation_level: str,
    matching_method: str,
    matching_confidence: str,
    risk_delta_note: str,
    old_scan_error_flag: str,
    new_scan_error_flag: str,
    review_flag: str,
) -> Dict[str, Any]:
    port = new_f.port if new_f else (old_f.port if old_f else "")
    return {
        "client_id": client_id,
        "engagement_old": engagement_old,
        "engagement_new": engagement_new,
        "old_host": old_host.host,
        "new_host": new_host.host,
        "old_hostname": old_host.hostname,
        "new_hostname": new_host.hostname,
        "port": port,
        "old_vt_oid": old_f.vt_oid if old_f else "",
        "new_vt_oid": new_f.vt_oid if new_f else "",
        "old_name": old_f.name if old_f else "",
        "new_name": new_f.name if new_f else "",
        "old_cves": old_f.cves if old_f else "",
        "new_cves": new_f.cves if new_f else "",
        "old_severity_label": old_f.severity_label if old_f else "",
        "new_severity_label": new_f.severity_label if new_f else "",
        "old_severity": old_f.severity if old_f and old_f.severity is not None else "",
        "new_severity": new_f.severity if new_f and new_f.severity is not None else "",
        "old_cvss_base": old_f.cvss_base if old_f and old_f.cvss_base is not None else "",
        "new_cvss_base": new_f.cvss_base if new_f and new_f.cvss_base is not None else "",
        "delta_status": delta_status,
        "remediation_level": remediation_level,
        "matching_method": matching_method,
        "matching_confidence": matching_confidence,
        "risk_delta_note": risk_delta_note,
        "old_scan_error_flag": old_scan_error_flag,
        "new_scan_error_flag": new_scan_error_flag,
        "review_flag": review_flag,
    }


def build_host_rows(
    client_id: str,
    engagement_old: str,
    engagement_new: str,
    matched_hosts: List[Tuple[Host, Host, str, str]],
    old_unmatched: List[Host],
    new_unmatched: List[Host],
    old_error_index: Dict[Tuple[str, str], List[str]],
    new_error_index: Dict[Tuple[str, str], List[str]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    def host_error_flag(host: Host, error_index: Dict[Tuple[str, str], List[str]]) -> str:
        return "YES" if any(h == host.host for (h, _p) in error_index.keys()) else "NO"

    def host_trend(old_h: Host, new_h: Host) -> str:
        old_score = old_h.critical * 5 + old_h.high * 4 + old_h.medium * 3 + old_h.low * 2
        new_score = new_h.critical * 5 + new_h.high * 4 + new_h.medium * 3 + new_h.low * 2
        if new_score < old_score:
            return "MIGLIORATO"
        if new_score > old_score:
            return "PEGGIORATO"
        return "INVARIATO"

    for old_h, new_h, method, confidence in matched_hosts:
        rows.append({
            "client_id": client_id,
            "engagement_old": engagement_old,
            "engagement_new": engagement_new,
            "host_status": "HOST_CONFERMATO",
            "old_host": old_h.host,
            "new_host": new_h.host,
            "old_hostname": old_h.hostname,
            "new_hostname": new_h.hostname,
            "matching_method": method,
            "matching_confidence": confidence,
            "old_findings_total": len(old_h.findings),
            "new_findings_total": len(new_h.findings),
            "old_critical": old_h.critical,
            "new_critical": new_h.critical,
            "old_high": old_h.high,
            "new_high": new_h.high,
            "old_medium": old_h.medium,
            "new_medium": new_h.medium,
            "old_low": old_h.low,
            "new_low": new_h.low,
            "host_risk_trend": host_trend(old_h, new_h),
            "error_presence_old": host_error_flag(old_h, old_error_index),
            "error_presence_new": host_error_flag(new_h, new_error_index),
            "notes": "Host correlato automaticamente.",
        })

    for old_h in old_unmatched:
        rows.append({
            "client_id": client_id,
            "engagement_old": engagement_old,
            "engagement_new": engagement_new,
            "host_status": "HOST_NON_PIU_RILEVATO",
            "old_host": old_h.host,
            "new_host": "",
            "old_hostname": old_h.hostname,
            "new_hostname": "",
            "matching_method": "NONE",
            "matching_confidence": "LOW",
            "old_findings_total": len(old_h.findings),
            "new_findings_total": 0,
            "old_critical": old_h.critical,
            "new_critical": 0,
            "old_high": old_h.high,
            "new_high": 0,
            "old_medium": old_h.medium,
            "new_medium": 0,
            "old_low": old_h.low,
            "new_low": 0,
            "host_risk_trend": "NON_VALUTABILE",
            "error_presence_old": host_error_flag(old_h, old_error_index),
            "error_presence_new": "NO",
            "notes": "Host presente nel vecchio assessment e assente nel nuovo. Non interpretare automaticamente come miglioramento.",
        })

    for new_h in new_unmatched:
        rows.append({
            "client_id": client_id,
            "engagement_old": engagement_old,
            "engagement_new": engagement_new,
            "host_status": "NUOVO_HOST",
            "old_host": "",
            "new_host": new_h.host,
            "old_hostname": "",
            "new_hostname": new_h.hostname,
            "matching_method": "NONE",
            "matching_confidence": "LOW",
            "old_findings_total": 0,
            "new_findings_total": len(new_h.findings),
            "old_critical": 0,
            "new_critical": new_h.critical,
            "old_high": 0,
            "new_high": new_h.high,
            "old_medium": 0,
            "new_medium": new_h.medium,
            "old_low": 0,
            "new_low": new_h.low,
            "host_risk_trend": "NUOVO_HOST",
            "error_presence_old": "NO",
            "error_presence_new": host_error_flag(new_h, new_error_index),
            "notes": "Host assente nel vecchio assessment e presente nel nuovo.",
        })

    return rows


# -----------------------------
# Finding comparison
# -----------------------------

def compare_findings_for_matched_host(
    client_id: str,
    engagement_old: str,
    engagement_new: str,
    old_host: Host,
    new_host: Host,
    old_error_index: Dict[Tuple[str, str], List[str]],
    new_error_index: Dict[Tuple[str, str], List[str]],
    manual_cases: List[ManualReviewCase],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    used_new_indices = set()

    new_index: Dict[Tuple[str, str, str], List[int]] = defaultdict(list)
    for idx, nf in enumerate(new_host.findings):
        for key in finding_identity_keys(nf):
            new_index[key].append(idx)

    for old_f in old_host.findings:
        matched_idx: Optional[int] = None
        matched_new: Optional[Finding] = None
        matched_method = "NONE"
        matched_confidence = "LOW"

        for key in finding_identity_keys(old_f):
            candidates = [i for i in new_index.get(key, []) if i not in used_new_indices]
            if len(candidates) == 1:
                matched_idx = candidates[0]
                matched_new = new_host.findings[matched_idx]
                matched_method = key[1]
                matched_confidence = "HIGH" if key[1] in {"VT_OID", "CVES"} else "MEDIUM"
                break
            elif len(candidates) > 1:
                for i in candidates:
                    nf = new_host.findings[i]
                    manual_cases.append(ManualReviewCase(
                        case_type="FINDING_MATCH_PROBABLE",
                        old_host=old_host.host,
                        new_host=new_host.host,
                        old_hostname=old_host.hostname,
                        new_hostname=new_host.hostname,
                        old_port=old_f.port,
                        new_port=nf.port,
                        old_vt_oid=old_f.vt_oid,
                        new_vt_oid=nf.vt_oid,
                        old_name=old_f.name,
                        new_name=nf.name,
                        reason="Più finding candidati corrispondono alla stessa identità logica.",
                        recommended_manual_action="Verificare manualmente quale finding del nuovo assessment corrisponde a quello precedente.",
                    ))
                rows.append(build_finding_row(
                    client_id, engagement_old, engagement_new,
                    old_host, new_host,
                    old_f, None,
                    "VERIFICA_MANUALE", "N/A", matched_method, "LOW",
                    "Corrispondenza ambigua: più candidati plausibili nel nuovo assessment.",
                    "YES" if (old_host.host, old_f.port) in old_error_index else "NO",
                    "YES" if (new_host.host, old_f.port) in new_error_index else "NO",
                    "YES",
                ))
                matched_idx = -1
                break

        if matched_idx == -1:
            continue

        if matched_new is None:
            probable_candidates = [nf for idx, nf in enumerate(new_host.findings) if idx not in used_new_indices and probable_finding_match(old_f, nf)]
            if probable_candidates:
                for nf in probable_candidates:
                    manual_cases.append(ManualReviewCase(
                        case_type="FINDING_MATCH_PROBABLE",
                        old_host=old_host.host,
                        new_host=new_host.host,
                        old_hostname=old_host.hostname,
                        new_hostname=new_host.hostname,
                        old_port=old_f.port,
                        new_port=nf.port,
                        old_vt_oid=old_f.vt_oid,
                        new_vt_oid=nf.vt_oid,
                        old_name=old_f.name,
                        new_name=nf.name,
                        reason="Stessa porta e segnali di similarità, ma identità non pienamente confermata.",
                        recommended_manual_action="Verificare manualmente se i finding rappresentano la stessa vulnerabilità.",
                    ))
                rows.append(build_finding_row(
                    client_id, engagement_old, engagement_new,
                    old_host, new_host,
                    old_f, None,
                    "VERIFICA_MANUALE", "N/A", "PROBABLE_MATCH", "LOW",
                    "Match probabile non classificato automaticamente.",
                    "YES" if (old_host.host, old_f.port) in old_error_index else "NO",
                    "YES" if (new_host.host, old_f.port) in new_error_index else "NO",
                    "YES",
                ))
                continue

            # If new side has scan errors on same host/port, do not declare resolved automatically.
            if (new_host.host, old_f.port) in new_error_index:
                rows.append(build_finding_row(
                    client_id, engagement_old, engagement_new,
                    old_host, new_host,
                    old_f, None,
                    "VERIFICA_MANUALE", "N/A", "NONE", "LOW",
                    "Finding assente nel nuovo report ma presenza di errori/timeout sullo stesso host/porta nel nuovo assessment.",
                    "YES" if (old_host.host, old_f.port) in old_error_index else "NO",
                    "YES",
                    "YES",
                ))
            else:
                rows.append(build_finding_row(
                    client_id, engagement_old, engagement_new,
                    old_host, new_host,
                    old_f, None,
                    "RISOLTA", "N/A", "NONE", "HIGH",
                    "Presente nel precedente assessment e assente nel nuovo.",
                    "YES" if (old_host.host, old_f.port) in old_error_index else "NO",
                    "NO",
                    "NO",
                ))
            continue

        used_new_indices.add(matched_idx)
        status, level, note = classify_delta(old_f, matched_new)
        rows.append(build_finding_row(
            client_id, engagement_old, engagement_new,
            old_host, new_host,
            old_f, matched_new,
            status, level, matched_method, matched_confidence, note,
            "YES" if (old_host.host, old_f.port) in old_error_index else "NO",
            "YES" if (new_host.host, matched_new.port) in new_error_index else "NO",
            "NO",
        ))

    for idx, new_f in enumerate(new_host.findings):
        if idx in used_new_indices:
            continue
        rows.append(build_finding_row(
            client_id, engagement_old, engagement_new,
            old_host, new_host,
            None, new_f,
            "NUOVA", "N/A", "NONE", "HIGH",
            "Assente nel precedente assessment e presente nel nuovo.",
            "NO",
            "YES" if (new_host.host, new_f.port) in new_error_index else "NO",
            "NO",
        ))

    return rows


# -----------------------------
# Summary and scoring
# -----------------------------

def weighted_score(findings: Iterable[Finding]) -> int:
    return sum(severity_score_from_label(f.severity_label) for f in findings)


def summarize(
    old_hosts: List[Host],
    new_hosts: List[Host],
    host_rows: List[Dict[str, Any]],
    finding_rows: List[Dict[str, Any]],
    manual_cases: List[ManualReviewCase],
) -> Dict[str, Any]:
    fs = Counter(r["delta_status"] for r in finding_rows)
    old_findings = [f for h in old_hosts for f in h.findings]
    new_findings = [f for h in new_hosts for f in h.findings]

    old_labels = Counter(f.severity_label for f in old_findings)
    new_labels = Counter(f.severity_label for f in new_findings)

    score_old = weighted_score(old_findings)
    score_new = weighted_score(new_findings)
    score_delta = score_new - score_old

    partial_low = sum(1 for r in finding_rows if r["delta_status"] == "PARZIALMENTE_RISOLTA" and r["remediation_level"] == "BASSO")
    partial_medium = sum(1 for r in finding_rows if r["delta_status"] == "PARZIALMENTE_RISOLTA" and r["remediation_level"] == "MEDIO")
    partial_high = sum(1 for r in finding_rows if r["delta_status"] == "PARZIALMENTE_RISOLTA" and r["remediation_level"] == "ALTO")

    critical_resolved = sum(1 for r in finding_rows if r["delta_status"] == "RISOLTA" and r["old_severity_label"] == "critical")
    critical_worsened = sum(1 for r in finding_rows if r["delta_status"] == "PEGGIORATA" and r["new_severity_label"] == "critical")
    high_resolved = sum(1 for r in finding_rows if r["delta_status"] == "RISOLTA" and r["old_severity_label"] == "high")
    high_worsened = sum(1 for r in finding_rows if r["delta_status"] == "PEGGIORATA" and r["new_severity_label"] == "high")

    new_hosts_risky = sum(1 for r in host_rows if r["host_status"] == "NUOVO_HOST" and (int(r["new_critical"]) > 0 or int(r["new_high"]) > 0))

    overall_trend = "STABILE"
    overall_comment = "Variazione complessiva contenuta tra i due assessment."

    if score_delta < 0 and new_labels["critical"] <= old_labels["critical"] and new_labels["high"] <= old_labels["high"] and fs["PEGGIORATA"] <= max(1, fs["RISOLTA"] // 3) and new_hosts_risky == 0:
        overall_trend = "MIGLIORATA"
        overall_comment = "Riduzione netta del rischio osservato, con diminuzione delle vulnerabilità severe e prevalenza di finding risolti o attenuati."
    elif score_delta > 0 and (new_labels["critical"] > old_labels["critical"] or new_labels["high"] > old_labels["high"] or fs["PEGGIORATA"] > fs["RISOLTA"] or new_hosts_risky > 0):
        overall_trend = "PEGGIORATA"
        overall_comment = "Aumento del rischio osservato, con crescita del carico severo, peggioramenti o nuovi host problematici."
    elif (fs["RISOLTA"] > 0 or fs["PARZIALMENTE_RISOLTA"] > 0) and (fs["NUOVA"] > 0 or fs["PEGGIORATA"] > 0):
        overall_trend = "MISTA"
        overall_comment = "Il quadro presenta miglioramenti su parte delle vulnerabilità ma anche nuove esposizioni o peggioramenti su altri elementi."

    return {
        "host_stats": {
            "confirmed": sum(1 for r in host_rows if r["host_status"] == "HOST_CONFERMATO"),
            "new": sum(1 for r in host_rows if r["host_status"] == "NUOVO_HOST"),
            "not_seen_anymore": sum(1 for r in host_rows if r["host_status"] == "HOST_NON_PIU_RILEVATO"),
        },
        "finding_stats": {
            "resolved": fs["RISOLTA"],
            "partial_low": partial_low,
            "partial_medium": partial_medium,
            "partial_high": partial_high,
            "persistent": fs["PERSISTENTE"],
            "worsened": fs["PEGGIORATA"],
            "new": fs["NUOVA"],
            "manual_review": fs["VERIFICA_MANUALE"],
        },
        "severity_stats": {
            "critical_old_total": old_labels["critical"],
            "critical_new_total": new_labels["critical"],
            "critical_resolved": critical_resolved,
            "critical_worsened": critical_worsened,
            "high_old_total": old_labels["high"],
            "high_new_total": new_labels["high"],
            "high_resolved": high_resolved,
            "high_worsened": high_worsened,
            "medium_old_total": old_labels["medium"],
            "medium_new_total": new_labels["medium"],
            "low_old_total": old_labels["low"],
            "low_new_total": new_labels["low"],
        },
        "risk_scoring": {
            "score_old": score_old,
            "score_new": score_new,
            "score_delta": score_delta,
        },
        "overall_trend": overall_trend,
        "overall_comment": overall_comment,
        "manual_review_total": len(manual_cases),
    }


# -----------------------------
# Writers
# -----------------------------

def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_manual_csv(path: Path, cases: List[ManualReviewCase]) -> None:
    rows = [asdict(c) for c in cases]
    write_csv(path, rows)


def save_meta(path: Path, hosts: List[Host]) -> None:
    snapshot = []
    for h in hosts:
        snapshot.append({
            "host": h.host,
            "hostname": h.hostname,
            "critical": h.critical,
            "high": h.high,
            "medium": h.medium,
            "low": h.low,
            "findings_total": len(h.findings),
        })
    path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")


# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare two parsed OpenVAS assessments and generate delta analysis.")
    p.add_argument("--old-engagement", required=True)
    p.add_argument("--new-engagement", required=True)
    p.add_argument("--old-openvas-json", required=True)
    p.add_argument("--new-openvas-json", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--client-id", default="UNKNOWN_CLIENT")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logger = DeltaLogger()

    old_json_path = Path(args.old_openvas_json)
    new_json_path = Path(args.new_openvas_json)
    output_dir = Path(args.output_dir)
    meta_dir = output_dir / "meta"
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    if not old_json_path.exists():
        raise FileNotFoundError(f"Missing old OpenVAS JSON: {old_json_path}")
    if not new_json_path.exists():
        raise FileNotFoundError(f"Missing new OpenVAS JSON: {new_json_path}")

    logger.log(f"client_id={args.client_id}")
    logger.log(f"old_engagement={args.old_engagement}")
    logger.log(f"new_engagement={args.new_engagement}")
    logger.log(f"old_json={old_json_path}")
    logger.log(f"new_json={new_json_path}")

    old_payload = load_json(old_json_path)
    new_payload = load_json(new_json_path)

    old_hosts, old_errors = load_assessment_schema(old_payload, logger)
    new_hosts, new_errors = load_assessment_schema(new_payload, logger)

    if not old_hosts and not new_hosts:
        raise RuntimeError("Neither assessment contains parsable hosts/findings.")

    old_error_index = build_error_index(old_errors)
    new_error_index = build_error_index(new_errors)

    save_meta(meta_dir / "old_snapshot.json", old_hosts)
    save_meta(meta_dir / "new_snapshot.json", new_hosts)

    manual_cases: List[ManualReviewCase] = []
    matched_hosts, old_unmatched, new_unmatched = correlate_hosts(old_hosts, new_hosts, manual_cases, logger)

    host_rows = build_host_rows(
        args.client_id,
        args.old_engagement,
        args.new_engagement,
        matched_hosts,
        old_unmatched,
        new_unmatched,
        old_error_index,
        new_error_index,
    )

    finding_rows: List[Dict[str, Any]] = []
    for old_h, new_h, _method, _confidence in matched_hosts:
        finding_rows.extend(compare_findings_for_matched_host(
            args.client_id,
            args.old_engagement,
            args.new_engagement,
            old_h,
            new_h,
            old_error_index,
            new_error_index,
            manual_cases,
        ))

    summary = summarize(old_hosts, new_hosts, host_rows, finding_rows, manual_cases)
    matching_stats = {
        "old_hosts": len(old_hosts),
        "new_hosts": len(new_hosts),
        "matched_hosts": len(matched_hosts),
        "old_unmatched": len(old_unmatched),
        "new_unmatched": len(new_unmatched),
        "manual_review_cases": len(manual_cases),
    }
    (meta_dir / "matching_stats.json").write_text(json.dumps(matching_stats, indent=2, ensure_ascii=False), encoding="utf-8")

    write_csv(output_dir / "delta_hosts.csv", host_rows)
    write_csv(output_dir / "delta_findings.csv", finding_rows)
    write_manual_csv(output_dir / "manual_review_cases.csv", manual_cases)
    (output_dir / "delta_summary.json").write_text(
        json.dumps(
            {
                "client_id": args.client_id,
                "engagement_old": args.old_engagement,
                "engagement_new": args.new_engagement,
                **summary,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    logger.dump(output_dir / "delta_log.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
