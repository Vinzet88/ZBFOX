#!/usr/bin/env python3
"""
ZBFOX — Cyber Protection Continuity
compare_snapshot_delta.py

Confronta due engagement Snapshot (external o internal) e produce:
- delta_hosts.csv
- delta_services.csv
- delta_summary.json
- manual_review_cases.csv
- delta_log.txt
- delta_web.csv (solo external)
- delta_high_value_services.csv (solo internal, se disponibile)

Supporta dati reali da:
External:
- dnsx.txt / live_hosts.txt
- nmap.txt (-oN)
- httpx.txt

Internal:
- arp_scan.txt
- nmap_internal.txt (-oN)
- opzionale nmap_discovery.txt

Uso esempio:
  python3 compare_snapshot_delta.py \
    --old-engagement /opt/zbfox/engagements/ZBF-SNAP-EXT-20260324-CLIENTE \
    --new-engagement /opt/zbfox/engagements/ZBF-SNAP-EXT-20260415-CLIENTE \
    --client-id CLIENTE_X \
    --mode external \
    --old-httpx /path/old/httpx.txt \
    --new-httpx /path/new/httpx.txt \
    --old-nmap /path/old/nmap.txt \
    --new-nmap /path/new/nmap.txt \
    --old-dnsx /path/old/dnsx.txt \
    --new-dnsx /path/new/dnsx.txt \
    --output-dir /path/to/output
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

class DeltaLogger:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def log(self, msg: str) -> None:
        self.lines.append(msg)

    def dump(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------
# Data models
# ------------------------------------------------------------

@dataclass
class HostRecord:
    host_key: str
    ip: str
    hostname: str
    fqdn: str
    mac: str
    vendor: str
    source_mode: str


@dataclass
class ServiceRecord:
    host_key: str
    ip: str
    mac: str
    port: str
    protocol: str
    service: str
    product: str
    version: str
    banner_raw: str


@dataclass
class WebRecord:
    host_key: str
    url: str
    scheme: str
    port: str
    status_code: str
    title: str
    webserver: str
    tech: str
    cdn: str
    ip: str


@dataclass
class HighValueRecord:
    host_key: str
    ip: str
    mac: str
    port: str
    protocol: str
    service: str
    is_high_value: str


@dataclass
class ManualReviewCase:
    case_type: str
    old_host: str
    new_host: str
    old_ip: str
    new_ip: str
    old_mac: str
    new_mac: str
    old_port: str
    new_port: str
    old_value: str
    new_value: str
    reason: str
    recommended_manual_action: str


# ------------------------------------------------------------
# Normalization helpers
# ------------------------------------------------------------

def norm_str(value: Any) -> str:
    return str(value or "").strip()


def norm_lower(value: Any) -> str:
    return norm_str(value).lower()


def norm_hostname(value: Any) -> str:
    s = norm_lower(value)
    s = s.rstrip(".")
    s = re.sub(r"\s+", " ", s)
    return s


def norm_mac(value: Any) -> str:
    s = norm_lower(value)
    if not s:
        return ""
    s = re.sub(r"[^0-9a-f]", "", s)
    if len(s) != 12:
        return ""
    return ":".join(s[i:i+2] for i in range(0, 12, 2))


def norm_url_host(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/:]+)", url.strip(), re.I)
    return norm_hostname(m.group(1)) if m else ""


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


# ------------------------------------------------------------
# Parsing helpers: dnsx, httpx, arp-scan, nmap
# ------------------------------------------------------------

def parse_dnsx(path: Optional[Path], logger: DeltaLogger) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not path or not path.exists():
        logger.log("dnsx/live_hosts file missing: continuing without host->ip support")
        return mapping
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    logger.log(f"Parsing dnsx/live_hosts: {path} ({len(lines)} lines)")
    for line in lines:
        # expected: host [A] [1.2.3.4]
        m = re.match(r"^(\S+)\s+\[A\]\s+\[([^\]]+)\]", line.strip())
        if m:
            mapping[norm_hostname(m.group(1))] = norm_str(m.group(2))
            continue
        # fallback: host ip
        parts = line.strip().split()
        if len(parts) >= 2:
            host = norm_hostname(parts[0])
            ip = norm_str(parts[-1].strip("[]"))
            if host and ip:
                mapping[host] = ip
    return mapping


def split_httpx_segments(line: str) -> List[str]:
    # Segments like [200], [Apache], [Title], [WordPress,PHP]
    return re.findall(r"\[([^\]]*)\]", line)


def parse_httpx(path: Path, dnsx_map: Dict[str, str], logger: DeltaLogger) -> Tuple[List[WebRecord], List[HostRecord]]:
    records: List[WebRecord] = []
    hosts: Dict[str, HostRecord] = {}
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    logger.log(f"Parsing httpx: {path} ({len(lines)} lines)")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        url_match = re.match(r"^(https?://\S+)", line, re.I)
        if not url_match:
            continue
        url = url_match.group(1)
        host = norm_url_host(url)
        ip = dnsx_map.get(host, "")
        port = "443" if url.lower().startswith("https://") else "80"
        url_port_match = re.match(r"^https?://[^/:]+:(\d+)", url, re.I)
        if url_port_match:
            port = url_port_match.group(1)
        segs = split_httpx_segments(line)
        status = segs[0].strip() if len(segs) >= 1 else ""
        title = segs[1].strip() if len(segs) >= 2 else ""
        server = segs[2].strip() if len(segs) >= 3 else ""
        tech = segs[3].strip() if len(segs) >= 4 else ""
        cdn = "yes" if "cloudfront" in line.lower() or "akamai" in line.lower() or "cloudflare" in line.lower() else "no"
        scheme = "https" if url.lower().startswith("https://") else "http"
        host_key = host or ip or url
        records.append(WebRecord(
            host_key=host_key,
            url=url,
            scheme=scheme,
            port=port,
            status_code=status,
            title=title,
            webserver=server,
            tech=tech,
            cdn=cdn,
            ip=ip,
        ))
        if host_key not in hosts:
            hosts[host_key] = HostRecord(
                host_key=host_key,
                ip=ip,
                hostname=host,
                fqdn=host,
                mac="",
                vendor="",
                source_mode="external",
            )
    return records, list(hosts.values())


def parse_arp_scan(path: Path, logger: DeltaLogger) -> List[HostRecord]:
    hosts: List[HostRecord] = []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    logger.log(f"Parsing arp_scan: {path} ({len(lines)} lines)")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Interface:") or line.startswith("Starting arp-scan") or line.startswith("Ending arp-scan") or line.startswith("Packets sent"):
            continue
        parts = re.split(r"\t+", line)
        if len(parts) < 2:
            parts = re.split(r"\s{2,}", line)
        if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0].strip()):
            ip = norm_str(parts[0])
            mac = norm_mac(parts[1])
            vendor = norm_str(parts[2]) if len(parts) >= 3 else ""
            host_key = mac or ip
            hosts.append(HostRecord(
                host_key=host_key,
                ip=ip,
                hostname="",
                fqdn="",
                mac=mac,
                vendor=vendor,
                source_mode="internal",
            ))
    return hosts


def parse_nmap_oneline(path: Path, mode: str, logger: DeltaLogger) -> Tuple[List[HostRecord], List[ServiceRecord], Dict[str, Set[str]]]:
    hosts: Dict[str, HostRecord] = {}
    services: List[ServiceRecord] = []
    open_ports_by_host: Dict[str, Set[str]] = defaultdict(set)

    current_ip = ""
    current_hostname = ""
    current_mac = ""

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    logger.log(f"Parsing nmap -oN: {path} ({len(lines)} lines)")

    host_header_re = re.compile(r"^Nmap scan report for (.+)$")
    port_row_re = re.compile(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)\s*(.*)$", re.I)
    mac_re = re.compile(r"^MAC Address:\s+([0-9A-Fa-f:.-]{11,17})\s*(?:\((.*)\))?$")

    def finalize_host() -> None:
        nonlocal current_ip, current_hostname, current_mac
        if not current_ip and not current_hostname and not current_mac:
            return
        host_key = current_mac or current_hostname or current_ip
        if host_key not in hosts:
            hosts[host_key] = HostRecord(
                host_key=host_key,
                ip=current_ip,
                hostname=current_hostname,
                fqdn=current_hostname,
                mac=current_mac,
                vendor="",
                source_mode=mode,
            )

    for raw_line in lines:
        line = raw_line.rstrip()
        m = host_header_re.match(line)
        if m:
            finalize_host()
            current_ip = ""
            current_hostname = ""
            current_mac = ""
            subject = m.group(1).strip()
            # Examples:
            # host.example.com (1.2.3.4)
            # 192.168.1.10
            m2 = re.match(r"^(.*?)\s+\((\d+\.\d+\.\d+\.\d+)\)$", subject)
            if m2:
                current_hostname = norm_hostname(m2.group(1))
                current_ip = norm_str(m2.group(2))
            else:
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", subject):
                    current_ip = norm_str(subject)
                else:
                    current_hostname = norm_hostname(subject)
            continue

        m = mac_re.match(line)
        if m:
            current_mac = norm_mac(m.group(1))
            continue

        m = port_row_re.match(line.strip())
        if m:
            port, proto, state, service, extra = m.groups()
            if state.lower() != "open":
                continue
            host_key = current_mac or current_hostname or current_ip
            if not host_key:
                continue
            if host_key not in hosts:
                hosts[host_key] = HostRecord(
                    host_key=host_key,
                    ip=current_ip,
                    hostname=current_hostname,
                    fqdn=current_hostname,
                    mac=current_mac,
                    vendor="",
                    source_mode=mode,
                )
            banner_raw = extra.strip()
            product = ""
            version = ""
            if banner_raw:
                # heuristic split: first token product, rest version/details
                parts = banner_raw.split()
                product = parts[0]
                version = " ".join(parts[1:]) if len(parts) > 1 else ""
            services.append(ServiceRecord(
                host_key=host_key,
                ip=current_ip,
                mac=current_mac,
                port=port,
                protocol=proto.lower(),
                service=service.strip().lower(),
                product=product,
                version=version,
                banner_raw=banner_raw,
            ))
            open_ports_by_host[host_key].add(f"{port}/{proto.lower()}")

    finalize_host()
    return list(hosts.values()), services, open_ports_by_host


# ------------------------------------------------------------
# Optional CSV loaders
# ------------------------------------------------------------

def parse_internal_services_csv(path: Optional[Path], logger: DeltaLogger) -> List[ServiceRecord]:
    if not path or not path.exists():
        return []
    rows: List[ServiceRecord] = []
    logger.log(f"Parsing internal_services.csv: {path}")
    with path.open("r", newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ip = norm_str(r.get("ip") or r.get("host") or r.get("target"))
            mac = norm_mac(r.get("mac"))
            host_key = mac or ip
            rows.append(ServiceRecord(
                host_key=host_key,
                ip=ip,
                mac=mac,
                port=norm_str(r.get("port")),
                protocol=norm_lower(r.get("protocol") or r.get("proto")),
                service=norm_lower(r.get("service")),
                product=norm_str(r.get("product")),
                version=norm_str(r.get("version")),
                banner_raw=norm_str(r.get("banner") or r.get("raw")),
            ))
    return rows


def parse_high_value_csv(path: Optional[Path], logger: DeltaLogger) -> List[HighValueRecord]:
    if not path or not path.exists():
        return []
    rows: List[HighValueRecord] = []
    logger.log(f"Parsing internal_high_value_services.csv: {path}")
    with path.open("r", newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ip = norm_str(r.get("ip") or r.get("host") or r.get("target"))
            mac = norm_mac(r.get("mac"))
            host_key = mac or ip
            rows.append(HighValueRecord(
                host_key=host_key,
                ip=ip,
                mac=mac,
                port=norm_str(r.get("port")),
                protocol=norm_lower(r.get("protocol") or r.get("proto")),
                service=norm_lower(r.get("service")),
                is_high_value="yes",
            ))
    return rows


# ------------------------------------------------------------
# Correlation helpers
# ------------------------------------------------------------

def correlate_hosts_internal(old_hosts: List[HostRecord], new_hosts: List[HostRecord], manual: List[ManualReviewCase], logger: DeltaLogger) -> Tuple[List[Tuple[HostRecord, HostRecord, str, str]], List[HostRecord], List[HostRecord]]:
    matched: List[Tuple[HostRecord, HostRecord, str, str]] = []
    old_used: Set[str] = set()
    new_used: Set[str] = set()

    old_by_mac = {h.mac: h for h in old_hosts if h.mac}
    new_by_mac = {h.mac: h for h in new_hosts if h.mac}
    for mac, old_h in old_by_mac.items():
        if mac in new_by_mac:
            new_h = new_by_mac[mac]
            matched.append((old_h, new_h, "MAC", "HIGH"))
            old_used.add(old_h.host_key)
            new_used.add(new_h.host_key)

    old_by_ip = {h.ip: h for h in old_hosts if h.host_key not in old_used and h.ip}
    new_by_ip = {h.ip: h for h in new_hosts if h.host_key not in new_used and h.ip}
    for ip, old_h in old_by_ip.items():
        if ip in new_by_ip:
            new_h = new_by_ip[ip]
            matched.append((old_h, new_h, "IP", "MEDIUM"))
            old_used.add(old_h.host_key)
            new_used.add(new_h.host_key)

    old_unmatched = [h for h in old_hosts if h.host_key not in old_used]
    new_unmatched = [h for h in new_hosts if h.host_key not in new_used]

    logger.log(f"Internal host matching: matched={len(matched)} old_unmatched={len(old_unmatched)} new_unmatched={len(new_unmatched)}")
    return matched, old_unmatched, new_unmatched


def correlate_hosts_external(old_hosts: List[HostRecord], new_hosts: List[HostRecord], manual: List[ManualReviewCase], logger: DeltaLogger) -> Tuple[List[Tuple[HostRecord, HostRecord, str, str]], List[HostRecord], List[HostRecord]]:
    matched: List[Tuple[HostRecord, HostRecord, str, str]] = []
    old_used: Set[str] = set()
    new_used: Set[str] = set()

    old_by_name = {h.hostname or h.fqdn: h for h in old_hosts if (h.hostname or h.fqdn)}
    new_by_name = {h.hostname or h.fqdn: h for h in new_hosts if (h.hostname or h.fqdn)}
    for name, old_h in old_by_name.items():
        if name in new_by_name:
            new_h = new_by_name[name]
            matched.append((old_h, new_h, "HOSTNAME", "HIGH"))
            old_used.add(old_h.host_key)
            new_used.add(new_h.host_key)

    old_by_ip = {h.ip: h for h in old_hosts if h.host_key not in old_used and h.ip}
    new_by_ip = {h.ip: h for h in new_hosts if h.host_key not in new_used and h.ip}
    for ip, old_h in old_by_ip.items():
        if ip in new_by_ip:
            new_h = new_by_ip[ip]
            matched.append((old_h, new_h, "IP", "MEDIUM"))
            old_used.add(old_h.host_key)
            new_used.add(new_h.host_key)

    old_unmatched = [h for h in old_hosts if h.host_key not in old_used]
    new_unmatched = [h for h in new_hosts if h.host_key not in new_used]

    logger.log(f"External host matching: matched={len(matched)} old_unmatched={len(old_unmatched)} new_unmatched={len(new_unmatched)}")
    return matched, old_unmatched, new_unmatched


# ------------------------------------------------------------
# Delta builders
# ------------------------------------------------------------

def service_key(s: ServiceRecord) -> Tuple[str, str, str]:
    return (s.port, s.protocol, s.service)


def web_key(w: WebRecord) -> Tuple[str, str, str]:
    return (w.url.lower(), w.port, w.scheme)


def high_value_key(h: HighValueRecord) -> Tuple[str, str, str]:
    return (h.port, h.protocol, h.service)


def classify_service_delta(old: ServiceRecord, new: ServiceRecord) -> Tuple[str, str]:
    changed = []
    if (old.product or "") != (new.product or ""):
        changed.append("product")
    if (old.version or "") != (new.version or ""):
        changed.append("version")
    if (old.banner_raw or "") != (new.banner_raw or ""):
        changed.append("banner")
    if changed:
        risk_hint = "Variazione di banner/prodotto/versione sullo stesso servizio"
        return "SERVIZIO_MODIFICATO", risk_hint
    return "SERVIZIO_INVARIATO", "Servizio invariato tra i due snapshot"


def classify_web_delta(old: WebRecord, new: WebRecord) -> str:
    if any([
        old.status_code != new.status_code,
        old.title != new.title,
        old.webserver != new.webserver,
        old.tech != new.tech,
        old.cdn != new.cdn,
        old.ip != new.ip,
    ]):
        return "ENDPOINT_WEB_MODIFICATO"
    return "ENDPOINT_WEB_INVARIATO"


def classify_high_value_delta(old: HighValueRecord, new: HighValueRecord) -> str:
    if old.service != new.service:
        return "HIGH_VALUE_MODIFICATO"
    return "HIGH_VALUE_INVARIATO"


def build_host_rows(client_id: str, engagement_old: str, engagement_new: str, mode: str,
                    matched: List[Tuple[HostRecord, HostRecord, str, str]],
                    old_unmatched: List[HostRecord], new_unmatched: List[HostRecord],
                    old_host_ports: Dict[str, Set[str]], new_host_ports: Dict[str, Set[str]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for old_h, new_h, method, confidence in matched:
        old_count = len(old_host_ports.get(old_h.host_key, set()))
        new_count = len(new_host_ports.get(new_h.host_key, set()))
        trend = "INVARIATA"
        if new_count > old_count:
            trend = "AUMENTATA"
        elif new_count < old_count:
            trend = "RIDOTTA"
        rows.append({
            "client_id": client_id,
            "engagement_old": engagement_old,
            "engagement_new": engagement_new,
            "mode": mode,
            "host_status": "HOST_CONFERMATO",
            "matching_method": method,
            "matching_confidence": confidence,
            "old_host_key": old_h.host_key,
            "new_host_key": new_h.host_key,
            "old_ip": old_h.ip,
            "new_ip": new_h.ip,
            "old_hostname": old_h.hostname or old_h.fqdn,
            "new_hostname": new_h.hostname or new_h.fqdn,
            "old_mac": old_h.mac,
            "new_mac": new_h.mac,
            "old_open_services": old_count,
            "new_open_services": new_count,
            "host_surface_trend": trend,
            "notes": "Host correlato automaticamente",
        })

    for h in old_unmatched:
        rows.append({
            "client_id": client_id,
            "engagement_old": engagement_old,
            "engagement_new": engagement_new,
            "mode": mode,
            "host_status": "HOST_NON_PIU_RILEVATO",
            "matching_method": "NONE",
            "matching_confidence": "LOW",
            "old_host_key": h.host_key,
            "new_host_key": "",
            "old_ip": h.ip,
            "new_ip": "",
            "old_hostname": h.hostname or h.fqdn,
            "new_hostname": "",
            "old_mac": h.mac,
            "new_mac": "",
            "old_open_services": len(old_host_ports.get(h.host_key, set())),
            "new_open_services": 0,
            "host_surface_trend": "NON_VALUTABILE",
            "notes": "Host presente nel vecchio snapshot e assente nel nuovo",
        })

    for h in new_unmatched:
        rows.append({
            "client_id": client_id,
            "engagement_old": engagement_old,
            "engagement_new": engagement_new,
            "mode": mode,
            "host_status": "NUOVO_HOST",
            "matching_method": "NONE",
            "matching_confidence": "LOW",
            "old_host_key": "",
            "new_host_key": h.host_key,
            "old_ip": "",
            "new_ip": h.ip,
            "old_hostname": "",
            "new_hostname": h.hostname or h.fqdn,
            "old_mac": "",
            "new_mac": h.mac,
            "old_open_services": 0,
            "new_open_services": len(new_host_ports.get(h.host_key, set())),
            "host_surface_trend": "AUMENTATA",
            "notes": "Host assente nel vecchio snapshot e presente nel nuovo",
        })

    return rows


def build_service_rows(client_id: str, engagement_old: str, engagement_new: str, mode: str,
                       matched_hosts: List[Tuple[HostRecord, HostRecord, str, str]],
                       old_services: List[ServiceRecord], new_services: List[ServiceRecord]) -> List[Dict[str, Any]]:
    old_by_host: Dict[str, List[ServiceRecord]] = defaultdict(list)
    new_by_host: Dict[str, List[ServiceRecord]] = defaultdict(list)
    for s in old_services:
        old_by_host[s.host_key].append(s)
    for s in new_services:
        new_by_host[s.host_key].append(s)

    rows: List[Dict[str, Any]] = []
    for old_h, new_h, _m, _c in matched_hosts:
        old_map = {service_key(s): s for s in old_by_host.get(old_h.host_key, [])}
        new_map = {service_key(s): s for s in new_by_host.get(new_h.host_key, [])}
        all_keys = set(old_map) | set(new_map)
        for key in sorted(all_keys):
            old_s = old_map.get(key)
            new_s = new_map.get(key)
            if old_s and new_s:
                status, risk_hint = classify_service_delta(old_s, new_s)
            elif old_s and not new_s:
                status, risk_hint = "SERVIZIO_RIMOSSO", "Servizio non più esposto nel nuovo snapshot"
            else:
                status, risk_hint = "NUOVO_SERVIZIO", "Nuovo servizio esposto nel nuovo snapshot"
            rows.append({
                "client_id": client_id,
                "engagement_old": engagement_old,
                "engagement_new": engagement_new,
                "mode": mode,
                "host_key": new_h.host_key or old_h.host_key,
                "ip": new_h.ip or old_h.ip,
                "mac": new_h.mac or old_h.mac,
                "port": key[0],
                "protocol": key[1],
                "old_service": old_s.service if old_s else "",
                "new_service": new_s.service if new_s else "",
                "old_product": old_s.product if old_s else "",
                "new_product": new_s.product if new_s else "",
                "old_version": old_s.version if old_s else "",
                "new_version": new_s.version if new_s else "",
                "service_delta_status": status,
                "risk_hint": risk_hint,
                "review_flag": "NO",
            })
    return rows


def build_web_rows(client_id: str, engagement_old: str, engagement_new: str,
                   matched_hosts: List[Tuple[HostRecord, HostRecord, str, str]],
                   old_web: List[WebRecord], new_web: List[WebRecord]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    old_by_host: Dict[str, List[WebRecord]] = defaultdict(list)
    new_by_host: Dict[str, List[WebRecord]] = defaultdict(list)
    for w in old_web:
        old_by_host[w.host_key].append(w)
    for w in new_web:
        new_by_host[w.host_key].append(w)

    for old_h, new_h, _m, _c in matched_hosts:
        old_map = {web_key(w): w for w in old_by_host.get(old_h.host_key, [])}
        new_map = {web_key(w): w for w in new_by_host.get(new_h.host_key, [])}
        all_keys = set(old_map) | set(new_map)
        for key in sorted(all_keys):
            old_w = old_map.get(key)
            new_w = new_map.get(key)
            if old_w and new_w:
                status = classify_web_delta(old_w, new_w)
            elif old_w and not new_w:
                status = "ENDPOINT_WEB_RIMOSSO"
            else:
                status = "NUOVO_ENDPOINT_WEB"
            rows.append({
                "client_id": client_id,
                "engagement_old": engagement_old,
                "engagement_new": engagement_new,
                "host_key": new_h.host_key or old_h.host_key,
                "url": key[0],
                "port": key[1],
                "old_status_code": old_w.status_code if old_w else "",
                "new_status_code": new_w.status_code if new_w else "",
                "old_title": old_w.title if old_w else "",
                "new_title": new_w.title if new_w else "",
                "old_webserver": old_w.webserver if old_w else "",
                "new_webserver": new_w.webserver if new_w else "",
                "old_tech": old_w.tech if old_w else "",
                "new_tech": new_w.tech if new_w else "",
                "old_cdn": old_w.cdn if old_w else "",
                "new_cdn": new_w.cdn if new_w else "",
                "old_ip": old_w.ip if old_w else "",
                "new_ip": new_w.ip if new_w else "",
                "web_delta_status": status,
                "review_flag": "NO",
            })
    return rows


def build_high_value_rows(client_id: str, engagement_old: str, engagement_new: str,
                          matched_hosts: List[Tuple[HostRecord, HostRecord, str, str]],
                          old_hv: List[HighValueRecord], new_hv: List[HighValueRecord]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    old_by_host: Dict[str, List[HighValueRecord]] = defaultdict(list)
    new_by_host: Dict[str, List[HighValueRecord]] = defaultdict(list)
    for r in old_hv:
        old_by_host[r.host_key].append(r)
    for r in new_hv:
        new_by_host[r.host_key].append(r)

    for old_h, new_h, _m, _c in matched_hosts:
        old_map = {high_value_key(r): r for r in old_by_host.get(old_h.host_key, [])}
        new_map = {high_value_key(r): r for r in new_by_host.get(new_h.host_key, [])}
        all_keys = set(old_map) | set(new_map)
        for key in sorted(all_keys):
            old_r = old_map.get(key)
            new_r = new_map.get(key)
            if old_r and new_r:
                status = classify_high_value_delta(old_r, new_r)
                risk_hint = "Servizio high-value invariato o modificato"
            elif old_r and not new_r:
                status = "HIGH_VALUE_RIMOSSO"
                risk_hint = "Servizio high-value non più osservato nel nuovo snapshot"
            else:
                status = "NUOVO_HIGH_VALUE"
                risk_hint = "Nuovo servizio high-value emerso nel nuovo snapshot"
            rows.append({
                "client_id": client_id,
                "engagement_old": engagement_old,
                "engagement_new": engagement_new,
                "host_key": new_h.host_key or old_h.host_key,
                "ip": new_h.ip or old_h.ip,
                "mac": new_h.mac or old_h.mac,
                "port": key[0],
                "protocol": key[1],
                "service": key[2],
                "high_value_delta_status": status,
                "risk_hint": risk_hint,
                "review_flag": "NO",
            })
    return rows


# ------------------------------------------------------------
# Summary / scoring
# ------------------------------------------------------------

def compute_overall_trend(mode: str, host_rows: List[Dict[str, Any]], service_rows: List[Dict[str, Any]],
                          web_rows: List[Dict[str, Any]], hv_rows: List[Dict[str, Any]]) -> Tuple[str, str]:
    score = 0

    for row in host_rows:
        status = row["host_status"]
        if status == "NUOVO_HOST":
            score += 2
        elif status == "HOST_NON_PIU_RILEVATO":
            score -= 1

    for row in service_rows:
        status = row["service_delta_status"]
        if status == "NUOVO_SERVIZIO":
            score += 1
        elif status == "SERVIZIO_RIMOSSO":
            score -= 1
        elif status == "SERVIZIO_MODIFICATO":
            score += 1

    for row in web_rows:
        status = row["web_delta_status"]
        if status == "NUOVO_ENDPOINT_WEB":
            score += 2
        elif status == "ENDPOINT_WEB_RIMOSSO":
            score -= 1
        elif status == "ENDPOINT_WEB_MODIFICATO":
            score += 1

    for row in hv_rows:
        status = row["high_value_delta_status"]
        if status == "NUOVO_HIGH_VALUE":
            score += 4
        elif status == "HIGH_VALUE_RIMOSSO":
            score -= 3
        elif status == "HIGH_VALUE_MODIFICATO":
            score += 1

    has_positive = score > 1
    has_negative = score < -1

    if hv_rows:
        has_new_hv = any(r["high_value_delta_status"] == "NUOVO_HIGH_VALUE" for r in hv_rows)
        if has_new_hv and score <= 0:
            return "MISTA", "Si osserva la comparsa di nuovi servizi high-value a fronte di una riduzione o stabilità di altri elementi della superficie."

    if has_positive and not has_negative:
        return "AUMENTATA", "La superficie osservata risulta aumentata, con comparsa di nuovi host, servizi o elementi potenzialmente sensibili."
    if has_negative and not has_positive:
        return "RIDOTTA", "La superficie osservata risulta ridotta, con diminuzione di host, servizi o esposizioni rispetto al ciclo precedente."
    if abs(score) <= 1:
        return "STABILE", "La superficie osservata non presenta variazioni sostanziali rispetto al ciclo precedente."
    return "MISTA", "Il confronto mostra una combinazione di riduzioni e nuove esposizioni, senza un andamento univoco della superficie osservata."


def build_summary(client_id: str, engagement_old: str, engagement_new: str, mode: str,
                  host_rows: List[Dict[str, Any]], service_rows: List[Dict[str, Any]],
                  web_rows: List[Dict[str, Any]], hv_rows: List[Dict[str, Any]],
                  manual_cases: List[ManualReviewCase]) -> Dict[str, Any]:
    host_counter = Counter(r["host_status"] for r in host_rows)
    svc_counter = Counter(r["service_delta_status"] for r in service_rows)
    web_counter = Counter(r["web_delta_status"] for r in web_rows)
    hv_counter = Counter(r["high_value_delta_status"] for r in hv_rows)

    overall_trend, overall_comment = compute_overall_trend(mode, host_rows, service_rows, web_rows, hv_rows)

    summary: Dict[str, Any] = {
        "client_id": client_id,
        "engagement_old": engagement_old,
        "engagement_new": engagement_new,
        "mode": mode,
        "host_stats": {
            "confirmed": host_counter["HOST_CONFERMATO"],
            "new": host_counter["NUOVO_HOST"],
            "not_seen_anymore": host_counter["HOST_NON_PIU_RILEVATO"],
            "manual_review": host_counter["VERIFICA_MANUALE"],
        },
        "service_stats": {
            "new": svc_counter["NUOVO_SERVIZIO"],
            "removed": svc_counter["SERVIZIO_RIMOSSO"],
            "modified": svc_counter["SERVIZIO_MODIFICATO"],
            "unchanged": svc_counter["SERVIZIO_INVARIATO"],
            "manual_review": svc_counter["VERIFICA_MANUALE"],
        },
        "overall_trend": overall_trend,
        "overall_comment": overall_comment,
        "manual_review_total": len(manual_cases),
    }

    if mode == "external":
        summary["web_stats"] = {
            "new": web_counter["NUOVO_ENDPOINT_WEB"],
            "removed": web_counter["ENDPOINT_WEB_RIMOSSO"],
            "modified": web_counter["ENDPOINT_WEB_MODIFICATO"],
            "unchanged": web_counter["ENDPOINT_WEB_INVARIATO"],
            "manual_review": web_counter["VERIFICA_MANUALE"],
        }
    else:
        summary["high_value_stats"] = {
            "new": hv_counter["NUOVO_HIGH_VALUE"],
            "removed": hv_counter["HIGH_VALUE_RIMOSSO"],
            "modified": hv_counter["HIGH_VALUE_MODIFICATO"],
            "unchanged": hv_counter["HIGH_VALUE_INVARIATO"],
            "manual_review": hv_counter["VERIFICA_MANUALE"],
        }

    return summary


# ------------------------------------------------------------
# Writers
# ------------------------------------------------------------

def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_manual_csv(path: Path, rows: List[ManualReviewCase]) -> None:
    write_csv(path, [asdict(r) for r in rows])


def save_meta_snapshot(path: Path, rows: List[HostRecord]) -> None:
    path.write_text(json.dumps([asdict(r) for r in rows], indent=2, ensure_ascii=False), encoding="utf-8")


# ------------------------------------------------------------
# Main pipeline
# ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare two snapshot engagements and build surface delta.")
    p.add_argument("--old-engagement", required=True)
    p.add_argument("--new-engagement", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--mode", choices=["external", "internal"], required=True)
    p.add_argument("--output-dir", required=True)

    # external
    p.add_argument("--old-httpx")
    p.add_argument("--new-httpx")
    p.add_argument("--old-nmap")
    p.add_argument("--new-nmap")
    p.add_argument("--old-dnsx")
    p.add_argument("--new-dnsx")

    # internal
    p.add_argument("--old-arp-scan")
    p.add_argument("--new-arp-scan")
    p.add_argument("--old-nmap-internal")
    p.add_argument("--new-nmap-internal")
    p.add_argument("--old-nmap-discovery")
    p.add_argument("--new-nmap-discovery")
    p.add_argument("--old-internal-services-csv")
    p.add_argument("--new-internal-services-csv")
    p.add_argument("--old-high-value-csv")
    p.add_argument("--new-high-value-csv")
    return p.parse_args()


def validate_paths(args: argparse.Namespace) -> None:
    if args.mode == "external":
        for attr in ["old_httpx", "new_httpx", "old_nmap", "new_nmap"]:
            path = getattr(args, attr)
            if not path or not Path(path).exists():
                raise FileNotFoundError(f"Missing required external input: {attr} -> {path}")
    else:
        for attr in ["old_arp_scan", "new_arp_scan", "old_nmap_internal", "new_nmap_internal"]:
            path = getattr(args, attr)
            if not path or not Path(path).exists():
                raise FileNotFoundError(f"Missing required internal input: {attr} -> {path}")


def main() -> int:
    args = parse_args()
    validate_paths(args)
    logger = DeltaLogger()

    output_dir = Path(args.output_dir)
    meta_dir = output_dir / "meta"
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    manual_cases: List[ManualReviewCase] = []

    old_hosts: List[HostRecord] = []
    new_hosts: List[HostRecord] = []
    old_services: List[ServiceRecord] = []
    new_services: List[ServiceRecord] = []
    old_web: List[WebRecord] = []
    new_web: List[WebRecord] = []
    old_hv: List[HighValueRecord] = []
    new_hv: List[HighValueRecord] = []
    old_host_ports: Dict[str, Set[str]] = defaultdict(set)
    new_host_ports: Dict[str, Set[str]] = defaultdict(set)

    if args.mode == "external":
        old_dnsx = parse_dnsx(Path(args.old_dnsx) if args.old_dnsx else None, logger)
        new_dnsx = parse_dnsx(Path(args.new_dnsx) if args.new_dnsx else None, logger)

        old_web, old_httpx_hosts = parse_httpx(Path(args.old_httpx), old_dnsx, logger)
        new_web, new_httpx_hosts = parse_httpx(Path(args.new_httpx), new_dnsx, logger)

        old_nmap_hosts, old_services, old_host_ports = parse_nmap_oneline(Path(args.old_nmap), "external", logger)
        new_nmap_hosts, new_services, new_host_ports = parse_nmap_oneline(Path(args.new_nmap), "external", logger)

        # Merge host inventories from nmap + httpx
        old_map = {h.host_key: h for h in old_nmap_hosts}
        for h in old_httpx_hosts:
            if h.host_key not in old_map:
                old_map[h.host_key] = h
        new_map = {h.host_key: h for h in new_nmap_hosts}
        for h in new_httpx_hosts:
            if h.host_key not in new_map:
                new_map[h.host_key] = h
        old_hosts = list(old_map.values())
        new_hosts = list(new_map.values())

        matched, old_unmatched, new_unmatched = correlate_hosts_external(old_hosts, new_hosts, manual_cases, logger)
        host_rows = build_host_rows(args.client_id, args.old_engagement, args.new_engagement, args.mode,
                                    matched, old_unmatched, new_unmatched, old_host_ports, new_host_ports)
        service_rows = build_service_rows(args.client_id, args.old_engagement, args.new_engagement, args.mode,
                                          matched, old_services, new_services)
        web_rows = build_web_rows(args.client_id, args.old_engagement, args.new_engagement,
                                  matched, old_web, new_web)
        hv_rows = []

    else:
        old_hosts = parse_arp_scan(Path(args.old_arp_scan), logger)
        new_hosts = parse_arp_scan(Path(args.new_arp_scan), logger)

        old_nmap_hosts, old_services_nmap, old_host_ports = parse_nmap_oneline(Path(args.old_nmap_internal), "internal", logger)
        new_nmap_hosts, new_services_nmap, new_host_ports = parse_nmap_oneline(Path(args.new_nmap_internal), "internal", logger)

        # enrich arp-scan hosts with hostname/ip from nmap hosts if same MAC or IP
        def enrich(base_hosts: List[HostRecord], nmap_hosts: List[HostRecord]) -> List[HostRecord]:
            by_mac = {h.mac: h for h in nmap_hosts if h.mac}
            by_ip = {h.ip: h for h in nmap_hosts if h.ip}
            result = []
            for h in base_hosts:
                candidate = by_mac.get(h.mac) or by_ip.get(h.ip)
                if candidate:
                    result.append(HostRecord(
                        host_key=h.host_key,
                        ip=h.ip or candidate.ip,
                        hostname=candidate.hostname,
                        fqdn=candidate.fqdn,
                        mac=h.mac,
                        vendor=h.vendor,
                        source_mode="internal",
                    ))
                else:
                    result.append(h)
            # add nmap hosts not present in arp by ip/mac
            known_keys = {r.host_key for r in result}
            for nh in nmap_hosts:
                if nh.host_key not in known_keys:
                    result.append(nh)
            return result

        old_hosts = enrich(old_hosts, old_nmap_hosts)
        new_hosts = enrich(new_hosts, new_nmap_hosts)

        old_services_csv = parse_internal_services_csv(Path(args.old_internal_services_csv) if args.old_internal_services_csv else None, logger)
        new_services_csv = parse_internal_services_csv(Path(args.new_internal_services_csv) if args.new_internal_services_csv else None, logger)
        old_services = old_services_csv or old_services_nmap
        new_services = new_services_csv or new_services_nmap

        old_hv = parse_high_value_csv(Path(args.old_high_value_csv) if args.old_high_value_csv else None, logger)
        new_hv = parse_high_value_csv(Path(args.new_high_value_csv) if args.new_high_value_csv else None, logger)

        matched, old_unmatched, new_unmatched = correlate_hosts_internal(old_hosts, new_hosts, manual_cases, logger)
        host_rows = build_host_rows(args.client_id, args.old_engagement, args.new_engagement, args.mode,
                                    matched, old_unmatched, new_unmatched, old_host_ports, new_host_ports)
        service_rows = build_service_rows(args.client_id, args.old_engagement, args.new_engagement, args.mode,
                                          matched, old_services, new_services)
        web_rows = []
        hv_rows = build_high_value_rows(args.client_id, args.old_engagement, args.new_engagement,
                                        matched, old_hv, new_hv) if (old_hv or new_hv) else []

    summary = build_summary(args.client_id, args.old_engagement, args.new_engagement, args.mode,
                            host_rows, service_rows, web_rows, hv_rows, manual_cases)

    write_csv(output_dir / "delta_hosts.csv", host_rows)
    write_csv(output_dir / "delta_services.csv", service_rows)
    if args.mode == "external":
        write_csv(output_dir / "delta_web.csv", web_rows)
    if args.mode == "internal" and hv_rows:
        write_csv(output_dir / "delta_high_value_services.csv", hv_rows)
    write_manual_csv(output_dir / "manual_review_cases.csv", manual_cases)
    (output_dir / "delta_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    save_meta_snapshot(meta_dir / "old_hosts_snapshot.json", old_hosts)
    save_meta_snapshot(meta_dir / "new_hosts_snapshot.json", new_hosts)
    logger.dump(output_dir / "delta_log.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
