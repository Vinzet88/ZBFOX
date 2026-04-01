#!/bin/bash

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

usage() {
  echo "Uso: $0 <ENGAGEMENT_PATH>"
  echo "Esempio: $0 /opt/zbfox/engagements/ZBF-ASSESS-20260323-ACME"
  exit 1
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[!] Tool mancante: $tool"
    exit 1
  fi
}

log_timeline() {
  local msg="$1"
  echo "- $(date '+%Y-%m-%d %H:%M:%S') - ${msg}" >> "${TIMELINE_FILE}"
}

log_note() {
  local msg="$1"
  echo "- ${msg}" >> "${PHASE2_NOTE_FILE}"
}

sanitize_segment() {
  echo "$1" | tr '/:.' '_' | tr -cd '[:alnum:]_-'
}

bootstrap_phase_dirs() {
  mkdir -p \
    "$RAW_DIR/phase2" \
    "$PROCESSED_DIR/phase2" \
    "$SCANS_DIR/phase2" \
    "$EVIDENCE_DIR/phase2" \
    "$ENGAGEMENT_PATH/logs" \
    "$ENGAGEMENT_PATH/tmp"
}

run_cmd() {
  local desc="$1"
  local outfile="$2"
  shift 2
  echo "[*] ${desc}"
  "$@" > "$outfile" 2>&1 || true
}

autodetect_iface() {
  python3 - <<'PY' "$RAW_DIR/phase2/mod01_ip_br_link.txt" "$RAW_DIR/phase2/mod01_ip_br_addr.txt"
import sys,re
linkf, addrf = sys.argv[1:]
link_lines = open(linkf).read().splitlines()
addr_lines = open(addrf).read().splitlines()
up = []
for line in link_lines:
    parts = line.split()
    if len(parts) >= 2:
        iface,state = parts[0],parts[1]
        if iface != 'lo' and state == 'UP':
            up.append(iface)
addr = {}
for line in addr_lines:
    parts = line.split()
    if len(parts) >= 3:
        iface = parts[0]
        ips = [p for p in parts[2:] if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', p)]
        if ips:
            addr[iface] = ips[0]
prio = []
for iface in up:
    if iface in addr:
        if iface.startswith(('eth','en')):
            score = 0
        elif iface.startswith('wlan'):
            score = 1
        else:
            score = 2
        prio.append((score, iface))
prio.sort()
print(prio[0][1] if prio else '')
PY
}

mod01_collect() {
  log_timeline "MOD01 start"
  run_cmd "MOD01 ip -br link" "$RAW_DIR/phase2/mod01_ip_br_link.txt" ip -br link
  run_cmd "MOD01 ip -br addr" "$RAW_DIR/phase2/mod01_ip_br_addr.txt" ip -br addr
  IFACE="$(autodetect_iface)"
  if [ -z "$IFACE" ]; then
    echo "[!] Nessuna interfaccia valida rilevata"
    exit 1
  fi
  echo "[*] IFACE selezionata: $IFACE"
  log_note "IFACE selezionata automaticamente: $IFACE"

  run_cmd "MOD01 ip addr show dev $IFACE" "$RAW_DIR/phase2/mod01_ip_addr_${IFACE}.txt" ip addr show dev "$IFACE"
  run_cmd "MOD01 ip route" "$RAW_DIR/phase2/mod01_ip_route.txt" ip route

  if command -v resolvectl >/dev/null 2>&1; then
    run_cmd "MOD01 resolvectl status" "$RAW_DIR/phase2/mod01_resolvectl_status.txt" resolvectl status
  fi
  run_cmd "MOD01 resolv.conf" "$RAW_DIR/phase2/mod01_resolv_conf.txt" cat /etc/resolv.conf
  if command -v hostnamectl >/dev/null 2>&1; then
    run_cmd "MOD01 hostnamectl" "$RAW_DIR/phase2/mod01_hostnamectl.txt" hostnamectl
  else
    run_cmd "MOD01 hostname" "$RAW_DIR/phase2/mod01_hostname.txt" hostname
  fi
  run_cmd "MOD01 ethtool $IFACE" "$RAW_DIR/phase2/mod01_ethtool_${IFACE}.txt" ethtool "$IFACE"

  python3 - <<'PY' "$ENGAGEMENT_PATH" "$IFACE"
import os,sys,re,json,ipaddress,datetime
root, iface = sys.argv[1:]
raw = os.path.join(root,'raw','phase2')
proc = os.path.join(root,'processed','phase2')

def read(path):
    try: return open(path).read()
    except: return ''
link = read(os.path.join(raw,'mod01_ip_br_link.txt'))
addr = read(os.path.join(raw,'mod01_ip_br_addr.txt'))
ipaddr = read(os.path.join(raw,f'mod01_ip_addr_{iface}.txt'))
routes = read(os.path.join(raw,'mod01_ip_route.txt'))
resolvectl = read(os.path.join(raw,'mod01_resolvectl_status.txt'))
resolv = read(os.path.join(raw,'mod01_resolv_conf.txt'))
hostnamectl = read(os.path.join(raw,'mod01_hostnamectl.txt')) or read(os.path.join(raw,'mod01_hostname.txt'))
ethtool = read(os.path.join(raw,f'mod01_ethtool_{iface}.txt'))
mac = ''
mtu = ''
ipv4 = ''
cidr = ''
subnet = ''
for line in ipaddr.splitlines():
    m = re.search(r'link/\w+\s+([0-9a-f:]{17})', line, re.I)
    if m: mac = m.group(1).lower()
    m = re.search(r'mtu\s+(\d+)', line)
    if m: mtu = m.group(1)
    m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
    if m:
        ipv4 = m.group(1); cidr = m.group(2)
        subnet = str(ipaddress.ip_network(f"{ipv4}/{cidr}", strict=False))
state = ''
for line in link.splitlines():
    parts = line.split()
    if len(parts) >= 2 and parts[0] == iface:
        state = parts[1]
        if not mac and len(parts) >= 3: mac = parts[2].lower()
        break
gateway = ''
connected = []
remote = []
for line in routes.splitlines():
    line = line.strip()
    m = re.match(r'default via\s+(\d+\.\d+\.\d+\.\d+)', line)
    if m:
        gateway = m.group(1)
        continue
    if 'scope link' in line:
        m = re.match(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
        if m: connected.append(m.group(1))
    elif ' via ' in line:
        m = re.match(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
        if m: remote.append(m.group(1))

dns_servers = []
search_domains = []
for text in (resolvectl,resolv):
    for line in text.splitlines():
        if 'DNS Servers' in line:
            dns_servers += re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
        elif line.startswith('nameserver'):
            dns_servers += re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
        elif 'DNS Domain' in line:
            search_domains += re.findall(r'([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)', line)
        elif line.startswith('search '):
            search_domains += line.split()[1:]

dns_servers = sorted(set(dns_servers))
search_domains = sorted(set(search_domains))
hostname = ''
host_static = ''
for line in hostnamectl.splitlines():
    if 'Static hostname:' in line:
        host_static = line.split(':',1)[1].strip()
    elif 'Transient hostname:' in line and not hostname:
        hostname = line.split(':',1)[1].strip()
if not hostname: hostname = host_static or hostnamectl.strip().splitlines()[0].strip() if hostnamectl.strip() else ''
speed = duplex = ''
carrier = ''
for line in ethtool.splitlines():
    if 'Speed:' in line: speed = line.split(':',1)[1].strip()
    elif 'Duplex:' in line: duplex = line.split(':',1)[1].strip()
    elif 'Link detected:' in line: carrier = line.split(':',1)[1].strip()
initial = {
    'timestamp': datetime.datetime.now().astimezone().isoformat(),
    'interface': iface,
    'mac_address': mac,
    'ipv4': ipv4,
    'cidr': cidr,
    'subnet': subnet,
    'gateway': gateway,
    'dns_servers': dns_servers,
    'search_domains': search_domains,
    'hostname': hostname,
    'host_static_name': host_static,
    'link_state': state,
    'link_speed': speed,
    'duplex': duplex,
    'mtu': mtu,
    'connected_routes': connected,
    'candidate_remote_routes': remote,
}
iface_status = {
    'interface': iface,
    'state': state,
    'mac_address': mac,
    'mtu': mtu,
    'speed': speed,
    'duplex': duplex,
    'carrier_detected': carrier,
}
route_candidates = {
    'default_gateway': gateway,
    'connected_subnets': connected,
    'candidate_remote_segments': remote,
}
for name,obj in [('initial_access.json',initial),('interface_status.json',iface_status),('route_candidates.json',route_candidates)]:
    with open(os.path.join(proc,name),'w') as f: json.dump(obj,f,indent=2)
PY
  log_timeline "MOD01 completed"
}

mod02_l2() {
  log_timeline "MOD02 start"
  run_cmd "MOD02 ip neigh pre" "$RAW_DIR/phase2/mod02_ip_neigh_pre.txt" ip neigh
  run_cmd "MOD02 ip neigh flush" "$RAW_DIR/phase2/mod02_ip_neigh_flush.txt" sudo ip neigh flush dev "$IFACE"
  run_cmd "MOD02 arp-scan" "$RAW_DIR/phase2/mod02_arp_scan_localnet.txt" sudo arp-scan --interface="$IFACE" --localnet
  run_cmd "MOD02 arp-scan retry" "$RAW_DIR/phase2/mod02_arp_scan_localnet_retry.txt" sudo arp-scan --interface="$IFACE" --localnet --retry=3 --timeout=500
  run_cmd "MOD02 passive capture" "$ENGAGEMENT_PATH/logs/mod02_tcpdump.log" sudo timeout 30 tcpdump -i "$IFACE" -nn -e -w "$RAW_DIR/phase2/mod02_passive_30s.pcap"
  run_cmd "MOD02 ip neigh post" "$RAW_DIR/phase2/mod02_ip_neigh_post.txt" ip neigh

  python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,re,csv,json,datetime,collections
root = sys.argv[1]
raw = os.path.join(root,'raw','phase2')
proc = os.path.join(root,'processed','phase2')
init = json.load(open(os.path.join(proc,'initial_access.json')))
subnet = init.get('subnet','')
files = {
    'ip_neigh_pre': os.path.join(raw,'mod02_ip_neigh_pre.txt'),
    'arp1': os.path.join(raw,'mod02_arp_scan_localnet.txt'),
    'arp2': os.path.join(raw,'mod02_arp_scan_localnet_retry.txt'),
    'ip_neigh_post': os.path.join(raw,'mod02_ip_neigh_post.txt'),
}
records = {}
first_seen = datetime.datetime.now().astimezone().isoformat()

def ensure(ip):
    records.setdefault(ip, {'ip':ip,'mac':'','vendor':'','source_tools':set(),'first_seen':first_seen,'last_seen':first_seen,'neighbor_state':'','is_duplicate':'false','role_hint':'','notes':''})
    return records[ip]
for key in ('ip_neigh_pre','ip_neigh_post'):
    try: lines = open(files[key]).read().splitlines()
    except: lines = []
    for line in lines:
        m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-f:]{17}))?\s+(\S+)', line, re.I)
        if not m: continue
        ip, dev, mac, state = m.groups()
        rec = ensure(ip)
        if mac: rec['mac'] = mac.lower()
        rec['neighbor_state'] = state
        rec['source_tools'].add('ip_neigh')
for key in ('arp1','arp2'):
    try: lines = open(files[key]).read().splitlines()
    except: lines = []
    for line in lines:
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)$', line.strip(), re.I)
        if not m: continue
        ip, mac, vendor = m.groups()
        rec = ensure(ip)
        rec['mac'] = mac.lower()
        rec['vendor'] = vendor.strip()
        rec['source_tools'].add('arp_scan')
        rec['last_seen'] = datetime.datetime.now().astimezone().isoformat()
# duplicate MAC detection
mac_index = collections.defaultdict(list)
for ip, rec in records.items():
    if rec['mac']: mac_index[rec['mac']].append(ip)
for mac, ips in mac_index.items():
    if len(ips) > 1:
        for ip in ips:
            records[ip]['is_duplicate'] = 'true'
# role hints
net_vendors = ('fortinet','cisco','sophos','mikrotik','ubiquiti')
storage_vendors = ('synology','qnap','netapp')
printer_vendors = ('brother','canon','lexmark','xerox')
server_vendors = ('vmware','hewlett','hpe','supermicro','dell','lenovo')
infra_rows = []
for rec in records.values():
    vend = rec['vendor'].lower()
    reason = []
    if rec['ip'] == init.get('gateway'):
        rec['role_hint'] = 'gateway_candidate'; reason.append('default_gateway')
    elif any(v in vend for v in net_vendors):
        rec['role_hint'] = 'network/security'; reason.append('network_vendor')
    elif any(v in vend for v in storage_vendors):
        rec['role_hint'] = 'storage_candidate'; reason.append('storage_vendor')
    elif any(v in vend for v in printer_vendors):
        rec['role_hint'] = 'printer_candidate'; reason.append('printer_vendor')
    elif any(v in vend for v in server_vendors):
        rec['role_hint'] = 'server_candidate'; reason.append('server_vendor')
    if reason:
        infra_rows.append({'ip':rec['ip'],'mac':rec['mac'],'vendor':rec['vendor'],'reason':'|'.join(reason),'evidence':rec['vendor'] or rec['ip'],'priority':'medium' if rec['role_hint'] != 'gateway_candidate' else 'high','source':'mod02'})
# write CSVs
with open(os.path.join(proc,'l2_hosts.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','mac','vendor','source_tools','first_seen','last_seen','neighbor_state','is_duplicate','role_hint','notes'])
    writer.writeheader()
    for rec in sorted(records.values(), key=lambda x: tuple(int(p) for p in x['ip'].split('.'))):
        rec = rec.copy(); rec['source_tools'] = '|'.join(sorted(rec['source_tools']))
        writer.writerow(rec)
with open(os.path.join(proc,'l2_infra_candidates.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','mac','vendor','reason','evidence','priority','source'])
    writer.writeheader(); writer.writerows(infra_rows)
vendor_counter = collections.Counter(r['vendor'] for r in records.values() if r['vendor'])
summary = {
    'local_subnet': subnet,
    'total_hosts_detected': len(records),
    'hosts_from_ip_neigh': sum(1 for r in records.values() if 'ip_neigh' in r['source_tools']),
    'hosts_from_arp_scan': sum(1 for r in records.values() if 'arp_scan' in r['source_tools']),
    'unique_mac_count': len([m for m in mac_index if m]),
    'top_vendors': vendor_counter.most_common(10),
    'infra_hints': [r['ip'] for r in infra_rows[:10]],
    'suspicious_duplicates': [{'mac':m,'ips':ips} for m,ips in mac_index.items() if len(ips)>1],
}
json.dump(summary, open(os.path.join(proc,'l2_summary.json'),'w'), indent=2)
PY
  log_timeline "MOD02 completed"
}

mod03_l3() {
  log_timeline "MOD03 start"
  GATEWAY="$(jq -r '.gateway' "$PROCESSED_DIR/phase2/initial_access.json")"
  LOCAL_SUBNET="$(jq -r '.subnet' "$PROCESSED_DIR/phase2/initial_access.json")"
  mapfile -t DNS_IPS < <(jq -r '.dns_servers[]?' "$PROCESSED_DIR/phase2/initial_access.json" 2>/dev/null || true)
  [ -n "$GATEWAY" ] && run_cmd "MOD03 ping gateway" "$RAW_DIR/phase2/mod03_ping_gateway.txt" ping -c 3 "$GATEWAY"
  for dns in "${DNS_IPS[@]:-}"; do
    [ -n "$dns" ] && run_cmd "MOD03 ping dns $dns" "$RAW_DIR/phase2/mod03_ping_dns_${dns}.txt" ping -c 3 "$dns"
  done
  run_cmd "MOD03 fping local" "$RAW_DIR/phase2/mod03_fping_local.txt" fping -a -g "$LOCAL_SUBNET" -r 1 -t 250
  sudo nmap -sn -PE -PP -PS21,22,80,135,139,443,445,3389 -PA80,135,443,445 -PU53,123,137,161 "$LOCAL_SUBNET" -oA "$SCANS_DIR/phase2/mod03_nmap_sn_local" >/dev/null 2>&1 || true
  python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,re,csv,json,datetime,xml.etree.ElementTree as ET
root = sys.argv[1]
raw = os.path.join(root,'raw','phase2')
scans = os.path.join(root,'scans','phase2')
proc = os.path.join(root,'processed','phase2')
init = json.load(open(os.path.join(proc,'initial_access.json')))
route_info = json.load(open(os.path.join(proc,'route_candidates.json')))
records = {}
now = datetime.datetime.now().astimezone().isoformat()
def ensure(ip):
    records.setdefault(ip, {'ip':ip,'segment':'','method':'','host_up':'true','latency_ms':'','hostname':'','is_local_subnet':'false','is_remote_segment':'false','source_tools':set(),'first_seen':now,'last_seen':now,'notes':''})
    return records[ip]
# fping
try:
    for line in open(os.path.join(raw,'mod03_fping_local.txt')).read().splitlines():
        ip = line.strip()
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            rec = ensure(ip); rec['segment'] = init.get('subnet',''); rec['is_local_subnet'] = 'true'; rec['method'] = 'fping'; rec['source_tools'].add('fping')
except: pass
# nmap local
xmlp = os.path.join(scans,'mod03_nmap_sn_local.xml')
if os.path.exists(xmlp):
    rootxml = ET.parse(xmlp).getroot()
    for host in rootxml.findall('host'):
        st = host.find('status')
        if st is None or st.get('state') != 'up': continue
        ip=''; hostname=''; latency=''
        for a in host.findall('address'):
            if a.get('addrtype')=='ipv4': ip = a.get('addr','')
        hs = host.find('hostnames')
        if hs is not None:
            hn = hs.find('hostname')
            if hn is not None: hostname = hn.get('name','')
        times = host.find('times')
        if times is not None: latency = times.get('srtt','')
        if ip:
            rec = ensure(ip); rec['segment'] = init.get('subnet',''); rec['is_local_subnet']='true'; rec['hostname']=hostname or rec['hostname']; rec['latency_ms']=latency; rec['source_tools'].add('nmap-sn-rich'); rec['method']='nmap-sn-rich'
# remote segments
segments = []
reach_rows = []
for seg in route_info.get('candidate_remote_segments',[]):
    sname = seg.replace('/','_').replace('.','_')
    xmlp = os.path.join(scans,f'mod03_nmap_sn_{sname}.xml')
    if not os.path.exists(xmlp):
        reach_rows.append({'segment':seg,'source':'route_candidates','reachability':'unknown','status':'not_tested','notes':''})
        continue
    hosts_up = 0
    rootxml = ET.parse(xmlp).getroot()
    for host in rootxml.findall('host'):
        st = host.find('status')
        if st is None or st.get('state') != 'up': continue
        ip=''; hostname=''
        for a in host.findall('address'):
            if a.get('addrtype')=='ipv4': ip = a.get('addr','')
        hs = host.find('hostnames')
        if hs is not None:
            hn = hs.find('hostname')
            if hn is not None: hostname = hn.get('name','')
        if ip:
            hosts_up += 1
            rec = ensure(ip); rec['segment']=seg; rec['is_remote_segment']='true'; rec['hostname']=hostname or rec['hostname']; rec['source_tools'].add('nmap-sn-remote'); rec['method']='nmap-sn-remote'
    reach_rows.append({'segment':seg,'source':'route_candidates','reachability':'reachable' if hosts_up else 'none','status':'tested','notes':f'hosts_up={hosts_up}'})
# write live_hosts
with open(os.path.join(proc,'live_hosts.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','segment','method','host_up','latency_ms','hostname','is_local_subnet','is_remote_segment','source_tools','first_seen','last_seen','notes'])
    writer.writeheader()
    for rec in sorted(records.values(), key=lambda x: tuple(int(p) for p in x['ip'].split('.'))):
        out = rec.copy(); out['source_tools'] = '|'.join(sorted(out['source_tools']))
        writer.writerow(out)
with open(os.path.join(proc,'reachable_segments.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['segment','source','reachability','status','notes'])
    writer.writeheader(); writer.writerows(reach_rows)
summary = {
    'local_subnet': init.get('subnet',''),
    'local_hosts_up': sum(1 for r in records.values() if r['is_local_subnet']=='true'),
    'remote_segments_tested': [r['segment'] for r in reach_rows if r['status']=='tested'],
    'remote_segments_reachable': [r['segment'] for r in reach_rows if r['reachability']=='reachable'],
    'remote_segments_unreachable': [r['segment'] for r in reach_rows if r['reachability']=='none'],
    'host_discovery_methods': sorted({m for r in records.values() for m in r['source_tools']}),
    'coverage_notes': []
}
json.dump(summary, open(os.path.join(proc,'reachability_summary.json'),'w'), indent=2)
PY
  log_timeline "MOD03 completed"
}

mod04_services() {
  log_timeline "MOD04 start"
  python3 - <<'PY' "$PROCESSED_DIR/phase2/live_hosts.csv" "$PROCESSED_DIR/phase2/live_hosts_local.txt" "$PROCESSED_DIR/phase2/live_hosts_remote.txt"
import csv,sys
src, localf, remotef = sys.argv[1:]
local=[]; remote=[]
with open(src) as f:
    for row in csv.DictReader(f):
        if row['host_up'] != 'true': continue
        if row['is_local_subnet'] == 'true': local.append(row['ip'])
        elif row['is_remote_segment'] == 'true': remote.append(row['ip'])
open(localf,'w').write('\n'.join(sorted(set(local))) + ('\n' if local else ''))
open(remotef,'w').write('\n'.join(sorted(set(remote))) + ('\n' if remote else ''))
PY
  if [ -s "$PROCESSED_DIR/phase2/live_hosts_local.txt" ]; then
    sudo nmap -Pn -sS -T4 --top-ports 200 -iL "$PROCESSED_DIR/phase2/live_hosts_local.txt" -oA "$SCANS_DIR/phase2/mod04_top200_local" >/dev/null 2>&1 || true
  fi
  if [ -s "$PROCESSED_DIR/phase2/live_hosts_remote.txt" ]; then
    sudo nmap -Pn -sS -T4 --top-ports 100 -iL "$PROCESSED_DIR/phase2/live_hosts_remote.txt" -oA "$SCANS_DIR/phase2/mod04_top100_remote" >/dev/null 2>&1 || true
  fi
  python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,re,csv,json,xml.etree.ElementTree as ET,collections
root=sys.argv[1]
proc=os.path.join(root,'processed','phase2')
scans=os.path.join(root,'scans','phase2')
live={}
with open(os.path.join(proc,'live_hosts.csv')) as f:
    for r in csv.DictReader(f): live[r['ip']]=r
service_rows = {}

def ingest(xmlpath, source):
    if not os.path.exists(xmlpath): return
    rx=ET.parse(xmlpath).getroot()
    for host in rx.findall('host'):
        ip='';
        for a in host.findall('address'):
            if a.get('addrtype')=='ipv4': ip=a.get('addr','')
        if not ip: continue
        seg = live.get(ip,{}).get('segment','')
        hn = live.get(ip,{}).get('hostname','')
        ports = host.find('ports')
        if ports is None: continue
        for p in ports.findall('port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open': continue
            svc = p.find('service')
            key=(ip,p.get('protocol',''),p.get('portid',''))
            service_rows[key]={
                'ip':ip,'segment':seg,'port':p.get('portid',''),'proto':p.get('protocol',''),'state':'open',
                'service': svc.get('name','') if svc is not None else '',
                'product': svc.get('product','') if svc is not None else '',
                'version': svc.get('version','') if svc is not None else '',
                'extrainfo': svc.get('extrainfo','') if svc is not None else '',
                'hostname': hn,'source_scan': source,'first_seen':'','last_seen':'','notes':''
            }
ingest(os.path.join(scans,'mod04_top200_local.xml'),'mod04_top200_local')
ingest(os.path.join(scans,'mod04_top100_remote.xml'),'mod04_top100_remote')
# write initial top services
with open(os.path.join(proc,'services_top.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','segment','port','proto','state','service','product','version','extrainfo','hostname','source_scan','first_seen','last_seen','notes'])
    writer.writeheader(); writer.writerows(sorted(service_rows.values(), key=lambda r:(tuple(int(p) for p in r['ip'].split('.')), int(r['port']))))
# enrichment targets
interesting_ports={'53','80','88','135','139','389','443','445','636','3268','3269','3389','22','161','548','631','9100','8006','5000','5001','8443','9443','5985','5986'}
targets=sorted({r['ip'] for r in service_rows.values() if r['port'] in interesting_ports})
open(os.path.join(proc,'service_enrichment_targets.txt'),'w').write('\n'.join(targets)+('\n' if targets else ''))
# aggregate open ports by host
byhost=collections.defaultdict(list)
for r in service_rows.values(): byhost[r['ip']].append(r)
rows=[]; infra=[]
for ip, ports in byhost.items():
    plist=sorted({p['port'] for p in ports}, key=lambda x:int(x))
    pset=set(plist)
    role=''
    if {'53','88','135','139','389','445'}.issubset(pset): role='domain_controller_candidate'
    elif {'5000','5001'} & pset or {'2049','111'} <= pset: role='nas_storage_candidate'
    elif {'8006'} & pset or {'902','903'} <= pset: role='hypervisor_candidate'
    elif {'9100','515','631'} & pset: role='printer_candidate'
    elif {'135','139','445','3389'} & pset: role='windows_server_candidate'
    elif {'22','443'} & pset and ip.endswith('.1'): role='gateway_appliance_candidate'
    rows.append({'ip':ip,'hostname':live.get(ip,{}).get('hostname',''),'segment':live.get(ip,{}).get('segment',''),'open_port_count':len(plist),'ports':'|'.join(plist),'likely_role':role,'notes':''})
    if role:
        infra.append({'ip':ip,'hostname':live.get(ip,{}).get('hostname',''),'reason':role,'evidence':'ports='+('|'.join(plist)),'priority':'high' if 'domain' in role or 'gateway' in role else 'medium','promoted_by':'mod04','confirmed_role':'','confidence':'medium','notes':''})
with open(os.path.join(proc,'open_ports_by_host.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','hostname','segment','open_port_count','ports','likely_role','notes'])
    writer.writeheader(); writer.writerows(rows)
with open(os.path.join(proc,'infra_candidates.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','hostname','reason','evidence','priority','promoted_by','confirmed_role','confidence','notes'])
    writer.writeheader(); writer.writerows(infra)
summary={
    'hosts_scanned': len(byhost),
    'segments_scanned': sorted(set(r['segment'] for r in live.values() if r['segment'])),
    'top_ports_profile':'200_local_100_remote',
    'total_open_ports': len(service_rows),
    'top_services': collections.Counter((r['service'] or 'unknown') for r in service_rows.values()).most_common(15),
    'infra_candidates_promoted': [r['ip'] for r in infra],
    'web_candidates': sorted({r['ip'] for r in service_rows.values() if r['port'] in {'80','443','8080','8443','9443','8006','5000','5001'}}),
    'admin_surface_candidates': sorted({r['ip'] for r in service_rows.values() if r['port'] in {'22','443','3389','5900','5985','5986','8006','8443','9443','5000','5001'}}),
}
json.dump(summary, open(os.path.join(proc,'service_summary.json'),'w'), indent=2)
PY
  if [ -s "$PROCESSED_DIR/phase2/service_enrichment_targets.txt" ]; then
    sudo nmap -Pn -sS -sV -T4 -iL "$PROCESSED_DIR/phase2/service_enrichment_targets.txt" -oA "$SCANS_DIR/phase2/mod04_sv_enrichment" >/dev/null 2>&1 || true
    python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,csv,xml.etree.ElementTree as ET
root=sys.argv[1]
proc=os.path.join(root,'processed','phase2')
scans=os.path.join(root,'scans','phase2')
svxml=os.path.join(scans,'mod04_sv_enrichment.xml')
if os.path.exists(svxml):
    rows={}
    with open(os.path.join(proc,'services_top.csv')) as f:
        for r in csv.DictReader(f): rows[(r['ip'],r['proto'],r['port'])]=r
    rx=ET.parse(svxml).getroot()
    for host in rx.findall('host'):
        ip=''
        for a in host.findall('address'):
            if a.get('addrtype')=='ipv4': ip=a.get('addr','')
        ports=host.find('ports')
        if not ip or ports is None: continue
        for p in ports.findall('port'):
            st = p.find('state')
            if st is None or st.get('state')!='open': continue
            svc = p.find('service')
            key=(ip,p.get('protocol',''),p.get('portid',''))
            if key in rows and svc is not None:
                rows[key]['service']=svc.get('name', rows[key]['service'])
                rows[key]['product']=svc.get('product', rows[key]['product'])
                rows[key]['version']=svc.get('version', rows[key]['version'])
                rows[key]['extrainfo']=svc.get('extrainfo', rows[key]['extrainfo'])
                rows[key]['source_scan']='mod04_sv_enrichment'
    with open(os.path.join(proc,'services_top.csv'),'w',newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['ip','segment','port','proto','state','service','product','version','extrainfo','hostname','source_scan','first_seen','last_seen','notes'])
        writer.writeheader(); writer.writerows(rows.values())
PY
  fi
  log_timeline "MOD04 completed"
}

mod05_core() {
  log_timeline "MOD05 start"
  python3 - <<'PY' "$PROCESSED_DIR/phase2/infra_candidates.csv" "$PROCESSED_DIR/phase2/core_fingerprint_targets.txt" "$PROCESSED_DIR/phase2/core_fingerprint_targets_small.txt"
import csv,sys
src,out1,out2=sys.argv[1:]
rows=[]
with open(src) as f:
    rows=list(csv.DictReader(f))
ips=[r['ip'] for r in rows if r.get('ip')]
open(out1,'w').write('\n'.join(ips)+('\n' if ips else ''))
small=ips[:5]
open(out2,'w').write('\n'.join(small)+('\n' if small else ''))
PY
  if [ -s "$PROCESSED_DIR/phase2/core_fingerprint_targets.txt" ]; then
    sudo nmap -Pn -O -T4 -iL "$PROCESSED_DIR/phase2/core_fingerprint_targets.txt" -oA "$SCANS_DIR/phase2/mod05_os_core" >/dev/null 2>&1 || true
  fi
  if [ -s "$PROCESSED_DIR/phase2/core_fingerprint_targets_small.txt" ]; then
    sudo nmap -Pn -A -T4 -iL "$PROCESSED_DIR/phase2/core_fingerprint_targets_small.txt" -oA "$SCANS_DIR/phase2/mod05_aggr_core_small" >/dev/null 2>&1 || true
  fi
  python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,csv,json,xml.etree.ElementTree as ET,subprocess,re
root=sys.argv[1]
proc=os.path.join(root,'processed','phase2')
scans=os.path.join(root,'scans','phase2')
services=[]
with open(os.path.join(proc,'services_top.csv')) as f:
    services=list(csv.DictReader(f))
infra=[]
with open(os.path.join(proc,'infra_candidates.csv')) as f:
    infra=list(csv.DictReader(f))
roles={r['ip']:r for r in infra}
rows={ip:{'ip':ip,'hostname':roles[ip].get('hostname',''),'segment':'','candidate_role':roles[ip].get('reason',''),'os_hint':'','device_hint':'','web_hint':'','tls_hint':'','dns_hint':'','admin_surface':'false','confidence':'low','source_tools':'','notes':''} for ip in roles}
# parse nmap O
for xmlname in ('mod05_os_core.xml','mod05_aggr_core_small.xml'):
    path=os.path.join(scans,xmlname)
    if not os.path.exists(path): continue
    rx=ET.parse(path).getroot()
    for host in rx.findall('host'):
        ip=''
        for a in host.findall('address'):
            if a.get('addrtype')=='ipv4': ip=a.get('addr','')
        if ip not in rows: continue
        osmatch=host.find('os')
        if osmatch is not None:
            om=osmatch.find('osmatch')
            if om is not None: rows[ip]['os_hint']=om.get('name','')
        ports=host.find('ports')
        if ports is not None:
            for p in ports.findall('port'):
                st=p.find('state')
                if st is not None and st.get('state')=='open' and p.get('portid') in {'22','443','3389','5900','5985','5986','8006','8443','9443','5000','5001'}:
                    rows[ip]['admin_surface']='true'
for s in services:
    ip=s['ip'];
    if ip not in rows: continue
    if s['port'] in {'80','443','8080','8443','9443','8006','5000','5001'}:
        scheme='https' if s['port'] in {'443','8443','9443','8006','5001'} else 'http'
        try:
            out=subprocess.run(['curl','-k','-I','-m','5',f'{scheme}://{ip}:{s["port"]}'], capture_output=True, text=True)
            open(os.path.join(root,'raw','phase2',f'mod05_curl_{ip}_{s["port"]}.txt'),'w').write(out.stdout+out.stderr)
            m=re.search(r'^Server:\s*(.+)$', out.stdout, re.M|re.I)
            if m: rows[ip]['web_hint']=m.group(1).strip()
        except: pass
        try:
            out=subprocess.run(['bash','-lc',f"echo | openssl s_client -connect {ip}:{s['port']} -servername {ip} 2>/dev/null"], capture_output=True, text=True)
            open(os.path.join(root,'raw','phase2',f'mod05_tls_{ip}_{s["port"]}.txt'),'w').write(out.stdout)
            m=re.search(r'subject=.*?CN\s*=\s*([^,/\n]+)', out.stdout)
            if m: rows[ip]['tls_hint']=m.group(1).strip()
        except: pass
    try:
        out=subprocess.run(['dig','-x',ip], capture_output=True, text=True)
        open(os.path.join(root,'raw','phase2',f'mod05_dig_ptr_{ip}.txt'),'w').write(out.stdout)
        m=re.search(r'PTR\s+([^\s.][^\n]+)', out.stdout)
        if m: rows[ip]['dns_hint']=m.group(1).strip().rstrip('.')
    except: pass
# confidence/confirmed role
webrows=[]; dnsrows=[]
for ip,row in rows.items():
    score=0
    if row['os_hint']: score+=1
    if row['web_hint']: score+=1
    if row['tls_hint']: score+=1
    if row['dns_hint']: score+=1
    if row['admin_surface']=='true': score+=1
    row['confidence']='high' if score>=3 else 'medium' if score>=2 else 'low'
    row['source_tools']='nmap|curl|openssl|dig'
    if row['dns_hint']:
        dnsrows.append({'ip':ip,'reverse_name':row['dns_hint'],'forward_match':'','dns_hint_type':'ptr','notes':''})
    if row['web_hint'] or row['tls_hint']:
        webrows.append({'ip':ip,'port':'','url':'','server_header':row['web_hint'],'title_hint':'','tls_subject':row['tls_hint'],'tls_issuer':'','tls_san':'','source_tool':'mod05','notes':''})
    # crude confirmations
    if 'domain_controller' in row['candidate_role'] and row['os_hint'].lower().find('windows')>=0:
        roles[ip]['confirmed_role']='domain_controller_candidate'
    elif 'hypervisor' in row['candidate_role'] and ('vmware' in row['web_hint'].lower() or 'proxmox' in row['web_hint'].lower()):
        roles[ip]['confirmed_role']='hypervisor_candidate'
    elif 'storage' in row['candidate_role'] and any(x in (row['web_hint']+' '+row['tls_hint']).lower() for x in ('synology','qnap')):
        roles[ip]['confirmed_role']='nas_storage_candidate'
    roles[ip]['confidence']=row['confidence']
with open(os.path.join(proc,'core_asset_fingerprint.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','hostname','segment','candidate_role','os_hint','device_hint','web_hint','tls_hint','dns_hint','admin_surface','confidence','source_tools','notes'])
    writer.writeheader(); writer.writerows(rows.values())
with open(os.path.join(proc,'web_tls_hints.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','port','url','server_header','title_hint','tls_subject','tls_issuer','tls_san','source_tool','notes'])
    writer.writeheader(); writer.writerows(webrows)
with open(os.path.join(proc,'dns_hints.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','reverse_name','forward_match','dns_hint_type','notes'])
    writer.writeheader(); writer.writerows(dnsrows)
with open(os.path.join(proc,'infra_candidates.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ip','hostname','reason','evidence','priority','promoted_by','confirmed_role','confidence','notes'])
    writer.writeheader(); writer.writerows(roles.values())
PY
  log_timeline "MOD05 completed"
}

mod06_passive() {
  log_timeline "MOD06 start"
  run_cmd "MOD06 passive capture" "$ENGAGEMENT_PATH/logs/mod06_tcpdump.log" sudo timeout 30 tcpdump -i "$IFACE" -nn -e -w "$RAW_DIR/phase2/mod06_passive_30s.pcap"
  run_cmd "MOD06 decode pcap" "$RAW_DIR/phase2/mod06_passive_30s.txt" tcpdump -nn -e -r "$RAW_DIR/phase2/mod06_passive_30s.pcap"
  run_cmd "MOD06 name services" "$RAW_DIR/phase2/mod06_passive_name_services.txt" tcpdump -nn -r "$RAW_DIR/phase2/mod06_passive_30s.pcap" 'port 53 or port 67 or port 68 or port 137 or port 5353 or port 5355'
  run_cmd "MOD06 broadcast" "$RAW_DIR/phase2/mod06_passive_broadcast.txt" tcpdump -nn -e -r "$RAW_DIR/phase2/mod06_passive_30s.pcap" 'arp or broadcast or multicast'
  python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,re,csv,json,collections
root=sys.argv[1]
raw=os.path.join(root,'raw','phase2')
proc=os.path.join(root,'processed','phase2')
rows=[]
packet_count=0
protos=collections.Counter()
name_hints=[]
for path in [os.path.join(raw,'mod06_passive_name_services.txt'), os.path.join(raw,'mod06_passive_broadcast.txt')]:
    try: lines=open(path).read().splitlines()
    except: lines=[]
    for line in lines:
        packet_count += 1
        proto=''
        if '5353' in line: proto='mdns'
        elif '5355' in line: proto='llmnr'
        elif ' 53 ' in line or '.53:' in line: proto='dns'
        elif ' 137 ' in line or '.137:' in line: proto='nbns'
        elif 'ARP' in line: proto='arp'
        elif 'DHCP' in line or 'bootp' in line.lower(): proto='dhcp'
        protos[proto or 'other'] += 1
        ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
        src_ip = ips[0] if ips else ''
        dst_ip = ips[1] if len(ips)>1 else ''
        macs = re.findall(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line, re.I)
        src_mac = macs[0].lower() if macs else ''
        dst_mac = macs[1].lower() if len(macs)>1 else ''
        name=''
        m = re.search(r'\?\s*([A-Za-z0-9_.-]+(?:\.local|\.[A-Za-z0-9_.-]+)?)', line)
        if m:
            name = m.group(1)
            name_hints.append(name)
        rows.append({'src_ip':src_ip,'src_mac':src_mac,'dst_ip':dst_ip,'dst_mac':dst_mac,'proto':proto or 'other','port':'','name_hint':name,'service_hint':proto or 'other','source_file':os.path.basename(path),'notes':''})
with open(os.path.join(proc,'passive_hints.csv'),'w',newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['src_ip','src_mac','dst_ip','dst_mac','proto','port','name_hint','service_hint','source_file','notes'])
    writer.writeheader(); writer.writerows(rows)
summary={'capture_seconds':30,'packet_count':packet_count,'protocol_hints':protos.most_common(),'name_hints':sorted(set(name_hints))[:50],'broadcast_activity':[r for r,c in protos.items() if r in ('arp','mdns','llmnr','nbns','dhcp')],'domain_hints':sorted({n.split('.',1)[1] for n in name_hints if '.' in n})[:20],'notes':[]}
json.dump(summary, open(os.path.join(proc,'passive_summary.json'),'w'), indent=2)
PY
  log_timeline "MOD06 completed"
}

build_phase2_summary() {
  python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,csv,json
root=sys.argv[1]
proc=os.path.join(root,'processed','phase2')
init=json.load(open(os.path.join(proc,'initial_access.json')))
l2=json.load(open(os.path.join(proc,'l2_summary.json')))
reach=json.load(open(os.path.join(proc,'reachability_summary.json')))
svc=json.load(open(os.path.join(proc,'service_summary.json')))
passive=json.load(open(os.path.join(proc,'passive_summary.json')))
summary={
  'engagement_id': os.path.basename(root),
  'interface': init.get('interface',''),
  'local_subnet': init.get('subnet',''),
  'gateway': init.get('gateway',''),
  'dns_servers': init.get('dns_servers',[]),
  'l2_total_hosts': l2.get('total_hosts_detected',0),
  'l3_local_hosts_up': reach.get('local_hosts_up',0),
  'remote_segments_reachable': reach.get('remote_segments_reachable',[]),
  'services_total_open': svc.get('total_open_ports',0),
  'infra_candidates': svc.get('infra_candidates_promoted',[]),
  'passive_protocols': passive.get('protocol_hints',[]),
  'verdict': 'READY' if init.get('subnet') and svc.get('total_open_ports',0) >= 0 else 'READY WITH CONSTRAINTS'
}
json.dump(summary, open(os.path.join(proc,'phase2_summary.json'),'w'), indent=2)
PY
}

print_banner
echo

if [ "$#" -ne 1 ]; then
  usage
fi

ENGAGEMENT_PATH="$1"
if [ ! -d "$ENGAGEMENT_PATH" ]; then
  echo "[!] Engagement path non trovato: ${ENGAGEMENT_PATH}"
  exit 1
fi

for dir in scope notes raw processed scans evidence report scripts; do
  if [ ! -d "${ENGAGEMENT_PATH}/${dir}" ]; then
    echo "[!] Directory mancante: ${ENGAGEMENT_PATH}/${dir}"
    exit 1
  fi
done

ENGAGEMENT_FILE="${ENGAGEMENT_PATH}/scope/engagement.yaml"
TIMELINE_FILE="${ENGAGEMENT_PATH}/notes/timeline.md"
PHASE2_NOTE_FILE="${ENGAGEMENT_PATH}/notes/phase2.md"
RAW_DIR="${ENGAGEMENT_PATH}/raw"
PROCESSED_DIR="${ENGAGEMENT_PATH}/processed"
SCANS_DIR="${ENGAGEMENT_PATH}/scans"
EVIDENCE_DIR="${ENGAGEMENT_PATH}/evidence"

if [ ! -f "$ENGAGEMENT_FILE" ]; then
  echo "[!] File mancante: ${ENGAGEMENT_FILE}"
  exit 1
fi

if ! grep -q "package_code: ASSESS" "$ENGAGEMENT_FILE"; then
  echo "[!] Questo engagement non risulta di tipo ASSESS."
  exit 1
fi

for tool in ip ethtool nmap arp-scan ping fping traceroute dig host curl openssl tcpdump jq python3 sudo; do
  require_tool "$tool"
done

bootstrap_phase_dirs
log_timeline "Avvio run_assessment.sh"

mod01_collect
mod02_l2
mod03_l3
mod04_services
mod05_core
mod06_passive
build_phase2_summary

log_timeline "Completato run_assessment.sh"

echo
for f in \
  "$PROCESSED_DIR/phase2/initial_access.json" \
  "$PROCESSED_DIR/phase2/l2_hosts.csv" \
  "$PROCESSED_DIR/phase2/live_hosts.csv" \
  "$PROCESSED_DIR/phase2/services_top.csv" \
  "$PROCESSED_DIR/phase2/infra_candidates.csv" \
  "$PROCESSED_DIR/phase2/core_asset_fingerprint.csv" \
  "$PROCESSED_DIR/phase2/passive_hints.csv" \
  "$PROCESSED_DIR/phase2/phase2_summary.json"; do
  [ -f "$f" ] && echo "[+] $f"
done
