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

log_timeline() {
  local msg="$1"
  echo "- $(date '+%Y-%m-%d %H:%M:%S') - ${msg}" >> "${TIMELINE_FILE}"
}

print_banner
echo

if [ "$#" -ne 1 ]; then
  usage
fi

ENGAGEMENT_PATH="$1"
ENGAGEMENT_FILE="${ENGAGEMENT_PATH}/scope/engagement.yaml"
TIMELINE_FILE="${ENGAGEMENT_PATH}/notes/timeline.md"
RAW_DIR="${ENGAGEMENT_PATH}/raw"
PROCESSED_DIR="${ENGAGEMENT_PATH}/processed"
REPORT_DIR="${ENGAGEMENT_PATH}/report"

for dir in scope notes raw processed report; do
  if [ ! -d "${ENGAGEMENT_PATH}/${dir}" ]; then
    echo "[!] Directory mancante: ${ENGAGEMENT_PATH}/${dir}"
    exit 1
  fi
done

if ! grep -q "package_code: ASSESS" "$ENGAGEMENT_FILE"; then
  echo "[!] Questo engagement non risulta di tipo ASSESS."
  exit 1
fi

PHASE2_DIR="${PROCESSED_DIR}/phase2"
for file in initial_access.json l2_summary.json reachability_summary.json service_summary.json infra_candidates.csv phase2_summary.json; do
  if [ ! -f "${PHASE2_DIR}/${file}" ]; then
    echo "[!] File mancante: ${PHASE2_DIR}/${file}"
    exit 1
  fi
done

log_timeline "Avvio generate_assessment_report_blocks1.sh"

python3 - <<'PY' "$ENGAGEMENT_PATH"
import os,sys,csv,json,collections
root=sys.argv[1]
proc=os.path.join(root,'processed','phase2')
report=os.path.join(root,'report')
eng=os.path.join(root,'scope','engagement.yaml')
client=''; eid=''; date=''
for line in open(eng):
    if line.startswith('client_name:'): client=line.split(':',1)[1].strip()
    elif line.startswith('engagement_id:'): eid=line.split(':',1)[1].strip()
    elif line.startswith('date:'): date=line.split(':',1)[1].strip()
init=json.load(open(os.path.join(proc,'initial_access.json')))
l2=json.load(open(os.path.join(proc,'l2_summary.json')))
reach=json.load(open(os.path.join(proc,'reachability_summary.json')))
svc=json.load(open(os.path.join(proc,'service_summary.json')))
phase2=json.load(open(os.path.join(proc,'phase2_summary.json')))
infra=[]
with open(os.path.join(proc,'infra_candidates.csv')) as f: infra=list(csv.DictReader(f))
open_ports=[]
with open(os.path.join(proc,'open_ports_by_host.csv')) as f: open_ports=list(csv.DictReader(f))
core=[]
cpf=os.path.join(proc,'core_asset_fingerprint.csv')
if os.path.exists(cpf):
    with open(cpf) as f: core=list(csv.DictReader(f))
passive=[]
ppf=os.path.join(proc,'passive_summary.json')
if os.path.exists(ppf): passive=json.load(open(ppf))
# Risk matrix phase1 (pre-VA)
findings=[]
risk=[]
def add_finding(level, title, reason, category, impact, likelihood, confidence, rec=''):
    findings.append(f'[{level}] {title} -> {reason}')
    risk.append({'area':'internal','category':category,'type':title,'impact':impact,'likelihood':likelihood,'confidence':confidence,'level':level,'reason':reason})
# conditions
admin_count = len(svc.get('admin_surface_candidates',[]))
remote_count = len(reach.get('remote_segments_reachable',[]))
infra_count = len(infra)
web_count = len(svc.get('web_candidates',[]))
open_total = svc.get('total_open_ports',0)
dup_l2 = len(l2.get('suspicious_duplicates',[]))
if admin_count >= 3:
    add_finding('MEDIUM','Administrative surfaces concentration','Più superfici amministrative risultano già visibili in fase iniziale, elemento da verificare con priorità.','admin_surface','medium','high','medium')
if remote_count >= 1:
    add_finding('MEDIUM','Reachable remote segments','Dal punto di ingresso risultano raggiungibili segmenti ulteriori rispetto alla subnet locale.','segmentation','medium','medium','medium')
if infra_count == 0:
    add_finding('LOW','Weak infrastructure identification','Il fingerprint iniziale non ha ancora confermato asset core in modo robusto; possibile rete poco parlante o incompleta.','visibility','low','medium','low')
if web_count >= 2:
    add_finding('LOW','Multiple internal web surfaces','Sono presenti più superfici web interne già nelle prime fasi di ricognizione.','web_surface','low','medium','medium')
if open_total >= 100:
    add_finding('MEDIUM','Wide service exposure footprint','La prima scansione top-ports evidenzia una superficie servizi ampia.','service_exposure','medium','medium','medium')
if dup_l2 > 0:
    add_finding('LOW','L2 duplicate MAC patterns','Sono emersi MAC duplicati su IP differenti; da contestualizzare architetturalmente.','l2_anomaly','low','low','low')
level_counts=collections.Counter(r['level'] for r in risk)
if level_counts['MEDIUM'] >= 3:
    overall='MEDIUM'
    overall_reason="La fase iniziale evidenzia una superficie interna già articolata, con segmenti e superfici amministrative che meritano verifica strutturata."
elif level_counts['MEDIUM'] >= 1:
    overall='LOW-MEDIUM'
    overall_reason="La ricognizione iniziale segnala alcuni elementi di attenzione, ma la valutazione deve essere completata con l'ingest del Vulnerability Assessment."
else:
    overall='LOW'
    overall_reason="La fase iniziale non evidenzia, da sola, una criticità strutturale elevata, pur richiedendo il completamento dell'analisi VA."
# processed outputs
with open(os.path.join(root,'processed','assessment_findings_phase1.txt'),'w') as f:
    if findings: f.write('\n'.join(findings) + '\n')
with open(os.path.join(root,'processed','risk_matrix_phase1.csv'),'w',newline='') as f:
    w=csv.DictWriter(f, fieldnames=['area','category','type','impact','likelihood','confidence','level','reason'])
    w.writeheader(); w.writerows(risk)
# blocks
with open(os.path.join(report,'01_summary_metrics.md'),'w') as f:
    f.write('# Summary Metrics\n\n')
    f.write(f'- Engagement ID: {eid}\n')
    f.write(f'- Cliente: {client}\n')
    f.write(f'- Data: {date}\n')
    f.write(f'- Interfaccia di ingresso: {init.get("interface","")}\n')
    f.write(f'- Subnet locale: {init.get("subnet","")}\n')
    f.write(f'- Host L2 rilevati: {l2.get("total_hosts_detected",0)}\n')
    f.write(f'- Host L3 up: {reach.get("local_hosts_up",0)}\n')
    f.write(f'- Porte aperte rilevate (top profile): {open_total}\n')
    f.write(f'- Asset core candidati: {infra_count}\n')
    f.write(f'- Segmenti remoti raggiungibili: {len(reach.get("remote_segments_reachable",[]))}\n')
with open(os.path.join(report,'02_initial_positioning.md'),'w') as f:
    f.write('# Initial Positioning\n\n')
    f.write(f'- IP nodo: {init.get("ipv4","")}\n')
    f.write(f'- Gateway: {init.get("gateway","")}\n')
    f.write(f'- DNS: {", ".join(init.get("dns_servers",[])) or "nessuno"}\n')
    f.write(f'- Search domains: {", ".join(init.get("search_domains",[])) or "nessuno"}\n')
    f.write(f'- Route remote candidate: {", ".join(init.get("candidate_remote_routes",[])) or "nessuna"}\n')
with open(os.path.join(report,'03_internal_surface.md'),'w') as f:
    f.write('# Internal Surface\n\n')
    f.write(f'- Host L2 unici: {l2.get("unique_mac_count",0)}\n')
    f.write(f'- Top vendor: {l2.get("top_vendors",[])}\n')
    f.write(f'- Segmenti remoti confermati: {", ".join(reach.get("remote_segments_reachable",[])) or "nessuno"}\n')
with open(os.path.join(report,'04_services_detected.md'),'w') as f:
    f.write('# Services Detected\n\n')
    tops = svc.get('top_services',[])
    for name,count in tops[:15]:
        f.write(f'- {name}: {count}\n')
    f.write('\n## Host con maggiore superficie\n\n')
    for row in sorted(open_ports, key=lambda r:int(r.get('open_port_count','0')), reverse=True)[:15]:
        f.write(f"- {row['ip']} ({row['likely_role'] or 'unclassified'}) -> {row['open_port_count']} porte [{row['ports']}]\n")
with open(os.path.join(report,'05_core_assets.md'),'w') as f:
    f.write('# Core Assets\n\n')
    if not infra:
        f.write('Nessun asset core ancora promosso automaticamente.\n')
    for row in infra[:20]:
        f.write(f"- {row['ip']} -> {row['reason']} | priority={row['priority']} | confidence={row.get('confidence','')}\n")
with open(os.path.join(report,'06_risk_assessment_auto_phase1.md'),'w') as f:
    f.write('# Risk Assessment (Auto, Phase 1)\n\n')
    f.write(f'- Livello di rischio proposto: **{overall}**\n\n')
    f.write(f'{overall_reason}\n\n')
    f.write('## Finding preliminari\n\n')
    if findings:
        for line in findings: f.write(f'- {line}\n')
    else:
        f.write('- Nessun finding preliminare automatico generato.\n')
with open(os.path.join(report,'07_recommendations_auto_phase1.md'),'w') as f:
    f.write('# Recommendations (Auto, Phase 1)\n\n')
    recs = [
        'Consolidare la mappatura degli asset promossi come core candidate e verificarne il ruolo effettivo.',
        'Riesaminare le superfici amministrative interne emerse nella prima scansione top-ports.',
        'Validare la reale necessità dei segmenti remoti raggiungibili dal punto di ingresso.',
        'Integrare la lettura della postura con l ingest del Vulnerability Assessment prima della valutazione finale del rischio.'
    ]
    for rec in recs: f.write(f'- {rec}\n')
with open(os.path.join(report,'assessment_report_draft_phase1.md'),'w') as f:
    f.write('# Assessment Report Draft (Phase 1)\n\n')
    for part in ['01_summary_metrics.md','02_initial_positioning.md','03_internal_surface.md','04_services_detected.md','05_core_assets.md','06_risk_assessment_auto_phase1.md','07_recommendations_auto_phase1.md']:
        f.write(open(os.path.join(report,part)).read())
        f.write('\n\n')
PY

log_timeline "Completato generate_assessment_report_blocks1.sh"

echo
for f in \
  "$REPORT_DIR/01_summary_metrics.md" \
  "$REPORT_DIR/02_initial_positioning.md" \
  "$REPORT_DIR/03_internal_surface.md" \
  "$REPORT_DIR/04_services_detected.md" \
  "$REPORT_DIR/05_core_assets.md" \
  "$REPORT_DIR/06_risk_assessment_auto_phase1.md" \
  "$REPORT_DIR/07_recommendations_auto_phase1.md" \
  "$REPORT_DIR/assessment_report_draft_phase1.md" \
  "$ENGAGEMENT_PATH/processed/assessment_findings_phase1.txt" \
  "$ENGAGEMENT_PATH/processed/risk_matrix_phase1.csv"; do
  [ -f "$f" ] && echo "[+] $f"
done
