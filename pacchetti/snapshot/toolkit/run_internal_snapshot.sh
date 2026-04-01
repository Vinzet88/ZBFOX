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
  echo "Esempio: $0 /opt/zbfox/engagements/ZBF-SNAP-INT-20260319-ACME"
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

collect_internal_scope() {
  echo "[*] Inserisci i parametri della rete interna."
  echo

  read -r -p "Subnet CIDR da analizzare (es. 192.168.17.0/24): " INTERNAL_SUBNET
  INTERNAL_SUBNET="$(echo "$INTERNAL_SUBNET" | xargs)"

  if [ -z "$INTERNAL_SUBNET" ]; then
    echo "[!] Subnet non valida."
    exit 1
  fi

  read -r -p "Host/IP da escludere (separati da virgola, es. 192.168.17.1,192.168.17.255) [opzionale]: " EXCLUDE_INPUT
  EXCLUDE_INPUT="$(echo "$EXCLUDE_INPUT" | tr -d ' ')"

  {
    echo "# Internal scope"
    echo "subnet: ${INTERNAL_SUBNET}"
    echo "exclude: ${EXCLUDE_INPUT:-none}"
  } > "${SCOPE_DIR}/internal_scope.txt"

  echo
  echo "[+] Scope interno salvato in ${SCOPE_DIR}/internal_scope.txt"
  echo
}

build_exclude_regex() {
  if [ -z "${EXCLUDE_INPUT:-}" ]; then
    EXCLUDE_REGEX=""
    return
  fi

  EXCLUDE_REGEX="$(echo "$EXCLUDE_INPUT" | sed 's/,/|/g' | sed 's/\./\\./g')"
}

run_discovery() {
  echo "[*] MOD01 - Host discovery on-site"
  log_timeline "Avvio host discovery interno"

  sudo arp-scan --localnet | tee "${RAW_DIR}/arp_scan.txt" >/dev/null
  sudo nmap -sn "${INTERNAL_SUBNET}" -oN "${RAW_DIR}/nmap_discovery.txt" >/dev/null 2>&1

  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "${RAW_DIR}/arp_scan.txt" | sort -u > "${PROCESSED_DIR}/tmp_arp.txt" || true
  grep "Nmap scan report for" "${RAW_DIR}/nmap_discovery.txt" | awk '{print $NF}' | sort -u > "${PROCESSED_DIR}/tmp_nmap.txt" || true

  cat "${PROCESSED_DIR}/tmp_arp.txt" "${PROCESSED_DIR}/tmp_nmap.txt" | sed '/^\s*$/d' | sort -u > "${PROCESSED_DIR}/targets_internal_raw.txt"

  if [ -n "${EXCLUDE_REGEX}" ]; then
    grep -vE "${EXCLUDE_REGEX}" "${PROCESSED_DIR}/targets_internal_raw.txt" > "${PROCESSED_DIR}/targets_internal.txt" || true
  else
    cp "${PROCESSED_DIR}/targets_internal_raw.txt" "${PROCESSED_DIR}/targets_internal.txt"
  fi

  rm -f "${PROCESSED_DIR}/tmp_arp.txt" "${PROCESSED_DIR}/tmp_nmap.txt" "${PROCESSED_DIR}/targets_internal_raw.txt"

  log_timeline "Host discovery interno completato"
}

run_service_scan() {
  if [ ! -s "${PROCESSED_DIR}/targets_internal.txt" ]; then
    echo "[!] Nessun target interno rilevato dopo la discovery."
    exit 1
  fi

  echo "[*] MOD02 - Service enumeration"
  log_timeline "Avvio enumerazione servizi interna"

  nmap -iL "${PROCESSED_DIR}/targets_internal.txt" \
    -sS \
    -sV \
    -T3 \
    --top-ports 100 \
    -oN "${RAW_DIR}/nmap_internal.txt" >/dev/null 2>&1

  log_timeline "Enumerazione servizi interna completata"
}

build_internal_csv() {
  echo "[*] MOD03 - Parsing risultati"

  awk '
    /^Nmap scan report for / {host=$NF}
    /^[0-9]+\/tcp/ && $2=="open" {
      split($1,p,"/")
      port=p[1]
      service=$3
      version=""
      for(i=4;i<=NF;i++) version=version $i " "
      gsub(/^[ \t]+|[ \t]+$/, "", version)
      print host "," port "," service "," version
    }
  ' "${RAW_DIR}/nmap_internal.txt" > "${PROCESSED_DIR}/internal_services.csv"

  awk -F, '
    $2 ~ /^(21|22|23|25|80|110|139|143|443|445|3389|5900|8080|8443)$/
  ' "${PROCESSED_DIR}/internal_services.csv" > "${PROCESSED_DIR}/internal_high_value_services.csv"

  awk -F, '
    $2=="21"   {print "[HIGH] FTP esposto su " $1 " -> possibile servizio legacy o trasferimento file non ottimizzato"}
    $2=="22"   {print "[MEDIUM] SSH esposto su " $1 " -> accesso remoto diretto rilevato"}
    $2=="23"   {print "[HIGH] Telnet esposto su " $1 " -> protocollo legacy non cifrato"}
    $2=="25"   {print "[MEDIUM] SMTP esposto su " $1 " -> servizio di posta accessibile"}
    $2=="80"   {print "[INFO] HTTP esposto su " $1 " -> endpoint web accessibile"}
    $2=="110"  {print "[MEDIUM] POP3 esposto su " $1 " -> servizio di posta legacy/accessibile"}
    $2=="139"  {print "[HIGH] NetBIOS esposto su " $1 " -> servizio tipicamente interno rilevato"}
    $2=="143"  {print "[MEDIUM] IMAP esposto su " $1 " -> servizio di posta accessibile"}
    $2=="443"  {print "[INFO] HTTPS esposto su " $1 " -> endpoint web cifrato accessibile"}
    $2=="445"  {print "[HIGH] SMB esposto su " $1 " -> file sharing o servizio interno accessibile"}
    $2=="3389" {print "[HIGH] RDP esposto su " $1 " -> accesso remoto Windows rilevato"}
    $2=="5900" {print "[HIGH] VNC esposto su " $1 " -> accesso remoto grafico rilevato"}
    $2=="8080" {print "[MEDIUM] Servizio web alternativo esposto su " $1 " -> possibile pannello o applicazione non standard"}
    $2=="8443" {print "[MEDIUM] HTTPS alternativo esposto su " $1 " -> possibile pannello o interfaccia amministrativa"}
  ' "${PROCESSED_DIR}/internal_services.csv" > "${PROCESSED_DIR}/internal_findings.txt"

  cut -d, -f1 "${PROCESSED_DIR}/internal_services.csv" | sort -u > "${PROCESSED_DIR}/hosts_with_open_ports.txt"

  log_timeline "Parsing e normalizzazione risultati interni completati"
}

prepare_evidence() {
  echo "[*] MOD04 - Preparazione evidenze"

  {
    echo "host_attivi: $(wc -l < "${PROCESSED_DIR}/targets_internal.txt" 2>/dev/null || echo 0)"
    echo "host_con_porte_aperte: $(wc -l < "${PROCESSED_DIR}/hosts_with_open_ports.txt" 2>/dev/null || echo 0)"
    echo "servizi_totali: $(wc -l < "${PROCESSED_DIR}/internal_services.csv" 2>/dev/null || echo 0)"
    echo "servizi_high_value: $(wc -l < "${PROCESSED_DIR}/internal_high_value_services.csv" 2>/dev/null || echo 0)"
  } > "${EVIDENCE_DIR}/summary_internal.txt"

  cp "${PROCESSED_DIR}/internal_findings.txt" "${EVIDENCE_DIR}/internal_findings_evidence.txt" 2>/dev/null || true

  log_timeline "Evidenze interne preparate"
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

for dir in scope notes raw processed evidence report; do
  if [ ! -d "${ENGAGEMENT_PATH}/${dir}" ]; then
    echo "[!] Directory mancante: ${ENGAGEMENT_PATH}/${dir}"
    exit 1
  fi
done

ENGAGEMENT_FILE="${ENGAGEMENT_PATH}/scope/engagement.yaml"
TIMELINE_FILE="${ENGAGEMENT_PATH}/notes/timeline.md"

SCOPE_DIR="${ENGAGEMENT_PATH}/scope"
RAW_DIR="${ENGAGEMENT_PATH}/raw"
PROCESSED_DIR="${ENGAGEMENT_PATH}/processed"
EVIDENCE_DIR="${ENGAGEMENT_PATH}/evidence"

if [ ! -f "$ENGAGEMENT_FILE" ]; then
  echo "[!] File mancante: ${ENGAGEMENT_FILE}"
  exit 1
fi

if ! grep -q "mode: internal" "$ENGAGEMENT_FILE"; then
  echo "[!] Questo engagement non risulta in modalità internal."
  exit 1
fi

require_tool arp-scan
require_tool nmap
require_tool awk
require_tool grep
require_tool sort

mkdir -p "$SCOPE_DIR" "$RAW_DIR" "$PROCESSED_DIR" "$EVIDENCE_DIR"

collect_internal_scope
build_exclude_regex
run_discovery
run_service_scan
build_internal_csv
prepare_evidence

log_timeline "Completato run_internal_snapshot.sh"

echo
echo "[+] Internal Snapshot completato"
echo "[+] Scope interno: ${SCOPE_DIR}/internal_scope.txt"
echo "[+] raw/arp_scan.txt"
echo "[+] raw/nmap_discovery.txt"
echo "[+] raw/nmap_internal.txt"
echo "[+] processed/targets_internal.txt"
echo "[+] processed/internal_services.csv"
echo "[+] processed/internal_high_value_services.csv"
echo "[+] processed/internal_findings.txt"
echo "[+] processed/hosts_with_open_ports.txt"
echo "[+] evidence/summary_internal.txt"
echo "[+] evidence/internal_findings_evidence.txt"
