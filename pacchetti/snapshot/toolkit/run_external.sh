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
  echo "Esempio: $0 /opt/zbfox/engagements/ZBF-SNAP-EXT-20260319-ACME"
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

safe_name() {
  echo "$1" | tr '/:.' '___' | tr -cd '[:alnum:]_-'
}

collect_targets() {
  echo "[*] Inserisci i target esterni."
  echo "[*] Un target per riga. Riga vuota per terminare."
  echo "[*] Ammessi: domini, IP, subnet"
  echo

  : > "${TARGETS_FILE}"

  while true; do
    read -r -p "Target: " target
    target="$(echo "$target" | xargs)"

    if [ -z "$target" ]; then
      break
    fi

    echo "$target" >> "${TARGETS_FILE}"
  done

  if [ ! -s "${TARGETS_FILE}" ]; then
    echo "[!] Nessun target inserito. Uscita."
    exit 1
  fi

  sort -u "${TARGETS_FILE}" -o "${TARGETS_FILE}"

  echo
  echo "[+] Targets salvati in ${TARGETS_FILE}:"
  cat "${TARGETS_FILE}"
  echo
}

extract_osint_hosts() {
  local target="$1"

  # Estrazione conservativa: hostname e domini dalla theHarvester output
  grep -Eo '([A-Za-z0-9._-]+\.)+[A-Za-z]{2,}' "${RAW_DIR}/theharvester.txt" \
    | grep -F "$target" \
    | sort -u >> "${PROCESSED_DIR}/osint_hosts.txt" || true
}

prepare_processed_files() {
  : > "${PROCESSED_DIR}/osint_hosts.txt"
  : > "${PROCESSED_DIR}/subdomains.txt"
  : > "${PROCESSED_DIR}/all_hosts.txt"
  : > "${PROCESSED_DIR}/live_hosts.txt"
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
TARGETS_FILE="${ENGAGEMENT_PATH}/scope/targets.txt"
TIMELINE_FILE="${ENGAGEMENT_PATH}/notes/timeline.md"

RAW_DIR="${ENGAGEMENT_PATH}/raw"
PROCESSED_DIR="${ENGAGEMENT_PATH}/processed"
SCANS_DIR="${ENGAGEMENT_PATH}/scans"
EVIDENCE_DIR="${ENGAGEMENT_PATH}/evidence"

if [ ! -f "$ENGAGEMENT_FILE" ]; then
  echo "[!] File mancante: ${ENGAGEMENT_FILE}"
  exit 1
fi

if ! grep -q "mode: external" "$ENGAGEMENT_FILE"; then
  echo "[!] Questo engagement non risulta in modalità external."
  exit 1
fi

require_tool theHarvester
require_tool subfinder
require_tool amass
require_tool dnsx
require_tool httpx
require_tool nmap

mkdir -p "$RAW_DIR" "$PROCESSED_DIR" "$SCANS_DIR" "$EVIDENCE_DIR"

collect_targets
prepare_processed_files
log_timeline "Avvio run_external_snapshot.sh"

echo "[*] MOD01 - OSINT aziendale"
: > "${RAW_DIR}/theharvester.txt"

while IFS= read -r target; do
  [ -z "$target" ] && continue
  echo "[*] theHarvester -> $target"
  log_timeline "theHarvester su $target"

  theHarvester -d "$target" -b all >> "${RAW_DIR}/theharvester.txt" 2>/dev/null || true
  extract_osint_hosts "$target"
done < "${TARGETS_FILE}"

sort -u "${PROCESSED_DIR}/osint_hosts.txt" -o "${PROCESSED_DIR}/osint_hosts.txt"

echo "[*] MOD02 - Subdomain Discovery"
: > "${RAW_DIR}/subfinder.txt"

while IFS= read -r target; do
  [ -z "$target" ] && continue
  echo "[*] subfinder -> $target"
  log_timeline "subfinder su $target"

  subfinder -d "$target" -all -silent >> "${RAW_DIR}/subfinder.txt" 2>/dev/null || true
done < "${TARGETS_FILE}"

sort -u "${RAW_DIR}/subfinder.txt" > "${PROCESSED_DIR}/subdomains.txt"
cat "${PROCESSED_DIR}/osint_hosts.txt" "${PROCESSED_DIR}/subdomains.txt" \
  | sed '/^\s*$/d' \
  | sort -u > "${PROCESSED_DIR}/all_hosts.txt"

echo "[*] MOD03 - Aggressive enumeration"
: > "${RAW_DIR}/amass.txt"

WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

while IFS= read -r target; do
  [ -z "$target" ] && continue
  echo "[*] amass -> $target"
  log_timeline "amass su $target"

  timeout 180 ~/go/bin/amass enum \
    -d "$target" \
    -active \
    -w "$WORDLIST" \
    >> "${RAW_DIR}/amass.txt" 2>/dev/null || true
done < "${TARGETS_FILE}"

cat "${PROCESSED_DIR}/all_hosts.txt" "${RAW_DIR}/amass.txt" \
  | sed '/^\s*$/d' \
  | sort -u > "${PROCESSED_DIR}/all_hosts.tmp"

mv "${PROCESSED_DIR}/all_hosts.tmp" "${PROCESSED_DIR}/all_hosts.txt"

echo "[*] dnsx -> live hosts"
dnsx -l "${PROCESSED_DIR}/all_hosts.txt" -a -resp \
  | tee "${RAW_DIR}/dnsx.txt" >/dev/null || true

awk '{print $1}' "${RAW_DIR}/dnsx.txt" | sed '/^\s*$/d' | sort -u > "${PROCESSED_DIR}/live_hosts.txt"

echo "[*] httpx -> superficie web"
~/go/bin/httpx -l "${PROCESSED_DIR}/live_hosts.txt" \
  -ports 80,443,8080,8443 \
  -title \
  -status-code \
  -tech-detect \
  -ip \
  -cdn \
  -server \
  -o "${RAW_DIR}/httpx.txt" >/dev/null 2>&1 || true

echo "[*] nmap -> servizi esposti"
timeout -s TERM -k 5s 10m nmap -iL "${PROCESSED_DIR}/live_hosts.txt" \
  -sS \
  -sV \
  -T3 \
  --top-ports 100 \
  -oN "${RAW_DIR}/nmap.txt" >/dev/null 2>&1 || true

echo "[*] Preparazione evidenze sintetiche"

grep -Ei 'login|admin|dashboard|vpn|401|403|302|staging|test|dev|backup|old' "${RAW_DIR}/httpx.txt" \
  > "${EVIDENCE_DIR}/web_findings.txt" || true

grep -Ei '22/tcp|21/tcp|25/tcp|143/tcp|3389/tcp|445/tcp|5900/tcp' "${RAW_DIR}/nmap.txt" \
  > "${EVIDENCE_DIR}/exposed_services.txt" || true

{
  echo "domini_e_sottodomini: $(wc -l < "${PROCESSED_DIR}/all_hosts.txt" 2>/dev/null || echo 0)"
  echo "host_attivi: $(wc -l < "${PROCESSED_DIR}/live_hosts.txt" 2>/dev/null || echo 0)"
  echo "endpoint_web: $(wc -l < "${RAW_DIR}/httpx.txt" 2>/dev/null || echo 0)"
} > "${EVIDENCE_DIR}/summary.txt"

log_timeline "Completato run_external_snapshot.sh"

echo
echo "[+] External Snapshot completato"
echo "[+] Target: ${TARGETS_FILE}"
echo "[+] OSINT hosts: ${PROCESSED_DIR}/osint_hosts.txt"
echo "[+] Subdomains: ${PROCESSED_DIR}/subdomains.txt"
echo "[+] All hosts: ${PROCESSED_DIR}/all_hosts.txt"
echo "[+] Live hosts: ${PROCESSED_DIR}/live_hosts.txt"
echo "[+] raw/theharvester.txt"
echo "[+] raw/subfinder.txt"
echo "[+] raw/amass.txt"
echo "[+] raw/dnsx.txt"
echo "[+] raw/httpx.txt"
echo "[+] raw/nmap.txt"
echo "[+] evidence/web_findings.txt"
echo "[+] evidence/exposed_services.txt"
echo "[+] evidence/summary.txt"
