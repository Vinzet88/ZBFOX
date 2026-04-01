#!/bin/bash

set -euo pipefail

BASE_DIR="/opt/zbfox/engagements"

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
  echo "Uso: $0 <CLIENTE>"
  echo "Esempio: $0 ACME"
  exit 1
}

sanitize_client() {
  echo "$1" \
    | tr '[:lower:]' '[:upper:]' \
    | tr ' ' '_' \
    | tr -cd 'A-Z0-9_-'
}

print_banner
echo

mkdir -p "$BASE_DIR"

if [ "$#" -ne 1 ]; then
  usage
fi

CLIENT_RAW="$1"
CLIENT="$(sanitize_client "$CLIENT_RAW")"
DATE="$(date +%Y%m%d)"
PACKAGE="ASSESS"
SCOPE_TYPE="internal_lan_assessment"
ENGAGEMENT_ID="ZBF-${PACKAGE}-${DATE}-${CLIENT}"
ENGAGEMENT_PATH="${BASE_DIR}/${ENGAGEMENT_ID}"

if [ -d "$ENGAGEMENT_PATH" ]; then
  echo "[!] Engagement già esistente: ${ENGAGEMENT_PATH}"
  exit 1
fi

echo "[*] Creazione engagement: ${ENGAGEMENT_ID}"
echo "[*] Cliente: ${CLIENT_RAW}"
echo "[*] Package: Cyber Security Assessment"
echo

mkdir -p "${ENGAGEMENT_PATH}"/{scope,notes,raw,processed,scans,evidence,report,scripts,logs,tmp}

cat > "${ENGAGEMENT_PATH}/scope/engagement.yaml" <<YAML
engagement_id: ${ENGAGEMENT_ID}
client_name: ${CLIENT_RAW}
client_code: ${CLIENT}
package: Cyber Security Assessment
package_code: ${PACKAGE}
mode: internal
scope_type: ${SCOPE_TYPE}
date: ${DATE}
analyst: ZBFOX
status: initialized

assessment_model:
  phase_1_authorization: completed_or_pending
  phase_2_collection: not_started
  phase_3_report_blocks: not_started
  phase_4_va_ingest: not_started

notes: >
  Engagement creato automaticamente tramite new_engagement_assessment.sh
YAML

cat > "${ENGAGEMENT_PATH}/scope/access_point.txt" <<EOF2
# Descrivere il punto di accesso autorizzato
# Esempi:
# Sala server - presa patch panel 12
# Ufficio amministrazione - switch piano 1
# VLAN assegnata dal cliente
EOF2

cat > "${ENGAGEMENT_PATH}/scope/network_hypothesis.md" <<EOF2
# Network Hypothesis - ${ENGAGEMENT_ID}

## Assunzioni iniziali

- Cliente potenzialmente inconsapevole della topologia reale
- Perimetro tecnico da ricostruire a partire dall'accesso LAN autorizzato
- Nessun target definito ex ante oltre al punto di ingresso
EOF2

cat > "${ENGAGEMENT_PATH}/notes/observations.md" <<EOF2
# Observations - ${ENGAGEMENT_ID}

## Initial notes

EOF2

cat > "${ENGAGEMENT_PATH}/notes/timeline.md" <<EOF2
# Timeline - ${ENGAGEMENT_ID}

- $(date '+%Y-%m-%d %H:%M:%S') - Engagement creato automaticamente
EOF2

cat > "${ENGAGEMENT_PATH}/notes/phase2.md" <<EOF2
# Phase 2 Notes - ${ENGAGEMENT_ID}

EOF2

cat > "${ENGAGEMENT_PATH}/notes/phase3.md" <<EOF2
# Phase 3 Notes - ${ENGAGEMENT_ID}

EOF2

echo "[+] Engagement creato in: ${ENGAGEMENT_PATH}"
echo "[+] File iniziali creati:"
echo "    - scope/engagement.yaml"
echo "    - scope/access_point.txt"
echo "    - scope/network_hypothesis.md"
echo "    - notes/observations.md"
echo "    - notes/timeline.md"
echo "    - notes/phase2.md"
echo "    - notes/phase3.md"
echo
echo "[+] ENGAGEMENT_PATH=${ENGAGEMENT_PATH}"
