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
  echo "Uso: $0 <CLIENTE> <MODE>"
  echo "MODE: external | internal"
  echo "Esempio: $0 ACME external"
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

if [ "$#" -ne 2 ]; then
  usage
fi

CLIENT_RAW="$1"
CLIENT="$(sanitize_client "$CLIENT_RAW")"
MODE="$2"
DATE="$(date +%Y%m%d)"

case "$MODE" in
  external)
    PACKAGE="SNAP-EXT"
    SCOPE_TYPE="external_blackbox"
    ;;
  internal)
    PACKAGE="SNAP-INT"
    SCOPE_TYPE="internal_lan"
    ;;
  *)
    echo "[!] MODE non valido. Usa: external | internal"
    exit 1
    ;;
esac

ENGAGEMENT_ID="ZBF-${PACKAGE}-${DATE}-${CLIENT}"
ENGAGEMENT_PATH="${BASE_DIR}/${ENGAGEMENT_ID}"

if [ -d "$ENGAGEMENT_PATH" ]; then
  echo "[!] Engagement già esistente: ${ENGAGEMENT_PATH}"
  exit 1
fi

echo "[*] Creazione engagement: ${ENGAGEMENT_ID}"
echo "[*] Cliente: ${CLIENT_RAW}"
echo "[*] Modalità: ${MODE}"
echo

mkdir -p "${ENGAGEMENT_PATH}"/{scope,notes,raw,processed,scans,evidence,report,scripts}

cat > "${ENGAGEMENT_PATH}/scope/engagement.yaml" <<EOF
engagement_id: ${ENGAGEMENT_ID}
client_name: ${CLIENT_RAW}
client_code: ${CLIENT}
package: Cyber Snapshot
package_code: ${PACKAGE}
mode: ${MODE}
scope_type: ${SCOPE_TYPE}
date: ${DATE}
analyst: ZBFOX
status: initialized

targets:
  - to_be_defined

notes: >
  Engagement creato automaticamente tramite new_engagement.sh
EOF

cat > "${ENGAGEMENT_PATH}/scope/targets.txt" <<EOF
# Inserire un target per riga
# Esempi:
# example.com
# portal.example.com
# 192.168.1.0/24
EOF

cat > "${ENGAGEMENT_PATH}/notes/observations.md" <<EOF
# Observations - ${ENGAGEMENT_ID}

## Initial notes

EOF

cat > "${ENGAGEMENT_PATH}/notes/timeline.md" <<EOF
# Timeline - ${ENGAGEMENT_ID}

- $(date '+%Y-%m-%d %H:%M:%S') - Engagement creato automaticamente
EOF

echo "[+] Engagement creato in: ${ENGAGEMENT_PATH}"
echo "[+] File iniziali creati:"
echo "    - scope/engagement.yaml"
echo "    - scope/targets.txt"
echo "    - notes/observations.md"
echo "    - notes/timeline.md"
echo
echo "[+] ENGAGEMENT_PATH=${ENGAGEMENT_PATH}"
