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

log_timeline() {
  local msg="$1"
  echo "- $(date '+%Y-%m-%d %H:%M:%S') - ${msg}" >> "${TIMELINE_FILE}"
}

count_file_lines() {
  local file="$1"
  if [ -f "$file" ]; then
    wc -l < "$file" | tr -d ' '
  else
    echo 0
  fi
}

safe_grep_count() {
  local pattern="$1"
  local file="$2"

  if [ ! -f "$file" ]; then
    echo 0
    return
  fi

  grep -Ec "$pattern" "$file" 2>/dev/null || true
}

append_recommendation() {
  local text="$1"
  grep -Fxq "$text" "${REPORT_DIR}/07_recommendations_auto.tmp" 2>/dev/null || echo "$text" >> "${REPORT_DIR}/07_recommendations_auto.tmp"
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
INTERNAL_SCOPE_FILE="${ENGAGEMENT_PATH}/scope/internal_scope.txt"
TIMELINE_FILE="${ENGAGEMENT_PATH}/notes/timeline.md"

RAW_DIR="${ENGAGEMENT_PATH}/raw"
PROCESSED_DIR="${ENGAGEMENT_PATH}/processed"
EVIDENCE_DIR="${ENGAGEMENT_PATH}/evidence"
REPORT_DIR="${ENGAGEMENT_PATH}/report"

TARGETS_FILE="${PROCESSED_DIR}/targets_internal.txt"
SERVICES_FILE="${PROCESSED_DIR}/internal_services.csv"
HIGH_VALUE_FILE="${PROCESSED_DIR}/internal_high_value_services.csv"
FINDINGS_FILE="${PROCESSED_DIR}/internal_findings.txt"
HOSTS_WITH_OPEN_PORTS_FILE="${PROCESSED_DIR}/hosts_with_open_ports.txt"

if [ ! -f "$ENGAGEMENT_FILE" ]; then
  echo "[!] File mancante: ${ENGAGEMENT_FILE}"
  exit 1
fi

if ! grep -q "mode: internal" "$ENGAGEMENT_FILE"; then
  echo "[!] Questo engagement non risulta in modalità internal."
  exit 1
fi

mkdir -p "$REPORT_DIR"

ENGAGEMENT_ID="$(grep '^engagement_id:' "$ENGAGEMENT_FILE" | head -1 | cut -d':' -f2- | xargs || true)"
CLIENT_NAME="$(grep '^client_name:' "$ENGAGEMENT_FILE" | head -1 | cut -d':' -f2- | xargs || true)"
DATE_VALUE="$(grep '^date:' "$ENGAGEMENT_FILE" | head -1 | cut -d':' -f2- | xargs || true)"

TOTAL_HOSTS_DISCOVERED="$(count_file_lines "$TARGETS_FILE")"
TOTAL_HOSTS_WITH_OPEN_PORTS="$(count_file_lines "$HOSTS_WITH_OPEN_PORTS_FILE")"
TOTAL_SERVICES="$(count_file_lines "$SERVICES_FILE")"
TOTAL_HIGH_VALUE_SERVICES="$(count_file_lines "$HIGH_VALUE_FILE")"

FTP_COUNT=0
SSH_COUNT=0
TELNET_COUNT=0
SMTP_COUNT=0
HTTP_COUNT=0
POP3_COUNT=0
NETBIOS_COUNT=0
IMAP_COUNT=0
HTTPS_COUNT=0
SMB_COUNT=0
RDP_COUNT=0
VNC_COUNT=0
HTTP_ALT_COUNT=0
HTTPS_ALT_COUNT=0

if [ -f "$SERVICES_FILE" ]; then
  FTP_COUNT="$(awk -F, '$2=="21"{c++} END{print c+0}' "$SERVICES_FILE")"
  SSH_COUNT="$(awk -F, '$2=="22"{c++} END{print c+0}' "$SERVICES_FILE")"
  TELNET_COUNT="$(awk -F, '$2=="23"{c++} END{print c+0}' "$SERVICES_FILE")"
  SMTP_COUNT="$(awk -F, '$2=="25"{c++} END{print c+0}' "$SERVICES_FILE")"
  HTTP_COUNT="$(awk -F, '$2=="80"{c++} END{print c+0}' "$SERVICES_FILE")"
  POP3_COUNT="$(awk -F, '$2=="110"{c++} END{print c+0}' "$SERVICES_FILE")"
  NETBIOS_COUNT="$(awk -F, '$2=="139"{c++} END{print c+0}' "$SERVICES_FILE")"
  IMAP_COUNT="$(awk -F, '$2=="143"{c++} END{print c+0}' "$SERVICES_FILE")"
  HTTPS_COUNT="$(awk -F, '$2=="443"{c++} END{print c+0}' "$SERVICES_FILE")"
  SMB_COUNT="$(awk -F, '$2=="445"{c++} END{print c+0}' "$SERVICES_FILE")"
  RDP_COUNT="$(awk -F, '$2=="3389"{c++} END{print c+0}' "$SERVICES_FILE")"
  VNC_COUNT="$(awk -F, '$2=="5900"{c++} END{print c+0}' "$SERVICES_FILE")"
  HTTP_ALT_COUNT="$(awk -F, '$2=="8080"{c++} END{print c+0}' "$SERVICES_FILE")"
  HTTPS_ALT_COUNT="$(awk -F, '$2=="8443"{c++} END{print c+0}' "$SERVICES_FILE")"
fi

HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

echo "asset,service,evidence_type,exposure,access,control,risk_level,reason" > "${PROCESSED_DIR}/internal_risk_matrix.csv"
: > "${REPORT_DIR}/07_recommendations_auto.tmp"

if [ "$FTP_COUNT" -gt 0 ]; then
  echo "internal,ftp,internal_service,medium,high,medium,HIGH,FTP interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Verificare la necessità dei servizi FTP interni e valutarne sostituzione o segmentazione, soprattutto se utilizzati per trasferimenti non controllati."
fi

if [ "$TELNET_COUNT" -gt 0 ]; then
  echo "internal,telnet,internal_service,medium,high,high,HIGH,Telnet interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Rimuovere o sostituire eventuali servizi Telnet interni, in quanto protocollo legacy non cifrato."
fi

if [ "$NETBIOS_COUNT" -gt 0 ]; then
  echo "internal,netbios,internal_service,medium,high,high,HIGH,NetBIOS interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Verificare l'esposizione di servizi NetBIOS e la reale necessità della loro disponibilità nella rete interna."
fi

if [ "$SMB_COUNT" -gt 0 ]; then
  echo "internal,smb,internal_service,medium,high,high,HIGH,SMB interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Riesaminare l'esposizione di SMB tra host interni, limitandola ai soli casi necessari e coerenti con l'operatività."
fi

if [ "$RDP_COUNT" -gt 0 ]; then
  echo "internal,rdp,internal_service,medium,high,medium,HIGH,RDP interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Verificare gli accessi RDP interni e valutarne il contenimento attraverso segmentazione, allowlist o jump host dedicati."
fi

if [ "$VNC_COUNT" -gt 0 ]; then
  echo "internal,vnc,internal_service,medium,high,medium,HIGH,VNC interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Limitare l'uso di VNC a contesti strettamente amministrativi e non diffusamente accessibili nella LAN."
fi

if [ "$SSH_COUNT" -gt 0 ]; then
  echo "internal,ssh,internal_service,medium,medium,medium,MEDIUM,SSH interno rilevato" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Verificare la coerenza dei servizi SSH interni con i reali fabbisogni amministrativi e limitarne l'esposizione laterale."
fi

if [ "$SMTP_COUNT" -gt 0 ] || [ "$POP3_COUNT" -gt 0 ] || [ "$IMAP_COUNT" -gt 0 ]; then
  echo "internal,mail,internal_service,medium,medium,medium,MEDIUM,Servizi mail interni rilevati" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Verificare che i servizi mail interni siano strettamente necessari e collocati su host coerenti con il loro ruolo."
fi

if [ "$HTTP_ALT_COUNT" -gt 0 ] || [ "$HTTPS_ALT_COUNT" -gt 0 ]; then
  echo "internal,alt_web,management_surface,medium,medium,medium,MEDIUM,Servizi web alternativi interni rilevati" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Riesaminare la presenza di servizi web su porte alternative, spesso associati a pannelli di gestione o applicazioni non standard."
fi

if [ "$HTTP_COUNT" -gt 0 ] || [ "$HTTPS_COUNT" -gt 0 ]; then
  echo "internal,web,internal_service,low,low,low,INFO,Servizi web interni rilevati" >> "${PROCESSED_DIR}/internal_risk_matrix.csv"
  INFO_COUNT=$((INFO_COUNT + 1))
fi

if [ "$HIGH_COUNT" -ge 2 ] || { [ "$HIGH_COUNT" -ge 1 ] && [ "$MEDIUM_COUNT" -ge 2 ]; }; then
  OVERALL_RISK="HIGH"
  OVERALL_REASON="La ricognizione interna evidenzia una superficie di rete con più servizi ad alto impatto potenziale, inclusi accessi remoti, protocolli legacy o componenti tipicamente sensibili alla propagazione laterale."
elif [ "$HIGH_COUNT" -ge 1 ] || [ "$MEDIUM_COUNT" -ge 2 ]; then
  OVERALL_RISK="MEDIUM"
  OVERALL_REASON="La rete interna mostra una superficie articolata, con più servizi che meritano verifica in termini di necessità, collocazione e controllo degli accessi."
else
  OVERALL_RISK="LOW"
  OVERALL_REASON="La superficie osservata appare complessivamente contenuta, pur richiedendo le normali verifiche di coerenza tra servizi attivi, ruolo degli host e necessità operative."
fi

if [ ! -s "${REPORT_DIR}/07_recommendations_auto.tmp" ]; then
  append_recommendation "- Verificare periodicamente la coerenza tra host rilevati, servizi attivi e necessità operative reali."
  append_recommendation "- Riesaminare la distribuzione dei servizi interni per ridurre superfici non necessarie e contenere il rischio di movimento laterale."
fi

{
  echo "# Sommario"
  echo
  echo "- Engagement ID: ${ENGAGEMENT_ID}"
  echo "- Cliente: ${CLIENT_NAME}"
  echo "- Data: ${DATE_VALUE}"
  echo "- Host rilevati: ${TOTAL_HOSTS_DISCOVERED}"
  echo "- Host con porte aperte: ${TOTAL_HOSTS_WITH_OPEN_PORTS}"
  echo "- Servizi totali rilevati: ${TOTAL_SERVICES}"
  echo "- Servizi high-value: ${TOTAL_HIGH_VALUE_SERVICES}"
  echo "- High findings: ${HIGH_COUNT}"
  echo "- Medium findings: ${MEDIUM_COUNT}"
  echo "- Low findings: ${LOW_COUNT}"
  echo "- Info findings: ${INFO_COUNT}"
} > "${REPORT_DIR}/01_summary_metrics.md"

{
   echo
  if [ -f "$INTERNAL_SCOPE_FILE" ]; then
    cat "$INTERNAL_SCOPE_FILE"
  else
    echo "Scope interno non disponibile."
  fi
} > "${REPORT_DIR}/02_internal_scope.md"

{
  echo
  echo "## Prime evidenze"
  echo
  echo "- Host rilevati: ${TOTAL_HOSTS_DISCOVERED}"
  echo "- Host con porte aperte: ${TOTAL_HOSTS_WITH_OPEN_PORTS}"
  echo "- Servizi totali rilevati: ${TOTAL_SERVICES}"
  echo "- Servizi high-value: ${TOTAL_HIGH_VALUE_SERVICES}"
  echo
  echo "## Campione host con porte aperte"
  echo
  if [ -f "$HOSTS_WITH_OPEN_PORTS_FILE" ] && [ -s "$HOSTS_WITH_OPEN_PORTS_FILE" ]; then
    head -20 "$HOSTS_WITH_OPEN_PORTS_FILE" | while IFS= read -r line; do
      echo "- $line"
    done
  else
    echo "- Nessun host con porte aperte rilevato"
  fi
} > "${REPORT_DIR}/03_internal_surface.md"

{
   echo
  echo "- FTP (21/tcp): ${FTP_COUNT}"
  echo "- SSH (22/tcp): ${SSH_COUNT}"
  echo "- Telnet (23/tcp): ${TELNET_COUNT}"
  echo "- SMTP (25/tcp): ${SMTP_COUNT}"
  echo "- HTTP (80/tcp): ${HTTP_COUNT}"
  echo "- POP3 (110/tcp): ${POP3_COUNT}"
  echo "- NetBIOS (139/tcp): ${NETBIOS_COUNT}"
  echo "- IMAP (143/tcp): ${IMAP_COUNT}"
  echo "- HTTPS (443/tcp): ${HTTPS_COUNT}"
  echo "- SMB (445/tcp): ${SMB_COUNT}"
  echo "- RDP (3389/tcp): ${RDP_COUNT}"
  echo "- VNC (5900/tcp): ${VNC_COUNT}"
  echo "- HTTP alternativo (8080/tcp): ${HTTP_ALT_COUNT}"
  echo "- HTTPS alternativo (8443/tcp): ${HTTPS_ALT_COUNT}"
} > "${REPORT_DIR}/04_services_detected.md"

{
 
  echo
  echo
  echo "## Finding preliminari"
  echo
  if [ -f "$FINDINGS_FILE" ] && [ -s "$FINDINGS_FILE" ]; then
    cat "$FINDINGS_FILE"
  else
    echo "Nessun finding preliminare generato."
  fi
  echo
  echo "## Servizi high-value"
  echo
  if [ -f "$HIGH_VALUE_FILE" ] && [ -s "$HIGH_VALUE_FILE" ]; then
    head -50 "$HIGH_VALUE_FILE"
  else
    echo "Nessun servizio high-value rilevato."
  fi
} > "${REPORT_DIR}/05_attention_points.md"

{
 
  echo
  echo "- Livello di rischio proposto: **${OVERALL_RISK}**"
  echo
  echo "${OVERALL_REASON}"
  echo
  } > "${REPORT_DIR}/06_risk_assessment_auto.md"

{
 
  echo
  cat "${REPORT_DIR}/07_recommendations_auto.tmp"
} > "${REPORT_DIR}/07_recommendations_auto.md"

{
  echo "# Internal Snapshot Report Draft"
  echo
  echo "## 1. Riferimenti engagement"
  echo
  cat "${REPORT_DIR}/01_summary_metrics.md"
  echo
  echo "## 2. Scope interno"
  echo
  cat "${REPORT_DIR}/02_internal_scope.md"
  echo
  echo "## 3. Superficie interna"
  echo
  cat "${REPORT_DIR}/03_internal_surface.md"
  echo
  echo "## 4. Servizi rilevati"
  echo
  cat "${REPORT_DIR}/04_services_detected.md"
  echo
  echo "## 5. Elementi di attenzione"
  echo
  cat "${REPORT_DIR}/05_attention_points.md"
  echo
  echo "## 6. Valutazione del rischio"
  echo
  cat "${REPORT_DIR}/06_risk_assessment_auto.md"
  echo
  echo "## 7. Raccomandazioni"
  echo
  cat "${REPORT_DIR}/07_recommendations_auto.md"
} > "${REPORT_DIR}/internal_snapshot_report_draft.md"

rm -f "${REPORT_DIR}/07_recommendations_auto.tmp"

log_timeline "Completato generate_internal_report_blocks.sh"

echo
echo "[+] Blocchi report interni generati"
echo "[+] ${REPORT_DIR}/01_summary_metrics.md"
echo "[+] ${REPORT_DIR}/02_internal_scope.md"
echo "[+] ${REPORT_DIR}/03_internal_surface.md"
echo "[+] ${REPORT_DIR}/04_services_detected.md"
echo "[+] ${REPORT_DIR}/05_attention_points.md"
echo "[+] ${REPORT_DIR}/06_risk_assessment_auto.md"
echo "[+] ${REPORT_DIR}/07_recommendations_auto.md"
echo "[+] ${REPORT_DIR}/internal_snapshot_report_draft.md"
echo "[+] ${PROCESSED_DIR}/internal_risk_matrix.csv"
