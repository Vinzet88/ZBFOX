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

safe_grep_count_i() {
  local pattern="$1"
  local file="$2"

  if [ ! -f "$file" ]; then
    echo 0
    return
  fi

  grep -Eic "$pattern" "$file" 2>/dev/null || true
}

append_recommendation() {
  local text="$1"
  grep -Fxq "$text" "${REPORT_DIR}/06_recommendations_auto.tmp" 2>/dev/null || echo "$text" >> "${REPORT_DIR}/06_recommendations_auto.tmp"
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
TARGETS_FILE="${ENGAGEMENT_PATH}/scope/targets.txt"
TIMELINE_FILE="${ENGAGEMENT_PATH}/notes/timeline.md"

RAW_DIR="${ENGAGEMENT_PATH}/raw"
PROCESSED_DIR="${ENGAGEMENT_PATH}/processed"
EVIDENCE_DIR="${ENGAGEMENT_PATH}/evidence"
REPORT_DIR="${ENGAGEMENT_PATH}/report"

ALL_HOSTS_FILE="${PROCESSED_DIR}/all_hosts.txt"
LIVE_HOSTS_FILE="${PROCESSED_DIR}/live_hosts.txt"
HTTPX_FILE="${RAW_DIR}/httpx.txt"
NMAP_FILE="${RAW_DIR}/nmap.txt"

if [ ! -f "$ENGAGEMENT_FILE" ]; then
  echo "[!] File mancante: ${ENGAGEMENT_FILE}"
  exit 1
fi

if ! grep -q "mode: external" "$ENGAGEMENT_FILE"; then
  echo "[!] Questo engagement non risulta in modalità external."
  exit 1
fi

mkdir -p "$REPORT_DIR"

ENGAGEMENT_ID="$(grep '^engagement_id:' "$ENGAGEMENT_FILE" | head -1 | cut -d':' -f2- | xargs || true)"
CLIENT_NAME="$(grep '^client_name:' "$ENGAGEMENT_FILE" | head -1 | cut -d':' -f2- | xargs || true)"
DATE_VALUE="$(grep '^date:' "$ENGAGEMENT_FILE" | head -1 | cut -d':' -f2- | xargs || true)"

TOTAL_TARGETS="$(count_file_lines "$TARGETS_FILE")"
TOTAL_HOSTS="$(count_file_lines "$ALL_HOSTS_FILE")"
TOTAL_LIVE_HOSTS="$(count_file_lines "$LIVE_HOSTS_FILE")"
TOTAL_HTTP_ENDPOINTS="$(count_file_lines "$HTTPX_FILE")"

SSH_COUNT="$(safe_grep_count '22/tcp[[:space:]]+open' "$NMAP_FILE")"
FTP_COUNT="$(safe_grep_count '21/tcp[[:space:]]+open' "$NMAP_FILE")"
TELNET_COUNT="$(safe_grep_count '23/tcp[[:space:]]+open' "$NMAP_FILE")"
SMTP_COUNT="$(safe_grep_count '25/tcp[[:space:]]+open' "$NMAP_FILE")"
IMAP_COUNT="$(safe_grep_count '143/tcp[[:space:]]+open' "$NMAP_FILE")"
SMB_COUNT="$(safe_grep_count '445/tcp[[:space:]]+open' "$NMAP_FILE")"
RDP_COUNT="$(safe_grep_count '3389/tcp[[:space:]]+open' "$NMAP_FILE")"
VNC_COUNT="$(safe_grep_count '5900/tcp[[:space:]]+open' "$NMAP_FILE")"
HTTP_80_COUNT="$(safe_grep_count '80/tcp[[:space:]]+open' "$NMAP_FILE")"
HTTPS_443_COUNT="$(safe_grep_count '443/tcp[[:space:]]+open' "$NMAP_FILE")"

LOGIN_POINTS_COUNT="$(safe_grep_count_i 'login|admin|dashboard|vpn|signin|auth|sso' "$HTTPX_FILE")"
RESTRICTED_POINTS_COUNT="$(safe_grep_count '\[401\]|\[403\]' "$HTTPX_FILE")"
REDIRECT_COUNT="$(safe_grep_count '\[30[1278]\]' "$HTTPX_FILE")"
NONPROD_COUNT="$(safe_grep_count_i 'staging|test|dev|backup|old|preprod|internal' "$HTTPX_FILE")"

HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

: > "${PROCESSED_DIR}/external_findings.txt"
echo "asset,service,evidence_type,exposure,access,control,risk_level,reason" > "${PROCESSED_DIR}/risk_matrix.csv"
: > "${REPORT_DIR}/06_recommendations_auto.tmp"

if [ "$FTP_COUNT" -gt 0 ]; then
  echo "[HIGH] FTP esposto pubblicamente -> servizio di trasferimento file raggiungibile da Internet, da verificare con priorità." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,ftp,public_service,high,high,medium,HIGH,FTP esposto pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Verificare la necessità di eventuali servizi FTP pubblicamente esposti e valutarne rimozione, sostituzione o restrizione."
fi

if [ "$TELNET_COUNT" -gt 0 ]; then
  echo "[HIGH] Telnet esposto pubblicamente -> protocollo legacy di accesso remoto non adeguato all'esposizione Internet." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,telnet,public_service,high,high,high,HIGH,Telnet esposto pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Rimuovere con urgenza eventuali esposizioni Telnet o sostituirle con soluzioni di accesso remoto adeguatamente protette."
fi

if [ "$SMB_COUNT" -gt 0 ]; then
  echo "[HIGH] SMB esposto pubblicamente -> servizio normalmente non destinato all'esposizione Internet." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,smb,public_service,high,high,high,HIGH,SMB esposto pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Verificare immediatamente l'eventuale esposizione di servizi SMB e limitarne l'accesso a reti strettamente controllate."
fi

if [ "$RDP_COUNT" -gt 0 ]; then
  echo "[HIGH] RDP esposto pubblicamente -> accesso remoto direttamente raggiungibile da Internet." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,rdp,public_service,high,high,medium,HIGH,RDP esposto pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Riesaminare la necessità dell'esposizione diretta di RDP e applicare restrizioni, segmentazione e controlli di accesso rafforzati."
fi

if [ "$VNC_COUNT" -gt 0 ]; then
  echo "[HIGH] VNC esposto pubblicamente -> servizio di controllo remoto accessibile da Internet." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,vnc,public_service,high,high,medium,HIGH,VNC esposto pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  HIGH_COUNT=$((HIGH_COUNT + 1))
  append_recommendation "- Verificare l'esposizione di servizi VNC e limitarli a contesti amministrativi non pubblici."
fi

if [ "$SSH_COUNT" -gt 0 ]; then
  echo "[MEDIUM] SSH esposto pubblicamente -> presenza di accesso remoto tecnico direttamente raggiungibile." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,ssh,public_service,high,high,medium,MEDIUM,SSH esposto pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Verificare la necessità dei servizi SSH esposti e limitarne l'accesso dove possibile tramite allowlist, VPN o filtri dedicati."
fi

if [ "$SMTP_COUNT" -gt 0 ] || [ "$IMAP_COUNT" -gt 0 ]; then
  echo "[MEDIUM] Servizi mail esposti pubblicamente -> da verificare in relazione all'effettiva necessità operativa e alla loro configurazione." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,mail,public_service,high,medium,medium,MEDIUM,Servizi mail esposti pubblicamente" >> "${PROCESSED_DIR}/risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Verificare che i servizi mail pubblici siano strettamente necessari, coerenti con l'architettura attesa e correttamente gestiti."
fi

if [ "$LOGIN_POINTS_COUNT" -gt 0 ]; then
  echo "[MEDIUM] Interfacce di autenticazione o pannelli di accesso rilevati sulla superficie web pubblica." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,auth_panel,web_surface,high,high,medium,MEDIUM,Login o pannelli pubblici rilevati" >> "${PROCESSED_DIR}/risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Riesaminare l'esposizione delle interfacce di autenticazione pubbliche e valutarne segregazione o protezione aggiuntiva."
fi

if [ "$RESTRICTED_POINTS_COUNT" -gt 0 ]; then
  echo "[LOW] Endpoint che rispondono con 401/403 -> presenza di superfici accessibili ma soggette a controllo di accesso." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,restricted_endpoint,http_status,medium,medium,low,LOW,Endpoint 401/403 rilevati" >> "${PROCESSED_DIR}/risk_matrix.csv"
  LOW_COUNT=$((LOW_COUNT + 1))
fi

if [ "$REDIRECT_COUNT" -gt 0 ]; then
  echo "[LOW] Redirect applicativi presenti -> utile verificare verso quali componenti o flussi di accesso indirizzano." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,redirects,http_status,medium,low,low,LOW,Redirect applicativi rilevati" >> "${PROCESSED_DIR}/risk_matrix.csv"
  LOW_COUNT=$((LOW_COUNT + 1))
fi

if [ "$NONPROD_COUNT" -gt 0 ]; then
  echo "[MEDIUM] Pattern riconducibili ad ambienti non produttivi o secondari rilevati sulla superficie pubblica." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,nonprod,hostname_pattern,high,medium,medium,MEDIUM,Pattern non produttivi rilevati" >> "${PROCESSED_DIR}/risk_matrix.csv"
  MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
  append_recommendation "- Verificare che ambienti di test, staging, backup o componenti non destinati alla pubblicazione non risultino esposti inutilmente."
fi

if [ "$TOTAL_HTTP_ENDPOINTS" -gt 0 ]; then
  echo "[INFO] Superficie web pubblica rilevata -> presenza di endpoint HTTP/HTTPS raggiungibili." >> "${PROCESSED_DIR}/external_findings.txt"
  echo "internet,web_surface,http_presence,high,low,low,INFO,Endpoint web pubblici rilevati" >> "${PROCESSED_DIR}/risk_matrix.csv"
  INFO_COUNT=$((INFO_COUNT + 1))
fi

if [ "$HIGH_COUNT" -ge 2 ] || { [ "$HIGH_COUNT" -ge 1 ] && [ "$MEDIUM_COUNT" -ge 2 ]; }; then
  OVERALL_RISK="HIGH"
  OVERALL_REASON="Dall'analisi emerge una superficie di esposizione pubblica non trascurabile, con più elementi che possono costituire punti di ingresso o richiedere una verifica prioritaria."
elif [ "$HIGH_COUNT" -ge 1 ] || [ "$MEDIUM_COUNT" -ge 2 ]; then
  OVERALL_RISK="MEDIUM"
  OVERALL_REASON="L'analisi ha evidenziato una superficie esposta articolata, con asset e servizi pubblicamente raggiungibili che meritano verifica e governo strutturato."
else
  OVERALL_RISK="LOW"
  OVERALL_REASON="La superficie osservata risulta complessivamente contenuta e composta in prevalenza da servizi coerenti con una normale presenza digitale, pur richiedendo monitoraggio periodico."
fi

if [ ! -s "${REPORT_DIR}/06_recommendations_auto.tmp" ]; then
  append_recommendation "- Verificare periodicamente la necessità degli asset esposti pubblicamente e mantenerne sotto controllo configurazione e accessibilità."
  append_recommendation "- Riesaminare nel tempo la coerenza tra superficie pubblica rilevata e servizi effettivamente necessari all'operatività."
fi

{
  echo "# Summary Metrics"
  echo
  echo "- Engagement ID: ${ENGAGEMENT_ID}"
  echo "- Cliente: ${CLIENT_NAME}"
  echo "- Data: ${DATE_VALUE}"
  echo "- Target autorizzati: ${TOTAL_TARGETS}"
  echo "- Domini / host aggregati: ${TOTAL_HOSTS}"
  echo "- Host live: ${TOTAL_LIVE_HOSTS}"
  echo "- Endpoint web rilevati: ${TOTAL_HTTP_ENDPOINTS}"
  echo "- High findings: ${HIGH_COUNT}"
  echo "- Medium findings: ${MEDIUM_COUNT}"
  echo "- Low findings: ${LOW_COUNT}"
  echo "- Info findings: ${INFO_COUNT}"
} > "${REPORT_DIR}/01_summary_metrics.md"

{
  echo
  if [ -f "$TARGETS_FILE" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && echo "- $line"
    done < "$TARGETS_FILE"
  else
    echo "- Nessun target disponibile"
  fi
} > "${REPORT_DIR}/02_scope_targets.md"

{
  echo
  echo "## Prime evidenze"
  echo
  echo "- Totale domini/host aggregati: ${TOTAL_HOSTS}"
  echo "- Totale host risolti o attivi: ${TOTAL_LIVE_HOSTS}"
  echo "- Totale endpoint web pubblici rilevati: ${TOTAL_HTTP_ENDPOINTS}"
  echo
  echo "host live"
  echo
  if [ -f "$LIVE_HOSTS_FILE" ] && [ -s "$LIVE_HOSTS_FILE" ]; then
    head -20 "$LIVE_HOSTS_FILE" | while IFS= read -r line; do
      echo "- $line"
    done
  else
    echo "- Nessun host live rilevato"
  fi
} > "${REPORT_DIR}/03_exposed_surface.md"

{
 
  echo
  echo "- HTTP (80/tcp): ${HTTP_80_COUNT}"
  echo "- HTTPS (443/tcp): ${HTTPS_443_COUNT}"
  echo "- SSH (22/tcp): ${SSH_COUNT}"
  echo "- FTP (21/tcp): ${FTP_COUNT}"
  echo "- Telnet (23/tcp): ${TELNET_COUNT}"
  echo "- SMTP (25/tcp): ${SMTP_COUNT}"
  echo "- IMAP (143/tcp): ${IMAP_COUNT}"
  echo "- SMB (445/tcp): ${SMB_COUNT}"
  echo "- RDP (3389/tcp): ${RDP_COUNT}"
  echo "- VNC (5900/tcp): ${VNC_COUNT}"
} > "${REPORT_DIR}/04_services_detected.md"

{
 
  echo
  echo "- Endpoint con login/admin/dashboard/vpn/auth/sso: ${LOGIN_POINTS_COUNT}"
  echo "- Endpoint con stato 401/403: ${RESTRICTED_POINTS_COUNT}"
  echo "- Redirect applicativi (30x): ${REDIRECT_COUNT}"
  echo "- Pattern riconducibili a test/staging/dev/backup: ${NONPROD_COUNT}"
  echo
  echo "## Finding preliminari"
  echo
  if [ -s "${PROCESSED_DIR}/external_findings.txt" ]; then
    cat "${PROCESSED_DIR}/external_findings.txt"
  else
    echo "Nessun finding preliminare generato."
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
  cat "${REPORT_DIR}/06_recommendations_auto.tmp"
} > "${REPORT_DIR}/07_recommendations_auto.md"

{
  echo "# External Snapshot Report Draft"
  echo
  echo "## 1. Riferimenti engagement"
  echo
  cat "${REPORT_DIR}/01_summary_metrics.md"
  echo
  echo "## 2. Target autorizzati"
  echo
  cat "${REPORT_DIR}/02_scope_targets.md"
  echo
  echo "## 3. Superficie esposta"
  echo
  cat "${REPORT_DIR}/03_exposed_surface.md"
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
} > "${REPORT_DIR}/external_snapshot_report_draft.md"

rm -f "${REPORT_DIR}/06_recommendations_auto.tmp"

log_timeline "Completato generate_external_report_blocks.sh"

echo
echo "[+] Blocchi report generati"
echo "[+] ${REPORT_DIR}/01_summary_metrics.md"
echo "[+] ${REPORT_DIR}/02_scope_targets.md"
echo "[+] ${REPORT_DIR}/03_exposed_surface.md"
echo "[+] ${REPORT_DIR}/04_services_detected.md"
echo "[+] ${REPORT_DIR}/05_attention_points.md"
echo "[+] ${REPORT_DIR}/06_risk_assessment_auto.md"
echo "[+] ${REPORT_DIR}/07_recommendations_auto.md"
echo "[+] ${REPORT_DIR}/external_snapshot_report_draft.md"
echo "[+] ${PROCESSED_DIR}/external_findings.txt"
echo "[+] ${PROCESSED_DIR}/risk_matrix.csv"
