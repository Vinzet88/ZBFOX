#!/usr/bin/env bash
set -Eeuo pipefail

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

# Genera una bozza report Markdown leggibile a partire da:
#   - delta_summary.json
#   - delta_hosts.csv
#   - delta_services.csv
#   - manual_review_cases.csv
#   - delta_web.csv (external, se presente)
#   - delta_high_value_services.csv (internal, se presente)
#
# Output:
#   - 01_delta_summary_metrics.md
#   - 02_scope_and_inputs.md
#   - 03_host_variations.md
#   - 04_service_surface_delta.md
#   - 05_web_or_high_value_delta.md
#   - 06_surface_trend_analysis.md
#   - 07_attention_points.md
#   - 08_recommendations_delta.md
#   - snapshot_delta_report_draft.md
# ============================================================

SCRIPT_NAME="$(basename "$0")"
DELTA_DIR=""
CLIENT_ID=""

print_banner() {
  cat <<'EOF'
============================================================
 ZBFOX — Cyber Protection Continuity
 generate_report_snapshot_delta.sh
 Snapshot Surface DELTA Report Generator
============================================================
EOF
}

print_usage() {
  cat <<EOF
Uso:
  $SCRIPT_NAME \
    --delta-dir /path/to/snapshot_delta_dir \
    --client CLIENT_ID

Parametri obbligatori:
  --delta-dir   Cartella contenente delta_summary.json e i CSV DELTA
  --client      Identificativo cliente

Esempio:
  $SCRIPT_NAME \
    --delta-dir /opt/zbfox/engagements/ZBF-SNAP-EXT-20260415-CLIENTE/report/delta_ZBF-SNAP-EXT-20260324-CLIENTE_vs_ZBF-SNAP-EXT-20260415-CLIENTE \
    --client CLIENTE_X
EOF
}

die() {
  echo
  echo "[ZBFOX][ERROR] $1" >&2
  echo >&2
  print_usage >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Comando richiesto non trovato: $1"
}

parse_args() {
  [[ $# -gt 0 ]] || { print_banner; die "Nessun argomento fornito."; }
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --delta-dir)
        [[ $# -ge 2 ]] || die "Valore mancante per --delta-dir"
        DELTA_DIR="$2"
        shift 2
        ;;
      --client)
        [[ $# -ge 2 ]] || die "Valore mancante per --client"
        CLIENT_ID="$2"
        shift 2
        ;;
      -h|--help)
        print_banner
        print_usage
        exit 0
        ;;
      *)
        print_banner
        die "Argomento non riconosciuto: $1"
        ;;
    esac
  done

  [[ -n "$DELTA_DIR" ]] || die "Parametro obbligatorio mancante: --delta-dir"
  [[ -n "$CLIENT_ID" ]] || die "Parametro obbligatorio mancante: --client"
}

validate_inputs() {
  require_cmd jq
  require_cmd python3

  DELTA_DIR="$(python3 - <<'PY' "$DELTA_DIR"
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
)"

  [[ -d "$DELTA_DIR" ]] || die "Cartella DELTA non trovata: $DELTA_DIR"
  [[ -f "$DELTA_DIR/delta_summary.json" ]] || die "File mancante: $DELTA_DIR/delta_summary.json"
  [[ -f "$DELTA_DIR/delta_hosts.csv" ]] || die "File mancante: $DELTA_DIR/delta_hosts.csv"
  [[ -f "$DELTA_DIR/delta_services.csv" ]] || die "File mancante: $DELTA_DIR/delta_services.csv"
  [[ -f "$DELTA_DIR/manual_review_cases.csv" ]] || die "File mancante: $DELTA_DIR/manual_review_cases.csv"
}

main() {
  parse_args "$@"
  validate_inputs
  print_banner

  local report_dir="$DELTA_DIR/report"
  mkdir -p "$report_dir"

  local summary_json="$DELTA_DIR/delta_summary.json"
  local hosts_csv="$DELTA_DIR/delta_hosts.csv"
  local services_csv="$DELTA_DIR/delta_services.csv"
  local manual_csv="$DELTA_DIR/manual_review_cases.csv"
  local web_csv="$DELTA_DIR/delta_web.csv"
  local hv_csv="$DELTA_DIR/delta_high_value_services.csv"

  local engagement_old engagement_new mode overall_trend overall_comment
  local hosts_confirmed hosts_new hosts_missing
  local svc_new svc_removed svc_modified svc_unchanged svc_manual

  engagement_old="$(jq -r '.engagement_old // "N/A"' "$summary_json")"
  engagement_new="$(jq -r '.engagement_new // "N/A"' "$summary_json")"
  mode="$(jq -r '.mode // "N/A"' "$summary_json")"
  overall_trend="$(jq -r '.overall_trend // "N/A"' "$summary_json")"
  overall_comment="$(jq -r '.overall_comment // "N/A"' "$summary_json")"

  hosts_confirmed="$(jq -r '.host_stats.confirmed // 0' "$summary_json")"
  hosts_new="$(jq -r '.host_stats.new // 0' "$summary_json")"
  hosts_missing="$(jq -r '.host_stats.not_seen_anymore // 0' "$summary_json")"

  svc_new="$(jq -r '.service_stats.new // 0' "$summary_json")"
  svc_removed="$(jq -r '.service_stats.removed // 0' "$summary_json")"
  svc_modified="$(jq -r '.service_stats.modified // 0' "$summary_json")"
  svc_unchanged="$(jq -r '.service_stats.unchanged // 0' "$summary_json")"
  svc_manual="$(jq -r '.service_stats.manual_review // 0' "$summary_json")"

  cat > "$report_dir/01_delta_summary_metrics.md" <<EOF
## 1. Summary Metrics

- Client ID: **$CLIENT_ID**
- Snapshot precedente: **$engagement_old**
- Snapshot corrente: **$engagement_new**
- Modalità: **$mode**
- Trend complessivo della superficie: **$overall_trend**

### Host overview
- Host confermati: **$hosts_confirmed**
- Nuovi host: **$hosts_new**
- Host non più rilevati: **$hosts_missing**

### Service overview
- Nuovi servizi: **$svc_new**
- Servizi rimossi: **$svc_removed**
- Servizi modificati: **$svc_modified**
- Servizi invariati: **$svc_unchanged**
- Casi manual review: **$svc_manual**
EOF

  cat > "$report_dir/02_scope_and_inputs.md" <<EOF
## 2. Scope and Inputs

Questa analisi DELTA confronta due cicli di Snapshot riferiti allo stesso cliente e valuta come è cambiata la superficie osservata nel tempo.

Input utilizzati:
- **delta_summary.json** per il riepilogo quantitativo e il giudizio finale;
- **delta_hosts.csv** per le variazioni di perimetro e la conferma degli host;
- **delta_services.csv** per il confronto porte/servizi;
- **manual_review_cases.csv** per eventuali casi non classificabili automaticamente.
EOF

  if [[ -f "$web_csv" ]]; then
    cat >> "$report_dir/02_scope_and_inputs.md" <<EOF
- **delta_web.csv** per il confronto degli endpoint web e degli attributi applicativi.
EOF
  fi
  if [[ -f "$hv_csv" ]]; then
    cat >> "$report_dir/02_scope_and_inputs.md" <<EOF
- **delta_high_value_services.csv** per il confronto dei servizi interni a maggiore rilevanza operativa.
EOF
  fi

  cat >> "$report_dir/02_scope_and_inputs.md" <<EOF

L'obiettivo non è descrivere vulnerabilità profonde, ma leggere l'evoluzione dell'esposizione osservabile: host, porte, servizi, endpoint e variazioni di superficie.
EOF

  python3 - <<'PY' "$hosts_csv" "$services_csv" "$manual_csv" "$report_dir" "$web_csv" "$hv_csv" "$mode"
import csv, sys, os
hosts_csv, services_csv, manual_csv, report_dir, web_csv, hv_csv, mode = sys.argv[1:8]

# Host block
new_hosts = []
missing_hosts = []
confirmed_changed = []
with open(hosts_csv, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        status = row.get('host_status','')
        if status == 'NUOVO_HOST':
            new_hosts.append(row)
        elif status == 'HOST_NON_PIU_RILEVATO':
            missing_hosts.append(row)
        elif status == 'HOST_CONFERMATO' and row.get('host_surface_trend') in {'AUMENTATA','RIDOTTA'}:
            confirmed_changed.append(row)

with open(os.path.join(report_dir, '03_host_variations.md'), 'w', encoding='utf-8') as out:
    out.write('## 3. Host Variations\n\n')

    out.write('### Nuovi host rilevati\n')
    if new_hosts:
        for r in new_hosts:
            label = r.get('new_hostname') or r.get('new_ip') or r.get('new_host_key') or 'N/A'
            out.write(f"- **{label}** — open services: {r.get('new_open_services','0')}\n")
    else:
        out.write('- Nessun nuovo host rilevato.\n')
    out.write('\n')

    out.write('### Host non più rilevati\n')
    if missing_hosts:
        for r in missing_hosts:
            label = r.get('old_hostname') or r.get('old_ip') or r.get('old_host_key') or 'N/A'
            out.write(f"- **{label}** — open services precedenti: {r.get('old_open_services','0')}\n")
    else:
        out.write('- Nessun host precedentemente osservato risulta assente nel ciclo più recente.\n')
    out.write('\n')

    out.write('### Host confermati con variazione di superficie\n')
    if confirmed_changed:
        for r in confirmed_changed:
            label = r.get('new_hostname') or r.get('new_ip') or r.get('new_host_key') or 'N/A'
            out.write(f"- **{label}** — trend: {r.get('host_surface_trend','N/A')}, old services: {r.get('old_open_services','0')}, new services: {r.get('new_open_services','0')}\n")
    else:
        out.write('- Nessuna variazione host-level rilevante oltre al quadro generale già riportato.\n')
    out.write('\n')

# Services block
svc_new, svc_removed, svc_modified, svc_unchanged, svc_manual = [], [], [], [], []
with open(services_csv, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        status = row.get('service_delta_status','')
        if status == 'NUOVO_SERVIZIO':
            svc_new.append(row)
        elif status == 'SERVIZIO_RIMOSSO':
            svc_removed.append(row)
        elif status == 'SERVIZIO_MODIFICATO':
            svc_modified.append(row)
        elif status == 'SERVIZIO_INVARIATO':
            svc_unchanged.append(row)
        elif status == 'VERIFICA_MANUALE':
            svc_manual.append(row)

with open(os.path.join(report_dir, '04_service_surface_delta.md'), 'w', encoding='utf-8') as out:
    out.write('## 4. Service Surface Delta\n\n')
    sections = [
        ('Nuovi servizi', svc_new),
        ('Servizi rimossi', svc_removed),
        ('Servizi modificati', svc_modified),
        ('Servizi invariati', svc_unchanged),
        ('Verifica manuale', svc_manual),
    ]
    for title, rows in sections:
        out.write(f'### {title}\n')
        if rows:
            for r in rows[:20]:
                host = r.get('ip') or r.get('host_key') or 'N/A'
                port = r.get('port','N/A')
                proto = r.get('protocol','N/A')
                old_s = r.get('old_service','')
                new_s = r.get('new_service','')
                if title == 'Servizi rimossi':
                    desc = old_s or 'N/A'
                elif title == 'Nuovi servizi':
                    desc = new_s or 'N/A'
                else:
                    desc = f"{old_s or 'N/A'} -> {new_s or 'N/A'}"
                out.write(f"- **{host}:{port}/{proto}** — {desc}\n")
            if len(rows) > 20:
                out.write(f"- ... ulteriori {len(rows)-20} elementi omessi nella bozza sintetica\n")
        else:
            out.write('- Nessun elemento in questa categoria.\n')
        out.write('\n')

# External web OR internal high value block
with open(os.path.join(report_dir, '05_web_or_high_value_delta.md'), 'w', encoding='utf-8') as out:
    if mode == 'external' and os.path.isfile(web_csv):
        out.write('## 5. Web Exposure Delta\n\n')
        web_new, web_removed, web_modified, web_unchanged = [], [], [], []
        with open(web_csv, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                status = row.get('web_delta_status','')
                if status == 'NUOVO_ENDPOINT_WEB':
                    web_new.append(row)
                elif status == 'ENDPOINT_WEB_RIMOSSO':
                    web_removed.append(row)
                elif status == 'ENDPOINT_WEB_MODIFICATO':
                    web_modified.append(row)
                elif status == 'ENDPOINT_WEB_INVARIATO':
                    web_unchanged.append(row)

        sections = [
            ('Nuovi endpoint web', web_new),
            ('Endpoint web rimossi', web_removed),
            ('Endpoint web modificati', web_modified),
            ('Endpoint web invariati', web_unchanged),
        ]
        for title, rows in sections:
            out.write(f'### {title}\n')
            if rows:
                for r in rows[:20]:
                    url = r.get('url','N/A')
                    if title == 'Endpoint web modificati':
                        details = f"status {r.get('old_status_code','')} -> {r.get('new_status_code','')}, tech {r.get('old_tech','')} -> {r.get('new_tech','')}"
                        out.write(f"- **{url}** — {details}\n")
                    else:
                        out.write(f"- **{url}**\n")
                if len(rows) > 20:
                    out.write(f"- ... ulteriori {len(rows)-20} elementi omessi nella bozza sintetica\n")
            else:
                out.write('- Nessun elemento in questa categoria.\n')
            out.write('\n')

    elif mode == 'internal' and os.path.isfile(hv_csv):
        out.write('## 5. High-Value Services Delta\n\n')
        hv_new, hv_removed, hv_modified, hv_unchanged = [], [], [], []
        with open(hv_csv, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                status = row.get('high_value_delta_status','')
                if status == 'NUOVO_HIGH_VALUE':
                    hv_new.append(row)
                elif status == 'HIGH_VALUE_RIMOSSO':
                    hv_removed.append(row)
                elif status == 'HIGH_VALUE_MODIFICATO':
                    hv_modified.append(row)
                elif status == 'HIGH_VALUE_INVARIATO':
                    hv_unchanged.append(row)

        sections = [
            ('Nuovi high-value services', hv_new),
            ('High-value services rimossi', hv_removed),
            ('High-value services modificati', hv_modified),
            ('High-value services invariati', hv_unchanged),
        ]
        for title, rows in sections:
            out.write(f'### {title}\n')
            if rows:
                for r in rows[:20]:
                    host = r.get('ip') or r.get('host_key') or 'N/A'
                    out.write(f"- **{host}:{r.get('port','N/A')}/{r.get('protocol','N/A')}** — {r.get('service','N/A')}\n")
                if len(rows) > 20:
                    out.write(f"- ... ulteriori {len(rows)-20} elementi omessi nella bozza sintetica\n")
            else:
                out.write('- Nessun elemento in questa categoria.\n')
            out.write('\n')
    else:
        out.write('## 5. Additional Exposure Delta\n\n')
        out.write('- Nessun file aggiuntivo disponibile per endpoint web o high-value services.\n')

# Attention points from manual
manual_cases = []
with open(manual_csv, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        manual_cases.append(row)

with open(os.path.join(report_dir, '07_attention_points.md'), 'w', encoding='utf-8') as out:
    out.write('## 7. Attention Points\n\n')
    if new_hosts:
        out.write('- La presenza di nuovi host modifica il perimetro osservato e richiede una contestualizzazione operativa.\n')
    if svc_new:
        out.write('- I nuovi servizi emersi devono essere validati per capire se rappresentano espansioni attese o esposizioni non governate.\n')
    if svc_modified:
        out.write('- Le modifiche di banner, prodotto o versione indicano variazioni della superficie che meritano verifica.\n')
    if mode == 'external' and os.path.isfile(web_csv):
        out.write('- Per il perimetro external, le variazioni web vanno lette anche in chiave applicativa e non solo infrastrutturale.\n')
    if mode == 'internal' and os.path.isfile(hv_csv):
        out.write('- In ambito internal, la comparsa di servizi high-value richiede priorità superiore rispetto alle semplici variazioni di port inventory.\n')
    if manual_cases:
        out.write(f'- Sono presenti **{len(manual_cases)}** casi da verifica manuale che richiedono conferma operativa.\n')
    if not any([new_hosts, svc_new, svc_modified, manual_cases]):
        out.write('- Non emergono particolari punti di attenzione oltre al delta già classificato automaticamente.\n')

    out.write('\n### Casi da verifica manuale\n')
    if manual_cases:
        for row in manual_cases[:15]:
            out.write(f"- {row.get('case_type','N/A')}: {row.get('reason','N/A')}\n")
        if len(manual_cases) > 15:
            out.write(f"- ... ulteriori {len(manual_cases)-15} casi omessi nella bozza sintetica\n")
    else:
        out.write('- Nessun caso da verifica manuale.\n')
PY

  cat > "$report_dir/06_surface_trend_analysis.md" <<EOF
## 6. Surface Trend Analysis

Il giudizio complessivo del ciclo è **$overall_trend**.

$overall_comment

### Interpretazione operativa
- Il giudizio finale non descrive vulnerabilità profonde, ma l'andamento della superficie osservata tra i due snapshot.
- La lettura complessiva deriva dal confronto tra host, servizi, endpoint o high-value services, a seconda della modalità di acquisizione.
- Il dettaglio tecnico resta nel delta host-by-host e service-by-service, mentre questo blocco ne sintetizza il significato operativo.
EOF

  cat > "$report_dir/08_recommendations_delta.md" <<EOF
## 8. Recommendations

In base al confronto DELTA della superficie osservata, le priorità operative suggerite sono:

1. **Validare i nuovi host e i nuovi servizi**: ogni espansione del perimetro va verificata rapidamente per distinguere ciò che è atteso da ciò che non lo è.
2. **Confermare la rimozione degli elementi non più osservati**: un host o un servizio assente nel nuovo snapshot non va letto automaticamente come miglioramento senza conferma operativa.
3. **Approfondire le modifiche di superficie**: variazioni di banner, versione, stack web o servizio possono indicare cambi architetturali, aggiornamenti o nuove esposizioni.
4. **Trattare con priorità gli elementi high-value**: in ambito internal, i servizi a maggiore rilevanza operativa devono essere seguiti con particolare attenzione.
5. **Ripetere il confronto nel tempo**: il valore dello Snapshot DELTA cresce se applicato in modo continuativo su finestre temporali successive.
EOF

  cat > "$report_dir/snapshot_delta_report_draft.md" <<EOF
# ZBFOX — Cyber Protection Continuity
## Snapshot Surface DELTA Draft Report

**Client ID:** $CLIENT_ID  
**Snapshot precedente:** $engagement_old  
**Snapshot corrente:** $engagement_new  
**Modalità:** $mode  
**Trend complessivo:** $overall_trend

---

$(cat "$report_dir/01_delta_summary_metrics.md")

---

$(cat "$report_dir/02_scope_and_inputs.md")

---

$(cat "$report_dir/03_host_variations.md")

---

$(cat "$report_dir/04_service_surface_delta.md")

---

$(cat "$report_dir/05_web_or_high_value_delta.md")

---

$(cat "$report_dir/06_surface_trend_analysis.md")

---

$(cat "$report_dir/07_attention_points.md")

---

$(cat "$report_dir/08_recommendations_delta.md")
EOF

  echo
  echo "[ZBFOX][OK] Snapshot DELTA report generato."
  echo "[ZBFOX][OK] Cartella report: $report_dir"
  echo "[ZBFOX][OK] Draft finale: $report_dir/snapshot_delta_report_draft.md"
}

main "$@"
