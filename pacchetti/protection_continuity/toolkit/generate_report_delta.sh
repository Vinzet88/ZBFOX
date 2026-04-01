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
#   - delta_findings.csv
#   - manual_review_cases.csv
#
# Output:
#   - 01_delta_summary_metrics.md
#   - 02_scope_and_inputs.md
#   - 03_host_variations.md
#   - 04_vulnerability_delta.md
#   - 05_risk_trend_analysis.md
#   - 06_attention_points.md
#   - 07_recommendations_delta.md
#   - continuity_report_draft.md
#
# Uso:
#   generate_report_delta.sh \
#     --delta-dir /path/to/delta_dir \
#     --client CLIENT_ID
#
# Requisiti:
#   - jq
#   - python3
# ============================================================

SCRIPT_NAME="$(basename "$0")"
DELTA_DIR=""
CLIENT_ID=""

print_banner() {
  cat <<'EOF'
============================================================
 ZBFOX — Cyber Protection Continuity
 generate_report_delta.sh
 DELTA Report Draft Generator
============================================================
EOF
}

print_usage() {
  cat <<EOF
Uso:
  $SCRIPT_NAME \
    --delta-dir /path/to/delta_dir \
    --client CLIENT_ID

Parametri obbligatori:
  --delta-dir   Cartella contenente delta_summary.json e i CSV DELTA
  --client      Identificativo cliente

Esempio:
  $SCRIPT_NAME \
    --delta-dir /opt/zbfox/engagements/ZBF-ASSESS-20260326-H2/report/delta_ZBF-ASSESS-20260326-H1_vs_ZBF-ASSESS-20260326-H2 \
    --client ZBFOX_LAB
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
  [[ -f "$DELTA_DIR/delta_findings.csv" ]] || die "File mancante: $DELTA_DIR/delta_findings.csv"
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
  local findings_csv="$DELTA_DIR/delta_findings.csv"
  local manual_csv="$DELTA_DIR/manual_review_cases.csv"

  local engagement_old engagement_new overall_trend overall_comment
  local hosts_confirmed hosts_new hosts_missing
  local resolved persistent worsened newfind partial_low partial_medium partial_high manual_total
  local high_old high_new medium_old medium_new low_old low_new crit_old crit_new
  local score_old score_new score_delta

  engagement_old="$(jq -r '.engagement_old // "N/A"' "$summary_json")"
  engagement_new="$(jq -r '.engagement_new // "N/A"' "$summary_json")"
  overall_trend="$(jq -r '.overall_trend // "N/A"' "$summary_json")"
  overall_comment="$(jq -r '.overall_comment // "N/A"' "$summary_json")"

  hosts_confirmed="$(jq -r '.host_stats.confirmed // 0' "$summary_json")"
  hosts_new="$(jq -r '.host_stats.new // 0' "$summary_json")"
  hosts_missing="$(jq -r '.host_stats.not_seen_anymore // 0' "$summary_json")"

  resolved="$(jq -r '.finding_stats.resolved // 0' "$summary_json")"
  persistent="$(jq -r '.finding_stats.persistent // 0' "$summary_json")"
  worsened="$(jq -r '.finding_stats.worsened // 0' "$summary_json")"
  newfind="$(jq -r '.finding_stats.new // 0' "$summary_json")"
  partial_low="$(jq -r '.finding_stats.partial_low // 0' "$summary_json")"
  partial_medium="$(jq -r '.finding_stats.partial_medium // 0' "$summary_json")"
  partial_high="$(jq -r '.finding_stats.partial_high // 0' "$summary_json")"
  manual_total="$(jq -r '.finding_stats.manual_review // 0' "$summary_json")"

  crit_old="$(jq -r '.severity_stats.critical_old_total // 0' "$summary_json")"
  crit_new="$(jq -r '.severity_stats.critical_new_total // 0' "$summary_json")"
  high_old="$(jq -r '.severity_stats.high_old_total // 0' "$summary_json")"
  high_new="$(jq -r '.severity_stats.high_new_total // 0' "$summary_json")"
  medium_old="$(jq -r '.severity_stats.medium_old_total // 0' "$summary_json")"
  medium_new="$(jq -r '.severity_stats.medium_new_total // 0' "$summary_json")"
  low_old="$(jq -r '.severity_stats.low_old_total // 0' "$summary_json")"
  low_new="$(jq -r '.severity_stats.low_new_total // 0' "$summary_json")"

  score_old="$(jq -r '.risk_scoring.score_old // 0' "$summary_json")"
  score_new="$(jq -r '.risk_scoring.score_new // 0' "$summary_json")"
  score_delta="$(jq -r '.risk_scoring.score_delta // 0' "$summary_json")"

  # Block 01 - summary metrics
  cat > "$report_dir/01_delta_summary_metrics.md" <<EOF
## 1. Summary Metrics

- Client ID: **$CLIENT_ID**
- Assessment precedente: **$engagement_old**
- Assessment corrente: **$engagement_new**
- Trend complessivo: **$overall_trend**
- Risk score precedente: **$score_old**
- Risk score corrente: **$score_new**
- Delta score: **$score_delta**

### Host overview
- Host confermati: **$hosts_confirmed**
- Nuovi host: **$hosts_new**
- Host non più rilevati: **$hosts_missing**

### Finding overview
- Vulnerabilità risolte: **$resolved**
- Vulnerabilità parzialmente risolte: **$((partial_low + partial_medium + partial_high))**
- Vulnerabilità persistenti: **$persistent**
- Vulnerabilità peggiorate: **$worsened**
- Vulnerabilità nuove: **$newfind**
- Casi da verifica manuale: **$manual_total**
EOF

  # Block 02 - scope and inputs
  cat > "$report_dir/02_scope_and_inputs.md" <<EOF
## 2. Scope and Inputs

Questa analisi DELTA confronta due cicli di Assessment riferiti allo stesso perimetro operativo, utilizzando come base i file prodotti dal motore di confronto ZBFOX.

Input utilizzati:
- \
	t**delta_summary.json** per il riepilogo quantitativo e il trend complessivo;
- \
	t**delta_hosts.csv** per le variazioni di perimetro e la conferma degli host osservati;
- \
	t**delta_findings.csv** per il confronto vulnerabilità-per-vulnerabilità;
- \
	t**manual_review_cases.csv** per eventuali casi non classificabili automaticamente.

L'obiettivo non è solo misurare la differenza numerica tra i due assessment, ma interpretare in modo ordinato come è cambiata la postura di rischio osservata.
EOF

  # Prepare summaries from CSV via Python
  python3 - <<'PY' "$hosts_csv" "$findings_csv" "$manual_csv" "$report_dir"
import csv, sys, os
hosts_csv, findings_csv, manual_csv, report_dir = sys.argv[1:5]

# Host blocks
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
        elif status == 'HOST_CONFERMATO' and row.get('host_risk_trend') in {'MIGLIORATO','PEGGIORATO'}:
            confirmed_changed.append(row)

with open(os.path.join(report_dir, '03_host_variations.md'), 'w', encoding='utf-8') as out:
    out.write('## 3. Host Variations\n\n')
    if new_hosts:
        out.write('### Nuovi host rilevati\n')
        for r in new_hosts:
            out.write(f"- **{r.get('new_host') or 'N/A'}** ({r.get('new_hostname') or 'hostname assente'}) — findings: {r.get('new_findings_total','0')}, high: {r.get('new_high','0')}, critical: {r.get('new_critical','0')}\n")
        out.write('\n')
    else:
        out.write('### Nuovi host rilevati\n- Nessun nuovo host rilevato.\n\n')

    if missing_hosts:
        out.write('### Host non più rilevati\n')
        for r in missing_hosts:
            out.write(f"- **{r.get('old_host') or 'N/A'}** ({r.get('old_hostname') or 'hostname assente'}) — findings precedenti: {r.get('old_findings_total','0')}\n")
        out.write('\n')
    else:
        out.write('### Host non più rilevati\n- Nessun host precedentemente osservato risulta assente nel ciclo più recente.\n\n')

    if confirmed_changed:
        out.write('### Host confermati con variazione di trend\n')
        for r in confirmed_changed:
            out.write(f"- **{r.get('new_host') or r.get('old_host') or 'N/A'}** — trend: {r.get('host_risk_trend','N/A')}, old findings: {r.get('old_findings_total','0')}, new findings: {r.get('new_findings_total','0')}\n")
        out.write('\n')
    else:
        out.write('### Host confermati con variazione di trend\n- Nessuna variazione host-level particolarmente rilevante oltre al quadro generale già riportato.\n\n')

# Findings blocks
resolved = []
partial = []
persistent = []
worsened = []
newf = []
manual = []
with open(findings_csv, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        status = row.get('delta_status','')
        if status == 'RISOLTA':
            resolved.append(row)
        elif status == 'PARZIALMENTE_RISOLTA':
            partial.append(row)
        elif status == 'PERSISTENTE':
            persistent.append(row)
        elif status == 'PEGGIORATA':
            worsened.append(row)
        elif status == 'NUOVA':
            newf.append(row)
        elif status == 'VERIFICA_MANUALE':
            manual.append(row)

def fmt(row, old=False):
    host = row.get('old_host' if old else 'new_host') or row.get('old_host') or row.get('new_host') or 'N/A'
    port = row.get('port','N/A')
    title = row.get('old_name' if old else 'new_name') or row.get('old_name') or row.get('new_name') or 'N/A'
    sev = row.get('old_severity_label' if old else 'new_severity_label') or row.get('old_severity_label') or row.get('new_severity_label') or 'N/A'
    return f"- **{host}:{port}** — {title} [{sev}]"

with open(os.path.join(report_dir, '04_vulnerability_delta.md'), 'w', encoding='utf-8') as out:
    out.write('## 4. Vulnerability Delta\n\n')
    sections = [
        ('Risolte', resolved, True),
        ('Parzialmente risolte', partial, False),
        ('Persistenti', persistent, False),
        ('Peggiorate', worsened, False),
        ('Nuove', newf, False),
        ('Verifica manuale', manual, False),
    ]
    for title, rows, old in sections:
        out.write(f'### {title}\n')
        if rows:
            for row in rows[:15]:
                line = fmt(row, old=old)
                if row.get('delta_status') == 'PARZIALMENTE_RISOLTA':
                    line += f" — livello: {row.get('remediation_level','N/A')}"
                out.write(line + '\n')
            if len(rows) > 15:
                out.write(f"- ... ulteriori {len(rows)-15} elementi omessi nella bozza sintetica\n")
        else:
            out.write('- Nessun elemento in questa categoria.\n')
        out.write('\n')

# Manual review block from dedicated CSV if needed
manual_cases = []
with open(manual_csv, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        manual_cases.append(row)

with open(os.path.join(report_dir, '06_attention_points.md'), 'w', encoding='utf-8') as out:
    out.write('## 6. Attention Points\n\n')
    if worsened:
        out.write('- Sono presenti vulnerabilità peggiorate rispetto al ciclo precedente; queste richiedono priorità elevata.\n')
    if newf:
        out.write('- Sono emerse nuove vulnerabilità nel ciclo più recente; va verificata l’origine del nuovo rischio osservato.\n')
    if persistent:
        out.write('- Permane un gruppo di vulnerabilità persistenti: il delta è positivo solo in parte e richiede continuità di follow-up.\n')
    if manual_cases:
        out.write(f'- Sono presenti **{len(manual_cases)}** casi da verifica manuale; il giudizio automatico non è sufficiente per quei finding/host.\n')
    if not any([worsened, newf, persistent, manual_cases]):
        out.write('- Non emergono elementi di attenzione oltre al delta già classificato automaticamente.\n')

    out.write('\n### Casi da verifica manuale\n')
    if manual_cases:
        for row in manual_cases[:15]:
            out.write(f"- {row.get('case_type','N/A')}: {row.get('reason','N/A')}\n")
        if len(manual_cases) > 15:
            out.write(f"- ... ulteriori {len(manual_cases)-15} casi omessi nella bozza sintetica\n")
    else:
        out.write('- Nessun caso da verifica manuale.\n')
PY

  # Block 05 - risk trend analysis
  cat > "$report_dir/05_risk_trend_analysis.md" <<EOF
## 5. Risk Trend Analysis

Il giudizio complessivo del ciclo è **$overall_trend**.

$overall_comment

### Severity trend
- Critical: **$crit_old → $crit_new**
- High: **$high_old → $high_new**
- Medium: **$medium_old → $medium_new**
- Low: **$low_old → $low_new**

### Interpretazione operativa
- Il rischio osservato viene valutato sulla base del confronto puntuale tra vulnerabilità risolte, persistenti, nuove o peggiorate.
- Il delta score (**$score_delta**) esprime la variazione aggregata del carico di rischio tra i due assessment.
- Il giudizio finale non sostituisce il dettaglio tecnico del confronto finding-by-finding, ma lo sintetizza in una lettura operativa complessiva.
EOF

  # Block 07 - recommendations
  cat > "$report_dir/07_recommendations_delta.md" <<EOF
## 7. Recommendations

In base al confronto DELTA, le priorità operative suggerite sono:

1. **Chiudere il residuo persistente**: le vulnerabilità ancora presenti rappresentano il backlog reale del percorso di remediation.
2. **Verificare le vulnerabilità ad alta severità residue**: anche in un quadro migliorato, la permanenza di finding high/critical richiede attenzione prioritaria.
3. **Confermare la natura dei nuovi host**: i nuovi elementi di perimetro devono essere validati e contestualizzati rapidamente.
4. **Rieseguire il ciclo di confronto nel tempo**: il valore del DELTA aumenta se applicato in modo continuativo su coppie di assessment successive.
5. **Trattare separatamente i casi dubbi**: ogni finding o host in verifica manuale va escluso da conclusioni troppo assertive finché non viene chiarito.
EOF

  # Final draft
  cat > "$report_dir/continuity_report_draft.md" <<EOF
# ZBFOX — Cyber Protection Continuity
## Assessment DELTA Draft Report

**Client ID:** $CLIENT_ID  
**Assessment precedente:** $engagement_old  
**Assessment corrente:** $engagement_new  
**Trend complessivo:** $overall_trend

---

$(cat "$report_dir/01_delta_summary_metrics.md")

---

$(cat "$report_dir/02_scope_and_inputs.md")

---

$(cat "$report_dir/03_host_variations.md")

---

$(cat "$report_dir/04_vulnerability_delta.md")

---

$(cat "$report_dir/05_risk_trend_analysis.md")

---

$(cat "$report_dir/06_attention_points.md")

---

$(cat "$report_dir/07_recommendations_delta.md")
EOF

  echo
  echo "[ZBFOX][OK] Report DELTA generato."
  echo "[ZBFOX][OK] Cartella report: $report_dir"
  echo "[ZBFOX][OK] Draft finale: $report_dir/continuity_report_draft.md"
}

main "$@"
