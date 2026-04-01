#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# ZBFOX — Cyber Protection Continuity
# compare_assessment.sh
# ------------------------------------------------------------
# Wrapper per il confronto tra due engagement Assessment
# tramite motore Python compare_assessment_delta.py
#
# Output principali:
#   - delta_hosts.csv
#   - delta_findings.csv
#   - delta_summary.json
#   - manual_review_cases.csv
#   - delta_log.txt
#
# Uso previsto:
#   compare_assessment.sh \
#     --old /path/to/ASSESSMENT_OLD \
#     --new /path/to/ASSESSMENT_NEW \
#     --client CLIENTE_X \
#     --engine /path/to/compare_assessment_delta.py
#
# Note:
# - Se --engine non viene fornito, il wrapper cerca
#   compare_assessment_delta.py nella stessa cartella dello script.
# - Se --output-dir non viene fornito, viene creato in automatico
#   dentro il path del nuovo engagement.
# ============================================================

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ENGINE="$SCRIPT_DIR/compare_assessment_delta.py"
SECONDARY_ENGINE_1="/opt/zbfox/scripts/compare_assessment_delta.py"
SECONDARY_ENGINE_2="/opt/zbfox/continuity/compare_assessment_delta.py"

OLD_ENGAGEMENT=""
NEW_ENGAGEMENT=""
CLIENT_ID=""
ENGINE_PATH=""
OUTPUT_DIR=""
OLD_JSON=""
NEW_JSON=""

print_banner() {
  cat <<'EOF'
============================================================
 ZBFOX — Cyber Protection Continuity
 compare_assessment.sh
 Assessment DELTA & Risk Trend Engine Wrapper
============================================================
EOF
}

print_usage() {
  cat <<EOF
Uso:
  $SCRIPT_NAME \
    --old /path/to/ASSESSMENT_OLD \
    --new /path/to/ASSESSMENT_NEW \
    --client CLIENTE_X \
    [--engine /path/to/compare_assessment_delta.py] \
    [--output-dir /path/to/output_delta] \
    [--old-json /path/to/old/openvas_parsed.json] \
    [--new-json /path/to/new/openvas_parsed.json]

Parametri obbligatori:
  --old         Path dell'engagement Assessment precedente
  --new         Path dell'engagement Assessment più recente
  --client      Identificativo cliente

Parametri opzionali:
  --engine      Path del motore Python compare_assessment_delta.py
                Default: stessa cartella del wrapper
  --output-dir  Cartella output DELTA personalizzata
  --old-json    Path esplicito del JSON parsato vecchio
  --new-json    Path esplicito del JSON parsato nuovo
  -h, --help    Mostra questo messaggio

Ricerca automatica dei JSON:
  Se --old-json / --new-json non vengono forniti, il wrapper prova a trovare
  openvas_parsed.json nei path engagement indicati, cercando in:
    1) <engagement>/report/openvas_parsed.json
    2) <engagement>/processed/openvas_parsed.json
    3) <engagement>/openvas_parsed.json
    4) primo file chiamato openvas_parsed.json sotto l'engagement

Output predefinito:
  Se --output-dir non viene fornito, il DELTA viene scritto in:
    <new_engagement>/report/delta_<old_basename>_vs_<new_basename>/

Esempio corretto:
  $SCRIPT_NAME \
    --old /opt/zbfox/engagements/ZBF-ASSESS-20260324-LAN \
    --new /opt/zbfox/engagements/ZBF-ASSESS-20260415-LAN \
    --client ZBFOX_LAB

Esempio con engine esplicito:
  $SCRIPT_NAME \
    --old /data/CLIENTE_X/ASSESSMENT_2026-01-15 \
    --new /data/CLIENTE_X/ASSESSMENT_2026-03-15 \
    --client CLIENTE_X \
    --engine /opt/zbfox/continuity/compare_assessment_delta.py

Esempio ERRATO:
  $SCRIPT_NAME --old /data/old --new /data/new

Perché è errato:
  manca il parametro obbligatorio --client

EOF
}

die() {
  local msg="$1"
  echo
  echo "[ZBFOX][ERROR] $msg" >&2
  echo >&2
  print_usage >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Comando richiesto non trovato: $cmd"
}

abs_path() {
  local p="$1"
  if [[ -z "$p" ]]; then
    return 1
  fi
  python3 - <<'PY' "$p"
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
}

find_openvas_json() {
  local engagement="$1"
  local candidate=""

  if [[ -f "$engagement/report/openvas_parsed.json" ]]; then
    echo "$engagement/report/openvas_parsed.json"
    return 0
  fi

  if [[ -f "$engagement/processed/openvas_parsed.json" ]]; then
    echo "$engagement/processed/openvas_parsed.json"
    return 0
  fi

  if [[ -f "$engagement/openvas_parsed.json" ]]; then
    echo "$engagement/openvas_parsed.json"
    return 0
  fi

  candidate="$(find "$engagement" -type f -name 'openvas_parsed.json' 2>/dev/null | head -n 1 || true)"
  if [[ -n "$candidate" && -f "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

build_default_output_dir() {
  local old_base new_base
  old_base="$(basename "$OLD_ENGAGEMENT")"
  new_base="$(basename "$NEW_ENGAGEMENT")"
  echo "$NEW_ENGAGEMENT/report/delta_${old_base}_vs_${new_base}"
}

parse_args() {
  if [[ $# -eq 0 ]]; then
    print_banner
    die "Nessun argomento fornito."
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --old)
        [[ $# -ge 2 ]] || die "Valore mancante per --old"
        OLD_ENGAGEMENT="$2"
        shift 2
        ;;
      --new)
        [[ $# -ge 2 ]] || die "Valore mancante per --new"
        NEW_ENGAGEMENT="$2"
        shift 2
        ;;
      --client)
        [[ $# -ge 2 ]] || die "Valore mancante per --client"
        CLIENT_ID="$2"
        shift 2
        ;;
      --engine)
        [[ $# -ge 2 ]] || die "Valore mancante per --engine"
        ENGINE_PATH="$2"
        shift 2
        ;;
      --output-dir)
        [[ $# -ge 2 ]] || die "Valore mancante per --output-dir"
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --old-json)
        [[ $# -ge 2 ]] || die "Valore mancante per --old-json"
        OLD_JSON="$2"
        shift 2
        ;;
      --new-json)
        [[ $# -ge 2 ]] || die "Valore mancante per --new-json"
        NEW_JSON="$2"
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

  [[ -n "$OLD_ENGAGEMENT" ]] || die "Parametro obbligatorio mancante: --old"
  [[ -n "$NEW_ENGAGEMENT" ]] || die "Parametro obbligatorio mancante: --new"
  [[ -n "$CLIENT_ID" ]] || die "Parametro obbligatorio mancante: --client"
}

validate_inputs() {
  require_cmd python3
  require_cmd find

  OLD_ENGAGEMENT="$(abs_path "$OLD_ENGAGEMENT")"
  NEW_ENGAGEMENT="$(abs_path "$NEW_ENGAGEMENT")"

  [[ -d "$OLD_ENGAGEMENT" ]] || die "Path engagement vecchio non valido o inesistente: $OLD_ENGAGEMENT"
  [[ -d "$NEW_ENGAGEMENT" ]] || die "Path engagement nuovo non valido o inesistente: $NEW_ENGAGEMENT"

  if [[ -z "$ENGINE_PATH" ]]; then
    if [[ -f "$DEFAULT_ENGINE" ]]; then
      ENGINE_PATH="$DEFAULT_ENGINE"
    elif [[ -f "$SECONDARY_ENGINE_1" ]]; then
      ENGINE_PATH="$SECONDARY_ENGINE_1"
    elif [[ -f "$SECONDARY_ENGINE_2" ]]; then
      ENGINE_PATH="$SECONDARY_ENGINE_2"
    else
      ENGINE_PATH="$DEFAULT_ENGINE"
    fi
  fi
  ENGINE_PATH="$(abs_path "$ENGINE_PATH")"
  [[ -f "$ENGINE_PATH" ]] || die "Motore Python non trovato: $ENGINE_PATH"

  if [[ -z "$OLD_JSON" ]]; then
    OLD_JSON="$(find_openvas_json "$OLD_ENGAGEMENT" || true)"
  fi
  if [[ -z "$NEW_JSON" ]]; then
    NEW_JSON="$(find_openvas_json "$NEW_ENGAGEMENT" || true)"
  fi

  [[ -n "$OLD_JSON" ]] || die "Impossibile individuare openvas_parsed.json nel vecchio engagement"
  [[ -n "$NEW_JSON" ]] || die "Impossibile individuare openvas_parsed.json nel nuovo engagement"

  OLD_JSON="$(abs_path "$OLD_JSON")"
  NEW_JSON="$(abs_path "$NEW_JSON")"

  [[ -f "$OLD_JSON" ]] || die "File JSON vecchio non trovato: $OLD_JSON"
  [[ -f "$NEW_JSON" ]] || die "File JSON nuovo non trovato: $NEW_JSON"

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$(build_default_output_dir)"
  fi
  OUTPUT_DIR="$(abs_path "$OUTPUT_DIR")"
  mkdir -p "$OUTPUT_DIR"
}

run_engine() {
  print_banner
  cat <<EOF
[ZBFOX][INFO] Client ID        : $CLIENT_ID
[ZBFOX][INFO] Old engagement   : $OLD_ENGAGEMENT
[ZBFOX][INFO] New engagement   : $NEW_ENGAGEMENT
[ZBFOX][INFO] Old JSON         : $OLD_JSON
[ZBFOX][INFO] New JSON         : $NEW_JSON
[ZBFOX][INFO] Engine           : $ENGINE_PATH
[ZBFOX][INFO] Output directory : $OUTPUT_DIR
EOF
  echo
  echo "[ZBFOX][INFO] Avvio confronto Assessment DELTA..."
  echo

  python3 "$ENGINE_PATH" \
    --old-engagement "$OLD_ENGAGEMENT" \
    --new-engagement "$NEW_ENGAGEMENT" \
    --old-openvas-json "$OLD_JSON" \
    --new-openvas-json "$NEW_JSON" \
    --output-dir "$OUTPUT_DIR" \
    --client-id "$CLIENT_ID"

  echo
  echo "[ZBFOX][OK] Assessment DELTA completato."
  echo "[ZBFOX][OK] Output disponibili in: $OUTPUT_DIR"
  echo
  echo "[ZBFOX][OK] File principali:"
  echo "  - $OUTPUT_DIR/delta_hosts.csv"
  echo "  - $OUTPUT_DIR/delta_findings.csv"
  echo "  - $OUTPUT_DIR/delta_summary.json"
  echo "  - $OUTPUT_DIR/manual_review_cases.csv"
  echo "  - $OUTPUT_DIR/delta_log.txt"
}

main() {
  parse_args "$@"
  validate_inputs
  run_engine
}

main "$@"
