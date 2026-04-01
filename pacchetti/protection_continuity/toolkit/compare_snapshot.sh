#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# ZBFOX — Cyber Protection Continuity
# compare_snapshot.sh
# ------------------------------------------------------------
# Wrapper per il confronto tra due engagement Snapshot
# tramite motore Python compare_snapshot_delta.py
#
# Supporta modalità:
#   - external
#   - internal
#   - auto (dedotta dai file presenti)
#
# Output principali:
#   - delta_hosts.csv
#   - delta_services.csv
#   - delta_summary.json
#   - manual_review_cases.csv
#   - delta_log.txt
#   - delta_web.csv (external)
#   - delta_high_value_services.csv (internal, se disponibile)
# ============================================================

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ENGINE="$SCRIPT_DIR/compare_snapshot_delta.py"
SECONDARY_ENGINE_1="/opt/zbfox/scripts/compare_snapshot_delta.py"
SECONDARY_ENGINE_2="/opt/zbfox/continuity/compare_snapshot_delta.py"

OLD_ENGAGEMENT=""
NEW_ENGAGEMENT=""
CLIENT_ID=""
MODE="auto"
ENGINE_PATH=""
OUTPUT_DIR=""

# discovered inputs
OLD_HTTPX=""
NEW_HTTPX=""
OLD_NMAP=""
NEW_NMAP=""
OLD_DNSX=""
NEW_DNSX=""

OLD_ARP_SCAN=""
NEW_ARP_SCAN=""
OLD_NMAP_INTERNAL=""
NEW_NMAP_INTERNAL=""
OLD_NMAP_DISCOVERY=""
NEW_NMAP_DISCOVERY=""
OLD_INTERNAL_SERVICES_CSV=""
NEW_INTERNAL_SERVICES_CSV=""
OLD_HIGH_VALUE_CSV=""
NEW_HIGH_VALUE_CSV=""

print_banner() {
  cat <<'EOF'
============================================================
 ZBFOX — Cyber Protection Continuity
 compare_snapshot.sh
 Snapshot Surface DELTA Wrapper
============================================================
EOF
}

print_usage() {
  cat <<EOF
Uso:
  $SCRIPT_NAME \
    --old /opt/zbfox/engagements/ZBF-SNAP-EXT-20260324-CLIENTE \
    --new /opt/zbfox/engagements/ZBF-SNAP-EXT-20260415-CLIENTE \
    --client CLIENTE_X \
    [--mode auto|external|internal] \
    [--engine /path/to/compare_snapshot_delta.py] \
    [--output-dir /path/to/output_delta]

Parametri obbligatori:
  --old         Path engagement Snapshot precedente
  --new         Path engagement Snapshot più recente
  --client      Identificativo cliente

Parametri opzionali:
  --mode        auto | external | internal   (default: auto)
  --engine      Path esplicito del motore Python
  --output-dir  Cartella output DELTA personalizzata
  -h, --help    Mostra questo messaggio

Deduzione mode=auto:
  external se trova in old/new engagement:
    - raw/httpx.txt
    - raw/nmap.txt

  internal se trova in old/new engagement:
    - raw/arp_scan.txt
    - raw/nmap_internal.txt

  Se la deduzione non è univoca, usare --mode.

Output predefinito:
  Se --output-dir non viene fornito, il DELTA viene scritto in:
    <new_engagement>/report/delta_<old_basename>_vs_<new_basename>/

Esempio corretto:
  $SCRIPT_NAME \
    --old /opt/zbfox/engagements/ZBF-SNAP-EXT-20260324-CLIENTE \
    --new /opt/zbfox/engagements/ZBF-SNAP-EXT-20260415-CLIENTE \
    --client CLIENTE_X

Esempio corretto internal:
  $SCRIPT_NAME \
    --old /opt/zbfox/engagements/ZBF-SNAP-INT-20260324-CLIENTE \
    --new /opt/zbfox/engagements/ZBF-SNAP-INT-20260415-CLIENTE \
    --client CLIENTE_X

Esempio ERRATO:
  $SCRIPT_NAME --old /opt/zbfox/engagements/A --new /opt/zbfox/engagements/B

Perché è errato:
  manca il parametro obbligatorio --client
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

abs_path() {
  local p="$1"
  python3 - <<'PY' "$p"
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
}

find_first_existing() {
  for p in "$@"; do
    if [[ -n "$p" && -f "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

build_default_output_dir() {
  local old_base new_base
  old_base="$(basename "$OLD_ENGAGEMENT")"
  new_base="$(basename "$NEW_ENGAGEMENT")"
  echo "$NEW_ENGAGEMENT/report/delta_${old_base}_vs_${new_base}"
}

parse_args() {
  [[ $# -gt 0 ]] || { print_banner; die "Nessun argomento fornito."; }

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
      --mode)
        [[ $# -ge 2 ]] || die "Valore mancante per --mode"
        MODE="$2"
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

  case "$MODE" in
    auto|external|internal) ;;
    *) die "Valore non valido per --mode: $MODE" ;;
  esac
}

validate_base_inputs() {
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

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$(build_default_output_dir)"
  fi
  OUTPUT_DIR="$(abs_path "$OUTPUT_DIR")"
  mkdir -p "$OUTPUT_DIR"
}

detect_mode() {
  local old_has_ext=0 new_has_ext=0 old_has_int=0 new_has_int=0

  [[ -f "$OLD_ENGAGEMENT/raw/httpx.txt" && -f "$OLD_ENGAGEMENT/raw/nmap.txt" ]] && old_has_ext=1
  [[ -f "$NEW_ENGAGEMENT/raw/httpx.txt" && -f "$NEW_ENGAGEMENT/raw/nmap.txt" ]] && new_has_ext=1

  [[ -f "$OLD_ENGAGEMENT/raw/arp_scan.txt" && -f "$OLD_ENGAGEMENT/raw/nmap_internal.txt" ]] && old_has_int=1
  [[ -f "$NEW_ENGAGEMENT/raw/arp_scan.txt" && -f "$NEW_ENGAGEMENT/raw/nmap_internal.txt" ]] && new_has_int=1

  if [[ "$old_has_ext" -eq 1 && "$new_has_ext" -eq 1 && "$old_has_int" -eq 0 && "$new_has_int" -eq 0 ]]; then
    MODE="external"
    return 0
  fi
  if [[ "$old_has_int" -eq 1 && "$new_has_int" -eq 1 && "$old_has_ext" -eq 0 && "$new_has_ext" -eq 0 ]]; then
    MODE="internal"
    return 0
  fi

  die "Impossibile dedurre automaticamente la modalità snapshot. Specificare --mode external oppure --mode internal."
}

discover_external_inputs() {
  OLD_HTTPX="$(find_first_existing "$OLD_ENGAGEMENT/raw/httpx.txt" || true)"
  NEW_HTTPX="$(find_first_existing "$NEW_ENGAGEMENT/raw/httpx.txt" || true)"
  OLD_NMAP="$(find_first_existing "$OLD_ENGAGEMENT/raw/nmap.txt" || true)"
  NEW_NMAP="$(find_first_existing "$NEW_ENGAGEMENT/raw/nmap.txt" || true)"

  OLD_DNSX="$(find_first_existing \
    "$OLD_ENGAGEMENT/processed/live_hosts.txt" \
    "$OLD_ENGAGEMENT/raw/dnsx.txt" \
    "$OLD_ENGAGEMENT/dnsx.txt" || true)"
  NEW_DNSX="$(find_first_existing \
    "$NEW_ENGAGEMENT/processed/live_hosts.txt" \
    "$NEW_ENGAGEMENT/raw/dnsx.txt" \
    "$NEW_ENGAGEMENT/dnsx.txt" || true)"

  [[ -n "$OLD_HTTPX" ]] || die "File richiesto non trovato nel vecchio engagement: raw/httpx.txt"
  [[ -n "$NEW_HTTPX" ]] || die "File richiesto non trovato nel nuovo engagement: raw/httpx.txt"
  [[ -n "$OLD_NMAP" ]] || die "File richiesto non trovato nel vecchio engagement: raw/nmap.txt"
  [[ -n "$NEW_NMAP" ]] || die "File richiesto non trovato nel nuovo engagement: raw/nmap.txt"

  [[ -n "$OLD_DNSX" ]] || echo "[ZBFOX][WARN] dnsx/live_hosts non trovato nel vecchio engagement: si prosegue senza supporto host->IP"
  [[ -n "$NEW_DNSX" ]] || echo "[ZBFOX][WARN] dnsx/live_hosts non trovato nel nuovo engagement: si prosegue senza supporto host->IP"
}

discover_internal_inputs() {
  OLD_ARP_SCAN="$(find_first_existing "$OLD_ENGAGEMENT/raw/arp_scan.txt" || true)"
  NEW_ARP_SCAN="$(find_first_existing "$NEW_ENGAGEMENT/raw/arp_scan.txt" || true)"
  OLD_NMAP_INTERNAL="$(find_first_existing "$OLD_ENGAGEMENT/raw/nmap_internal.txt" || true)"
  NEW_NMAP_INTERNAL="$(find_first_existing "$NEW_ENGAGEMENT/raw/nmap_internal.txt" || true)"

  OLD_NMAP_DISCOVERY="$(find_first_existing "$OLD_ENGAGEMENT/raw/nmap_discovery.txt" || true)"
  NEW_NMAP_DISCOVERY="$(find_first_existing "$NEW_ENGAGEMENT/raw/nmap_discovery.txt" || true)"
  OLD_INTERNAL_SERVICES_CSV="$(find_first_existing "$OLD_ENGAGEMENT/processed/internal_services.csv" || true)"
  NEW_INTERNAL_SERVICES_CSV="$(find_first_existing "$NEW_ENGAGEMENT/processed/internal_services.csv" || true)"
  OLD_HIGH_VALUE_CSV="$(find_first_existing "$OLD_ENGAGEMENT/processed/internal_high_value_services.csv" || true)"
  NEW_HIGH_VALUE_CSV="$(find_first_existing "$NEW_ENGAGEMENT/processed/internal_high_value_services.csv" || true)"

  [[ -n "$OLD_ARP_SCAN" ]] || die "File richiesto non trovato nel vecchio engagement: raw/arp_scan.txt"
  [[ -n "$NEW_ARP_SCAN" ]] || die "File richiesto non trovato nel nuovo engagement: raw/arp_scan.txt"
  [[ -n "$OLD_NMAP_INTERNAL" ]] || die "File richiesto non trovato nel vecchio engagement: raw/nmap_internal.txt"
  [[ -n "$NEW_NMAP_INTERNAL" ]] || die "File richiesto non trovato nel nuovo engagement: raw/nmap_internal.txt"

  [[ -n "$OLD_NMAP_DISCOVERY" ]] || echo "[ZBFOX][WARN] nmap_discovery.txt non trovato nel vecchio engagement"
  [[ -n "$NEW_NMAP_DISCOVERY" ]] || echo "[ZBFOX][WARN] nmap_discovery.txt non trovato nel nuovo engagement"
  [[ -n "$OLD_INTERNAL_SERVICES_CSV" ]] || echo "[ZBFOX][WARN] internal_services.csv non trovato nel vecchio engagement: si userà nmap_internal.txt come base servizi"
  [[ -n "$NEW_INTERNAL_SERVICES_CSV" ]] || echo "[ZBFOX][WARN] internal_services.csv non trovato nel nuovo engagement: si userà nmap_internal.txt come base servizi"
  [[ -n "$OLD_HIGH_VALUE_CSV" ]] || echo "[ZBFOX][WARN] internal_high_value_services.csv non trovato nel vecchio engagement"
  [[ -n "$NEW_HIGH_VALUE_CSV" ]] || echo "[ZBFOX][WARN] internal_high_value_services.csv non trovato nel nuovo engagement"
}

run_engine() {
  print_banner
  echo "[ZBFOX][INFO] Client ID        : $CLIENT_ID"
  echo "[ZBFOX][INFO] Mode             : $MODE"
  echo "[ZBFOX][INFO] Old engagement   : $OLD_ENGAGEMENT"
  echo "[ZBFOX][INFO] New engagement   : $NEW_ENGAGEMENT"
  echo "[ZBFOX][INFO] Engine           : $ENGINE_PATH"
  echo "[ZBFOX][INFO] Output directory : $OUTPUT_DIR"
  echo

  if [[ "$MODE" == "external" ]]; then
    echo "[ZBFOX][INFO] Old httpx        : $OLD_HTTPX"
    echo "[ZBFOX][INFO] New httpx        : $NEW_HTTPX"
    echo "[ZBFOX][INFO] Old nmap         : $OLD_NMAP"
    echo "[ZBFOX][INFO] New nmap         : $NEW_NMAP"
    [[ -n "$OLD_DNSX" ]] && echo "[ZBFOX][INFO] Old dnsx/live    : $OLD_DNSX"
    [[ -n "$NEW_DNSX" ]] && echo "[ZBFOX][INFO] New dnsx/live    : $NEW_DNSX"
  else
    echo "[ZBFOX][INFO] Old arp-scan     : $OLD_ARP_SCAN"
    echo "[ZBFOX][INFO] New arp-scan     : $NEW_ARP_SCAN"
    echo "[ZBFOX][INFO] Old nmap-int     : $OLD_NMAP_INTERNAL"
    echo "[ZBFOX][INFO] New nmap-int     : $NEW_NMAP_INTERNAL"
    [[ -n "$OLD_INTERNAL_SERVICES_CSV" ]] && echo "[ZBFOX][INFO] Old services csv : $OLD_INTERNAL_SERVICES_CSV"
    [[ -n "$NEW_INTERNAL_SERVICES_CSV" ]] && echo "[ZBFOX][INFO] New services csv : $NEW_INTERNAL_SERVICES_CSV"
    [[ -n "$OLD_HIGH_VALUE_CSV" ]] && echo "[ZBFOX][INFO] Old high-value   : $OLD_HIGH_VALUE_CSV"
    [[ -n "$NEW_HIGH_VALUE_CSV" ]] && echo "[ZBFOX][INFO] New high-value   : $NEW_HIGH_VALUE_CSV"
  fi
  echo
  echo "[ZBFOX][INFO] Avvio Snapshot DELTA..."
  echo

  local cmd=(
    python3 "$ENGINE_PATH"
    --old-engagement "$OLD_ENGAGEMENT"
    --new-engagement "$NEW_ENGAGEMENT"
    --client-id "$CLIENT_ID"
    --mode "$MODE"
    --output-dir "$OUTPUT_DIR"
  )

  if [[ "$MODE" == "external" ]]; then
    cmd+=( --old-httpx "$OLD_HTTPX" --new-httpx "$NEW_HTTPX" )
    cmd+=( --old-nmap "$OLD_NMAP" --new-nmap "$NEW_NMAP" )
    [[ -n "$OLD_DNSX" ]] && cmd+=( --old-dnsx "$OLD_DNSX" )
    [[ -n "$NEW_DNSX" ]] && cmd+=( --new-dnsx "$NEW_DNSX" )
  else
    cmd+=( --old-arp-scan "$OLD_ARP_SCAN" --new-arp-scan "$NEW_ARP_SCAN" )
    cmd+=( --old-nmap-internal "$OLD_NMAP_INTERNAL" --new-nmap-internal "$NEW_NMAP_INTERNAL" )
    [[ -n "$OLD_NMAP_DISCOVERY" ]] && cmd+=( --old-nmap-discovery "$OLD_NMAP_DISCOVERY" )
    [[ -n "$NEW_NMAP_DISCOVERY" ]] && cmd+=( --new-nmap-discovery "$NEW_NMAP_DISCOVERY" )
    [[ -n "$OLD_INTERNAL_SERVICES_CSV" ]] && cmd+=( --old-internal-services-csv "$OLD_INTERNAL_SERVICES_CSV" )
    [[ -n "$NEW_INTERNAL_SERVICES_CSV" ]] && cmd+=( --new-internal-services-csv "$NEW_INTERNAL_SERVICES_CSV" )
    [[ -n "$OLD_HIGH_VALUE_CSV" ]] && cmd+=( --old-high-value-csv "$OLD_HIGH_VALUE_CSV" )
    [[ -n "$NEW_HIGH_VALUE_CSV" ]] && cmd+=( --new-high-value-csv "$NEW_HIGH_VALUE_CSV" )
  fi

  "${cmd[@]}"

  echo
  echo "[ZBFOX][OK] Snapshot DELTA completato."
  echo "[ZBFOX][OK] Mode            : $MODE"
  echo "[ZBFOX][OK] Output directory: $OUTPUT_DIR"
  echo "[ZBFOX][OK] File principali:"
  echo "  - $OUTPUT_DIR/delta_hosts.csv"
  echo "  - $OUTPUT_DIR/delta_services.csv"
  echo "  - $OUTPUT_DIR/delta_summary.json"
  echo "  - $OUTPUT_DIR/manual_review_cases.csv"
  echo "  - $OUTPUT_DIR/delta_log.txt"
  if [[ "$MODE" == "external" ]]; then
    echo "  - $OUTPUT_DIR/delta_web.csv"
  else
    [[ -f "$OUTPUT_DIR/delta_high_value_services.csv" ]] && echo "  - $OUTPUT_DIR/delta_high_value_services.csv"
  fi
}

main() {
  parse_args "$@"
  validate_base_inputs
  [[ "$MODE" == "auto" ]] && detect_mode

  case "$MODE" in
    external) discover_external_inputs ;;
    internal) discover_internal_inputs ;;
    *) die "Modalità non valida dopo deduzione: $MODE" ;;
  esac

  run_engine
}

main "$@"
