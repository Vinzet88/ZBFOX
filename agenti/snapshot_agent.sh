#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLKIT="$ROOT_DIR/pacchetti/snapshot/toolkit"

usage() {
  cat <<USAGE
Snapshot Agent
Uso:
  $0 init <CLIENTE> <external|internal>
  $0 run <ENGAGEMENT_PATH>
  $0 report <ENGAGEMENT_PATH> <external|internal>
USAGE
}

require_file() {
  [[ -f "$1" ]] || { echo "[snapshot-agent] File mancante: $1"; exit 1; }
}

cmd="${1:-}"
case "$cmd" in
  init)
    [[ $# -eq 3 ]] || { usage; exit 1; }
    require_file "$TOOLKIT/new_engagement.sh"
    "$TOOLKIT/new_engagement.sh" "$2" "$3"
    ;;
  run)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    require_file "$TOOLKIT/run_external.sh"
    require_file "$TOOLKIT/run_internal_snapshot.sh"
    if grep -q "mode: external" "$2/scope/engagement.yaml"; then
      "$TOOLKIT/run_external.sh" "$2"
    else
      "$TOOLKIT/run_internal_snapshot.sh" "$2"
    fi
    ;;
  report)
    [[ $# -eq 3 ]] || { usage; exit 1; }
    if [[ "$3" == "external" ]]; then
      require_file "$TOOLKIT/generate_external_report_blocks.sh"
      "$TOOLKIT/generate_external_report_blocks.sh" "$2"
    else
      require_file "$TOOLKIT/generate_internal_report_blocks.sh"
      "$TOOLKIT/generate_internal_report_blocks.sh" "$2"
    fi
    ;;
  *)
    usage
    exit 1
    ;;
esac
