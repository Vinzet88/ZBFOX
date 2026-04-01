#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLKIT="$ROOT_DIR/pacchetti/security_assessment/toolkit"

usage() {
  cat <<USAGE
Security Assessment Agent
Uso:
  $0 init <CLIENTE>
  $0 run <ENGAGEMENT_PATH>
  $0 parse-openvas <ENGAGEMENT_PATH> <OPENVAS_XML>
  $0 report <ENGAGEMENT_PATH>
USAGE
}

require_file() {
  [[ -f "$1" ]] || { echo "[assessment-agent] File mancante: $1"; exit 1; }
}

case "${1:-}" in
  init)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    require_file "$TOOLKIT/new_engagement_assessment.sh"
    "$TOOLKIT/new_engagement_assessment.sh" "$2"
    ;;
  run)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    require_file "$TOOLKIT/run_assessment.sh"
    "$TOOLKIT/run_assessment.sh" "$2"
    ;;
  parse-openvas)
    [[ $# -eq 3 ]] || { usage; exit 1; }
    require_file "$TOOLKIT/parse_openvas_report.sh"
    "$TOOLKIT/parse_openvas_report.sh" "$2" "$3"
    ;;
  report)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    require_file "$TOOLKIT/generate_assessment_report_blocks1.sh"
    require_file "$TOOLKIT/generate_assessment_report_blocks2.sh"
    "$TOOLKIT/generate_assessment_report_blocks1.sh" "$2"
    "$TOOLKIT/generate_assessment_report_blocks2.sh" "$2"
    ;;
  *)
    usage
    exit 1
    ;;
esac
