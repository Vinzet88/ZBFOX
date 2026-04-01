#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLKIT="$ROOT_DIR/pacchetti/protection_continuity/toolkit"

usage() {
  cat <<USAGE
Protection Continuity Agent
Uso:
  $0 compare-snapshot --old <PATH> --new <PATH> --client <CLIENT>
  $0 compare-assessment --old <PATH> --new <PATH> --client <CLIENT>
  $0 report-snapshot --delta-dir <PATH> --client <CLIENT>
  $0 report-assessment --delta-dir <PATH> --client <CLIENT>
USAGE
}

[[ $# -ge 1 ]] || { usage; exit 1; }
mode="$1"
shift

case "$mode" in
  compare-snapshot)
    "$TOOLKIT/compare_snapshot.sh" "$@"
    ;;
  compare-assessment)
    "$TOOLKIT/compare_assessment.sh" "$@"
    ;;
  report-snapshot)
    "$TOOLKIT/generate_report_snapshot_delta.sh" "$@"
    ;;
  report-assessment)
    "$TOOLKIT/generate_report_delta.sh" "$@"
    ;;
  *)
    usage
    exit 1
    ;;
esac
