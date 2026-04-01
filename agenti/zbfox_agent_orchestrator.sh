#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
ZBFOX Orchestrator
Uso:
  $0 snapshot <args...>
  $0 assessment <args...>
  $0 continuity <args...>

Esempi:
  $0 snapshot init ACME external
  $0 assessment run /opt/zbfox/engagements/ZBF-ASSESS-20260323-ACME
  $0 continuity compare-snapshot --old /path/old --new /path/new --client ACME
USAGE
}

[[ $# -ge 1 ]] || { usage; exit 1; }
service="$1"
shift

case "$service" in
  snapshot)
    "$SCRIPT_DIR/snapshot_agent.sh" "$@"
    ;;
  assessment)
    "$SCRIPT_DIR/security_assessment_agent.sh" "$@"
    ;;
  continuity)
    "$SCRIPT_DIR/protection_continuity_agent.sh" "$@"
    ;;
  *)
    usage
    exit 1
    ;;
esac
