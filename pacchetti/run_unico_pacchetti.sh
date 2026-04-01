#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAP_TOOLKIT="$ROOT_DIR/snapshot/toolkit"
ASSESS_TOOLKIT="$ROOT_DIR/security_assessment/toolkit"
CONT_TOOLKIT="$ROOT_DIR/protection_continuity/toolkit"

require_file() {
  local f="$1"
  [[ -f "$f" ]] || { echo "[!] Script mancante: $f"; exit 1; }
}

ask_non_empty() {
  local prompt="$1"
  local val=""
  while [[ -z "$val" ]]; do
    read -r -p "$prompt" val
    val="$(echo "$val" | xargs)"
  done
  printf '%s' "$val"
}

extract_engagement_path() {
  local output="$1"
  echo "$output" | sed -n 's/^\[+] ENGAGEMENT_PATH=//p' | tail -n1
}

run_snapshot() {
  local client="$1"
  echo
  echo "[SNAPSHOT] Scegli modalità:"
  echo "  1) INTERNAL"
  echo "  2) EXTERNAL"

  local mode_choice mode target eng_output eng_path
  mode_choice="$(ask_non_empty 'Selezione [1-2]: ')"

  case "$mode_choice" in
    1) mode="internal" ;;
    2) mode="external" ;;
    *) echo "[!] Scelta non valida"; exit 1 ;;
  esac

  target="$(ask_non_empty 'TARGET (CIDR/IP/host): ')"

  require_file "$SNAP_TOOLKIT/new_engagement.sh"
  eng_output="$(bash "$SNAP_TOOLKIT/new_engagement.sh" "$client" "$mode")"
  echo "$eng_output"
  eng_path="$(extract_engagement_path "$eng_output")"
  [[ -n "$eng_path" ]] || { echo "[!] Impossibile determinare ENGAGEMENT_PATH"; exit 1; }

  if [[ "$mode" == "external" ]]; then
    require_file "$SNAP_TOOLKIT/run_external.sh"
    printf '%s\n\n' "$target" | bash "$SNAP_TOOLKIT/run_external.sh" "$eng_path"
    require_file "$SNAP_TOOLKIT/generate_external_report_blocks.sh"
    bash "$SNAP_TOOLKIT/generate_external_report_blocks.sh" "$eng_path"
  else
    require_file "$SNAP_TOOLKIT/run_internal_snapshot.sh"
    printf '%s\n\n' "$target" | bash "$SNAP_TOOLKIT/run_internal_snapshot.sh" "$eng_path"
    require_file "$SNAP_TOOLKIT/generate_internal_report_blocks.sh"
    bash "$SNAP_TOOLKIT/generate_internal_report_blocks.sh" "$eng_path"
  fi

  echo "[+] Snapshot completato. Report in: $eng_path/report"
}

run_assessment() {
  local client="$1"
  local target phase2 xml_path assess_dir blocks1_md blocks1_txt out2

  target="$(ask_non_empty 'TARGET assessment (nota operativa): ')"

  require_file "$ASSESS_TOOLKIT/new_engagement_assessment.sh"
  local eng_output
  eng_output="$(bash "$ASSESS_TOOLKIT/new_engagement_assessment.sh" "$client")"
  echo "$eng_output"
  local eng_path
  eng_path="$(extract_engagement_path "$eng_output")"
  [[ -n "$eng_path" ]] || { echo "[!] Impossibile determinare ENGAGEMENT_PATH"; exit 1; }

  echo "$target" > "$eng_path/scope/target.txt"

  require_file "$ASSESS_TOOLKIT/run_assessment.sh"
  bash "$ASSESS_TOOLKIT/run_assessment.sh" "$eng_path"

  require_file "$ASSESS_TOOLKIT/generate_assessment_report_blocks1.sh"
  bash "$ASSESS_TOOLKIT/generate_assessment_report_blocks1.sh" "$eng_path"

  assess_dir="$eng_path/report/assessment"
  mkdir -p "$assess_dir"
  blocks1_md="$assess_dir/block1.md"
  blocks1_txt="$eng_path/report/block1.txt"

  if [[ -f "$eng_path/report/assessment_report_draft_phase1.md" ]]; then
    cp "$eng_path/report/assessment_report_draft_phase1.md" "$blocks1_md"
    cp "$eng_path/report/assessment_report_draft_phase1.md" "$blocks1_txt"
  fi

  read -r -p "Sei pronto per FASE 2 (parse report OpenVAS)? [y/N]: " phase2
  if [[ "$phase2" =~ ^[Yy]$ ]]; then
    xml_path="$(ask_non_empty 'Percorso XML OpenVAS: ')"
    require_file "$ASSESS_TOOLKIT/parse_openvas_report.sh"
    bash "$ASSESS_TOOLKIT/parse_openvas_report.sh" "$xml_path" "$eng_path/report"

    require_file "$ASSESS_TOOLKIT/generate_assessment_report_blocks2.sh"
    out2="$eng_path/report/assessment_report_final_phase2.md"
    bash "$ASSESS_TOOLKIT/generate_assessment_report_blocks2.sh" "$blocks1_md" "$eng_path/report/openvas_parsed.json" "$out2"
    echo "[+] Assessment fase 2 completata: $out2"
  else
    echo "[i] Fase 2 non eseguita ora. Block1 disponibile in: $blocks1_txt e $blocks1_md"
  fi
}

run_continuity() {
  local client="$1"
  local old_path new_path delta_dir

  old_path="$(ask_non_empty 'Posizione VECCHIA engagement: ')"
  new_path="$(ask_non_empty 'Posizione NUOVA engagement: ')"

  require_file "$CONT_TOOLKIT/compare_assessment.sh"
  bash "$CONT_TOOLKIT/compare_assessment.sh" --old "$old_path" --new "$new_path" --client "$client"

  delta_dir="$new_path/report/delta_$(basename "$old_path")_vs_$(basename "$new_path")"
  require_file "$CONT_TOOLKIT/generate_report_delta.sh"
  bash "$CONT_TOOLKIT/generate_report_delta.sh" --delta-dir "$delta_dir" --client "$client"

  echo "[+] Protection Continuity completata. Report in: $delta_dir/report"
}

main() {
  require_file "$SNAP_TOOLKIT/new_engagement.sh"
  require_file "$ASSESS_TOOLKIT/new_engagement_assessment.sh"
  require_file "$CONT_TOOLKIT/compare_assessment.sh"

  local client pkg
  echo "=== ZBFOX - Launcher Unico Pacchetti ==="
  client="$(ask_non_empty 'Nome Cliente: ')"

  echo
  echo "Pacchetti disponibili:"
  echo "  1) Snapshot"
  echo "  2) Security Assessment"
  echo "  3) Protection Continuity"
  pkg="$(ask_non_empty 'Pacchetto scelto [1-3]: ')"

  case "$pkg" in
    1) run_snapshot "$client" ;;
    2) run_assessment "$client" ;;
    3) run_continuity "$client" ;;
    *) echo "[!] Scelta pacchetto non valida"; exit 1 ;;
  esac
}

main "$@"
