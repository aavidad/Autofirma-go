#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT_DIR}/AVANCES_PARIDAD_JAVA_GO.md"
OUT="${ROOT_DIR}/docs/CHANGELOG_PARIDAD.md"

if [[ ! -f "${SRC}" ]]; then
  echo "ERROR: no existe ${SRC}" >&2
  exit 1
fi

tmp_file="$(mktemp)"
trap 'rm -f "${tmp_file}"' EXIT

{
  echo "# Changelog de Paridad Java -> Go"
  echo
  echo "_Generado automáticamente el $(date -Iseconds)_"
  echo
  echo "## Estado global"
  awk '
    /^## Estado global/ {blk=1; next}
    /^## / && blk==1 {blk=0}
    blk==1 && /^- \[[ x]\]/ {print}
  ' "${SRC}"
  echo
  echo "## Checklist pendiente"
  awk '
    /^## Checklist detallado/ {blk=1; next}
    /^## Bitácora de avances/ && blk==1 {blk=0}
    blk==1 && /^### / {section=$0; next}
    blk==1 && /^- \[ \]/ {
      if (section != "") {
        print section
        section=""
      }
      print $0
    }
  ' "${SRC}"
  echo
  echo "## Últimos avances (extracto)"
  awk '
    /^### 2026-02-17/ {blk=1}
    /^## Pendiente para hoy/ && blk==1 {print; blk=2; next}
    /^## / && blk==2 {blk=0}
    blk==1 || blk==2 {print}
  ' "${SRC}"
} > "${tmp_file}"

mv "${tmp_file}" "${OUT}"
echo "OK: ${OUT}"
