#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_SRC="${ROOT_DIR}/PLAN_MIGRACION_AUTOFIRMA_GO.md"
OUT="${ROOT_DIR}/docs/CHANGELOG_PARIDAD.md"

if [[ ! -f "${PLAN_SRC}" ]]; then
  echo "ERROR: no existe ${PLAN_SRC}" >&2
  exit 1
fi

tmp_file="$(mktemp)"
trap 'rm -f "${tmp_file}"' EXIT

{
  echo "# Changelog de Paridad Java -> Go"
  echo
  echo "Actualizado automaticamente el $(date -Iseconds)"
  echo
  echo "## Cambio de modelo documental"
  echo "Se usa fuente unica de estado y pendientes en:"
  echo "- \`PLAN_MIGRACION_AUTOFIRMA_GO.md\`"
  echo
  echo "## Resumen de pendiente real"
  awk '
    /^## Pendiente real \(priorizado\)/ {blk=1; next}
    /^## / && blk==1 {blk=0}
    blk==1 {print}
  ' "${PLAN_SRC}"
  echo
  echo "## Referencia"
  echo "Para detalle completo consultar:"
  echo "- \`PLAN_MIGRACION_AUTOFIRMA_GO.md\`"
} > "${tmp_file}"

mv "${tmp_file}" "${OUT}"
echo "OK: ${OUT}"
