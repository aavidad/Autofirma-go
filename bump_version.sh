#!/usr/bin/env bash
# =============================================================================
# bump_version.sh — Gestión de versión semántica para AutoFirma Dipgra
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputación de Granada
# =============================================================================
# Uso:
#   ./bump_version.sh                       # sube PATCH (0.0.1 → 0.0.2)
#   ./bump_version.sh --minor               # sube MINOR (0.0.9 → 0.1.0)
#   ./bump_version.sh --major               # sube MAJOR (0.9.9 → 1.0.0)
#   ./bump_version.sh --set 0.2.0           # fija versión exacta
#   ./bump_version.sh --show                # muestra versión actual
#   ./bump_version.sh --message "Cambios"   # añade entrada en CHANGELOG
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="${SCRIPT_DIR}/VERSION"
CHANGELOG_FILE="${SCRIPT_DIR}/CHANGELOG.md"
DATE="$(date +%Y-%m-%d)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${BLUE}[version]${RESET} $*"; }
ok()    { echo -e "${GREEN}[version]${RESET} ✓ $*"; }
error() { echo -e "${RED}[version]${RESET} ✗ $*" >&2; exit 1; }

# ─── Leer versión actual ───────────────────────────────────────────────────────
read_version() {
  if [[ ! -f "${VERSION_FILE}" ]]; then
    error "No se encontró ${VERSION_FILE}"
  fi
  local ver
  ver="$(tr -d '[:space:]' < "${VERSION_FILE}")"
  if ! [[ "${ver}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "Versión inválida en VERSION: '${ver}' (debe ser X.Y.Z)"
  fi
  echo "${ver}"
}

split_version() {
  local ver="$1"
  IFS='.' read -r MAJOR MINOR PATCH <<< "${ver}"
}

# ─── Escribir nueva versión ────────────────────────────────────────────────────
write_version() {
  local new_ver="$1"
  echo "${new_ver}" > "${VERSION_FILE}"
  ok "Versión actualizada: ${BOLD}${new_ver}${RESET}"
}

# ─── Actualizar CHANGELOG ──────────────────────────────────────────────────────
update_changelog() {
  local new_ver="$1"
  local message="$2"

  # Construir la nueva entrada
  local entry
  entry="## [${new_ver}] — ${DATE}\n\n### Añadido\n- ${message}\n"

  # Insertar DESPUÉS de la primera línea de "---"
  if grep -q "^---$" "${CHANGELOG_FILE}"; then
    sed -i "0,/^---$/s|^---$|---\n\n${entry}|" "${CHANGELOG_FILE}"
  else
    # Si no hay "---", añadir al final
    printf "\n%s" "$(printf '%b' "${entry}")" >> "${CHANGELOG_FILE}"
  fi
  ok "CHANGELOG.md actualizado con entrada para [${new_ver}]"
}

# ─── Mostrar versión ───────────────────────────────────────────────────────────
show_version() {
  local ver
  ver="$(read_version)"
  echo -e "${BOLD}${ver}${RESET}"
}

# ─── Main ──────────────────────────────────────────────────────────────────────
BUMP_TYPE="patch"   # patch | minor | major | set
NEW_VERSION_SET=""
CHANGELOG_MSG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --patch)          BUMP_TYPE="patch"; shift ;;
    --minor)          BUMP_TYPE="minor"; shift ;;
    --major)          BUMP_TYPE="major"; shift ;;
    --set)            BUMP_TYPE="set"; NEW_VERSION_SET="${2:-}"; shift 2 ;;
    --message|-m)     CHANGELOG_MSG="${2:-}"; shift 2 ;;
    --show)           show_version; exit 0 ;;
    -h|--help)
      grep '^#' "$0" | head -20 | sed 's/^# *//'
      exit 0 ;;
    *)
      error "Opción desconocida: $1" ;;
  esac
done

CURRENT="$(read_version)"
split_version "${CURRENT}"

case "${BUMP_TYPE}" in
  patch)
    PATCH=$((PATCH + 1))
    NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
    ;;
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
    ;;
  set)
    if [[ -z "${NEW_VERSION_SET}" ]]; then
      error "Debes indicar la versión con --set X.Y.Z"
    fi
    if ! [[ "${NEW_VERSION_SET}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      error "Formato inválido: '${NEW_VERSION_SET}' (debe ser X.Y.Z)"
    fi
    NEW_VERSION="${NEW_VERSION_SET}"
    ;;
esac

info "${CURRENT} → ${BOLD}${NEW_VERSION}${RESET}  (bump: ${BUMP_TYPE})"

write_version "${NEW_VERSION}"

if [[ -n "${CHANGELOG_MSG}" ]]; then
  update_changelog "${NEW_VERSION}" "${CHANGELOG_MSG}"
else
  # Añadir entrada vacía al changelog para que el dev la rellene
  update_changelog "${NEW_VERSION}" "*(pendiente de documentar)*"
fi

echo ""
echo -e "  Versión actual: ${BOLD}${GREEN}${NEW_VERSION}${RESET}"
echo -e "  Edita ${CHANGELOG_FILE} para añadir los detalles de los cambios."
