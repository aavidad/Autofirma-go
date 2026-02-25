#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET_ICON="${ROOT_DIR}/pkg/applog/assets/systray_icon_64.png"
BACKUP_ICON="${ASSET_ICON}.bak_test"
TEST_BIN="/tmp/autofirma-systray-test"

ICON_A="${1:-${ROOT_DIR}/pluma.png}"
ICON_B="${2:-${ROOT_DIR}/plumas2.png}"

if [[ ! -f "${ICON_A}" ]]; then
  echo "[ERROR] No existe el icono A: ${ICON_A}" >&2
  exit 1
fi
if [[ ! -f "${ICON_B}" ]]; then
  echo "[ERROR] No existe el icono B: ${ICON_B}" >&2
  exit 1
fi
if [[ ! -f "${ASSET_ICON}" ]]; then
  echo "[ERROR] No existe icono base del systray: ${ASSET_ICON}" >&2
  exit 1
fi

cleanup() {
  if [[ -f "${BACKUP_ICON}" ]]; then
    mv -f "${BACKUP_ICON}" "${ASSET_ICON}"
  fi
}
trap cleanup EXIT

cp -f "${ASSET_ICON}" "${BACKUP_ICON}"

prepare_icon() {
  local src="$1"
  if command -v convert >/dev/null 2>&1; then
    convert "${src}" -resize 64x64\! "${ASSET_ICON}"
  elif command -v magick >/dev/null 2>&1; then
    magick "${src}" -resize 64x64\! "${ASSET_ICON}"
  else
    cp -f "${src}" "${ASSET_ICON}"
  fi
}

build_test_bin() {
  (
    cd "${ROOT_DIR}"
    go build -o "${TEST_BIN}" ./cmd/autofirma
  )
}

run_preview() {
  local icon_path="$1"
  local name="$2"
  echo ""
  echo "=== Probando icono: ${name} ==="
  prepare_icon "${icon_path}"
  build_test_bin
  echo "Se abrirá el servidor con systray. Mira el icono y cierra con Ctrl+C."
  "${TEST_BIN}" --server
}

run_preview "${ICON_A}" "$(basename "${ICON_A}")"
read -r -p "Pulsa Enter para probar el segundo icono..."
run_preview "${ICON_B}" "$(basename "${ICON_B}")"

echo ""
echo "Elige icono final:"
echo "1) $(basename "${ICON_A}")"
echo "2) $(basename "${ICON_B}")"
read -r -p "Opción [1/2]: " opt

case "${opt}" in
  1) cp -f "${ICON_A}" "${ASSET_ICON}" ;;
  2) cp -f "${ICON_B}" "${ASSET_ICON}" ;;
  *)
    echo "Opción no válida, se mantiene el icono original."
    mv -f "${BACKUP_ICON}" "${ASSET_ICON}"
    BACKUP_ICON=""
    exit 0
    ;;
esac

echo "Icono seleccionado copiado en: ${ASSET_ICON}"
echo "Compilando binario final..."
build_test_bin
echo "OK. Si quieres instalarlo en /opt:"
echo "  sudo install -m 0755 ${TEST_BIN} /opt/autofirma-dipgra/autofirma"
