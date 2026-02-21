#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_BIN="/tmp/autofirma-desktop-qt-real"
DEST_DIR="/opt/autofirma-dipgra"
DEST_BIN="${DEST_DIR}/autofirma-desktop-qt-real"

echo "[1/3] Compilando qt-real..."
"${ROOT_DIR}/scripts/build_qt_real_linux.sh" "${TMP_BIN}"

echo "[2/3] Instalando en ${DEST_BIN}..."
sudo mkdir -p "${DEST_DIR}"
sudo install -m 0755 "${TMP_BIN}" "${DEST_BIN}"
if [[ -d "${ROOT_DIR}/cmd/qt_real/qml" ]]; then
  sudo mkdir -p "${DEST_DIR}/qml"
  sudo cp -a "${ROOT_DIR}/cmd/qt_real/qml/." "${DEST_DIR}/qml/"
elif [[ -d "${ROOT_DIR}/qml" ]]; then
  sudo mkdir -p "${DEST_DIR}/qml"
  sudo cp -a "${ROOT_DIR}/qml/." "${DEST_DIR}/qml/"
fi
if [[ -d "${ROOT_DIR}/assets" ]]; then
  sudo mkdir -p "${DEST_DIR}/assets"
  sudo cp -a "${ROOT_DIR}/assets/." "${DEST_DIR}/assets/"
fi

echo "[3/3] Verificando..."
file "${DEST_BIN}"
ls -la "${DEST_DIR}/qml" "${DEST_DIR}/assets" >/dev/null
echo "OK: qt-real actualizado."
