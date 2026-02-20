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

echo "[3/3] Verificando..."
file "${DEST_BIN}"
echo "OK: qt-real actualizado."
