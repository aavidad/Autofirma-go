#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_BIN="${1:-${ROOT_DIR}/out/autofirma-desktop-qt-real}"
QT_DIR="${ROOT_DIR}/cmd/qt_real"

if [[ ! -d "${QT_DIR}" ]]; then
  echo "[qt-real] Error: no existe ${QT_DIR}" >&2
  exit 1
fi

QMAKE_BIN="qmake6"
if ! command -v "$QMAKE_BIN" >/dev/null 2>&1; then
    QMAKE_BIN="qmake" # Fallback a qmake normal si no hay qmake6 (asumiendo Qt5)
    echo "[qt-real] Aviso: qmake6 no encontrado, usando qmake estándar."
fi

echo "[qt-real] Compilando con $QMAKE_BIN..."
(
    cd "${QT_DIR}"
    "$QMAKE_BIN"
    make clean
    make -j$(nproc)
)

mkdir -p "$(dirname "${OUT_BIN}")"
cp -f "${QT_DIR}/qt_real" "${OUT_BIN}"

# Sincronizar recursos
echo "[qt-real] Sincronizando recursos..."
mkdir -p "$(dirname "${OUT_BIN}")/qml"
cp -rf "${QT_DIR}/qml/"* "$(dirname "${OUT_BIN}")/qml/"

chmod +x "${OUT_BIN}"
echo "[qt-real] OK: ${OUT_BIN}"
