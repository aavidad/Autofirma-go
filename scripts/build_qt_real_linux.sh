#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_BIN="${1:-${ROOT_DIR}/out/autofirma-desktop-qt-real}"
SRC_FILE="${ROOT_DIR}/cmd/qt_real/main.cpp"

if [[ ! -f "${SRC_FILE}" ]]; then
  echo "[qt-real] Error: no existe ${SRC_FILE}" >&2
  exit 1
fi

if ! command -v g++ >/dev/null 2>&1; then
  echo "[qt-real] Error: g++ no encontrado" >&2
  exit 1
fi

if ! pkg-config --exists Qt6Widgets Qt6Network; then
  echo "[qt-real] Error: faltan Qt6Widgets/Qt6Network para compilar qt-real" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUT_BIN}")"
g++ -std=c++17 -O2 "${SRC_FILE}" -o "${OUT_BIN}" $(pkg-config --cflags --libs Qt6Widgets Qt6Network)
chmod +x "${OUT_BIN}"
echo "[qt-real] OK: ${OUT_BIN}"
