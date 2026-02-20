#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER_SCRIPT="${ROOT_DIR}/packaging/macos/install.sh"
PREFIX="${1:-/Applications/AutofirmaDipgra}"

if [[ ! -x "${INSTALLER_SCRIPT}" ]]; then
  echo "[install-trust-mac] ERROR: no se encuentra instalador: ${INSTALLER_SCRIPT}" >&2
  exit 1
fi

echo "[install-trust-mac] instalador: ${INSTALLER_SCRIPT}"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[install-trust-mac] se requieren permisos de administrador; solicitando sudo..."
  sudo "${INSTALLER_SCRIPT}" "${PREFIX}"
else
  "${INSTALLER_SCRIPT}" "${PREFIX}"
fi

APP_BIN="${PREFIX}/autofirma-desktop"
if [[ ! -x "${APP_BIN}" ]]; then
  echo "[install-trust-mac] ERROR: binario no encontrado tras instalación: ${APP_BIN}" >&2
  exit 1
fi

echo "[install-trust-mac] estado final de confianza:"
"${APP_BIN}" --trust-status || true

echo "[install-trust-mac] OK"
