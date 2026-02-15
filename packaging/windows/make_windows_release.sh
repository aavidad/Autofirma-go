#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REL_DIR="${ROOT_DIR}/release/windows"
BUNDLE_DIR="${REL_DIR}/bundle/AutofirmaDipgra"
NSI_FILE="${ROOT_DIR}/packaging/windows/autofirma_windows_installer.nsi"
ICON_FILE="${ROOT_DIR}/packaging/windows/autofirma.ico"
VERSION_FILE="${ROOT_DIR}/pkg/version/version.go"
DEFAULT_APP_VERSION="$(awk -F'"' '/CurrentVersion/ {print $2; exit}' "${VERSION_FILE}" 2>/dev/null || true)"
if [[ -z "${DEFAULT_APP_VERSION}" ]]; then
  DEFAULT_APP_VERSION="0.0.0"
fi
APP_VERSION="${APP_VERSION:-${DEFAULT_APP_VERSION}}"
UPDATE_JSON_URL="${UPDATE_JSON_URL:-https://autofirma.dipgra.es/version.json}"

mkdir -p "${REL_DIR}" "${BUNDLE_DIR}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}"

echo "[windows] Building GUI binary..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-H=windowsgui" -o "${BUNDLE_DIR}/autofirma-desktop.exe" ./cmd/gui
)

if [[ -f "${ICON_FILE}" ]]; then
  cp -f "${ICON_FILE}" "${BUNDLE_DIR}/autofirma.ico"
else
  echo "[windows] Warning: icon file not found at ${ICON_FILE}"
fi

echo "[windows] Building NSIS installer..."
(
  cd "${ROOT_DIR}"
  makensis \
    -DAPP_VERSION="${APP_VERSION}" \
    -DUPDATE_JSON_URL="${UPDATE_JSON_URL}" \
    -DBUNDLE_DIR="${BUNDLE_DIR}" \
    -DOUTFILE_PATH="${REL_DIR}/AutofirmaDipgra-windows-installer.exe" \
    "${NSI_FILE}"
)

echo "[windows] Done"
echo "[windows] Bundle: ${BUNDLE_DIR}"
echo "[windows] Installer: ${REL_DIR}/AutofirmaDipgra-windows-installer.exe"
