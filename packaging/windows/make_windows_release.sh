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
GUI_CMD_PKG="${GUI_CMD_PKG:-}"
PREBUILT_EXE="${PREBUILT_EXE:-}"

if ! command -v makensis >/dev/null 2>&1; then
  echo "[windows] Error: 'makensis' no esta instalado o no esta en PATH."
  echo "[windows] Instala NSIS y vuelve a ejecutar este script."
  exit 1
fi

mkdir -p "${REL_DIR}" "${BUNDLE_DIR}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}"

if [[ -n "${PREBUILT_EXE}" ]]; then
  if [[ ! -f "${PREBUILT_EXE}" ]]; then
    echo "[windows] Error: PREBUILT_EXE no existe: ${PREBUILT_EXE}"
    exit 1
  fi
  echo "[windows] Using prebuilt executable: ${PREBUILT_EXE}"
  cp -f "${PREBUILT_EXE}" "${BUNDLE_DIR}/autofirma-desktop.exe"
else
  if [[ -z "${GUI_CMD_PKG}" ]]; then
    if [[ -d "${ROOT_DIR}/cmd/gui" ]]; then
      GUI_CMD_PKG="./cmd/gui"
    else
      mapfile -t gui_candidates < <(find "${ROOT_DIR}/cmd" -maxdepth 1 -mindepth 1 -type d -name 'gui*' | sort)
      if [[ "${#gui_candidates[@]}" -eq 1 ]]; then
        rel_candidate="${gui_candidates[0]#${ROOT_DIR}/}"
        GUI_CMD_PKG="./${rel_candidate}"
        echo "[windows] Warning: usando paquete GUI detectado automaticamente: ${GUI_CMD_PKG}"
      elif [[ "${#gui_candidates[@]}" -gt 1 ]]; then
        echo "[windows] Error: hay varios candidatos GUI en cmd/:"
        printf '  - %s\n' "${gui_candidates[@]#${ROOT_DIR}/}"
        echo "[windows] Define GUI_CMD_PKG, por ejemplo:"
        echo "  GUI_CMD_PKG=./cmd/gui ./packaging/windows/make_windows_release.sh"
        exit 1
      else
        echo "[windows] Error: no se encontro paquete GUI en cmd/."
        echo "[windows] Crea cmd/gui, define GUI_CMD_PKG o usa PREBUILT_EXE."
        exit 1
      fi
    fi
  fi

  echo "[windows] Building GUI binary from ${GUI_CMD_PKG}..."
  (
    cd "${ROOT_DIR}"
    GOCACHE=/tmp/gocache GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
      go build -ldflags="-H=windowsgui" -o "${BUNDLE_DIR}/autofirma-desktop.exe" "${GUI_CMD_PKG}"
  )
fi

if [[ -f "${ICON_FILE}" ]]; then
  cp -f "${ICON_FILE}" "${BUNDLE_DIR}/autofirma.ico"
else
  echo "[windows] Warning: icon file not found at ${ICON_FILE}"
fi

if [[ -f "${ROOT_DIR}/packaging/windows/certs/fnmt-accomp.crt" ]]; then
  mkdir -p "${BUNDLE_DIR}/certs"
  cp -f "${ROOT_DIR}/packaging/windows/certs/fnmt-accomp.crt" "${BUNDLE_DIR}/certs/fnmt-accomp.crt"
else
  echo "[windows] Warning: cert file not found at packaging/windows/certs/fnmt-accomp.crt"
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
