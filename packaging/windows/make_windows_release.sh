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
GUI_CMD_PKG="${GUI_CMD_PKG:-./cmd/autofirma}"
HOST_CMD_PKG="${HOST_CMD_PKG:-./cmd/browser-bridge}"
PREBUILT_EXE="${PREBUILT_EXE:-}"
PREBUILT_HOST_EXE="${PREBUILT_HOST_EXE:-}"
PREBUILT_QT_EXE="${PREBUILT_QT_EXE:-}"
QT_REAL_EXE="${QT_REAL_EXE:-}"
CHROMIUM_IDS_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_IDS:-}"
FIREFOX_IDS_RAW="${AUTOFIRMA_FIREFOX_EXTENSION_IDS:-extension@dipgra.es}"
DIPGRA_EXTENSION_DIR="${DIPGRA_EXTENSION_DIR:-${ROOT_DIR}/../../DipgraExtension}"

json_array_from_csv() {
  local raw="$1"
  local out="["
  local first=1
  local item trimmed escaped
  IFS=',' read -r -a parts <<<"${raw}"
  for item in "${parts[@]:-}"; do
    trimmed="$(echo "${item}" | xargs)"
    [[ -n "${trimmed}" ]] || continue
    escaped="${trimmed//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    if [[ ${first} -eq 0 ]]; then
      out+=", "
    fi
    out+="\"${escaped}\""
    first=0
  done
  out+="]"
  printf '%s' "${out}"
}

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
  echo "[windows] Building GUI binary from ${GUI_CMD_PKG}..."
  (
    cd "${ROOT_DIR}"
    GOCACHE=/tmp/gocache GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
      go build -mod=mod -ldflags="-H=windowsgui" -o "${BUNDLE_DIR}/autofirma-desktop.exe" "${GUI_CMD_PKG}"
  )
fi

if [[ -n "${PREBUILT_HOST_EXE}" ]]; then
  if [[ ! -f "${PREBUILT_HOST_EXE}" ]]; then
    echo "[windows] Error: PREBUILT_HOST_EXE no existe: ${PREBUILT_HOST_EXE}"
    exit 1
  fi
  echo "[windows] Using prebuilt native host executable: ${PREBUILT_HOST_EXE}"
  cp -f "${PREBUILT_HOST_EXE}" "${BUNDLE_DIR}/autofirma-host.exe"
else
  echo "[windows] Building Native Messaging host binary..."
  (
    cd "${ROOT_DIR}"
    GOCACHE=/tmp/gocache GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
      go build -mod=mod -trimpath -ldflags="-s -w" -o "${BUNDLE_DIR}/autofirma-host.exe" "${HOST_CMD_PKG}"
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
if [[ -d "${ROOT_DIR}/config" ]]; then
  mkdir -p "${BUNDLE_DIR}/config"
  cp -a "${ROOT_DIR}/config/." "${BUNDLE_DIR}/config/"
fi

if [[ -d "${DIPGRA_EXTENSION_DIR}/extension" || -d "${DIPGRA_EXTENSION_DIR}/extension-firefox" ]]; then
  mkdir -p "${BUNDLE_DIR}/extensiones"
  if [[ -d "${DIPGRA_EXTENSION_DIR}/extension" ]]; then
    cp -a "${DIPGRA_EXTENSION_DIR}/extension" "${BUNDLE_DIR}/extensiones/chromium"
    if command -v zip >/dev/null 2>&1; then
      (
        cd "${BUNDLE_DIR}/extensiones"
        rm -f dipgra-extension-chromium.zip
        zip -qr dipgra-extension-chromium.zip chromium
      )
    fi
  fi
  if [[ -d "${DIPGRA_EXTENSION_DIR}/extension-firefox" ]]; then
    cp -a "${DIPGRA_EXTENSION_DIR}/extension-firefox" "${BUNDLE_DIR}/extensiones/firefox"
    if command -v zip >/dev/null 2>&1; then
      (
        cd "${BUNDLE_DIR}/extensiones"
        rm -f dipgra-extension-firefox.zip
        zip -qr dipgra-extension-firefox.zip firefox
        rm -f dipgra-extension-firefox.xpi
        cp -f dipgra-extension-firefox.zip dipgra-extension-firefox.xpi
      )
    fi
  fi
  echo "[windows] Extensiones Dipgra incluidas desde: ${DIPGRA_EXTENSION_DIR}"
else
fi

# Qt/QML resources
if [[ -d "${ROOT_DIR}/cmd/qt_real/qml" ]]; then
  mkdir -p "${BUNDLE_DIR}/qml"
  cp -a "${ROOT_DIR}/cmd/qt_real/qml/." "${BUNDLE_DIR}/qml/"
fi
if [[ -d "${ROOT_DIR}/assets" ]]; then
  mkdir -p "${BUNDLE_DIR}/assets"
  cp -a "${ROOT_DIR}/assets/." "${BUNDLE_DIR}/assets/"
fi

chromium_ids_json="$(json_array_from_csv "${CHROMIUM_IDS_RAW}")"
firefox_ids_json="$(json_array_from_csv "${FIREFOX_IDS_RAW}")"
allow_require="false"
if [[ "${chromium_ids_json}" != "[]" || "${firefox_ids_json}" != "[]" ]]; then
  allow_require="true"
fi
cat > "${BUNDLE_DIR}/native_messaging_allowlist.json" <<JSON
{
  "chromium_ids": ${chromium_ids_json},
  "firefox_ids": ${firefox_ids_json},
  "require_match": ${allow_require}
}
JSON

cat > "${BUNDLE_DIR}/autofirma-dipgra-server.bat" <<'BAT'
@echo off
"%~dp0autofirma-desktop.exe" --server %*
BAT

if [[ -n "${PREBUILT_QT_EXE}" ]]; then
  if [[ ! -f "${PREBUILT_QT_EXE}" ]]; then
    echo "[windows] Error: PREBUILT_QT_EXE no existe: ${PREBUILT_QT_EXE}"
    exit 1
  fi
  echo "[windows] Using prebuilt Qt wrapper executable: ${PREBUILT_QT_EXE}"
  cp -f "${PREBUILT_QT_EXE}" "${BUNDLE_DIR}/autofirma-desktop-qt-bin.exe"
else
  if [[ -d "${ROOT_DIR}/cmd/qt" ]]; then
    echo "[windows] Building Qt wrapper binary..."
    (
      cd "${ROOT_DIR}"
      GOCACHE=/tmp/gocache GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
        go build -mod=mod -ldflags="-H=windowsgui" -o "${BUNDLE_DIR}/autofirma-desktop-qt-bin.exe" ./cmd/qt
    )
  else
    echo "[windows] Aviso: no existe ./cmd/qt; no se incluirá wrapper Qt."
  fi
fi

if [[ -n "${QT_REAL_EXE}" ]]; then
  if [[ ! -f "${QT_REAL_EXE}" ]]; then
    echo "[windows] Error: QT_REAL_EXE no existe: ${QT_REAL_EXE}"
    exit 1
  fi
  cp -f "${QT_REAL_EXE}" "${BUNDLE_DIR}/autofirma-desktop-qt-real.exe"
  echo "[linux] Frontend Qt nativo incluido: ${QT_REAL_EXE}"
  
  # Qt Deployment (Solo si estamos en Windows o tenemos windeployqt en PATH)
  if command -v windeployqt >/dev/null 2>&1; then
    echo "[windows] Running windeployqt..."
    windeployqt --no-translations --no-compiler-runtime --qmldir "${ROOT_DIR}/cmd/qt_real/qml" "${BUNDLE_DIR}/autofirma-desktop-qt-real.exe"
  elif command -v windeployqt.exe >/dev/null 2>&1; then
    echo "[windows] Running windeployqt.exe..."
    windeployqt.exe --no-translations --no-compiler-runtime --qmldir "${ROOT_DIR}/cmd/qt_real/qml" "${BUNDLE_DIR}/autofirma-desktop-qt-real.exe"
  else
    echo "[windows] Warning: windeployqt no encontrado. Las DLLs de Qt deberán añadirse manualmente al bundle."
  fi
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
