#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REL_DIR="${ROOT_DIR}/release/macos"
BUNDLE_DIR="${REL_DIR}/bundle/AutofirmaDipgra"
PAYLOAD_DIR="${REL_DIR}/payload"
ARTIFACT_TGZ="${REL_DIR}/AutofirmaDipgra-macos.tar.gz"
ARTIFACT_RUN="${REL_DIR}/AutofirmaDipgra-macos-installer.run"
BIN_PATH="${BUNDLE_DIR}/autofirma-desktop"
HOST_BIN_PATH="${BUNDLE_DIR}/autofirma-host"
DIPGRA_EXTENSION_DIR="${DIPGRA_EXTENSION_DIR:-${ROOT_DIR}/../../DipgraExtension}"

mkdir -p "${REL_DIR}" "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
rm -rf "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
mkdir -p "${BUNDLE_DIR}" "${PAYLOAD_DIR}"

echo "[macos] Compilando binario GUI..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "${BIN_PATH}" ./cmd/gui
)
chmod +x "${BIN_PATH}"

echo "[macos] Compilando host nativo..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "${HOST_BIN_PATH}" ./cmd/autofirma-host
)
chmod +x "${HOST_BIN_PATH}"
if [[ -d "${ROOT_DIR}/config" ]]; then
  mkdir -p "${BUNDLE_DIR}/config"
  cp -a "${ROOT_DIR}/config/." "${BUNDLE_DIR}/config/"
fi
if [[ -d "${ROOT_DIR}/cmd/qt_real/qml" ]]; then
  mkdir -p "${BUNDLE_DIR}/qml"
  cp -a "${ROOT_DIR}/cmd/qt_real/qml/." "${BUNDLE_DIR}/qml/"
fi
if [[ -d "${ROOT_DIR}/assets" ]]; then
  mkdir -p "${BUNDLE_DIR}/assets"
  cp -a "${ROOT_DIR}/assets/." "${BUNDLE_DIR}/assets/"
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
  echo "[macos] Extensiones Dipgra incluidas desde: ${DIPGRA_EXTENSION_DIR}"
else
  echo "[macos] Aviso: no se encontró DipgraExtension (DIPGRA_EXTENSION_DIR=${DIPGRA_EXTENSION_DIR})."
fi

echo "[macos] Compilando frontend Qt nativo..."
QT_REAL_BIN="${BUNDLE_DIR}/autofirma-desktop-qt-real"
if [[ -d "${ROOT_DIR}/cmd/qt_real" ]]; then
    (
        cd "${ROOT_DIR}/cmd/qt_real"
        # Intentar qmake6 primero
        QMAKE_BIN="qmake6"
        if ! command -v qmake6 >/dev/null 2>&1; then QMAKE_BIN="qmake"; fi
        
        $QMAKE_BIN
        make clean
        make -j4
        cp -f qt_real "${QT_REAL_BIN}"
    )
    
    # Despliegue de librerías Qt (macdeployqt)
    MACDEPLOYQT="$(command -v macdeployqt || echo "/usr/local/opt/qt/bin/macdeployqt")"
    if [[ -x "$MACDEPLOYQT" ]]; then
        echo "[macos] Ejecutando macdeployqt..."
        # Nota: macdeployqt suele trabajar sobre .app, pero puede procesar binarios sueltos con -executable
        # Aquí lo ideal sería crear un .app real para macOS. Por ahora procesamos el binario.
        "$MACDEPLOYQT" "${QT_REAL_BIN}" -qmldir="${ROOT_DIR}/cmd/qt_real/qml" -always-overwrite
    else
        echo "[macos] Aviso: macdeployqt no encontrado. Las librerías de Qt deberán estar en el sistema."
    fi
fi

cat > "${BUNDLE_DIR}/README.txt" <<README
Autofirma Dipgra macOS

Ejecutable:
  ./autofirma-desktop
Host nativo:
  ./autofirma-host
Extensiones navegador:
  ./extensiones/dipgra-extension-chromium.zip
  ./extensiones/dipgra-extension-firefox.zip
README

(
  cd "${REL_DIR}/bundle"
  tar -czf "${ARTIFACT_TGZ}" "AutofirmaDipgra"
)

mkdir -p "${PAYLOAD_DIR}/AutofirmaDipgra"
cp -a "${BUNDLE_DIR}/." "${PAYLOAD_DIR}/AutofirmaDipgra/"
cp "${ROOT_DIR}/packaging/macos/install.sh" "${PAYLOAD_DIR}/install.sh"
cp -a "${ROOT_DIR}/packaging/macos/certs" "${PAYLOAD_DIR}/certs"
chmod +x "${PAYLOAD_DIR}/install.sh"

(
  cd "${PAYLOAD_DIR}"
  tar -czf payload.tar.gz AutofirmaDipgra install.sh certs
)

cat > "${ARTIFACT_RUN}" <<'HDR'
#!/usr/bin/env bash
set -euo pipefail

PREFIX="/Applications/AutofirmaDipgra"
PROFILE="${AUTOFIRMA_INSTALL_PERFIL:-${AUTOFIRMA_INSTALL_PROFILE:-completo}}"
SUBPROFILE_DESKTOP="${AUTOFIRMA_SUBPERFIL_ESCRITORIO:-${AUTOFIRMA_DESKTOP_SUBPROFILE:-fyne}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="${2:-/Applications/AutofirmaDipgra}"
      shift 2 || true
      ;;
    --perfil|--profile)
      PROFILE="${2:-completo}"
      shift 2 || true
      ;;
    --subperfil-escritorio|--subperfil-desktop|--subperfil)
      SUBPROFILE_DESKTOP="${2:-fyne}"
      shift 2 || true
      ;;
    *)
      echo "Uso: $0 [--prefix <ruta>] [--perfil minimo|escritorio|completo] [--subperfil-escritorio fyne|gio|qt]" >&2
      exit 1
      ;;
  esac
done

SELF="$0"
MARKER="__ARCHIVE_BELOW__"
LINE="$(awk -v m="$MARKER" '$0==m {print NR+1; exit}' "$SELF")"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

tail -n +"$LINE" "$SELF" | tar -xz -C "$TMPDIR"

if [[ "$EUID" -ne 0 ]]; then
  echo "Este instalador necesita permisos de administrador. Reintentando con sudo..."
  exec sudo "$TMPDIR/install.sh" "$PREFIX" --perfil "$PROFILE" --subperfil-escritorio "$SUBPROFILE_DESKTOP"
else
  exec "$TMPDIR/install.sh" "$PREFIX" --perfil "$PROFILE" --subperfil-escritorio "$SUBPROFILE_DESKTOP"
fi

exit 0
__ARCHIVE_BELOW__
HDR

cat "${PAYLOAD_DIR}/payload.tar.gz" >> "${ARTIFACT_RUN}"
chmod +x "${ARTIFACT_RUN}"

echo "[macos] Listo"
echo "[macos] Portable: ${ARTIFACT_TGZ}"
echo "[macos] Instalador: ${ARTIFACT_RUN}"
