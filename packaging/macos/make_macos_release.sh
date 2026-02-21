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
if [[ "${1:-}" == "--prefix" ]]; then
  PREFIX="${2:-/Applications/AutofirmaDipgra}"
  shift 2 || true
fi

SELF="$0"
MARKER="__ARCHIVE_BELOW__"
LINE="$(awk -v m="$MARKER" '$0==m {print NR+1; exit}' "$SELF")"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

tail -n +"$LINE" "$SELF" | tar -xz -C "$TMPDIR"

if [[ "$EUID" -ne 0 ]]; then
  echo "Este instalador necesita permisos de administrador. Reintentando con sudo..."
  exec sudo "$TMPDIR/install.sh" "$PREFIX"
else
  exec "$TMPDIR/install.sh" "$PREFIX"
fi

exit 0
__ARCHIVE_BELOW__
HDR

cat "${PAYLOAD_DIR}/payload.tar.gz" >> "${ARTIFACT_RUN}"
chmod +x "${ARTIFACT_RUN}"

echo "[macos] Listo"
echo "[macos] Portable: ${ARTIFACT_TGZ}"
echo "[macos] Instalador: ${ARTIFACT_RUN}"
