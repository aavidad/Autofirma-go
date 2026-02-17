#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REL_DIR="${ROOT_DIR}/release/linux"
BUNDLE_DIR="${REL_DIR}/bundle/AutofirmaDipgra"
PAYLOAD_DIR="${REL_DIR}/payload"
ARTIFACT_TGZ="${REL_DIR}/AutofirmaDipgra-linux-x64.tar.gz"
ARTIFACT_RUN="${REL_DIR}/AutofirmaDipgra-linux-installer.run"
BIN_PATH="${BUNDLE_DIR}/autofirma-desktop"
HOST_BIN_PATH="${BUNDLE_DIR}/autofirma-host"
CHECK_STATIC="${CHECK_STATIC:-1}"
BUILD_SELF_CONTAINED="${BUILD_SELF_CONTAINED:-1}"

mkdir -p "${REL_DIR}" "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
rm -rf "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
mkdir -p "${BUNDLE_DIR}" "${PAYLOAD_DIR}"

echo "[linux] Building GUI binary..."
if [[ "${BUILD_SELF_CONTAINED}" == "1" ]]; then
  (
    cd "${ROOT_DIR}"
    set +e
    GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w" -o "${BIN_PATH}" ./cmd/gui
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "[linux] Error: no se pudo compilar en modo autocontenido (CGO_ENABLED=0)."
      echo "[linux] Con el GUI actual (Gio), Linux requiere CGO para backend grafico."
      echo "[linux] Acciones posibles:"
      echo "[linux]  1) Migrar GUI a una opcion 100% Go sin CGO en Linux."
      echo "[linux]  2) Build temporal con BUILD_SELF_CONTAINED=0 (acepta dependencias del sistema)."
      exit $rc
    fi
  )
else
  (
    cd "${ROOT_DIR}"
    GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags="-s -w" -o "${BIN_PATH}" ./cmd/gui
  )
fi

chmod +x "${BIN_PATH}"

if [[ "${BUILD_SELF_CONTAINED}" == "1" && "${CHECK_STATIC}" == "1" ]]; then
  echo "[linux] Verifying binary is self-contained (no dynamic linker deps)..."

  if command -v readelf >/dev/null 2>&1; then
    if readelf -d "${BIN_PATH}" 2>/dev/null | grep -q '(NEEDED)'; then
      echo "[linux] Error: dynamic shared libraries detected via readelf."
      readelf -d "${BIN_PATH}" | sed 's/^/[linux] readelf: /'
      exit 1
    fi
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd_out="$(ldd "${BIN_PATH}" 2>&1 || true)"
    if ! grep -qiE 'not a dynamic executable|statically linked' <<<"${ldd_out}"; then
      echo "[linux] Error: ldd indicates dynamic dependencies:"
      printf '%s\n' "${ldd_out}" | sed 's/^/[linux] ldd: /'
      exit 1
    fi
  fi
fi

echo "[linux] Building Native Messaging host binary..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "${HOST_BIN_PATH}" ./cmd/autofirma-host
)

chmod +x "${HOST_BIN_PATH}"

cat > "${BUNDLE_DIR}/README.txt" <<README
Autofirma Dipgra Linux

Ejecutable:
  ./autofirma-desktop
Host nativo:
  ./autofirma-host

Notas de compilacion:
  - Modo autocontenido activo: ${BUILD_SELF_CONTAINED}
  - Build con CGO desactivado solo en modo autocontenido
  - Validacion de binario no dinamico solo en modo autocontenido
README

# Tarball portable
(
  cd "${REL_DIR}/bundle"
  tar -czf "${ARTIFACT_TGZ}" "AutofirmaDipgra"
)

# Installer payload
mkdir -p "${PAYLOAD_DIR}/AutofirmaDipgra"
cp -a "${BUNDLE_DIR}/." "${PAYLOAD_DIR}/AutofirmaDipgra/"
cp "${ROOT_DIR}/packaging/linux/install.sh" "${PAYLOAD_DIR}/install.sh"
chmod +x "${PAYLOAD_DIR}/install.sh"

(
  cd "${PAYLOAD_DIR}"
  tar -czf payload.tar.gz AutofirmaDipgra install.sh
)

cat > "${ARTIFACT_RUN}" <<'HDR'
#!/usr/bin/env bash
set -euo pipefail

PREFIX="/opt/autofirma-dipgra"
if [[ "${1:-}" == "--prefix" ]]; then
  PREFIX="${2:-/opt/autofirma-dipgra}"
  shift 2 || true
fi

SELF="$0"
MARKER="__ARCHIVE_BELOW__"
LINE="$(awk -v m="$MARKER" '$0==m {print NR+1; exit}' "$SELF")"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

tail -n +"$LINE" "$SELF" | tar -xz -C "$TMPDIR"

if [[ "$EUID" -ne 0 ]]; then
  echo "Este instalador necesita permisos de root. Reintentando con sudo..."
  exec sudo "$TMPDIR/install.sh" "$PREFIX"
else
  exec "$TMPDIR/install.sh" "$PREFIX"
fi

exit 0
__ARCHIVE_BELOW__
HDR

cat "${PAYLOAD_DIR}/payload.tar.gz" >> "${ARTIFACT_RUN}"
chmod +x "${ARTIFACT_RUN}"

echo "[linux] Done"
echo "[linux] Portable: ${ARTIFACT_TGZ}"
echo "[linux] Installer: ${ARTIFACT_RUN}"

# 5. Optional: Try to register CA in NSS DB (for Chrome/Firefox)
echo "Intentando registrar CA local en navegadores..."
CERTS_DIR="$HOME/.config/AutofirmaDipgra/certs"
if [ -f "$CERTS_DIR/rootCA.crt" ] && command -v certutil >/dev/null 2>&1; then
    certutil -d "sql:$HOME/.pki/nssdb" -A -t "CT,C,C" -n "Autofirma Dipgra Local Root CA" -i "$CERTS_DIR/rootCA.crt" 2>/dev/null || true
    echo "CA registrada/intendada en NSS DB (best effort)."
else
    echo "No se pudo registrar la CA automáticamente (falta certutil o no se ha ejecutado la app aun)."
fi

echo "Instalación completada. Ejecuta 'AutoFirma Dipgra' desde tu menú de aplicaciones."
