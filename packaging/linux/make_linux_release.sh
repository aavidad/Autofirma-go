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

mkdir -p "${REL_DIR}" "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
rm -rf "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
mkdir -p "${BUNDLE_DIR}" "${PAYLOAD_DIR}"

echo "[linux] Building GUI binary..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 go build -o "${BUNDLE_DIR}/autofirma-desktop" ./cmd/gui
)

chmod +x "${BUNDLE_DIR}/autofirma-desktop"

cat > "${BUNDLE_DIR}/README.txt" <<README
Autofirma Dipgra Linux

Ejecutable:
  ./autofirma-desktop
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
