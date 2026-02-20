#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_DIR="${ROOT_DIR}/release/linux/bundle/AutofirmaDipgra"
TARGET_DIR="/opt/autofirma-dipgra"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[reparar-qt] ERROR: falta comando requerido: $1" >&2
    exit 1
  }
}

need_cmd sudo
need_cmd install

if [[ ! -f "${BUNDLE_DIR}/autofirma-desktop" || ! -f "${BUNDLE_DIR}/autofirma-desktop-qt-bin" || ! -f "${BUNDLE_DIR}/autofirma-desktop-qt-real" ]]; then
  echo "[reparar-qt] Bundle incompleto en ${BUNDLE_DIR}" >&2
  echo "[reparar-qt] Genera primero el release:" >&2
  echo "  QT_RUNTIME_FROM_SYSTEM=1 BUILD_QT_REAL_FROM_SOURCE=1 BUILD_SELF_CONTAINED=0 ./packaging/linux/make_linux_release.sh" >&2
  exit 1
fi

echo "[reparar-qt] Copiando binarios a ${TARGET_DIR}..."
sudo mkdir -p "${TARGET_DIR}"
sudo install -m 0755 "${BUNDLE_DIR}/autofirma-desktop" "${TARGET_DIR}/autofirma-desktop"
sudo install -m 0755 "${BUNDLE_DIR}/autofirma-desktop-qt-bin" "${TARGET_DIR}/autofirma-desktop-qt-bin"
sudo install -m 0755 "${BUNDLE_DIR}/autofirma-desktop-qt-real" "${TARGET_DIR}/autofirma-desktop-qt-real"
sudo install -m 0755 "${BUNDLE_DIR}/autofirma-host" "${TARGET_DIR}/autofirma-host"
if [[ -d "${BUNDLE_DIR}/qt-runtime" ]]; then
  sudo rm -rf "${TARGET_DIR}/qt-runtime"
  sudo mkdir -p "${TARGET_DIR}/qt-runtime"
  sudo cp -a "${BUNDLE_DIR}/qt-runtime/." "${TARGET_DIR}/qt-runtime/"
fi

echo "[reparar-qt] Creando launchers en /usr/local/bin..."
sudo tee /usr/local/bin/autofirma-dipgra-qt >/dev/null <<'EOF'
#!/usr/bin/env bash
exec env AUTOFIRMA_QT_RUNTIME_DIR=/opt/autofirma-dipgra/qt-runtime "/opt/autofirma-dipgra/autofirma-desktop" -frontend qt "$@"
EOF
sudo tee /usr/local/bin/autofirma-dipgra >/dev/null <<'EOF'
#!/usr/bin/env bash
exec env AUTOFIRMA_QT_RUNTIME_DIR=/opt/autofirma-dipgra/qt-runtime "/opt/autofirma-dipgra/autofirma-desktop" -frontend qt "$@"
EOF
sudo tee /usr/local/bin/autofirma-dipgra-fyne >/dev/null <<'EOF'
#!/usr/bin/env bash
exec "/opt/autofirma-dipgra/autofirma-desktop" -frontend fyne "$@"
EOF
sudo tee /usr/local/bin/autofirma-dipgra-gio >/dev/null <<'EOF'
#!/usr/bin/env bash
exec "/opt/autofirma-dipgra/autofirma-desktop" -frontend gio "$@"
EOF
sudo chmod 0755 /usr/local/bin/autofirma-dipgra /usr/local/bin/autofirma-dipgra-qt /usr/local/bin/autofirma-dipgra-fyne /usr/local/bin/autofirma-dipgra-gio

echo "[reparar-qt] Verificación..."
file "${TARGET_DIR}/autofirma-desktop" | sed 's/^/[reparar-qt] /'
echo "[reparar-qt] OK. Arranca con: autofirma-dipgra-qt"
