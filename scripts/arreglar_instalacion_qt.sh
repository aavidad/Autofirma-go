#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

APP_DIR="/opt/autofirma-dipgra"
BIN_MAIN="${APP_DIR}/autofirma-desktop"
BIN_QT="${APP_DIR}/autofirma-desktop-qt-bin"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_MAIN="${ROOT_DIR}/release/linux/bundle/AutofirmaDipgra/autofirma-desktop"

if [[ ! -x "${BIN_QT}" ]]; then
  echo "[ERROR] No existe ${BIN_QT}."
  echo "Reinstala el paquete primero y vuelve a ejecutar este script."
  exit 1
fi

if [[ ! -x "${BUNDLE_MAIN}" ]]; then
  echo "[ERROR] No existe ${BUNDLE_MAIN}."
  echo "Genera antes el release Linux para restaurar el binario principal:"
  echo "  ./packaging/linux/make_linux_release.sh"
  exit 1
fi

echo "[1/4] Restaurando autofirma-desktop (binario Go principal)..."
sudo install -m 0755 "${BUNDLE_MAIN}" "${BIN_MAIN}"

echo "[2/4] Reescribiendo launchers..."
sudo rm -f /usr/local/bin/autofirma-dipgra

sudo tee /usr/local/bin/autofirma-dipgra >/dev/null <<'EOF'
#!/usr/bin/env bash
exec env AUTOFIRMA_QT_RUNTIME_DIR=/opt/autofirma-dipgra/qt-runtime "/opt/autofirma-dipgra/autofirma-desktop" -frontend qt "$@"
EOF

sudo tee /usr/local/bin/autofirma-dipgra-qt >/dev/null <<'EOF'
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

sudo chmod 0755 \
  /usr/local/bin/autofirma-dipgra \
  /usr/local/bin/autofirma-dipgra-qt \
  /usr/local/bin/autofirma-dipgra-fyne \
  /usr/local/bin/autofirma-dipgra-gio

echo "[3/4] Verificando binario..."
file "${BIN_MAIN}"

echo "[4/4] Probando version..."
autofirma-dipgra-qt --version || true

echo "OK: instalacion Qt reparada."
