#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_INSTALLER="${ROOT_DIR}/release/linux/AutofirmaDipgra-linux-installer.run"
INSTALLER_PATH="${1:-${DEFAULT_INSTALLER}}"

if [[ ! -f "${INSTALLER_PATH}" ]]; then
  echo "[install-trust] ERROR: installer not found: ${INSTALLER_PATH}" >&2
  echo "[install-trust] Usage: $0 [path_to_installer.run]" >&2
  exit 1
fi

if [[ ! -x "${INSTALLER_PATH}" ]]; then
  chmod +x "${INSTALLER_PATH}"
fi

echo "[install-trust] Installer: ${INSTALLER_PATH}"
echo "[install-trust] Requesting sudo once..."
sudo -v

echo "[install-trust] Running installer..."
sudo "${INSTALLER_PATH}"

APP_BIN="/opt/autofirma-dipgra/autofirma-desktop"
if [[ ! -x "${APP_BIN}" ]]; then
  if command -v autofirma-dipgra >/dev/null 2>&1; then
    APP_BIN="$(command -v autofirma-dipgra)"
  else
    echo "[install-trust] ERROR: autofirma-desktop not found after install" >&2
    exit 1
  fi
fi

echo "[install-trust] Applying user trust stores (NSS)..."
"${APP_BIN}" --install-trust

echo "[install-trust] Trust status:"
"${APP_BIN}" --trust-status

echo "[install-trust] Done."
