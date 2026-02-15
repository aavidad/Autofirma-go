#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

PREFIX="${1:-/opt/autofirma-dipgra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/AutofirmaDipgra"

if [[ ! -d "${APP_SRC}" ]]; then
  echo "ERROR: payload not found at ${APP_SRC}" >&2
  exit 1
fi

echo "[install] Installing into ${PREFIX}"
mkdir -p "${PREFIX}"
cp -a "${APP_SRC}/." "${PREFIX}/"
chmod +x "${PREFIX}/autofirma-desktop"

mkdir -p /usr/local/bin
ln -sf "${PREFIX}/autofirma-desktop" /usr/local/bin/autofirma-dipgra

mkdir -p /usr/local/share/applications
cat > /usr/local/share/applications/autofirma-dipgra.desktop <<DESKTOP
[Desktop Entry]
Name=Autofirma Dipgra
Comment=Firma electronica de documentos
Exec=${PREFIX}/autofirma-desktop %u
Terminal=false
Type=Application
Categories=Office;Security;
MimeType=x-scheme-handler/afirma;
DESKTOP

# Register afirma:// protocol handler in desktop DB if available
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/local/share/applications || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default autofirma-dipgra.desktop x-scheme-handler/afirma || true
fi
if command -v xdg-settings >/dev/null 2>&1; then
  xdg-settings set default-url-scheme-handler afirma autofirma-dipgra.desktop || true
fi

# Persist per-user association when installer is run with sudo.
if [[ -n "${SUDO_USER:-}" ]]; then
  USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
  if [[ -n "${USER_HOME}" ]]; then
    USER_APPS_DIR="${USER_HOME}/.local/share/applications"
    USER_MIMEAPPS="${USER_APPS_DIR}/mimeapps.list"
    mkdir -p "${USER_APPS_DIR}"
    if [[ ! -f "${USER_MIMEAPPS}" ]]; then
      cat > "${USER_MIMEAPPS}" <<MIMEAPPS
[Default Applications]
x-scheme-handler/afirma=autofirma-dipgra.desktop
MIMEAPPS
    elif ! grep -q '^x-scheme-handler/afirma=' "${USER_MIMEAPPS}"; then
      awk '
        BEGIN { done=0 }
        /^\[Default Applications\]$/ { print; print "x-scheme-handler/afirma=autofirma-dipgra.desktop"; done=1; next }
        { print }
        END {
          if (done==0) {
            print "[Default Applications]"
            print "x-scheme-handler/afirma=autofirma-dipgra.desktop"
          }
        }
      ' "${USER_MIMEAPPS}" > "${USER_MIMEAPPS}.tmp" && mv "${USER_MIMEAPPS}.tmp" "${USER_MIMEAPPS}"
    else
      sed -i 's#^x-scheme-handler/afirma=.*#x-scheme-handler/afirma=autofirma-dipgra.desktop#' "${USER_MIMEAPPS}"
    fi
    chown "${SUDO_USER}:${SUDO_USER}" "${USER_MIMEAPPS}" || true
  fi
fi

echo "[install] Done"
echo "[install] Binary: ${PREFIX}/autofirma-desktop"
echo "[install] Command: autofirma-dipgra"
