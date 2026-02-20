#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

PREFIX="${1:-/Applications/AutofirmaDipgra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/AutofirmaDipgra"
FNMT_ACCOMP_CERT="${SCRIPT_DIR}/certs/fnmt-accomp.crt"

if [[ ! -d "${APP_SRC}" ]]; then
  echo "ERROR: payload no encontrado en ${APP_SRC}" >&2
  exit 1
fi

install_fnmt_accomp_system_ca_macos() {
  if [[ ! -f "${FNMT_ACCOMP_CERT}" ]]; then
    echo "[install-mac] Aviso: no se encontró certificado FNMT ACCOMP en payload (${FNMT_ACCOMP_CERT})."
    return 0
  fi
  if ! openssl x509 -in "${FNMT_ACCOMP_CERT}" -noout >/dev/null 2>&1; then
    echo "[install-mac] Aviso: certificado FNMT ACCOMP inválido, se omite instalación."
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "[install-mac] Aviso: se omite instalación de CA FNMT ACCOMP en System.keychain (requiere root)."
    return 0
  fi
  security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain "${FNMT_ACCOMP_CERT}" >/dev/null 2>&1 || true
  echo "[install-mac] CA FNMT ACCOMP instalada/actualizada en System.keychain."
}

echo "[install-mac] Instalando en ${PREFIX}"
mkdir -p "${PREFIX}"
cp -a "${APP_SRC}/." "${PREFIX}/"
chmod +x "${PREFIX}/autofirma-desktop" || true
[[ -f "${PREFIX}/autofirma-host" ]] && chmod +x "${PREFIX}/autofirma-host" || true

echo "[install-mac] Generando certificados locales..."
"${PREFIX}/autofirma-desktop" --generate-certs || true

echo "[install-mac] Instalando confianza local..."
"${PREFIX}/autofirma-desktop" --install-trust || true
install_fnmt_accomp_system_ca_macos

echo "[install-mac] Exportando certificados compatibles Java en ${PREFIX}..."
"${PREFIX}/autofirma-desktop" --exportar-certs-java "${PREFIX}" || true

echo "[install-mac] Estado de confianza local..."
"${PREFIX}/autofirma-desktop" --trust-status || true

mkdir -p /usr/local/bin
ln -sf "${PREFIX}/autofirma-desktop" /usr/local/bin/autofirma-dipgra
if [[ -f "${PREFIX}/autofirma-host" ]]; then
  ln -sf "${PREFIX}/autofirma-host" /usr/local/bin/autofirma-host
fi

echo "[install-mac] Listo"
echo "[install-mac] Binario: ${PREFIX}/autofirma-desktop"
echo "[install-mac] Certificados Java: ${PREFIX}/autofirma.pfx ${PREFIX}/Autofirma_ROOT.cer ${PREFIX}/autofirma.cer"
