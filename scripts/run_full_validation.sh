#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STRICT_FORMATS=0
SKIP_TRUST=0
SKIP_SEDE_LOGCHECK=0
SEDE_LOG_FILE="/tmp/autofirma-launcher.log"
SEDE_SINCE_MINUTES=120

usage() {
  cat <<USAGE
Uso:
  $0 [opciones]

Opciones:
  --strict-formats       Ejecuta smoke de PAdES/XAdES en modo estricto.
  --skip-trust           Omite instalacion/comprobacion de trust local.
  --skip-sede-logcheck   Omite comprobacion de log de sede.
  --sede-log-file PATH   Ruta de log para smoke_sede_logcheck.sh (default: ${SEDE_LOG_FILE}).
  --since-minutes N      Ventana temporal para smoke_sede_logcheck.sh (default: ${SEDE_SINCE_MINUTES}).
  -h, --help             Muestra esta ayuda.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict-formats) STRICT_FORMATS=1; shift ;;
    --skip-trust) SKIP_TRUST=1; shift ;;
    --skip-sede-logcheck) SKIP_SEDE_LOGCHECK=1; shift ;;
    --sede-log-file) SEDE_LOG_FILE="${2:-}"; shift 2 ;;
    --since-minutes) SEDE_SINCE_MINUTES="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Argumento desconocido: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "${ROOT_DIR}"

cleanup() {
  echo "[full-check] stopping web compat server..."
  bash scripts/run_web_compat_server.sh stop || true
}
trap cleanup EXIT

echo "[full-check] 1/7 tests de codigo activo"
bash scripts/test_active_go.sh

echo "[full-check] 2/7 smoke host nativo"
if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
  bash scripts/smoke_native_host.sh --strict-formats
else
  bash scripts/smoke_native_host.sh
fi

if [[ "${SKIP_TRUST}" -eq 0 ]]; then
  echo "[full-check] 3/7 trust local (certificados + estado)"
  bash scripts/install_and_trust_linux.sh
else
  echo "[full-check] 3/7 trust local omitido (--skip-trust)"
fi

echo "[full-check] 4/7 servidor web compat (start/status)"
bash scripts/run_web_compat_server.sh start
bash scripts/run_web_compat_server.sh status

echo "[full-check] 5/7 handshake WSS (echo)"
bash scripts/ws_echo_client.py

echo "[full-check] 6/7 log local de web compat (ultimas lineas)"
tail -n 80 /tmp/autofirma-web-compat.log || true

if [[ "${SKIP_SEDE_LOGCHECK}" -eq 0 ]]; then
  echo "[full-check] 7/7 smoke de log de sede"
  bash scripts/smoke_sede_logcheck.sh --log-file "${SEDE_LOG_FILE}" --since-minutes "${SEDE_SINCE_MINUTES}"
else
  echo "[full-check] 7/7 smoke de log de sede omitido (--skip-sede-logcheck)"
fi

echo "[full-check] OK"
echo "[full-check] siguiente paso: prueba manual en sede con navegador y revisar /tmp/autofirma-web-compat.log"
