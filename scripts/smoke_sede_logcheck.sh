#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

LOG_FILE="/tmp/autofirma-launcher.log"
SINCE_MINUTES=120

usage() {
  cat <<USAGE
Uso: $0 [--log-file PATH] [--since-minutes N]

Comprueba la última ejecución de protocolo AutoFirma en el log del lanzador:
- respuesta de subida legacy body="OK" o respuesta websocket sin errores
- sin errores COD_103 / messageDigest
- sin trazas de fallback de ejecución Node.js
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log-file)
      LOG_FILE="${2:-}"
      shift 2
      ;;
    --since-minutes)
      SINCE_MINUTES="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Argumento no reconocido: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$LOG_FILE" ]]; then
  for candidate in \
    "${HOME}/.local/state/autofirma-dipgra/logs/autofirma-desktop-$(date +%F).log" \
    "/tmp/AutofirmaDipgra/logs/autofirma-desktop-$(date +%F).log"; do
    if [[ -f "${candidate}" ]]; then
      LOG_FILE="${candidate}"
      echo "INFO: log auto-detectado: ${LOG_FILE}"
      break
    fi
  done
fi

if [[ ! -f "$LOG_FILE" ]]; then
  echo "FALLO: no existe el archivo de log: $LOG_FILE" >&2
  exit 1
fi

if ! [[ "$SINCE_MINUTES" =~ ^[0-9]+$ ]]; then
  echo "FALLO: --since-minutes debe ser entero" >&2
  exit 1
fi

CUTOFF_EPOCH="$(date +%s)"
CUTOFF_EPOCH=$((CUTOFF_EPOCH - SINCE_MINUTES * 60))

TMP_FILTERED="$(mktemp)"
trap 'rm -f "$TMP_FILTERED"' EXIT

# Filter by timestamp prefix: "YYYY/MM/DD HH:MM:SS"
awk -v cutoff="$CUTOFF_EPOCH" '
function toepoch(s,  cmd, out) {
  gsub(/\//, "-", s);
  cmd = "date -d \"" s "\" +%s";
  cmd | getline out;
  close(cmd);
  return out + 0;
}
{
  ts = substr($0, 1, 19);
  if (ts ~ /^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$/) {
    if (toepoch(ts) >= cutoff) print $0;
  }
}
' "$LOG_FILE" > "$TMP_FILTERED"

if [[ ! -s "$TMP_FILTERED" ]]; then
  echo "FALLO: no hay líneas de log en los últimos ${SINCE_MINUTES} minutos" >&2
  exit 1
fi

if grep -Eiq 'COD_103|messageDigest|No se dispone del atributo firmado messageDigest' "$TMP_FILTERED"; then
  echo "FALLO: se detectó error COD_103/messageDigest en logs recientes" >&2
  grep -Ein 'COD_103|messageDigest|No se dispone del atributo firmado messageDigest' "$TMP_FILTERED" || true
  exit 1
fi

LEGACY_OK=0
WS_OK=0

if grep -Fq 'java-style upload response status=200 body="OK"' "$TMP_FILTERED"; then
  LEGACY_OK=1
fi

if grep -Eiq '\[WebSocket\] Sent result .*protocol_error=false' "$TMP_FILTERED"; then
  WS_OK=1
fi

if [[ "$LEGACY_OK" -ne 1 && "$WS_OK" -ne 1 ]]; then
  echo "FALLO: no hay subida legacy ni resultado websocket correcto en logs recientes" >&2
  exit 1
fi

if grep -Eiq 'Using Node binary|sign-cli\.js|binary-signer\.js|verify-cli\.js|node\.exe' "$TMP_FILTERED"; then
  echo "FALLO: se detectaron trazas de ejecución Node.js en logs recientes" >&2
  grep -Ein 'Using Node binary|sign-cli\.js|binary-signer\.js|verify-cli\.js|node\.exe' "$TMP_FILTERED" || true
  exit 1
fi

echo "OK: comprobación de log de sede correcta"
echo "  log_file=$LOG_FILE"
echo "  since_minutes=$SINCE_MINUTES"
if [[ "$WS_OK" -eq 1 ]]; then
  echo "  mode=websocket"
elif [[ "$LEGACY_OK" -eq 1 ]]; then
  echo "  mode=legacy-upload"
fi
