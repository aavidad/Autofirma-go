#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_TMP="/tmp/autofirma"
BIN_DST="/opt/autofirma-dipgra/autofirma"
LOG_DIR="${HOME}/.local/state/autofirma-dipgra/logs"
LOG_FILE="${LOG_DIR}/autofirma-$(date +%F).log"

TAIL_LOG=1
if [[ "${1:-}" == "--no-tail" ]]; then
  TAIL_LOG=0
fi

if [[ " ${GOFLAGS:-} " != *" -mod="* ]]; then
  GOFLAGS="${GOFLAGS:-} -mod=readonly"
fi

echo "[1/4] Parando procesos anteriores..."
pkill -f '/opt/autofirma-dipgra/autofirma|autofirma-web-compat|/cmd/autofirma' || true

echo "[2/4] Compilando binario..."
cd "${ROOT_DIR}"
GOCACHE=/tmp/go-build GOFLAGS="${GOFLAGS}" go build -o "${BIN_TMP}" ./cmd/autofirma

echo "[3/4] Instalando en ${BIN_DST}..."
sudo install -m 0755 "${BIN_TMP}" "${BIN_DST}"

echo "[4/4] Instalacion completada."
echo "Log: ${LOG_FILE}"

if [[ "${TAIL_LOG}" -eq 1 ]]; then
  mkdir -p "${LOG_DIR}"
  touch "${LOG_FILE}"
  echo
  echo "Siguiendo log (Ctrl+C para salir):"
  if command -v rg >/dev/null 2>&1; then
    tail -f "${LOG_FILE}" | rg -n "Received: afirma://sign|Sign format resolved|Sign success|Sign unsupported|Sent result|SAF_|ERR-"
  else
    tail -f "${LOG_FILE}" | grep -nE "Received: afirma://sign|Sign format resolved|Sign success|Sign unsupported|Sent result|SAF_|ERR-"
  fi
fi
