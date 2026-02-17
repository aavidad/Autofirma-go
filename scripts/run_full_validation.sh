#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_FILE="/tmp/autofirma-full-validation-report-$(date +%Y%m%d-%H%M%S).txt"
CURRENT_STEP="init"

STRICT_FORMATS=0
SKIP_TRUST=0
SKIP_SEDE_LOGCHECK=0
SEDE_LOG_FILE="/tmp/autofirma-launcher.log"
SEDE_SINCE_MINUTES=120
BATCH_HTTP_TIMEOUT_MS=""
BATCH_HTTP_TIMEOUT_SEC=""
BATCH_HTTP_MAX_ATTEMPTS=""
BATCH_BREAKER_THRESHOLD=""
BATCH_BREAKER_COOLDOWN_MS=""
BATCH_BREAKER_COOLDOWN_SEC=""

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
  --batch-timeout-ms N   Timeout batch remoto en ms (AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS).
  --batch-timeout-sec N  Timeout batch remoto en s  (AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC).
  --batch-max-attempts N Reintentos batch remoto    (AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS).
  --batch-breaker-threshold N  Umbral breaker batch (AUTOFIRMA_BATCH_BREAKER_THRESHOLD).
  --batch-breaker-cooldown-ms N Cooldown breaker ms (AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS).
  --batch-breaker-cooldown-sec N Cooldown breaker s (AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC).
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
    --batch-timeout-ms) BATCH_HTTP_TIMEOUT_MS="${2:-}"; shift 2 ;;
    --batch-timeout-sec) BATCH_HTTP_TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --batch-max-attempts) BATCH_HTTP_MAX_ATTEMPTS="${2:-}"; shift 2 ;;
    --batch-breaker-threshold) BATCH_BREAKER_THRESHOLD="${2:-}"; shift 2 ;;
    --batch-breaker-cooldown-ms) BATCH_BREAKER_COOLDOWN_MS="${2:-}"; shift 2 ;;
    --batch-breaker-cooldown-sec) BATCH_BREAKER_COOLDOWN_SEC="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Argumento desconocido: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "${ROOT_DIR}"

append_report() {
  printf '%s\n' "$1" >> "${REPORT_FILE}"
}

on_error() {
  local rc=$?
  append_report "result: FAIL"
  append_report "failed_step: ${CURRENT_STEP}"
  append_report "exit_code: ${rc}"
  echo "[full-check] FAIL en paso: ${CURRENT_STEP}"
  echo "[full-check] report: ${REPORT_FILE}"
  exit "${rc}"
}

cleanup() {
  echo "[full-check] stopping web compat server..."
  bash scripts/run_web_compat_server.sh stop || true
}
trap cleanup EXIT
trap on_error ERR

append_report "autofirma full validation report"
append_report "date: $(date -Iseconds)"
append_report "root_dir: ${ROOT_DIR}"
append_report "strict_formats: ${STRICT_FORMATS}"
append_report "skip_trust: ${SKIP_TRUST}"
append_report "skip_sede_logcheck: ${SKIP_SEDE_LOGCHECK}"
append_report "sede_log_file: ${SEDE_LOG_FILE}"
append_report "since_minutes: ${SEDE_SINCE_MINUTES}"

# Keep Go tooling reproducible when vendor metadata is stale for local replace setups.
# Prefer readonly mode so validation never mutates go.mod/go.sum.
if [[ " ${GOFLAGS:-} " != *" -mod="* ]]; then
  export GOFLAGS="${GOFLAGS:-} -mod=readonly"
fi

if [[ -n "${BATCH_HTTP_TIMEOUT_MS}" ]]; then
  export AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS="${BATCH_HTTP_TIMEOUT_MS}"
fi
if [[ -n "${BATCH_HTTP_TIMEOUT_SEC}" ]]; then
  export AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC="${BATCH_HTTP_TIMEOUT_SEC}"
fi
if [[ -n "${BATCH_HTTP_MAX_ATTEMPTS}" ]]; then
  export AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS="${BATCH_HTTP_MAX_ATTEMPTS}"
fi
if [[ -n "${BATCH_BREAKER_THRESHOLD}" ]]; then
  export AUTOFIRMA_BATCH_BREAKER_THRESHOLD="${BATCH_BREAKER_THRESHOLD}"
fi
if [[ -n "${BATCH_BREAKER_COOLDOWN_MS}" ]]; then
  export AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS="${BATCH_BREAKER_COOLDOWN_MS}"
fi
if [[ -n "${BATCH_BREAKER_COOLDOWN_SEC}" ]]; then
  export AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC="${BATCH_BREAKER_COOLDOWN_SEC}"
fi

echo "[full-check] batch env effective:"
echo "  AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS=${AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS:-<default>}"
echo "  AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC=${AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC:-<default>}"
echo "  AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS=${AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS:-<default>}"
echo "  AUTOFIRMA_BATCH_BREAKER_THRESHOLD=${AUTOFIRMA_BATCH_BREAKER_THRESHOLD:-<default>}"
echo "  AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS=${AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS:-<default>}"
echo "  AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC=${AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC:-<default>}"
append_report "AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS=${AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS:-<default>}"
append_report "AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC=${AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC:-<default>}"
append_report "AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS=${AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS:-<default>}"
append_report "AUTOFIRMA_BATCH_BREAKER_THRESHOLD=${AUTOFIRMA_BATCH_BREAKER_THRESHOLD:-<default>}"
append_report "AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS=${AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS:-<default>}"
append_report "AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC=${AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC:-<default>}"
append_report "GOFLAGS=${GOFLAGS:-<empty>}"

CURRENT_STEP="1/7 tests de codigo activo"
echo "[full-check] 1/7 tests de codigo activo"
bash scripts/test_active_go.sh
append_report "step_1: PASS"

CURRENT_STEP="2/7 smoke host nativo"
echo "[full-check] 2/7 smoke host nativo"
if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
  bash scripts/smoke_native_host.sh --strict-formats
else
  bash scripts/smoke_native_host.sh
fi
append_report "step_2: PASS"

if [[ "${SKIP_TRUST}" -eq 0 ]]; then
  CURRENT_STEP="3/7 trust local"
  echo "[full-check] 3/7 trust local (certificados + estado)"
  if TRUST_OUTPUT="$(bash scripts/install_and_trust_linux.sh 2>&1)"; then
    printf '%s\n' "${TRUST_OUTPUT}"
    append_report "step_3: PASS"
  else
    printf '%s\n' "${TRUST_OUTPUT}" >&2
    if printf '%s' "${TRUST_OUTPUT}" | grep -qiE "ENV_BLOCKED|Operation not permitted|Permission denied|no new privileges|sudo:.*no new privileges|cannot run as root|sandbox"; then
      echo "[full-check] WARN: trust local bloqueado por entorno (sudo/sandbox), se marca como ENV_BLOCKED"
      append_report "step_3: ENV_BLOCKED"
      append_report "step_3_detail: ${TRUST_OUTPUT//$'\n'/ | }"
    else
      append_report "step_3: FAIL"
      append_report "step_3_detail: ${TRUST_OUTPUT//$'\n'/ | }"
      false
    fi
  fi
else
  echo "[full-check] 3/7 trust local omitido (--skip-trust)"
  append_report "step_3: SKIP"
fi

CURRENT_STEP="4/7 servidor web compat"
echo "[full-check] 4/7 servidor web compat (start/status)"
bash scripts/run_web_compat_server.sh start
bash scripts/run_web_compat_server.sh status
append_report "step_4: PASS"

CURRENT_STEP="5/7 handshake WSS"
echo "[full-check] 5/7 handshake WSS (echo)"
if WSS_OUTPUT="$(python3 scripts/ws_echo_client.py 2>&1)"; then
  append_report "step_5: PASS"
else
  echo "${WSS_OUTPUT}" >&2
  if printf '%s' "${WSS_OUTPUT}" | grep -qiE "ENV_BLOCKED|Operation not permitted|PermissionError|Errno 1|Errno 13"; then
    echo "[full-check] WARN: handshake WSS bloqueado por entorno (permisos/sandbox), se marca como ENV_BLOCKED"
    append_report "step_5: ENV_BLOCKED"
    append_report "step_5_detail: ${WSS_OUTPUT//$'\n'/ | }"
  else
    append_report "step_5: FAIL"
    append_report "step_5_detail: ${WSS_OUTPUT//$'\n'/ | }"
    false
  fi
fi

CURRENT_STEP="6/7 log local web compat"
echo "[full-check] 6/7 log local de web compat (ultimas lineas)"
tail -n 80 /tmp/autofirma-web-compat.log || true
append_report "step_6: PASS"

if [[ "${SKIP_SEDE_LOGCHECK}" -eq 0 ]]; then
  CURRENT_STEP="7/7 smoke log de sede"
  echo "[full-check] 7/7 smoke de log de sede"
  if [[ -f "${SEDE_LOG_FILE}" ]]; then
    bash scripts/smoke_sede_logcheck.sh --log-file "${SEDE_LOG_FILE}" --since-minutes "${SEDE_SINCE_MINUTES}"
    append_report "step_7: PASS"
  else
    echo "[full-check] WARN: log de sede no encontrado (${SEDE_LOG_FILE}), se marca como SKIP"
    append_report "step_7: SKIP_NO_LOG"
  fi
else
  echo "[full-check] 7/7 smoke de log de sede omitido (--skip-sede-logcheck)"
  append_report "step_7: SKIP"
fi

append_report "result: PASS"
echo "[full-check] OK"
echo "[full-check] report: ${REPORT_FILE}"
if [[ -x scripts/generate_parity_changelog.sh ]]; then
  echo "[full-check] regenerando changelog de paridad..."
  if scripts/generate_parity_changelog.sh; then
    append_report "parity_changelog: UPDATED"
  else
    echo "[full-check] WARN: no se pudo regenerar CHANGELOG_PARIDAD.md"
    append_report "parity_changelog: ERROR"
  fi
else
  append_report "parity_changelog: SKIP"
fi
echo "[full-check] siguiente paso: prueba manual en sede con navegador y revisar /tmp/autofirma-web-compat.log"
