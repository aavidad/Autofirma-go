#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LAUNCHER_LOG="/tmp/autofirma-launcher.log"
WEB_LOG="/tmp/autofirma-web-compat.log"
HOST_LOG="/tmp/AutofirmaDipgra/logs/autofirma-host-$(date +%F).log"
SINCE_MINUTES=180
CLEAN_LOGS=0
REQUIRE_XADES_COUNTERSIGN=0

usage() {
  cat <<USAGE
Uso:
  $0 start [--clean-logs]
  $0 check [--launcher-log PATH] [--web-log PATH] [--host-log PATH] [--since-minutes N] [--require-xades-countersign]
  $0 stop

Comandos:
  start   Arranca servidor web compat y valida handshake WSS (echo=OK).
  check   Revisa logs recientes de sede y busca errores protocolarios.
          Con --require-xades-countersign exige evidencias de contrafirma XAdES.
  stop    Para servidor web compat.
USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: no se encontró el comando requerido: $1" >&2
    exit 1
  }
}

resolve_launcher_log() {
  if [[ -f "${LAUNCHER_LOG}" ]]; then
    return 0
  fi

  local candidates=(
    "${HOME}/.local/state/autofirma-dipgra/logs/autofirma-desktop-$(date +%F).log"
    "/tmp/AutofirmaDipgra/logs/autofirma-desktop-$(date +%F).log"
  )
  local c
  for c in "${candidates[@]}"; do
    if [[ -f "${c}" ]]; then
      LAUNCHER_LOG="${c}"
      echo "[sede-e2e] launcher log auto-detectado: ${LAUNCHER_LOG}"
      return 0
    fi
  done
}

resolve_host_log() {
  if [[ -f "${HOST_LOG}" ]]; then
    return 0
  fi

  local candidates=(
    "${HOME}/.local/state/autofirma-dipgra/logs/autofirma-host-$(date +%F).log"
    "/tmp/AutofirmaDipgra/logs/autofirma-host-$(date +%F).log"
  )
  local c
  for c in "${candidates[@]}"; do
    if [[ -f "${c}" ]]; then
      HOST_LOG="${c}"
      echo "[sede-e2e] host log auto-detectado: ${HOST_LOG}"
      return 0
    fi
  done
}

cmd_start() {
  require_cmd python3
  cd "${ROOT_DIR}"
  resolve_launcher_log || true
  resolve_host_log || true

  if [[ "${CLEAN_LOGS}" -eq 1 ]]; then
    : > "${WEB_LOG}"
    if [[ -f "${LAUNCHER_LOG}" ]]; then
      : > "${LAUNCHER_LOG}"
    fi
    echo "[sede-e2e] logs limpiados"
  fi

  bash scripts/run_web_compat_server.sh start
  bash scripts/run_web_compat_server.sh status
  python3 scripts/ws_echo_client.py

  echo "[sede-e2e] batch env effective:"
  echo "  AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS=${AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS:-<default>}"
  echo "  AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC=${AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC:-<default>}"
  echo "  AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS=${AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS:-<default>}"
  echo "  AUTOFIRMA_BATCH_BREAKER_THRESHOLD=${AUTOFIRMA_BATCH_BREAKER_THRESHOLD:-<default>}"
  echo "  AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS=${AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS:-<default>}"
  echo "  AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC=${AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC:-<default>}"

  cat <<EOF
[sede-e2e] servidor listo.
[sede-e2e] siguiente paso manual:
1) Abre una sede (Valide + otra adicional).
2) Ejecuta el flujo de firma completo.
3) Cuando acabes, lanza:
   $0 check --since-minutes ${SINCE_MINUTES}
EOF
}

emit_recent_matches() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  local since_minutes="${4:-${SINCE_MINUTES}}"
  if [[ ! -f "${file}" ]]; then
    return 0
  fi
  local cutoff_epoch now_epoch
  now_epoch="$(date +%s)"
  cutoff_epoch=$((now_epoch - since_minutes * 60))

  awk -v cutoff="${cutoff_epoch}" -v pat="${pattern}" -v lbl="${label}" '
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
    if (toepoch(ts) >= cutoff && $0 ~ pat) {
      print lbl ":" NR ":" $0;
    }
  }
}
' "${file}" | tail -n 40
}

append_recent_log_excerpt() {
  local file="$1"
  local label="$2"
  local since_minutes="${3:-${SINCE_MINUTES}}"
  local max_lines="${4:-80}"
  if [[ ! -f "${file}" ]]; then
    return 0
  fi
  local cutoff_epoch now_epoch
  now_epoch="$(date +%s)"
  cutoff_epoch=$((now_epoch - since_minutes * 60))

  awk -v cutoff="${cutoff_epoch}" '
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
' "${file}" | tail -n "${max_lines}" | sanitize_report_lines | sed "s|^|${label}: |"
}

sanitize_report_lines() {
  sed -E \
    -e 's/(idSession|idsession)=([^&[:space:]@]+)/\1=<masked>/Ig' \
    -e 's/(dat=)[^&[:space:]]+/\1<masked>/Ig' \
    -e 's/(tridata=)[^&[:space:]]+/\1<masked>/Ig' \
    -e 's/(certs=)[^&[:space:]]+/\1<masked>/Ig' \
    -e 's/(key=)[^&[:space:]]+/\1<masked>/Ig'
}

cmd_check() {
  cd "${ROOT_DIR}"
  resolve_launcher_log || true
  resolve_host_log || true

  if [[ ! -f "${WEB_LOG}" ]]; then
    echo "FALLO: no existe log web: ${WEB_LOG}" >&2
    exit 1
  fi

  echo "[sede-e2e] 1/3 smoke_sede_logcheck"
  if [[ -f "${LAUNCHER_LOG}" ]]; then
    bash scripts/smoke_sede_logcheck.sh --log-file "${LAUNCHER_LOG}" --since-minutes "${SINCE_MINUTES}"
  else
    echo "[sede-e2e] WARN: launcher log no encontrado (${LAUNCHER_LOG}); se omite smoke_sede_logcheck."
  fi

  echo "[sede-e2e] 2/3 buscar errores protocolarios recientes"
  local err_found=0
  local xades_countersign_seen=0

  if emit_recent_matches "${WEB_LOG}" 'SAF_03|ERR-[0-9]{2}' "web" "${SINCE_MINUTES}" | tee /tmp/sede-e2e-errors.tmp | grep -q .; then
    echo "FALLO: detectados SAF_03/ERR-* en log web (revisa líneas anteriores)" >&2
    err_found=1
  fi
  if emit_recent_matches "${LAUNCHER_LOG}" 'SAF_03|ERR-[0-9]{2}' "launcher" "${SINCE_MINUTES}" | tee -a /tmp/sede-e2e-errors.tmp | grep -q .; then
    echo "FALLO: detectados SAF_03/ERR-* en launcher log (revisa líneas anteriores)" >&2
    err_found=1
  fi

  if [[ "${REQUIRE_XADES_COUNTERSIGN}" -eq 1 ]]; then
    if emit_recent_matches "${LAUNCHER_LOG}" 'CounterSign compatible native multisign route for format=xades|CoSign native multisign route for format=xades|Sign success cert=.* format=xades' "launcher" "${SINCE_MINUTES}" >/tmp/sede-e2e-xades.tmp && grep -q . /tmp/sede-e2e-xades.tmp; then
      xades_countersign_seen=1
    elif emit_recent_matches "${HOST_LOG}" 'CounterSign compatible native multisign route for format=xades|CoSign native multisign route for format=xades|Sign success cert=.* format=xades' "host" "${SINCE_MINUTES}" >/tmp/sede-e2e-xades.tmp && grep -q . /tmp/sede-e2e-xades.tmp; then
      xades_countersign_seen=1
    else
      echo "FALLO: no se detectan evidencias de flujo XAdES/contrafirma en launcher/host log" >&2
      err_found=1
    fi

    if emit_recent_matches "${LAUNCHER_LOG}" 'firma XAdES fallida|CounterSign.*unsupported|ERROR_UNSUPPORTED_OPERATION|Operacion de lote no soportada' "launcher" "${SINCE_MINUTES}" | grep -q . ||
       emit_recent_matches "${HOST_LOG}" 'firma XAdES fallida|CounterSign.*unsupported|ERROR_UNSUPPORTED_OPERATION|Operacion de lote no soportada' "host" "${SINCE_MINUTES}" | grep -q .; then
      echo "FALLO: detectados errores en ruta XAdES/contrafirma" >&2
      err_found=1
    fi
  fi

  local ws_seen=0
  local legacy_seen=0
  if emit_recent_matches "${WEB_LOG}" 'Processing afirma protocol request|Sent result len=|WebSocket] Sent result .*protocol_error=false' "web" "${SINCE_MINUTES}" >/tmp/sede-e2e-flow.tmp && grep -q . /tmp/sede-e2e-flow.tmp; then
    ws_seen=1
  elif emit_recent_matches "${LAUNCHER_LOG}" 'Processing afirma protocol request|Sent result len=|WebSocket] Sent result .*protocol_error=false' "launcher" "${SINCE_MINUTES}" >/tmp/sede-e2e-flow.tmp && grep -q . /tmp/sede-e2e-flow.tmp; then
    ws_seen=1
  fi

  if emit_recent_matches "${LAUNCHER_LOG}" 'java-style upload response status=200 body="OK"' "launcher" "${SINCE_MINUTES}" >/tmp/sede-e2e-legacy.tmp && grep -q . /tmp/sede-e2e-legacy.tmp; then
    legacy_seen=1
  elif emit_recent_matches "${WEB_LOG}" 'java-style upload response status=200 body="OK"' "web" "${SINCE_MINUTES}" >/tmp/sede-e2e-legacy.tmp && grep -q . /tmp/sede-e2e-legacy.tmp; then
    legacy_seen=1
  fi

  if [[ "${ws_seen}" -eq 0 && "${legacy_seen}" -eq 0 ]]; then
    echo "FALLO: no hay evidencias recientes de flujo sede (ni websocket ni legacy-upload)" >&2
    err_found=1
  fi

  echo "[sede-e2e] 3/3 resumen"
  local report_file="/tmp/autofirma-sede-e2e-report-$(date +%Y%m%d-%H%M%S).txt"
  {
    echo "AutoFirma sede E2E report"
    echo "date: $(date -Iseconds)"
    echo "launcher_log: ${LAUNCHER_LOG}"
    echo "web_log: ${WEB_LOG}"
    echo "host_log: ${HOST_LOG}"
    echo "since_minutes: ${SINCE_MINUTES}"
    echo "websocket_protocol_traffic_seen: ${ws_seen}"
    echo "legacy_upload_traffic_seen: ${legacy_seen}"
    echo "require_xades_countersign: ${REQUIRE_XADES_COUNTERSIGN}"
    echo "xades_countersign_evidence_seen: ${xades_countersign_seen}"
    if [[ "${err_found}" -eq 0 ]]; then
      echo "result: OK"
    else
      echo "result: FALLO"
    fi
    echo
    echo "recent_web_log_excerpt:"
    append_recent_log_excerpt "${WEB_LOG}" "web" "${SINCE_MINUTES}" 80 || true
    echo
    echo "recent_launcher_log_excerpt:"
    append_recent_log_excerpt "${LAUNCHER_LOG}" "launcher" "${SINCE_MINUTES}" 80 || true
    echo
    echo "recent_host_log_excerpt:"
    append_recent_log_excerpt "${HOST_LOG}" "host" "${SINCE_MINUTES}" 80 || true
  } > "${report_file}"
  echo "[sede-e2e] report: ${report_file}"

  rm -f /tmp/sede-e2e-errors.tmp /tmp/sede-e2e-flow.tmp /tmp/sede-e2e-legacy.tmp
  rm -f /tmp/sede-e2e-xades.tmp

  if [[ "${err_found}" -ne 0 ]]; then
    exit 1
  fi
  echo "[sede-e2e] OK"
}

cmd_stop() {
  cd "${ROOT_DIR}"
  bash scripts/run_web_compat_server.sh stop
}

main() {
  if [[ $# -lt 1 ]]; then
    usage >&2
    exit 1
  fi

  local command="$1"
  shift

  case "${command}" in
    start)
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --clean-logs)
            CLEAN_LOGS=1
            shift
            ;;
          *)
            echo "Argumento no reconocido para start: $1" >&2
            usage >&2
            exit 1
            ;;
        esac
      done
      cmd_start
      ;;
    check)
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --launcher-log)
            LAUNCHER_LOG="${2:-}"
            shift 2
            ;;
          --web-log)
            WEB_LOG="${2:-}"
            shift 2
            ;;
          --host-log)
            HOST_LOG="${2:-}"
            shift 2
            ;;
          --since-minutes)
            SINCE_MINUTES="${2:-}"
            shift 2
            ;;
          --require-xades-countersign)
            REQUIRE_XADES_COUNTERSIGN=1
            shift
            ;;
          *)
            echo "Argumento no reconocido para check: $1" >&2
            usage >&2
            exit 1
            ;;
        esac
      done
      if ! [[ "${SINCE_MINUTES}" =~ ^[0-9]+$ ]]; then
        echo "FALLO: --since-minutes debe ser entero" >&2
        exit 1
      fi
      cmd_check
      ;;
    stop)
      cmd_stop
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "Comando no reconocido: ${command}" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
