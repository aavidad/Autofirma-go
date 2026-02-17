#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/autofirma-web-compat"
PORTS="${AUTOFIRMA_WS_PORTS:-63117,63118,63119}"
LOG_FILE="${AUTOFIRMA_WS_LOG:-/tmp/autofirma-web-compat.log}"
PID_FILE="${ROOT_DIR}/out/web_compat_server.pid"

build() {
  echo "[web-compat] building gui server binary..."
  if [[ " ${GOFLAGS:-} " != *" -mod="* ]]; then
    GOFLAGS="${GOFLAGS:-} -mod=readonly"
  fi
  GOCACHE=/tmp/go-build GOFLAGS="${GOFLAGS}" go build -o "${BIN}" ./cmd/gui
}

start() {
  if [[ -f "${PID_FILE}" ]]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
      echo "[web-compat] already running pid=${pid}"
      return 0
    fi
    rm -f "${PID_FILE}"
  fi
  build
  echo "[web-compat] starting server on ports: ${PORTS}"
  echo "[web-compat] logs: ${LOG_FILE}"
  AUTOFIRMA_WS_PORTS="${PORTS}" "${BIN}" --server >>"${LOG_FILE}" 2>&1 &
  PID=$!
  echo "[web-compat] pid=${PID}"
  echo "${PID}" > "${PID_FILE}"
  sleep 0.2
  if ! kill -0 "${PID}" 2>/dev/null; then
    echo "[web-compat] ERROR: server exited during startup" >&2
    echo "[web-compat] recent logs:" >&2
    tail -n 40 "${LOG_FILE}" >&2 || true
    rm -f "${PID_FILE}"
    return 1
  fi
}

stop() {
  if [[ -f "${PID_FILE}" ]]; then
    PID="$(cat "${PID_FILE}")"
    if kill -0 "${PID}" 2>/dev/null; then
      kill "${PID}"
      echo "[web-compat] stopped pid=${PID}"
    fi
    rm -f "${PID_FILE}"
  else
    echo "[web-compat] no pid file"
  fi
}

status() {
  if [[ -f "${PID_FILE}" ]]; then
    PID="$(cat "${PID_FILE}")"
    if kill -0 "${PID}" 2>/dev/null; then
      echo "[web-compat] running pid=${PID}"
      exit 0
    fi
    rm -f "${PID_FILE}"
  fi
  echo "[web-compat] not running"
  exit 1
}

mkdir -p "${ROOT_DIR}/out"

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  *)
    echo "Usage: $0 [start|stop|restart|status]" >&2
    exit 1
    ;;
esac
