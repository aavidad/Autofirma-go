#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/autofirma-web-compat"
PORTS="${AUTOFIRMA_WS_PORTS:-63117,63118,63119}"
LOG_FILE="${AUTOFIRMA_WS_LOG:-/tmp/autofirma-web-compat.log}"

build() {
  echo "[web-compat] building gui server binary..."
  GOCACHE=/tmp/go-build go build -o "${BIN}" ./cmd/gui
}

start() {
  build
  echo "[web-compat] starting server on ports: ${PORTS}"
  echo "[web-compat] logs: ${LOG_FILE}"
  AUTOFIRMA_WS_PORTS="${PORTS}" "${BIN}" --server >>"${LOG_FILE}" 2>&1 &
  PID=$!
  echo "[web-compat] pid=${PID}"
  echo "${PID}" > "${ROOT_DIR}/out/web_compat_server.pid"
}

stop() {
  if [[ -f "${ROOT_DIR}/out/web_compat_server.pid" ]]; then
    PID="$(cat "${ROOT_DIR}/out/web_compat_server.pid")"
    if kill -0 "${PID}" 2>/dev/null; then
      kill "${PID}"
      echo "[web-compat] stopped pid=${PID}"
    fi
    rm -f "${ROOT_DIR}/out/web_compat_server.pid"
  else
    echo "[web-compat] no pid file"
  fi
}

status() {
  if [[ -f "${ROOT_DIR}/out/web_compat_server.pid" ]]; then
    PID="$(cat "${ROOT_DIR}/out/web_compat_server.pid")"
    if kill -0 "${PID}" 2>/dev/null; then
      echo "[web-compat] running pid=${PID}"
      exit 0
    fi
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
