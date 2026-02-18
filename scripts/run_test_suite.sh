#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

os="$(uname -s 2>/dev/null || echo unknown)"
case "${os}" in
  Linux|Darwin)
    bash scripts/run_full_validation.sh "$@"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    powershell -ExecutionPolicy Bypass -File scripts/windows/run_full_validation_windows.ps1 "$@"
    ;;
  *)
    echo "Sistema no soportado por este wrapper: ${os}" >&2
    echo "Usa scripts/run_full_validation.sh o scripts/windows/run_full_validation_windows.ps1 según corresponda." >&2
    exit 1
    ;;
esac
