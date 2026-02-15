#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

BIN="/home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src/dist/autofirma-desktop"
LOG="/tmp/autofirma-launcher.log"

export LIBGL_ALWAYS_SOFTWARE=1
export MESA_LOADER_DRIVER_OVERRIDE=llvmpipe

{
  echo "$(date '+%Y/%m/%d %H:%M:%S') [LauncherSW] Launching with software GL: $*"
} >>"$LOG"

exec "$BIN" "$@" >>"$LOG" 2>&1
