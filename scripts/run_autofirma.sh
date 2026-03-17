#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

# Lanzador de desarrollo para el Browser Bridge
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[$(date)] Lanzando AutoFirma Browser Bridge con args: $@" >> /tmp/autofirma-go.log
# Intentar usar el binario en dist/ o el que esté en el PATH
if [[ -f "${ROOT_DIR}/dist/autofirma-browser-bridge" ]]; then
    exec "${ROOT_DIR}/dist/autofirma-browser-bridge" "$@" >> /tmp/autofirma-go.log 2>&1
else
    exec autofirma-browser-bridge "$@" >> /tmp/autofirma-go.log 2>&1
fi
