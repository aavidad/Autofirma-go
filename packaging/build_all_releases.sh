#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"${ROOT_DIR}/packaging/linux/make_linux_release.sh"
"${ROOT_DIR}/packaging/windows/make_windows_release.sh"

echo "All release artifacts generated under ${ROOT_DIR}/release"
