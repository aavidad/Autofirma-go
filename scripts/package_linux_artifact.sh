#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/out"
BUILD_DIR="${OUT_DIR}/package-linux"
VERSION_TAG="${1:-$(date +%Y%m%d_%H%M%S)}"
ARTIFACT="${OUT_DIR}/autofirma-host-linux-${VERSION_TAG}.tar.gz"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}" "${OUT_DIR}"

cd "${ROOT_DIR}"

echo "[package] building host binary"
GOCACHE=/tmp/go-build go build -o "${BUILD_DIR}/autofirma-host" ./cmd/autofirma-host

# Optional smoke test data
if [[ -d "${ROOT_DIR}/testdata" ]]; then
  mkdir -p "${BUILD_DIR}/testdata"
  cp -a "${ROOT_DIR}/testdata/." "${BUILD_DIR}/testdata/"
fi

# Optional helper docs/scripts
cp -a docs/protocol.md "${BUILD_DIR}/" || true
cp -a docs/COMPAT_STATUS_2026-02-13.md "${BUILD_DIR}/" || true
cp -a scripts/smoke_native_host.sh "${BUILD_DIR}/" || true

cat > "${BUILD_DIR}/README_PACKAGE.md" <<'PKG'
# AutoFirma Host Package

## Contents
- `autofirma-host`: native host binary (Go)
- `testdata/`: optional local smoke assets
- `smoke_native_host.sh`: quick compatibility check script

## Run
```bash
./autofirma-host
```

## Smoke
```bash
chmod +x smoke_native_host.sh
./smoke_native_host.sh
```
PKG

chmod +x "${BUILD_DIR}/autofirma-host"
chmod +x "${BUILD_DIR}/smoke_native_host.sh" || true

tar -C "${BUILD_DIR}" -czf "${ARTIFACT}" .

echo "[package] artifact created: ${ARTIFACT}"
