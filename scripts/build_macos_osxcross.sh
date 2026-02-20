#!/usr/bin/env bash
set -euo pipefail

# Build macOS binaries from Linux using osxcross.
# Requirements:
# - osxcross installed (target/bin in PATH or under /opt/osxcross/target/bin)
# - o64-clang (amd64) and oa64-clang (arm64) available

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/out/macos"
GOCACHE_DIR="${GOCACHE:-/tmp/gocache}"

if [[ -d "/opt/osxcross/target/bin" ]]; then
  export PATH="/opt/osxcross/target/bin:${PATH}"
fi

if ! command -v o64-clang >/dev/null 2>&1; then
  echo "ERROR: no se encontró o64-clang. Instala osxcross y añade target/bin al PATH." >&2
  exit 1
fi
if ! command -v oa64-clang >/dev/null 2>&1; then
  echo "ERROR: no se encontró oa64-clang. Instala osxcross con soporte arm64." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "[1/2] Compilando macOS amd64..."
(
  cd "${ROOT_DIR}"
  CC=o64-clang \
  CXX=o64-clang++ \
  CGO_ENABLED=1 \
  GOOS=darwin \
  GOARCH=amd64 \
  GOCACHE="${GOCACHE_DIR}" \
  go build -mod=readonly -o "${OUT_DIR}/autofirma-desktop-darwin-amd64" ./cmd/gui
)

echo "[2/2] Compilando macOS arm64..."
(
  cd "${ROOT_DIR}"
  CC=oa64-clang \
  CXX=oa64-clang++ \
  CGO_ENABLED=1 \
  GOOS=darwin \
  GOARCH=arm64 \
  GOCACHE="${GOCACHE_DIR}" \
  go build -mod=readonly -o "${OUT_DIR}/autofirma-desktop-darwin-arm64" ./cmd/gui
)

echo "OK: binarios generados en ${OUT_DIR}"
ls -lh "${OUT_DIR}"/autofirma-desktop-darwin-*
