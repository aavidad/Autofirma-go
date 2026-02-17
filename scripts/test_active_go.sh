#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
export GOCACHE="${GOCACHE:-/tmp/go-build}"
# Avoid false negatives in repos that intentionally use local replaces without synced vendor metadata.
# Use readonly mode to keep go.mod/go.sum untouched during validation.
if [[ " ${GOFLAGS:-} " != *" -mod="* ]]; then
  export GOFLAGS="${GOFLAGS:-} -mod=readonly"
fi

echo "[test-active] collecting active Go packages (cmd/, pkg/)..."
mapfile -t PKGS < <(go list ./cmd/... ./pkg/...)

if [[ ${#PKGS[@]} -eq 0 ]]; then
  echo "[test-active] no packages found"
  exit 1
fi

echo "[test-active] running go test on ${#PKGS[@]} packages..."
go test "${PKGS[@]}"
echo "[test-active] OK"
