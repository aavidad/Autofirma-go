#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[test] Ejecutando prueba de cancelación WebSocket..."
GOCACHE=/tmp/go-build GOFLAGS='-mod=readonly' go test ./cmd/autofirma -run TestWebSocketStopSendsCancelToClientDuringCallbackSign -count=1 -v
