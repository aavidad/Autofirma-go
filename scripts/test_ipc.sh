#!/bin/bash
# Script de prueba para el fork IPC de AutoFirma

SOCKET="/tmp/autofirma_ipc_test.sock"
BACKEND="./autofirma-qt-backend"

echo "--- PRUEBA DE COMUNICACIÓN IPC ---"

# 1. Iniciar backend en segundo plano
echo "Iniciando backend en modo IPC..."
$BACKEND -ipc -ipc-socket "$SOCKET" &
BACKEND_PID=$!

# Esperar a que el socket se cree
sleep 2

if [ ! -S "$SOCKET" ]; then
    echo "❌ Error: El socket no se ha creado en $SOCKET"
    kill $BACKEND_PID
    exit 1
fi

echo "✅ Backend activo en $SOCKET"

# 2. Enviar petición de certificados (usando socat si está disponible, o python)
echo "Solicitando certificados..."
RESPONSE=$(python3 -c "
import socket
import json
import sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('$SOCKET')
    s.sendall(json.dumps({'action': 'certificates', 'params': {}}).encode() + b'\n')
    f = s.makefile()
    line = f.readline()
    if line:
        print(line.strip())
    else:
        print('{\"ok\": false, \"error\": \"No response\"}')
except Exception as e:
    print(json.dumps({'ok': False, 'error': str(e)}))
finally:
    s.close()
")

echo "Respuesta recibida:"
echo "$RESPONSE" | python3 -m json.tool

# 3. Limpiar
echo "Cerrando backend..."
kill $BACKEND_PID
rm -f "$SOCKET"

echo "--- PRUEBA FINALIZADA ---"
