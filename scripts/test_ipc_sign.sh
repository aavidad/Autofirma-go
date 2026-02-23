#!/bin/bash
# Script de prueba de FIRMA para el fork IPC de AutoFirma

SOCKET="/tmp/autofirma_ipc_sign_test.sock"
BACKEND="./autofirma-qt-backend"
INPUT_FILE="/tmp/test_para_firmar.pdf"

# Crear PDF dummy si no existe
if [ ! -f "$INPUT_FILE" ]; then
    echo "Creando PDF de prueba..."
    echo "%PDF-1.4" > "$INPUT_FILE"
    echo "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj" >> "$INPUT_FILE"
    echo "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj" >> "$INPUT_FILE"
    echo "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj" >> "$INPUT_FILE"
    echo "xref" >> "$INPUT_FILE"
    echo "0 4" >> "$INPUT_FILE"
    echo "0000000000 65535 f " >> "$INPUT_FILE"
    echo "0000000018 00000 n " >> "$INPUT_FILE"
    echo "0000000067 00000 n " >> "$INPUT_FILE"
    echo "0000000122 00000 n " >> "$INPUT_FILE"
    echo "trailer << /Size 4 /Root 1 0 R >>" >> "$INPUT_FILE"
    echo "startxref" >> "$INPUT_FILE"
    echo "190" >> "$INPUT_FILE"
    echo "%%EOF" >> "$INPUT_FILE"
fi

echo "--- PRUEBA DE FIRMA IPC ---"

# 1. Iniciar backend
$BACKEND -ipc -ipc-socket "$SOCKET" &
BACKEND_PID=$!
sleep 2

# 2. Enviar petición de firma
echo "Solicitando firma del archivo $INPUT_FILE..."
PARAM_JSON=$(json_verify 2>/dev/null <<EOF
{
    "inputPath": "$INPUT_FILE",
    "outputPath": "/tmp/test_firmado_ipc.pdf",
    "format": "pades",
    "certificateIndex": 0
}
EOF
)

# Usar python para enviar el JSON exacto
RESPONSE=$(python3 -c "
import socket
import json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$SOCKET')
params = {
    'inputPath': '$INPUT_FILE',
    'outputPath': '/tmp/test_firmado_ipc.pdf',
    'format': 'pades',
    'certificateIndex': 0
}
req = {
    'action': 'sign',
    'params': params
}
s.sendall(json.dumps(req).encode() + b'\n')
f = s.makefile()
print(f.readline().strip())
s.close()
")

echo "Respuesta de firma:"
echo "$RESPONSE" | python3 -m json.tool

# 3. Limpiar
kill $BACKEND_PID
rm -f "$SOCKET"

if [[ "$RESPONSE" == *"\"ok\": true"* ]]; then
    echo "✅ Prueba de firma exitosa"
    ls -l /tmp/test_firmado_ipc.pdf
else
    echo "❌ Prueba de firma fallida"
fi
