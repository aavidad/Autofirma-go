# Native Host Protocol (JSON over Native Messaging)

## Transporte
- Canal: Native Messaging (stdin/stdout).
- Framing: 4 bytes little-endian con la longitud del payload JSON.
- Payload: UTF-8 JSON.

## Request
Estructura (`pkg/protocol.Request`):

```json
{
  "requestId": "1",
  "action": "ping",
  "certificateId": "...",
  "data": "BASE64",
  "pin": "1234",
  "format": "cades",
  "signatureOptions": {},
  "originalData": "BASE64",
  "signatureData": "BASE64"
}
```

Campos clave:
- `requestId`: string o number (se normaliza a string en la respuesta).
- `action`: `ping` | `getCertificates` | `sign` | `verify`.
- `format`: actualmente usado con `sign/verify` (`cades`, `pades`, `xades`).
- `data`, `originalData`, `signatureData`: Base64.

## Response
Estructura (`pkg/protocol.Response`):

```json
{
  "requestId": "1",
  "success": true,
  "error": "",
  "certificates": [],
  "signature": "BASE64",
  "signatureLen": 0,
  "result": {
    "valid": true,
    "signerName": "...",
    "timestamp": "...",
    "format": "CAdES",
    "algorithm": "SHA256withRSA",
    "reason": ""
  },
  "chunk": 0,
  "totalChunks": 1
}
```

Campos clave:
- `success`: estado general de la operación.
- `error`: mensaje si `success=false`.
- `chunk`: índice del fragmento actual (siempre serializado).
- `totalChunks`: solo cuando la respuesta va fragmentada.

## Fragmentación
- Si `signature` supera 512 KiB, la respuesta se fragmenta.
- Cada fragmento conserva el mismo `requestId`.
- Reconstrucción cliente: concatenar `signature` por orden de `chunk` (0..`totalChunks-1`).

## Acciones soportadas
- `ping`: salud del host.
- `getCertificates`: lista certificados disponibles en NSS/PKCS#11.
- `sign`: firma datos Base64 con certificado `certificateId`.
- `verify`: valida firma y devuelve objeto `result`.

## Comprobación rápida
Script reproducible:

```bash
cd plugin_autofirma_native/native-host-src
./scripts/smoke_native_host.sh
```
