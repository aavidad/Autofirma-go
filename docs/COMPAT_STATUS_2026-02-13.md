# Estado de compatibilidad (2026-02-13)

Entorno de trabajo aislado:
- `/home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src`

## Resultado smoke test
Comando:
- `./scripts/smoke_native_host.sh --strict-formats`

Resultado:
- `ping`: OK
- `getCertificates`: OK
- `sign(cades)`: OK
- `verify(cades)`: OK
- `sign(pades)`: OK
- `verify(pades)`: OK
- `sign(xades)`: OK
- `verify(xades)`: OK

## Cambios aplicados en esta iteración (solo en copia de trabajo)
- `pkg/signer/cades_openssl.go`
  - Firma y verificacion CAdES detached con OpenSSL (sin Node.js).
- `pkg/signer/pades_go.go`
  - Firma/verificacion PAdES en Go con `pdfsign`.
- `pkg/signer/xades_go.go`
  - Firma/verificacion XAdES en Go con XMLDSig.
- `pkg/signer/signer.go`
  - Eliminado fallback a `sign-cli.js`/`verify-cli.js`; rutas Go puras para CAdES/PAdES/XAdES.

## Backups previos
- `/home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/backups/20260213_121811`

## Nota
No se han aplicado estos cambios al árbol original del proyecto. Solo existen en el workspace aislado.
