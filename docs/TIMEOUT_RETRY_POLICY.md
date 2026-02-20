# Timeout y Retry Policy (host)

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## Umbral de payload grande
- `> 2 MiB` se considera payload grande.

## Defaults
- Firma (`sign`):
  - small: `45s`
  - large: `180s`
- Verificación (`verify`):
  - small: `30s`
  - large: `120s`
- Export PKCS#12 (`pk12util`): `45s`
- Reintentos:
  - small: `0`
  - large: `1`

## Variables de entorno
- `AUTOFIRMA_SIGN_TIMEOUT_SMALL_SEC`
- `AUTOFIRMA_SIGN_TIMEOUT_LARGE_SEC`
- `AUTOFIRMA_VERIFY_TIMEOUT_SMALL_SEC`
- `AUTOFIRMA_VERIFY_TIMEOUT_LARGE_SEC`
- `AUTOFIRMA_EXPORT_TIMEOUT_SEC`
- `AUTOFIRMA_RETRIES_SMALL`
- `AUTOFIRMA_RETRIES_LARGE`
- `AUTOFIRMA_EXPORT_RETRIES`

## Smoke de payload grande
```bash
cd /home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src
./scripts/smoke_large_payload.sh
```

Opcional (payload mayor):
```bash
PAYLOAD_MB=5 ./scripts/smoke_large_payload.sh
```
