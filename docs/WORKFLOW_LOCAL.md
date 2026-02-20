# Workflow Local (isolado)

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

Directorio de trabajo:
- `/home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src`

## 0) Guía funcional completa
Antes de pruebas/manuales, revisar:
- `docs/GUI_AYUDA_EXHAUSTIVA.md`
- `docs/SCRIPTS_PRUEBAS.md`
- `docs/SCRIPTS_COMPATIBILIDAD_SO.md`

## 1) Validación rápida de compatibilidad
```bash
cd /home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src
./scripts/smoke_native_host.sh
```

Modo estricto (falla si algún formato falla):
```bash
./scripts/smoke_native_host.sh --strict-formats
```

## 2) Requests E2E manuales
```bash
./scripts/e2e_native_request.sh ping
./scripts/e2e_native_request.sh getCertificates
./scripts/e2e_native_request.sh sign-cades
```

## 3) Empaquetado Linux reproducible
```bash
./scripts/package_linux_artifact.sh
```

Artifact resultante:
- `out/autofirma-host-linux-<timestamp>.tar.gz`

## 4) Smoke de payload grande (>2MB)
```bash
./scripts/smoke_large_payload.sh
```

Opcional:
```bash
PAYLOAD_MB=5 ./scripts/smoke_large_payload.sh
```

## 5) Política de timeout/retry
Ver:
- `docs/TIMEOUT_RETRY_POLICY.md`
