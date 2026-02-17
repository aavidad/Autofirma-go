# Avances Paridad Java -> Go (AutoFirma)

Ultima actualizacion: 2026-02-17  
Workspace: `/home/alberto/Trabajo/AutoFirma_Dipgra/autofirma_migracion/work/native-host-src`

## Estado de documentacion (unificado)
Desde hoy se unifica el seguimiento vivo en:
- `PLAN_MIGRACION_AUTOFIRMA_GO.md` (fuente unica de estado y pendientes reales)

Este archivo pasa a ser un resumen ejecutivo de paridad para compatibilidad con flujos existentes.

## Resumen real de avance

### Implementado (alto impacto)
- Protocolo `afirma://` robusto en `websocket/service` con mapeo de errores `SAF_*`.
- Operaciones funcionales en flujo protocolario/web:
  - `sign`, `cosign`, `countersign`, `selectcert`, `save`, `load`, `signandsave`.
- Batch local y remoto (JSON/XML), incluyendo trifasico `PRE -> PK1 -> POST`.
- Paridad fuerte en `selectcert`:
  - filtros avanzados,
  - `sticky/resetsticky`,
  - `mandatoryCertSelection`,
  - hints `defaultKeyStore/defaultKeyStoreLib/disableOpeningExternalStores`.
- PKCS#11 con fallback directo para PKCS#1 en Linux (`linux+cgo`).
- Robustez `service` legacy (framing, URL-encoding, errores y limites de memoria).
- Suite de tests en verde para codigo principal:
  - `go test -mod=mod ./cmd/gui/... ./pkg/...`.
  - Cobertura actual: `224` tests (`cmd/gui` + `pkg`).

### Brechas reales pendientes
1. Cierre de validacion automatica reproducible:
- ajustar `scripts/run_full_validation.sh` para no depender de `GOFLAGS=-mod=mod` en entornos con vendor inconsistente;
- distinguir en reporte bloqueos de entorno (ej. permisos socket sandbox) de fallos de producto.

2. Paridad funcional restante (segun alcance final de release):
- soporte `cosign/countersign` fuera de CAdES (si aplica frente a Java objetivo);
- estrategia PKCS#11 multi-plataforma (Windows/macOS) si se exige en alcance.

3. Cierre E2E real:
- validacion en sedes reales (Valide + otra),
- cierre trust TLS en navegadores objetivo,
- cierre release Windows/Linux (Go/No-Go).

## Estado por bloques
- P0 Estabilidad WebSocket y TLS local: **muy avanzado**, pendiente validacion final en entorno objetivo.
- P1 Compatibilidad completa protocolo `afirma://`: **muy avanzado**, pendiente validacion final contra variantes reales de sedes.
- P2 Firma avanzada CAdES/PAdES/XAdES: **baseline operativo completo**, pendiente cierre de casuistica avanzada por sede.
- P3 Certificados/dispositivos: **avanzado**, pendiente cierre multi-token y paridad fuera de Linux en PKCS#11 directo.
- P4 Packaging/integracion: **avanzado**, pendiente cierre final por plataforma.
- P5 E2E regresion sedes reales: **pendiente de cierre formal**.

## Referencia principal
Para el detalle operativo y plan ejecutable actualizado:
- `PLAN_MIGRACION_AUTOFIRMA_GO.md`
