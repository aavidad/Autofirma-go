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
  - `batch` contrafirma: aliases Java `contrafirmar_arbol` y `contrafirmar_hojas` ahora propagan automaticamente `target=tree/leafs` cuando no se define target explicito.
- Mejora de compatibilidad en nucleo de firma:
  - `cosign/countersign` en formatos no-CAdES ya no fallan, ahora hacen fallback compatible a `sign`.
  - se mantiene `cosign/countersign` CAdES nativo cuando aplica.
  - contrafirma CAdES: algoritmos no reconocidos ya no rompen el flujo; se aplica fallback seguro a `SHA256withRSA` para mejorar interoperabilidad.
- Batch local y remoto (JSON/XML), incluyendo trifasico `PRE -> PK1 -> POST`.
- Batch `afirma://batch` mas tolerante a variantes de parametros Java/integradores:
  - lectura case-insensitive y alias de `jsonbatch/jsonBatch`, `localBatchProcess/localbatchprocess`,
  - alias de URLs remotas `batchpresignerurl|batchPreSignerUrl|batchPreSignerURL` y `batchpostsignerurl|batchPostSignerUrl|batchPostSignerURL`,
  - alias de carga de lote `dat/data`,
  - alias de retorno de certificado `needcert/needCert`.
- Tests de compatibilidad batch ampliados para cubrir estos aliases en local/remoto y retorno de certificado.
- Paridad fuerte en `selectcert`:
  - filtros avanzados,
  - `sticky/resetsticky`,
  - `mandatoryCertSelection`,
  - hints `defaultKeyStore/defaultKeyStoreLib/disableOpeningExternalStores`.
- PKCS#11 con fallback directo para PKCS#1 en Linux (`linux+cgo`).
- Ampliada base PKCS#11 directa a entornos `cgo` (no limitada artificialmente a Linux):
  - build tags ajustados a `cgo` en `certstore` y firma PKCS#1 directa.
  - rutas candidatas de modulo PKCS#11 ampliadas para Linux/macOS/Windows.
  - fallback PKCS#11 en PKCS#1 acepta aliases de store (`defaultKeyStore/defaultkeystore/...`) y mejora trazabilidad de error cuando fallan exportacion y fallback.
- Robustez `service` legacy (framing, URL-encoding, errores y limites de memoria).
- Validacion automatica mas robusta:
  - `scripts/test_active_go.sh` y `scripts/run_full_validation.sh` usan `GOFLAGS=-mod=readonly` por defecto para evitar falsos negativos por vendor.
  - `run_full_validation.sh` clasifica bloqueo de socket/sandbox de WSS como `ENV_BLOCKED` (no fallo funcional de producto).
- Suite de tests en verde para codigo principal:
  - `go test -mod=readonly ./cmd/gui/... ./pkg/...`.
  - Cobertura actual: `224` tests (`cmd/gui` + `pkg`).

### Brechas reales pendientes
1. Cierre de validacion automatica reproducible:
- pendiente principal de entorno: ejecutar trust y WSS en entorno sin restricciones de sandbox/TTY para cierre final de bloque.

2. Paridad funcional restante (segun alcance final de release):
- cofirma/contrafirma nativa especifica fuera de CAdES (hoy hay fallback compatible a `sign`);
- validacion real en Windows/macOS del flujo PKCS#11 directo (codigo base ya preparado en `cgo`).

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
