# PLAN MIGRACION AUTOFIRMA GO (PENDIENTE REAL)

Fecha de revision: 2026-02-17
Repositorio: `work/native-host-src`
Commit revisado: `60f3bb656201ff7a8ee8093450842554c0277608`

## Conclusión de revisión profunda
El proyecto está bastante más avanzado de lo que refleja el checklist histórico.

Evidencias objetivas:
- Tests activos en verde en código principal:
  - `go test -mod=mod ./cmd/gui/... ./pkg/...` OK.
- Cobertura unitaria amplia para protocolo/paridad:
  - `224` tests en `cmd/gui` + `pkg`.
- Flujos core implementados y testeados:
  - `sign/cosign/countersign`, `selectcert`, `save/load/signandsave`, `batch` local y remoto (JSON/XML), `service` legacy, versiones `v/mcv/jvc`, hints de store y fallback PKCS#11.

## Pendiente real (priorizado)

### P0 - Cierre de validación reproducible (automatización)
1. Normalizar `run_full_validation.sh` para entornos con `vendor` inconsistente.
- Hallazgo: falla en paso `1/7` si no se fuerza `-mod=mod`.
- Evidencia: error `inconsistent vendoring` al ejecutar script sin `GOFLAGS=-mod=mod`.
- Objetivo: que el script pase sin depender de variable externa.

2. Separar claramente fallos de entorno vs fallos de producto en validación WSS.
- Hallazgo: en este entorno el paso `5/7` falla por permisos de socket (`PermissionError: Operation not permitted`), no por lógica de negocio.
- Objetivo: marcar este caso como `SKIP`/`ENV_BLOCKED` con mensaje explícito.

### P1 - Paridad funcional aún no cerrada al 100%
1. Completar cofirma/contrafirma nativa avanzada fuera de CAdES (si la sede lo exige).
- Estado actual: existe fallback compatible a `sign` fuera de CAdES (no rompe flujo), pero no hay implementacion nativa avanzada equivalente para todos los formatos.
- Evidencia: `pkg/signer/operations.go` aplica fallback a `SignData` cuando formato no es CAdES.

2. Completar estrategia PKCS#11 multi-plataforma (si alcance incluye Windows/macOS).
- Estado actual:
  - Firma PKCS#11 directa implementada para builds con `cgo` (Linux/macOS/Windows segun runtime y modulo disponible).
  - En entornos sin `cgo` se mantiene stub de no soporte.
- Evidencia:
  - `pkg/signer/pkcs1_pkcs11_cgo.go`
  - `pkg/signer/pkcs1_pkcs11_stub.go`
  - `pkg/certstore/pkcs11_stub.go`

3. Confirmar paridad avanzada criptográfica (solo con evidencia E2E real de sedes):
- CAdES avanzada ASN.1 completa.
- PAdES avanzada (LTV/políticas/sellos exigidos por sede concreta).
- XAdES avanzada por perfil real de sede.
- Nota: no hay fallo unitario actual; lo pendiente es validación de casos reales no cubiertos por test sintético.

### P2 - Cierre de integración real (release)
1. E2E de sedes reales (Valide + al menos 1 sede adicional) con evidencias saneadas.
- Criterio: flujo completo `launch -> sign -> save/retorno` sin `SAF_03/ERR-*` inesperados.

2. Cierre trust TLS y navegadores en entorno objetivo.
- Criterio: WSS local sin advertencias de CA en navegadores objetivo.

3. Cierre Windows de release (si es objetivo inmediato).
- Instalación/actualización/desinstalación.
- Registro `afirma://` en Chrome/Firefox/Edge.
- Firma con certs exportables/no exportables + 1 escenario token.

## Lo que NO considero pendiente (ya avanzado)
- Parser y compatibilidad protocolaria (`afirma://`, aliases, versiones, errores SAF).
- Flujos de operación básicos y batch remoto/local.
- Filtros `selectcert` y manejo de hints de almacén (`defaultKeyStore`, `defaultKeyStoreLib`, `disableOpeningExternalStores`).
- Fallback PKCS#11 directo para `PRE -> PK1` en builds con `cgo`.
- Robustez de `service` legacy en framing, URL-encoding y control de errores.

## Plan de ejecución corto (orden recomendado)
1. Endurecer `scripts/run_full_validation.sh` y dejar resultado reproducible en local CI-like.
2. Ejecutar batería E2E real en sedes y convertir hallazgos a tests de regresión.
3. Cerrar brechas de formato/plataforma según alcance real (cofirma/contrafirma nativa avanzada no CAdES y validacion real PKCS#11 fuera Linux).
4. Cierre de release (Linux/Windows) con checklist Go/No-Go.

## Definición de terminado
- Validación automática estable sin falsos negativos de entorno.
- E2E en sedes reales documentado con logs saneados.
- Sin operaciones críticas pendientes para el alcance de release.
- Checklist de release firmado para plataforma(s) objetivo.
