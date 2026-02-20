# Changelog de Paridad Java -> Go

Actualizado automaticamente el 2026-02-20T12:49:43+01:00

## Cambio de modelo documental
Se usa fuente unica de estado y pendientes en:
- `PLAN_MIGRACION_AUTOFIRMA_GO.md`

## Resumen de pendiente real

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
- Estado actual:
  - `XAdES`/`PAdES` ya usan ruta nativa de multisignado compatible.
  - `XAdES` distingue operacion `cosign` vs `countersign` en backend Go (con `target tree/leafs/signers`).
  - fallback a `SignData` solo para formatos no soportados.
- Evidencia:
  - `pkg/signer/operations.go`
  - `pkg/signer/xades_go.go`
  - `pkg/signer/operations_test.go`
  - `pkg/signer/xades_multisign_test.go`
- Cierre tecnico incorporado en esta iteracion:
  - matching de `signers` en XAdES countersign ampliado a `CN`, `DN`, serie decimal/hex y `SHA1` de certificado (alineado con criterios usados en CAdES).
- Pendiente tecnico para cierre 100%:
  - validacion interoperable en receptor real de la estructura de contrafirma XAdES generada.
  - decidir criterio final para `countersign` en PAdES (comportamiento compatible exigido por sedes).
  - ejecucion y archivo de evidencias con `scripts/run_sede_e2e.sh check --require-xades-countersign`.

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


## Referencia
Para detalle completo consultar:
- `PLAN_MIGRACION_AUTOFIRMA_GO.md`
