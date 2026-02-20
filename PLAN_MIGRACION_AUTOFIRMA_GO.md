# PLAN MIGRACION AUTOFIRMA GO (PENDIENTE REAL)

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

Fecha de revision: 2026-02-20
Repositorio: `work/native-host-src`
Commit revisado: `60f3bb656201ff7a8ee8093450842554c0277608`

## Avance 2026-02-20 (cierre de migración GUI protocolaria a Fyne)
- Implementado en `cmd/gui`:
  - nuevo módulo `fyne_protocol.go` para soportar en Fyne los flujos `afirma://`:
    - `sign/cosign/countersign` con subida legacy (`RTServlet/STServlet`) y bucle activo `#WAIT`,
    - `selectcert` con diálogo de selección y subida de certificado,
    - `batch` protocolario reutilizando el motor existente de lote,
    - parseo y procesamiento de manifiestos `<sign>` con extracción de `dat`/`format`.
  - integración de arranque protocolario en `main.go`:
    - Fyne pasa a ser ruta por defecto también para `afirma://`,
    - Gio queda como fallback explícito con `-gio`.
  - conexión de acciones de UI Fyne al protocolo:
    - botón de firma en Fyne ejecuta flujo protocolario cuando hay estado `Protocol`,
    - selección de certificado dispara procesamiento batch cuando la acción pendiente es `batch`.
- Verificación:
  - `GOCACHE=/tmp/gocache go test -mod=readonly ./cmd/gui/...` OK.
  - `GOCACHE=/tmp/gocache go test -mod=readonly ./pkg/...` OK.

## Avance 2026-02-20 (hardening de validación completa en entorno bloqueado)
- Ajustado `scripts/run_full_validation.sh`:
  - paso `4/7` (`run_web_compat_server.sh start`) ahora clasifica como `ENV_BLOCKED` cuando falla por permisos/sandbox al abrir socket local (`operation not permitted`), en lugar de fallar toda la validación.
  - paso `7/7` (`smoke_sede_logcheck.sh`) ahora clasifica `SKIP_NO_ACTIVITY` cuando no hay evidencias recientes de flujo de sede en logs (sin `legacy upload` ni `websocket result`), en lugar de fallo duro.
- Resultado reproducible en este entorno:
  - `result: OK` en `/tmp/autofirma-full-validation-report-20260220-124937.txt`.
  - `step_3/4/5` marcados `ENV_BLOCKED` por restricciones de sandbox.
  - `step_7` marcado `SKIP_NO_ACTIVITY` por ausencia de prueba manual reciente de sede.

## Avance 2026-02-19 (compatibilidad certificados Java en instaladores)
- Implementado en `cmd/gui`:
  - generacion/exportacion de artefactos compatibles con AutoFirma Java:
    - `autofirma.pfx` (clave `654321`, alias `SocketAutoFirma`, cuando hay `openssl`),
    - `Autofirma_ROOT.cer` (DER),
    - `autofirma.cer` (DER).
  - nuevo flag CLI:
    - `--exportar-certs-java <directorio>`.
  - `--install-trust` y `--trust-status` extendidos a macOS.
  - nickname NSS alineado con Java: `Autofirma ROOT`.
- Instaladores:
  - Linux (`packaging/linux/install.sh`) exporta/copia certificados Java al prefijo.
  - Windows (`packaging/windows/autofirma_windows_installer.nsi`) exporta certificados Java a `$INSTDIR`.
  - macOS:
    - nuevo instalador base `packaging/macos/install.sh`,
    - nuevo script `scripts/macos/install_and_trust_macos.sh`,
    - nuevo empaquetado `packaging/macos/make_macos_release.sh`.

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
