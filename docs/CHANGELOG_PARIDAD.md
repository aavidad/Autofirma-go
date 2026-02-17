# Changelog de Paridad Java -> Go

_Generado automáticamente el 2026-02-17T10:31:09+01:00_

## Estado global
- [ ] P0 - Estabilidad WebSocket y confianza TLS local
- [ ] P1 - Compatibilidad completa de protocolo `afirma://`
- [ ] P2 - Paridad de formatos de firma (CAdES/PAdES/XAdES avanzados)
- [ ] P3 - Certificados/dispositivos (NSS, PKCS#11, DNIe, smartcards)
- [ ] P4 - Packaging e integración sistema/navegadores
- [ ] P5 - Pruebas E2E de regresión contra sedes reales

## Checklist pendiente
### P0 - Estabilidad WebSocket y TLS
- [ ] Validar en navegador objetivo sin `unknown certificate authority`.
### P1 - Protocolo `afirma://`
- [ ] Cobertura de variantes legacy pendientes de sedes.
### P2 - Firma avanzada
- [ ] CAdES avanzada (atributos/cadena/paridad ASN.1 completa).
- [ ] PAdES avanzada (políticas, sellos, LTV según alcance).
- [ ] XAdES avanzada (perfiles y variantes requeridas por sede).
### P3 - Certificados y dispositivos
- [ ] Robustez multi-token y errores PIN/CAN.
- [ ] Cobertura ampliada de proveedores/entornos.
### P4 - Packaging e integración
- [ ] Paridad completa de comportamiento postinst con Java (todos los navegadores/escenarios).
### P5 - Validación E2E
- [ ] Suite de regresión reproducible para web compat.
- [ ] Casos de sedes reales con evidencias en logs saneados.
- [ ] Criterios de salida por bloque (Go/No-Go).

## Últimos avances (extracto)
### 2026-02-17
- Corregido bloqueo en `afirma://save` (flujo WebSocket interactivo):
  - `ParseProtocolURI` ya permite operaciones locales sin `id/rtservlet/stservlet` para `save`, `load`, `selectcert`, `signandsave` y `batch`.
  - Se mantiene validación estricta para `sign/cosign/countersign` cuando no llegan parámetros mínimos de sesión/datos (`idsession`/`dat`/`ksb64`/`properties`).
- Añadida cobertura en tests de parser:
  - `cmd/gui/protocol_parse_test.go`: caso `websocket save without servlets is allowed`.
- Validación ejecutada:
  - `GOCACHE=/tmp/go-build go test ./cmd/gui -run TestParseProtocolURI_AliasAndRequiredParams -v` OK.
  - `GOCACHE=/tmp/go-build go test ./cmd/gui/...` OK.
- Validación integral de bloque (avance):
  - Ejecutado `scripts/run_full_validation.sh --skip-sede-logcheck` con red habilitada:
    - `1/7` tests de código activo: `OK`.
    - `2/7` smoke host nativo: `OK` (CAdES/XAdES), PAdES `SKIP` por falta de `testdata/original.pdf`.
    - `3/7` trust local: bloqueado en entorno no interactivo por `sudo` (sin TTY).
  - Detectado y corregido fallo en script:
    - `scripts/run_full_validation.sh` ejecutaba `ws_echo_client.py` con `bash` en lugar de `python3`.
    - parche aplicado: paso `5/7` usa `python3 scripts/ws_echo_client.py`.
  - Re-ejecución `scripts/run_full_validation.sh --skip-trust --skip-sede-logcheck`:
    - handshake WSS (`5/7`) `OK`.
    - validación global del script `OK` (con skips declarados).
  - Hallazgo adicional en logs:
    - comprobación de updates (`https://autofirma.dipgra.es/version.json`) falla por CA no confiada en este entorno (`x509: certificate signed by unknown authority`).
    - no bloquea el flujo de compatibilidad WSS/protocolo.
  - Ajuste aplicado en código:
    - en `cmd/gui/ui.go`, el auto-check de actualizaciones se omite cuando se arranca en modo `--server` o `afirma://websocket`.
    - objetivo: eliminar ruido de error TLS de updates en logs de compatibilidad web y dejar foco en trazas de protocolo.
  - Ajuste adicional de ruido en logs:
    - en `cmd/gui/main.go`, ya no se registra `Arg present but no protocol detected` cuando el argumento es un flag CLI (por ejemplo `--server`).
    - en `cmd/gui/websocket.go`, cierre abrupto de cliente (`close 1006` / `unexpected EOF`) se registra como desconexión abrupta en lugar de error genérico de lectura.
  - Robustez adicional `service` legacy (casuística de integradores):
    - `extractLegacyParam` ahora decodifica valores URL-encoded (`%2B`, `%2F`, `%3D`) antes de procesar `cmd/fragment/send`.
    - impacto: mejora compatibilidad cuando la sede/intermediario transporta base64 escapado en query.
    - tests añadidos:
      - `TestLegacyServiceCmdURLEncodedBase64`
      - `TestLegacyServiceFragmentURLEncodedChunk`
  - Robustez adicional `batch` trifásico remoto (sede real):
    - reintentos automáticos en llamadas HTTP de `prefirma/postfirma` para errores transitorios:
      - red/transporte
      - `408`, `429`, `5xx`
    - no se reintenta en errores de parámetros (`400`), preservando mapeo `SAF_03`.
    - tests añadidos:
      - `TestBatchHTTPPostWithRetryRetriesTransientHTTP5xx`
      - `TestBatchHTTPPostWithRetryDoesNotRetryOnHTTP400`
      - `TestBatchHTTPPostWithRetryRetriesOnNetworkError`
    - timeout HTTP configurable para pre/post remoto:
      - variables soportadas:
        - `AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS`
        - `AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC`
      - por defecto: `15s`.
      - tests añadidos:
        - `TestResolveBatchHTTPTimeoutDefault`
        - `TestResolveBatchHTTPTimeoutFromMS`
        - `TestResolveBatchHTTPTimeoutFromSec`
        - `TestResolveBatchHTTPTimeoutInvalidFallsBackDefault`
    - número de reintentos configurable:
      - variable soportada:
        - `AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS`
      - por defecto: `3` (capado a `6`).
      - tests añadidos:
        - `TestResolveBatchHTTPMaxAttemptsDefault`
        - `TestResolveBatchHTTPMaxAttemptsFromEnv`
        - `TestResolveBatchHTTPMaxAttemptsInvalidFallsBackDefault`
        - `TestResolveBatchHTTPMaxAttemptsCapped`
    - trazas operativas añadidas para diagnóstico en sedes:
      - log de configuración efectiva por petición remota (`timeout`, `max_attempts`).
      - log por reintento transitorio con `attempt=n/m`.
      - saneado de URL en logs (solo `scheme://host/path`, sin query sensible).
    - circuito de protección por host remoto (circuit breaker simple):
      - se abre temporalmente tras 3 fallos consecutivos al mismo host de pre/post batch.
      - cooldown de 20s antes de permitir nuevos intentos.
      - éxito posterior reinicia estado del host.
      - cuando está abierto, mapea a `SAF_26` (servicio temporalmente no disponible).
      - tests añadidos:
        - `TestBatchRemoteCircuitOpensAfterThresholdFailures`
        - `TestBatchRemoteCircuitResetsOnSuccess`
        - `TestMapBatchRemoteHTTPErrorCircuitOpenReturnsSaf26`
    - parámetros del circuit breaker configurables por entorno:
      - `AUTOFIRMA_BATCH_BREAKER_THRESHOLD` (default `3`, cap `10`)
      - `AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS` / `AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC` (default `20s`, cap `5m`)
      - tests añadidos:
        - `TestResolveBatchRemoteBreakerThresholdDefault`
        - `TestResolveBatchRemoteBreakerThresholdFromEnv`
        - `TestResolveBatchRemoteBreakerThresholdCapped`
        - `TestResolveBatchRemoteBreakerCooldownDefault`
        - `TestResolveBatchRemoteBreakerCooldownFromMS`
        - `TestResolveBatchRemoteBreakerCooldownFromSec`
        - `TestResolveBatchRemoteBreakerCooldownCapped`
  - Soporte operativo para P1/E2E de sedes:
    - añadido `scripts/run_sede_e2e.sh` con comandos:
      - `start --clean-logs` (arranque + handshake WSS)
      - `check --since-minutes N` (validación de logs de sede y búsqueda de `SAF_03`/`ERR-*`)
      - `stop`
    - documentación actualizada en `docs/WEB_COMPAT_TEST.md`.
    - `scripts/run_sede_e2e.sh check` ahora adjunta en el reporte extractos recientes de:
      - log web compat (`/tmp/autofirma-web-compat.log`)
      - log launcher (`/tmp/autofirma-launcher.log`, si existe)
      para facilitar evidencias sin copia manual.
    - saneado adicional de extractos en reporte:
      - enmascarado de `idsession/idSession`, `dat`, `certs`, `tridata` y `key` en líneas de evidencia.
  - Automatización de validación con tuning batch:
    - `scripts/run_full_validation.sh` ahora acepta flags para ajustar en ejecución:
      - `--batch-timeout-ms|--batch-timeout-sec`
      - `--batch-max-attempts`
      - `--batch-breaker-threshold`
      - `--batch-breaker-cooldown-ms|--batch-breaker-cooldown-sec`
    - el script exporta las variables de entorno correspondientes y muestra valores efectivos al inicio.
    - `scripts/run_full_validation.sh` ahora genera reporte en `/tmp` con:
      - estado por paso (`PASS`/`SKIP`)
      - resultado final (`PASS`/`FAIL`)
      - paso fallido y código de salida cuando hay error.

## Pendiente para hoy (2026-02-17) - revisado
- [ ] Ejecutar pruebas E2E completas en sedes reales (al menos Valide + una sede adicional):
  - flujo `sign -> save -> upload/retorno`.
  - revisar logs para confirmar ausencia de `SAF_03`/`ERR-` no esperados.
- [ ] Completar robustez final de `service`/legacy:
  - cubrir variantes de framing/comandos que aparezcan en logs reales.
  - añadir test de regresión por cada variante nueva detectada.
- [ ] Cerrar batch “real” end-to-end:
  - validar prefirma/postfirma contra servicio real.
  - ajustar/revisar timeouts y reintentos.
- [ ] Validación ampliada de certificados/dispositivos:
  - escenarios NSS/PKCS#11 adicionales.
  - verificación de manejo de errores PIN/CAN y mensajes de UI.
- [ ] Empaquetado e instalación final:
  - generar artefactos de release (`.deb`/`.run`) con binario actualizado.
  - validar instalación limpia y asociación `afirma://` en otro equipo.
- [ ] QA y cierre de bloque:
  - ejecutar `scripts/run_full_validation.sh`.
  - anotar resultados y bloqueantes de release en este mismo archivo.

