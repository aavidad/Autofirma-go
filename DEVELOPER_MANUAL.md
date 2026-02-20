# Manual del Desarrollador

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## 1. Alcance del proyecto
AutoFirma Dipgra implementa un cliente compatible con AutoFirma Java, centrado en:
- Protocolo `afirma://` y variantes.
- Firma local y flujos de sede.
- Integracion con certificados de sistema.
- Seguridad operacional (TLS, dominios de confianza, diagnostico).

## 2. Binarios principales
### `cmd/autofirma-host`
- Native Messaging host.
- Entrada/salida JSON por `stdin/stdout`.
- Pensado para extensiones de navegador.

### `cmd/gui`
- App de escritorio (Gio) y motor de compatibilidad web.
- Ejecuta flujos de protocolo, WSS local, firma por lote y diagnosticos.
- Incluye modo experto y panel de pruebas.

## 3. Estructura tecnica relevante
- `cmd/gui/main.go`: flags, arranque, handler protocolo, bucle UI.
- `cmd/gui/protocol*.go`: parseo/ejecucion de acciones `afirma://`.
- `cmd/gui/websocket*.go`: servidor WSS local y canal de retorno.
- `cmd/gui/tls_*.go`: confianza TLS, diagnostico endpoint y truststore local.
- `pkg/signer/*`: implementacion CAdES/PAdES/XAdES, verificacion y utilidades.
- `pkg/certstore/*`: descubrimiento y uso de certificados por plataforma.
- `scripts/`: automatizacion de pruebas y validaciones.
- `packaging/`: instaladores y artefactos por SO.

## 4. Flags de `autofirma-desktop`
```bash
-server
-generate-certs
-install-trust
-trust-status
-exportar-certs-java <directorio>
-version
-ayuda-detallada
```

## 5. Flujos funcionales
### Firma/identificacion protocolaria
1. Entrada `afirma://...` desde navegador.
2. Parseo de accion (`sign`, `selectcert`, `batch`, etc.).
3. Descarga de datos (`rtservlet`) cuando aplica.
4. Operacion local (seleccion cert + firma).
5. Retorno por WSS o subida legacy (`stservlet`).

### Batch trifasico
1. Prefirma remota.
2. Firma local PKCS#1.
3. Postfirma remota.
4. Mapeo de errores con codigos `SAF_*` y mensajes accionables.

### WSS compat
1. Arranque por `afirma://websocket?ports=...`.
2. Bind en loopback.
3. Recepcion de operaciones `afirma://...` por canal WS.
4. Respuesta protocolaria por el mismo canal.

## 6. Seguridad y decisiones de diseno
- Prioridad de seguridad sobre conveniencia.
- Lista blanca de dominios para solicitudes web.
- Diagnostico de red/TLS con evidencias (DNS, TCP, TLS, endpoints).
- Logs saneados: no registrar payloads completos ni secretos.
- Cadena de confianza local gestionada por la app y por instaladores.

## 7. Certificados y UX tecnica
- Deteccion y etiquetado de certificados de representacion.
- Seleccion de certificado contextual segun accion protocolaria.
- Herramientas de exportacion y gestion de confianza desde GUI experto.

## 8. Pruebas y validacion
### Basicas
```bash
bash scripts/test_active_go.sh
bash scripts/smoke_native_host.sh
bash scripts/e2e_native_request.sh sign-cades
```

### Flujo completo
```bash
bash scripts/run_full_validation.sh
bash scripts/run_sede_e2e.sh start
bash scripts/run_sede_e2e.sh check --since-minutes 180
bash scripts/run_sede_e2e.sh stop
```

### Windows/macOS
Ver equivalentes en:
- `docs/SCRIPTS_COMPATIBILIDAD_SO.md`
- `scripts/windows/*`
- `scripts/macos/*`

## 9. Logs y depuracion
Rutas habituales:
- Linux: `~/.local/state/autofirma-dipgra/logs/`
- Temporal web compat: `/tmp/autofirma-web-compat.log`

Regla de depuracion:
- Correlacionar por hora, accion protocolaria y codigo de resultado.
- Priorizar trazas de `protocol.go`, `websocket.go`, `ui.go`.

## 10. Guias de cambio
### Cuando tocar protocolo
- Mantener compatibilidad de parametros con Java.
- No romper formatos de salida esperados por sedes.
- Añadir test de regresion en `cmd/gui/*_test.go`.

### Cuando tocar seguridad/TLS
- Mantener verificacion estricta por defecto.
- Añadir mensajes de error con causa y solucion.
- Actualizar instaladores y documentacion del truststore.

### Cuando tocar UI
- Mantener textos y logs en castellano.
- Evitar mezclar flujos: `selectcert` no debe abrir selector de PDF.
- Reflejar nuevos controles en `docs/GUI_AYUDA_EXHAUSTIVA.md`.
