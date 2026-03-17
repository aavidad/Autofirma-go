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
### `cmd/browser-bridge`
- Host de Native Messaging (se compila como `autofirma-browser-bridge`).
- Única función centralizada de Native Messaging delegada: Entrada/salida JSON por `stdin/stdout`.
- Pensado para comunicarse eficientemente con las extensiones de Chrome/Firefox.
- Reenvía el tráfico formateado y extrae la validación Caller (ID de extensión).

### `cmd/autofirma`
- App de escritorio local y motor de compatibilidad web local. Este componente fusiona lo que anteriormente se dividía entre `autofirma-desktop` y `autofirma-host`.
- Se compila como el binario principal (típicamente `autofirma` o `autofirma-core`).
- Ejecuta los flujos pesados y la lógica de firma de protocolo (`afirma://`).
- Levanta el Servidor WSS local, puertos legacy y ejecuta las solicitudes batch.
- Incluye un servidor REST sobre IPC (`127.0.0.1:63118`) mediante el que se comunican las GUIs de Qt.
- Actúa de fallback GUI ligero usando las librerías transversales Fyne o Gio.

### `cmd/gui-qml` / `cmd/gui-widgets`
- Interfaces de usuario avanzadas en C++/Qt.
- Ambas actúan como clientes del core Go (`cmd/autofirma`) mediante REST.
- `gui-qml` (Premium) y `gui-widgets` (Clícica).
- Comparten configuración (temas, certificados) mediante `QSettings`.

## 3. Estructura técnica relevante
- `cmd/autofirma/main.go`: Flags, arranque, detección de GUIs y bucle principal.
- `cmd/autofirma/protocol*.go`: Parseo/ejecución de acciones `afirma://`.
- `cmd/autofirma/websocket*.go`: Servidor WSS local y canal de retorno.
- `cmd/autofirma/ui_*.go`: Implementaciones de GUI ligeras (Fyne/Gio).
- `cmd/autofirma/rest_server.go`: API interna para que las GUIs externas controlen el core.
- `pkg/signer/*`: Implementación CAdES/PAdES/XAdES.
- `pkg/certstore/*`: Descubrimiento de certificados por plataforma.

### Inventario y trazabilidad (scripts/ejecutables/archivos)
- Inventario funcional regenerable: `docs/INVENTARIO_PROYECTO.md`
- Manifiesto exhaustivo de archivos trackeados: `docs/FILE_MANIFEST.txt`
- Regeneración:
```bash
bash scripts/generate_project_inventory.sh
```

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

## 11. Frontends Qt (QML/Widgets)

Las GUIs Qt son procesos independientes que se comunican con el backend Go vía REST HTTP o IPC.

### Estructura compartida

- `cmd/gui-qml/`: Interfaz moderna basada en QML y `BackendBridge` (REST).
- `cmd/gui-widgets/`: Interfaz clásica basada en `QMainWindow` y gestión directa de `QNetworkAccessManager`.

### Sincronización de Preferencias

Ambas interfaces comparten la misma base de configuración mediante `QSettings` para garantizar la paridad:
- **Organización:** `Diputacion de Granada`
- **Aplicación:** `AutoFirma Dipgra`
- **Ajustes:** `ui/themeIndex` (índice del tema visual), etc.

### Compilación y Ejecución (REST)

- **QML:** `cd cmd/gui-qml && qmake6 *.pro && make`
- **Widgets:** `cd cmd/gui-widgets && qmake6 *.pro && make`

El `Makefile` raíz gestiona la compilación de ambos y los organiza en `dist/` con prefijos `autofirma-gui-qml` y `autofirma-gui-widgets`.

### Empaquetado e instalables
- Linux: `packaging/linux/make_linux_release.sh`
- Windows (NSIS): `packaging/windows/make_windows_release.sh`
- macOS: `packaging/macos/make_macos_release.sh`
- Orquestación global: `packaging/build_all_releases.sh`

### Acceso Remoto Seguro (HTTPS)

Para habilitar el acceso remoto seguro a la API REST:
1. Generar certificados: `autofirma-desktop --generate-certs`
2. Iniciar con HTTPS: `autofirma-desktop --rest --rest-https --direccion-rest 0.0.0.0:63118`

Esto activará TLS usando los certificados locales. Se recomienda usar conjuntamente `--token-rest` para autorizar las peticiones.

## 12. Reglas de depuracion
- Correlacionar por hora, accion protocolaria y codigo de resultado.
- Priorizar trazas de `protocol.go`, `websocket.go`, `ui.go`.
- Los errores de linting del IDE en carpetas `backups/` son **falsos positivos** — ignorarlos.
