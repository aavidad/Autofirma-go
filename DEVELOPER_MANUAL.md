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

## 11. Frontend Qt (cmd/qt_real)

La GUI Qt es un proceso independiente que se comunica con el backend Go vía REST HTTP.

### Estructura

| Archivo | Propósito |
|---------|-----------|
| `cmd/qt_real/main.cpp` | Punto de entrada, lanza `BackendBridge::startBackend()` automáticamente |
| `cmd/qt_real/backendbridge.h/.cpp` | Puente REST-QML (HTTP sobre `127.0.0.1:63118`) |
| `cmd/qt_real/ipcbridge.h/.cpp` | Puente IPC alternativo (socket Unix) |
| `cmd/qt_real/qml/main.qml` | UI principal con todas las pestañas |
| `cmd/qt_real/qt_real.pro` | Proyecto qmake (compilar con `qmake6 && make`) |

### Arranque automático del backend

`BackendBridge::startBackend()` busca el binario `autofirma-desktop` en:
1. El mismo directorio que el ejecutable `qt_real`
2. PATH del sistema

Si no lo encuentra en 3 segundos, muestra error de estado.

### Señales de gestión del servicio (nuevas en v0.0.2)

```cpp
// Emitidas por BackendBridge hacia QML:
void serviceStatusReceived(bool installed, bool running, QString platform, QString method);
void serviceActionFinished(bool ok, QString message);

// Invocables desde QML:
Q_INVOKABLE void getServiceStatus();
Q_INVOKABLE void installService();
Q_INVOKABLE void uninstallService();
Q_INVOKABLE void startService();
Q_INVOKABLE void stopService();
```

### Endpoints REST del servicio (cmd/gui/rest_service_handlers.go)

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/service/status` | Estado actual (installed, running, platform, method) |
| POST | `/service/install` | Instala el servicio de usuario |
| POST | `/service/uninstall` | Desinstala el servicio |
| POST | `/service/start` | Inicia el servicio |
| POST | `/service/stop` | Para el servicio |

### Lógica de service_manager.go

`findCoreBackendBinary()` busca el binario `autofirma-desktop` (el core) evitando
instalar la GUI (`-gio`, `-qt`, `-fyne`) como servicio.

Orden de búsqueda:
1. Mismo directorio que el ejecutable actual
2. Un nivel arriba (`../autofirma-desktop`)
3. Dos niveles arriba
4. PATH del sistema
5. Si el ejecutable actual no tiene sufijo de GUI → se usa a sí mismo

## 12. Sistema de compilación e instalación

### Makefile

```bash
make build          # compila Go (cmd/gui) + Qt (cmd/qt_real) → dist/
make install        # ejecuta build + instala con sudo
make install-only   # instala desde dist/ existente (sin recompilar)
make uninstall      # desinstala todo limpiamente
make package        # genera release/linux/AutofirmaDipgra-X.Y.Z-linux-x64.tar.gz
make clean          # limpia artefactos
make version        # muestra versión actual
make bump           # sube PATCH (0.0.x → 0.0.x+1)
make bump-minor     # sube MINOR (0.x.y → 0.x+1.0)
make bump-major     # sube MAJOR (x.y.z → x+1.0.0)
```

### Instalador Linux (packaging/linux/build_and_install.sh)

Pasos que ejecuta `make install`:

1. **Detección** — lee `VERSION` instalado en `PREFIX`
2. **Parada de procesos** — mata instancias en ejecución
3. **Limpieza** — elimina binarios y QML viejos (conserva config y certs del usuario)
4. **Copia** — instala `autofirma-desktop`, `autofirma-qt`, `qml/` en `PREFIX`
5. **Symlinks** — crea `/usr/local/bin/autofirma-dipgra`, `autofirma-desktop`
6. **Desktop** — entrada `.desktop` + handler `afirma://`
7. **Native Messaging** — manifiestos para Chrome/Firefox (si existe `autofirma-host`)
8. **Certifciados** — invoca `--generate-certs` y `--install-trust` como usuario real

### Sistema de versiones

```
VERSION          ← fichero canónico con X.Y.Z
bump_version.sh  ← script de gestión
CHANGELOG.md     ← historial de cambios
```

Política:
- **PATCH** (`make bump`): cambios rutinarios, fixes menores
- **MINOR** (`make bump-minor`): cuando el usuario lo indique explícitamente
- **MAJOR** (`make bump-major`): cuando el usuario lo indique explícitamente

Con mensaje de cambio:
```bash
make bump MSG="Descripción del cambio"
# → sube PATCH, añade entrada al CHANGELOG automáticamente
```

## 13. Cuando tocar el frontend Qt

- Señales nuevas: declararlas en `backendbridge.h` (`signals:`) e implementarlas en `.cpp`
- Métodos invocables desde QML: `Q_INVOKABLE` en `.h` + implementación en `.cpp`
- QML usa `Connections { target: backend; function on<Señal>(...) {} }`
- Compilar siempre con `qmake6` (no `qmake5`): `cd cmd/qt_real && qmake6 qt_real.pro && make -j$(nproc)`
- Los errores de linting del IDE en carpetas `backups/` son **falsos positivos** — ignorarlos
