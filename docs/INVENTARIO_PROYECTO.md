# Inventario del Proyecto AutoFirma Dipgra

Generado automáticamente por `scripts/generate_project_inventory.sh`.

- Fecha: 2026-02-26 00:20:47 +0100
- Versión (`pkg/version/version.go`): 0.1.9
- Versión (`VERSION`): 0.1.1

## Objetivo

Documento de referencia para conocer:
- Qué ejecutables/componentes produce el proyecto.
- Qué scripts existen y para qué sirven.
- Qué áreas/directorios forman el repositorio.
- Dónde está el manifiesto exhaustivo de archivos trackeados.

## Ejecutables y Componentes en `cmd/`

| Ruta | Función |
|---|---|
| `cmd/autofirma` | Binario principal Go (`autofirma`): motor de firma, protocolo `afirma://`, WSS, REST local y frontends ligeros Fyne/Gio. |
| `cmd/browser-bridge` | Host de Native Messaging (`autofirma-browser-bridge`) para Chrome/Firefox (stdin/stdout JSON). |
| `cmd/gui-qml` | GUI de escritorio C++/Qt6/QML (`autofirma-gui-qml` / `autofirma-qt`). Cliente del core vía REST/IPC. |
| `cmd/gui-widgets` | GUI clásica C++/Qt Widgets (`autofirma-gui-widgets`). Cliente del core vía REST. |
| `cmd/gui_backup_20251223_121308` | Copia histórica de una GUI Go anterior (backup de referencia; no forma parte del build actual). |

## Binarios de salida habituales (`dist/` y releases)

| Binario/artefacto | Origen | Uso |
|---|---|---|
| `dist/autofirma` | `cmd/autofirma` | Binario principal (protocolo, WSS, REST, frontends ligeros). |
| `dist/autofirma-browser-bridge` | `cmd/browser-bridge` | Host de Native Messaging. |
| `dist/autofirma-gui-qml` | `cmd/gui-qml` | GUI Qt6/QML. |
| `dist/autofirma-gui-widgets` | `cmd/gui-widgets` | GUI Qt Widgets. |
| `dist/qml/` | recursos QML | Recursos para frontend Qt. |
| `release/linux/*` | `packaging/linux/*` | Bundle/instalador Linux. |
| `release/windows/*` | `packaging/windows/*` | Bundle/instalador Windows (NSIS). |
| `release/macos/*` | `packaging/macos/*` | Artefactos macOS. |

## Scripts del Proyecto (incluye `scripts/` y `packaging/`)

| Script/archivo | Propósito |
|---|---|
| `scripts/README.md` | Guía manual de scripts (resumen funcional). |
| `scripts/actualizar_qt_real.sh` | Actualiza/recompila el frontend Qt real y recursos asociados. |
| `scripts/arreglar_instalacion_qt.sh` | Ajusta rutas/instalación de Qt en Linux (compatibilidad de plugins/runtime). |
| `scripts/build_and_install.sh` | Compila e instala en Linux (integración de escritorio, protocolo y Native Messaging). |
| `scripts/build_macos_osxcross.sh` | Compila para macOS desde Linux con `osxcross`. |
| `scripts/build_qt_real_linux.sh` | Compila la GUI Qt/QML nativa (C++/Qt6) en Linux. |
| `scripts/e2e_native_request.sh` | Simula peticiones Native Messaging completas (sign/cades/pades/etc.). |
| `scripts/generate_parity_changelog.sh` | Genera changelog de paridad Java/Go. |
| `scripts/generate_project_inventory.sh` | Utilidad del proyecto (revisar contenido/script para detalle específico). |
| `scripts/inject_webservice_compat.js` | Inyecta capa de compatibilidad web en páginas de prueba/QA. |
| `scripts/instalar_lanzador_server.sh` | Instala lanzador/arranque del modo servidor (tray/websocket). |
| `scripts/install.sh` | Instalador auxiliar de Linux usado por scripts/packaging. |
| `scripts/install_and_trust_linux.sh` | Instala y registra confianza TLS/certificados locales en Linux. |
| `scripts/install_certificates.sh` | Instala certificados de confianza adicionales en el sistema/usuario. |
| `scripts/install_desktop.sh` | Instala integración de escritorio y handler `afirma://` en Linux. |
| `scripts/install_tsa_extras.sh` | Instala extras de TSA/certificados para pruebas y entornos específicos. |
| `scripts/interceptor-autofirma.js` | Script de inyección/interceptación para depurar llamadas web a AutoFirma. |
| `scripts/launch_autofirma_desktop_software.sh` | Lanzador de escritorio para pruebas con certificados software. |
| `scripts/macos/install_and_trust_macos.sh` | Instala y registra confianza TLS/certificados en macOS. |
| `scripts/package_linux_artifact.sh` | Genera artefacto Linux empaquetado desde `dist/`/`release`. |
| `scripts/patch_ipc.py` | Parche/utilidad para ajustar el canal IPC o datos de prueba. |
| `scripts/probar_iconos_systray.sh` | Pruebas manuales de iconos systray en Linux. |
| `scripts/process_ui.py` | Utilidad de procesado de UI/recursos (pipeline interno). |
| `scripts/rebuild_install_and_tail.sh` | Recompila, reinstala y abre logs en tiempo real para depuración. |
| `scripts/reparar_qt_linux.sh` | Repara dependencias/plugins Qt en Linux (entorno de desarrollo/ejecución). |
| `scripts/replace_global.py` | Reemplazos globales controlados en árbol de código. |
| `scripts/rewrite_ui.py` | Reescritura/parcheo automatizado de archivos de UI (QML/otros). |
| `scripts/run_autofirma.sh` | Lanzador de desarrollo para ejecutar la app/host con entorno local. |
| `scripts/run_full_validation.sh` | Suite de validación amplia (tests Go + checks de integración/compatibilidad). |
| `scripts/run_sede_e2e.sh` | Orquesta pruebas E2E contra sedes (start/check/stop) con logs y validaciones. |
| `scripts/run_test_suite.sh` | Wrapper de suite de pruebas de proyecto (rápida/completa según opciones). |
| `scripts/run_web_compat_server.sh` | Arranca/para el servidor web-compat local (`cmd/autofirma`) para pruebas con sedes. |
| `scripts/smoke_large_payload.sh` | Prueba payloads grandes en WebSocket/Native Messaging para robustez. |
| `scripts/smoke_native_host.sh` | Smoke test del host de Native Messaging. |
| `scripts/smoke_sede_logcheck.sh` | Smoke test de logs de sede: detecta errores protocolarios comunes en trazas. |
| `scripts/sniffer.js` | Sniffer de tráfico/protocolos web para depuración de compatibilidad. |
| `scripts/test-websocket.js` | Cliente de prueba Node/JS para el servidor WebSocket local. |
| `scripts/test_active_go.sh` | Ejecuta tests Go activos (`./cmd/...`, `./pkg/...`) para ciclo rápido de desarrollo. |
| `scripts/test_install.sh` | Comprobación rápida de instalación/entorno local. |
| `scripts/test_ipc.sh` | Pruebas del canal IPC local (sin interfaz de usuario). |
| `scripts/test_ipc_sign.sh` | Prueba firma vía IPC con documento/certificado. |
| `scripts/test_script.sh` | Script de pruebas varias/auxiliar (sandbox de desarrollo). |
| `scripts/test_websocket_cancel.sh` | Test de integración para cancelación WebSocket y retorno `CANCEL` al navegador. |
| `scripts/windows/e2e_native_request.ps1` | Pruebas E2E Native Messaging en Windows. |
| `scripts/windows/install_and_trust_windows.ps1` | Instalación y confianza TLS/certificados en Windows. |
| `scripts/windows/run_full_validation_windows.ps1` | Suite de validación en Windows. |
| `scripts/windows/run_test_suite.ps1` | Wrapper de pruebas del proyecto en Windows. |
| `scripts/windows/run_web_compat_server.ps1` | Arranque/parada del web-compat server en Windows. |
| `scripts/windows/smoke_native_host.ps1` | Smoke test del host nativo en Windows. |
| `scripts/windows/test_active_go.ps1` | Tests Go activos en Windows. |
| `scripts/ws_echo_client.py` | Cliente WebSocket de eco/inspección para pruebas manuales. |
| `scripts/ws_send_afirma_uri.py` | Cliente WS para enviar una URI `afirma://...` al servidor local (diagnóstico). |
| `packaging/build_all_releases.sh` | Orquestador multi-plataforma para generar releases de Linux/Windows/macOS. |
| `packaging/linux/build_and_install.sh` | Build+install Linux desde carpeta `packaging/` (wrapper del flujo de despliegue). |
| `packaging/linux/install.sh` | Script de instalación Linux usado por el instalador/packaging. |
| `packaging/linux/make_linux_release.sh` | Construye bundle e instalador Linux (`.run`/`.tar.gz`) con binarios, Qt runtime y extensiones. |
| `packaging/macos/install.sh` | Instalador auxiliar de macOS para packaging. |
| `packaging/macos/make_macos_release.sh` | Genera release/instalador para macOS. |
| `packaging/windows/autofirma_windows_installer.nsi` | Script NSIS del instalador Windows (secciones, registro `afirma://`, accesos directos). |
| `packaging/windows/make_windows_release.sh` | Genera bundle Windows e instalador NSIS; integra Qt6 y extensiones Dipgra. |

## Estructura del repositorio (resumen por área)

| Ruta | Descripción |
|---|---|
| `cmd/` | Ejecutables y frontends (core Go, bridge, Qt QML/Widgets). |
| `pkg/` | Librerías compartidas (firma, certificados, logs, TLS, versión, etc.). |
| `scripts/` | Scripts de build, pruebas, instalación y utilidades de desarrollo. |
| `packaging/` | Instaladores y empaquetado Linux/Windows/macOS. |
| `docs/` | Documentación técnica, compatibilidad, API REST, protocolo y guías de QA. |
| `config/` | Configuración estática (dominios permitidos/autoconfiados y otros). |
| `assets/` | Iconos y recursos gráficos. |
| `dist/` | Artefactos de compilación local (generados). |
| `release/` | Bundles/instaladores generados (release). |
| `clienteafirma-master/` | Referencia Java histórica/usada para paridad funcional. |
| `third_party/` | Dependencias de terceros embebidas/parcheadas. |
| `vendor/` | Dependencias vendorizadas de Go. |
| `backups/`, `backups_dev/`, `_backup_ediciones/` | Copias de seguridad y snapshots de trabajo. |

## Resumen de archivos trackeados por carpeta de primer nivel

| Carpeta/archivo superior | Nº ficheros trackeados |
|---|---:|
| `"clienteafirma-master` | 2 |
| `.gitignore` | 1 |
| `AGENTS.md` | 1 |
| `AVANCES_PARIDAD_JAVA_GO.md` | 1 |
| `CHANGELOG.md` | 1 |
| `DEVELOPER_MANUAL.md` | 1 |
| `LICENSE` | 1 |
| `Makefile` | 1 |
| `NOTICE` | 1 |
| `PLAN_MIGRACION_AUTOFIRMA_GO.md` | 1 |
| `PROJECT_STRUCTURE.md` | 1 |
| `README.md` | 1 |
| `SESSION_TRACKER.md` | 1 |
| `USER_MANUAL.md` | 1 |
| `VERSION` | 1 |
| `WEBSOCKET_USAGE.md` | 1 |
| `WSS_TEST.md` | 1 |
| `assets` | 8 |
| `backups_dev` | 2 |
| `build.sh` | 1 |
| `bump_version.sh` | 1 |
| `clienteafirma-master` | 3121 |
| `cmd` | 107 |
| `config` | 3 |
| `docs` | 19 |
| `es-gob-afirma.desktop` | 1 |
| `go.mod` | 1 |
| `go.sum` | 1 |
| `icon_64.png` | 1 |
| `outputs` | 6 |
| `packaging` | 9 |
| `pkg` | 42 |
| `pluma.png` | 1 |
| `pluma.png~` | 1 |
| `plumas.png` | 1 |
| `plumas2.png` | 1 |
| `restaura.sh` | 1 |
| `scripts` | 51 |
| `test-autofirma-wss.html` | 1 |
| `test_install.sh` | 1 |
| `third_party` | 64 |

## Manifiesto exhaustivo de archivos

Listado completo de ficheros trackeados del repositorio (uno por línea):

- `docs/FILE_MANIFEST.txt`

Se genera con el mismo script y sirve como inventario exhaustivo para auditoría/documentación.
