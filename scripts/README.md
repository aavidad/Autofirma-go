# Documentación de Scripts y Utilidades

Este directorio contiene herramientas para el desarrollo, pruebas y despliegue del proyecto.

## Inventario completo (scripts + ejecutables + archivos)

Además de este resumen, existe un inventario regenerable que documenta:
- scripts de `scripts/` y `packaging/`
- ejecutables/componentes de `cmd/`
- resumen de áreas del repositorio
- manifiesto exhaustivo de archivos trackeados

Generación:

```bash
bash scripts/generate_project_inventory.sh
```

Salidas:
- `docs/INVENTARIO_PROYECTO.md`
- `docs/FILE_MANIFEST.txt`

## 🚀 Instalación y Despliegue

| Script | Propósito |
| :--- | :--- |
| `build_and_install.sh` | **Instalador principal para Linux**. Detecta dependencias, compila los componentes y configura el sistema (asociación de protocolo, iconos, Native Messaging). |
| `install.sh` | Script auxiliar de instalación, usado a veces por el sistema de empaquetado. |
| `run_autofirma.sh` | Lanzador rápido diseñado para desarrollo. Configura el entorno y lanza el Bridge del navegador. |
| `instalar_lanzador_server.sh` | Configura el arranque automático (systemd/autostart) del backend en modo servidor. |

## 🛠️ Desarrollo y Compilación

| Script | Propósito |
| :--- | :--- |
| `reparar_qt_linux.sh` | Soluciona automáticamente problemas de librerías faltantes (`libxcb`, `libQt6`, etc.) en sistemas Linux. |
| `arreglar_instalacion_qt.sh` |Similar al anterior, enfocado en corregir rutas de plugins de Qt. |
| `build_qt_real_linux.sh` | Atajo para compilar específicamente la versión QML. |
| `rebuild_install_and_tail.sh` | Utilidad de desarrollo: recompila, instala y abre el log en tiempo real. |

## 🧪 Pruebas (Test Suite)

| Script | Propósito |
| :--- | :--- |
| `run_full_validation.sh` | **Suite de validación completa**. Ejecuta todos los tests unitarios y de integración. |
| `run_sede_e2e.sh` | Realiza pruebas Reales contra sedes electrónicas actuales para verificar compatibilidad. |
| `smoke_native_host.sh` | Prueba de "humo" para verificar que el Bridge con el navegador responde correctamente. |
| `test_ipc_sign.sh` | Prueba la firma de archivos a través del socket IPC (sin usar la GUI). |
| `e2e_native_request.sh` | Simula peticiones Native Messaging complejas (firma CAdES, PAdES, etc). |

## 🧹 Utilidades de Limpieza y Paridad

| Script | Propósito |
| :--- | :--- |
| `generate_parity_changelog.sh` | Genera un reporte de las funciones de AutoFirma Java que ya han sido portadas a Go. |
| `process_ui.py` | Script Python para procesar archivos de interfaz o recursos. |
| `rewrite_ui.py` | Utilidad para transformar o parchear archivos QML dinámicamente. |
| `sniffer.js` | Herramienta para depurar comunicaciones WebSocket entre el navegador y la app. |
| `test-websocket.js` | Cliente de prueba para el servidor WebSocket interno. |

---

*Nota para desarrolladores: Casi todos los scripts aceptan el flag `--help` para ver opciones adicionales.*
