# CHANGELOG — AutoFirma Dipgra

Formato: `MAJOR.MINOR.PATCH` — se incrementa el PATCH salvo indicación expresa.

---

## [0.0.2] — 2026-02-21

### Añadido
- Test del sistema de versionado


## [0.0.1] — 2026-02-21

### Añadido
- Gestión de servicio de usuario multiplataforma (Linux systemd, macOS launchd, Windows Task Scheduler)
- Endpoints REST `/service/status|install|uninstall|start|stop`
- Panel de configuración en la GUI Qt con control del servicio (instalar, desinstalar, iniciar, parar)
- Indicador de estado del servicio en tiempo real (color verde/naranja/rojo)
- `BackendBridge::getServiceStatus/installService/uninstallService/startService/stopService` en C++
- Búsqueda inteligente del binario core (`autofirma-desktop`) evitando instalar la GUI como servicio
- Makefile con targets: `build`, `install`, `uninstall`, `package`, `clean`
- Instalador Linux (`packaging/linux/build_and_install.sh`) con:
  - Detección y limpieza de versiones anteriores
  - Instalación de binarios, QML, symlinks, entrada .desktop y manifiestos Native Messaging
  - Desinstalación completa sin dejar rastro
- Sistema de versionado con `VERSION`, `CHANGELOG.md` y `bump_version.sh`

