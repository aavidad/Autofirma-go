# AutoFirma-Go

**AutoFirma-Go** es un port de alto rendimiento de la aplicación cliente de firma electrónica @firma (AutoFirma), reescrito completamente en **Go (Golang)**.

Esta implementación elimina la necesidad de tener instalada la Máquina Virtual de Java (JVM) en el equipo del usuario, ofreciendo una solución mucho más ligera, rápida y segura para la firma electrónica en entornos de escritorio (Windows y Linux).

## 🚀 Características Principales

*   **Sin Dependencias de Java**: Ejecutable nativo y autocontenido.
*   **Alto Rendimiento**: Inicio instantáneo y consumo de memoria mínimo (vs >200MB de la versión Java).
*   **Compatibilidad Total**:
    *   Soporta los mismos protocolos de invocación que la AutoFirma original (`afirma://`).
    *   Funciona como *Native Messaging Host* para extensiones modernas de navegador.
    *   Incluye servidor WebSocket local (`wss://127.0.0.1:63117`) para compatibilidad con aplicaciones web legacy.
*   **Formatos de Firma Soportados**:
    *   **PAdES** (PDF Advanced Electronic Signatures) - Niveles Básico.
    *   **XAdES** (XML Advanced Electronic Signatures) - Enveloping/Detached.
    *   **CAdES** (CMS Advanced Electronic Signatures).
*   **Integración con Almacenes de Certificados**:
    *   **Windows**: Uso nativo de CAPI/CNG (soporta DNIe y Tarjetas Criptográficas sin configuración extra).
    *   **Linux**: Integración automática con almacenes NSS (Firefox/Chrome) y soporte PCKS#11.

## 🛠️ Instalación y Uso

Para usuarios finales, consulte el [Manual de Usuario](USER_MANUAL.md).

Para desarrolladores que deseen compilar o contribuir al proyecto, consulte el [Manual del Desarrollador](DEVELOPER_MANUAL.md).

## 📦 Compilación desde Código Fuente

Requisitos: **Go 1.22** o superior.

```bash
# Clonar el repositorio
git clone https://github.com/aavidad/Autofirma-go.git
cd Autofirma-go

# Compilar el componente Host (Backend invisible)
go build -o autofirma-host ./cmd/autofirma-host

# Compilar la aplicación de Escritorio (GUI / WebSocket Server)
go build -o autofirma-desktop ./cmd/gui
```

### Generación del Instalador (Windows)
El proyecto incluye script NSIS para generar el instalador `.exe`.

```bash
# Desde la raiz del proyecto
./packaging/windows/make_windows_release.sh
```

Si su paquete GUI no esta en `cmd/gui` (por ejemplo `cmd/gui_backup_20251223_121308`), indique el paquete manualmente:

```bash
GUI_CMD_PKG=./cmd/gui_backup_20251223_121308 ./packaging/windows/make_windows_release.sh
```

Salida esperada:
* `release/windows/bundle/AutofirmaDipgra/autofirma-desktop.exe`
* `release/windows/AutofirmaDipgra-windows-installer.exe`

## 📄 Licencia

Este proyecto es software libre distribuido bajo la licencia **GPLv3** (GNU General Public License v3.0). Consulte el archivo `LICENSE` para más detalles.

---
*Desarrollado por la Oficina de Software Libre de la Diputación de Granada.*
