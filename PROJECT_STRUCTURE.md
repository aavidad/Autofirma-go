# Mapa del Proyecto: Estructura y Archivos

Este documento sirve como guía para programadores externos que deseen entender la organización de AutoFirma Dipgra (Go).

## 📂 Directorios Principales

### 🏗️ Aplicaciones (`cmd/`)
Cada subdirectorio aquí genera un binario ejecutable independiente.
*   **`autofirma/`**: El corazón del proyecto. Contiene el motor lógico (fichajes, protocolos, criptografía) y las interfaces ligeras escritas en Go (**Gio** y **Fyne**).
*   **`gui-qml/`**: Interfaz de usuario premium. Escrita en **C++/Qt 6** con **QML**. Es la interfaz visual por defecto recomendada.
*   **`gui-widgets/`**: Interfaz de usuario clásica. Escrita en **C++/Qt Widgets** sin QML. Más ligera y conservadora.
*   **`browser-bridge/`**: El host de **Native Messaging**. Es el programa que los navegadores (Chrome/Firefox) ejecutan para comunicarse con la aplicación.

### 📦 Lógica Compartida (`pkg/`)
Librerías internas reutilizables.
*   **`pkg/signer/`**: Implementación de firmas digitales (PAdES, CAdES, XAdES).
*   **`pkg/certstore/`**: Abstracción para acceder a los certificados del sistema/tarjetas en Windows y Linux.
*   **`pkg/applog/`**: Gestión de logs persistentes en disco.
*   **`pkg/version/`**: Manejo de la información de compilación y versión.

### 🛠️ Herramientas y Recursos
*   **`scripts/`**: Automatización de tareas, tests E2E, reparadores de librerías e instaladores. (Ver `scripts/README.md`).
*   **`config/`**: Listas blancas de dominios permitidos y archivos de configuración estática.
*   **`assets/`**: Logotipos, iconos y recursos visuales para todas las plataformas.
*   **`packaging/`**: Archivos necesarios para generar instaladores (NSIS para Windows, `.deb`, manifiestos).
*   **`third_party/`**: Librerías externas que han sido parcheadas o incluidas localmente por motivos de seguridad o compatibilidad.

---

## 📄 Archivos Clave en la Raíz

| Archivo | Función |
| :--- | :--- |
| **`Makefile`** | Orquestador de compilación. Usa `make build` para generar todo el proyecto. |
| **`VERSION`** | Archivo de texto plano con la versión actual (ej: `1.2.3`). Es la fuente única de verdad. |
| **`README.md`** | Visión general, características principales y guía rápida. |
| **`DEVELOPER_MANUAL.md`** | Explicación técnica detallada de los flujos internos y arquitectura. |
| **`USER_MANUAL.md`** | Guía de instalación y uso para el usuario final. |
| **`go.mod` / `go.sum`** | Definición de dependencias del lenguaje Go. |
| **`build.sh`** | Un atajo de conveniencia que invoca al Makefile con parámetros óptimos. |
| **`bump_version.sh`** | Sistema automatizado para subir versiones y actualizar el CHANGELOG. |

---

## 🗺️ Flujo de Ejecución (Resumen)
1. El usuario pincha un enlace `afirma://` en el navegador.
2. El navegador lanza a **`browser-bridge`**.
3. El bridge despierta al Core (**`autofirma`**) indicándole la operación.
4. El Core arranca la interfaz visual (**`gui-qml`**) para que el usuario elija su certificado y confirme la operación.
5. El Core realiza la firma y devuelve el resultado al navegador.
