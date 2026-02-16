# Manual del Desarrollador: AutoFirma-Go Native Host

Este documento describe la arquitectura, estructura de código y flujos de datos del proyecto **AutoFirma-Go Native Host**. Está dirigido a programadores que deseen mantener, extender o depurar la aplicación.

## 1. Visión General de la Arquitectura

El proyecto consta de dos binarios principales que comparten la misma lógica de negocio:

1.  **AutoFirma Host (`cmd/autofirma-host`)**:
    *   **Rol**: Native Messaging Host para navegadores (Chrome, Edge, Firefox).
    *   **Comunicación**: Recibe JSON a través de `Stdin` y responde por `Stdout`.
    *   **Ciclo de Vida**: Lanzado por el navegador cuando una web invoca la extensión. Muere cuando se cierra el canal de comunicación.
    *   **Interfaz**: No tiene UI propia (delega la selección de certificados a la extensión del navegador).

2.  **AutoFirma Desktop / GUI (`cmd/gui`)**:
    *   **Rol**: Aplicación de escritorio y Servidor de compatibilidad.
    *   **Funciones**:
        *   **Servidor WebSocket**: Escucha en el puerto `63117` (y otros configurables) para atender peticiones de webs antiguas (protocolo `afirma://websocket` o conexión directa WSS).
        *   **Protocol Handler**: Atiende ejecuciones tipo `afirma://sign?...`.
        *   **Interfaz Gráfica**: Muestra ventanas de selección de certificados (GioUI) cuando actúa como servidor.
    *   **Ciclo de Vida**: Persistente si se ejecuta como servidor (`-server`).

---

## 2. Estructura del Proyecto

```
.
├── cmd/
│   ├── autofirma-host/      # Punto de entrada del Native Host (CLI sin UI)
│   │   └── main.go          # Bucle de lectura Stdin/Stdout, routing y chunking
│   └── gui/                 # Punto de entrada de la aplicación de Escritorio
│       └── main.go          # Inicialización de GioUI y Servidor WebSocket
├── pkg/
│   ├── protocol/            # Definiciones de tipos JSON (Request/Response)
│   ├── signer/              # Lógica CORE de firma (PAdES, XAdES, CAdES)
│   ├── certstore/           # Abstracción para acceder a almacenes de certificados
│   ├── applog/              # Sistema de logs rotatorios
│   ├── updater/             # Lógica de auto-actualización
│   └── version/             # Control de versiones del proyecto
├── packaging/               # Scripts de empaquetado y release
│   ├── linux/               # Generador de instalador .run y scripts de registro
│   └── windows/             # Scripts NSIS para instalador .exe
├── build.sh                 # Script de compilación simple (Legacy/Dev)
└── go.mod                   # Definición de módulos y dependencias
```

---

## 3. Flujo de Datos

### 3.1. Flujo "Native Messaging" (Moderno)

Este es el flujo principal usado por la extensión del navegador.

1.  **Web**: JS invoca `chrome.runtime.sendNativeMessage`.
2.  **Navegador**: Ejecuta el binario `autofirma-host`.
3.  **Host (`main.go`)**:
    *   Lee la longitud del mensaje (4 bytes, little-endian).
    *   Lee el JSON del mensaje.
4.  **Routing**:
    *   Si Acción = `getCertificates` -> Llama a `certstore.GetSystemCertificates()` -> Devuelve lista JSON.
    *   (El navegador muestra UI de selección al usuario).
    *   Si Acción = `sign` -> Recibe `certificateID` y `data` (Base64).
5.  **Signer (`pkg/signer`)**:
    *   Localiza el certificado por ID.
    *   **Windows**: Intenta firmar usando el almacén de Windows directamente (CAPI vía PowerShell/.NET) sin exportar clave privada.
    *   **Fallback / Linux**: Exporta certificado+clave a un PKCS#12 temporal (`.p12` o `.pfx`) protegido por contraseña aleatoria (usando `pk12util` en Linux o `Export-PfxCertificate` en Windows).
    *   Realiza la operación criptográfica (OpenSSL para CAdES, Go puro para PAdES/XAdES).
    *   Borra archivos temporales.
6.  **Respuesta**:
    *   Si la firma es < 512KB encapsula en un JSON response.
    *   Si la firma es > 512KB, trocea la respuesta (Chunking) para evitar límites del pipe de Native Messaging.

### 3.2. Flujo WebSocket (Compatibilidad)

1.  **Web**: Conecta a `wss://localhost:63117`.
2.  **Desktop (`cmd/gui`)**: Acepta conexión.
3.  **Petición**: Recibe JSON `sign`.
4.  **UI Interan**: Como no hay "extension" intermedia, el propio `cmd/gui` lanza una ventana nativa (GioUI) pidiendo al usuario seleccionar certificado.
5.  **Signer**: Mismo proceso que arriba.

---

## 4. Detalles de Implementación Críticos

### 4.1. Gestión de Certificados (`pkg/certstore`)
La aplicación abstrae la complejidad de los almacenes del SO:

*   **Linux**:
    *   Busca la base de datos NSS de Firefox/Chrome en `~/.pki/nssdb` o directorios de perfiles de Firefox.
    *   Usa `pk12util` para exportar claves (requiere que la DB no tenga password maestra o que se gestione externamente).
*   **Windows**:
    *   Usa PowerShell para interrogar `Cert:\CurrentUser\My`.
    *   Obtiene `Thumbprint`, `Subject`, `Issuer`, etc.

### 4.2. Estrategia de Firma en Windows (`pkg/signer/signer.go`)
Para evitar problemas con claves marcadas como "No exportables", la aplicación implementa una estrategia de dos fases:

1.  **Store-First (Preferida)**: Intenta instruir a Windows para que firme el hash usando la clave custodiada por el sistema. Esto funciona incluso con claves no exportables (tarjetas criptográficas, certificados corporativos protegidos).
2.  **Export-Fallback**: Si la primera falla, intenta exportar el certificado a un archivo `.pfx` temporal y firmar con la librería interna de Go.

### 4.3. Protocolo (`pkg/protocol`)
Estructura básica de una petición:

```json
{
  "action": "sign",
  "request_id": "req-123",
  "certificate_id": "FINGERPRINT_HEX_DEL_CERTIFICADO",
  "data": "BASE64_DEL_CONTENIDO_A_FIRMAR",
  "format": "pades", // cades, xades, pades
  "signature_options": { // Opcional
    "reason": "Firmado por AutoFirma-Go",
    "location": "Granada"
  }
}
```

---

## 5. Guía para Programadores

### Cómo compilar y empaquetar

Existen scripts dedicados para generar releases listos para distribución:

**Para Linux:**
Genera un instalador `.run` autocontenido y un `.tar.gz`.
```bash
./packaging/linux/make_linux_release.sh
```

**Para Windows (vía NSIS):**
Requiere `makensis` instalado.
```bash
./packaging/windows/make_windows_release.sh
```

**Compilación manual para desarrollo:**
```bash
# Host Nativo
go build -o autofirma-host ./cmd/autofirma-host

# Aplicación Desktop
go build -o autofirma-desktop ./cmd/gui
```

### Cómo añadir un nuevo formato de firma
1.  Crea un archivo nuevo en `pkg/signer/` (ej. `jades_go.go`).
2.  Implementa la función de firma que acepte `inputFile`, `p12Path`, `password`.
3.  Registra el nuevo caso en el `switch` principal de `signer.go` dentro de la función `SignData`.

### Depuración
Los logs se escriben en:
*   **Linux**: `~/.cache/autofirma-host/autofirma-host.log`
*   **Windows**: `%LOCALAPPDATA%\autofirma-host\autofirma-host.log`

Para ver los logs en tiempo real mientras usas la extensión:
```bash
tail -f ~/.cache/autofirma-host/autofirma-host.log
```

### Notas sobre Seguridad
*   **Archivos Temporales**: El `signer` crea archivos `.p12` y de datos en el directorio temporal del sistema. Es crítico asegurar que los `defer os.Remove(...)` se ejecuten siempre.
*   **Logs**: Nunca loguear el campo `data` de la petición ni los contenidos del `.p12`, ya que contienen información sensible del usuario o su clave privada.

---

**Autor**: Equipo de Desarrollo - Oficina de Software Diputación de Granada
