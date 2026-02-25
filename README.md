# AutoFirma Dipgra (Go)

Cliente de firma electronica en Go, compatible con flujos de AutoFirma Java (`afirma://`) y con sedes que usan `Native Messaging`, `WSS` o subida legacy.

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## Estado actual
- Compatible con Windows, Linux y macOS.
- Flujos soportados: `sign`, `cosign`, `countersign`, `selectcert`, `batch`, `websocket`, `service`, `save`.
- Modos de uso: simple y experto.
- Seguridad reforzada: lista blanca de dominios, diagnostico TLS/red, trust local, trazas saneadas.
- Integración Native Messaging con extensión Dipgra (`com.dipgra.autofirma`) y alias legacy (`com.autofirma.native`).

## Funcionalidades principales
- Firma y verificacion: CAdES, PAdES, XAdES.
- Protocolo `afirma://` con parseo robusto y mensajes en castellano.
- Servidor WebSocket local seguro (`wss://127.0.0.1`).
- Firma por lotes (prefirma, firma local PKCS#1, postfirma).
- Seleccion de certificado con etiquetas funcionales (incluida representacion).
- Diagnostico guiado de errores de firma con propuestas de solucion.
- Panel de pruebas en GUI (modo experto) para ejecutar scripts de validacion.
- Gestion de confianza TLS local y utilidades de instalacion por SO.

## Documentacion
- Uso funcional completo: `USER_MANUAL.md`
- Arquitectura y desarrollo: `DEVELOPER_MANUAL.md`
- Ayuda funcional exhaustiva GUI: `docs/GUI_AYUDA_EXHAUSTIVA.md`
- Scripts de pruebas (cuando y como usarlos): `docs/SCRIPTS_PRUEBAS.md`
- Compatibilidad de scripts por SO: `docs/SCRIPTS_COMPATIBILIDAD_SO.md`
- Cambios de paridad Java/Go: `docs/CHANGELOG_PARIDAD.md`

## Compilacion rapida
Requisito: Go 1.22+

```bash
go build -mod=readonly -o autofirma-browser-bridge ./cmd/browser-bridge
go build -mod=readonly -o autofirma ./cmd/autofirma
```

## Compilacion por sistema
### Linux (nativo)
Requisitos recomendados:
- `go` 1.22+
- `zip` (para generar ZIP de extensiones en release)
- `qmake6` y `make` (si se compila frontend Qt real)

Comandos:
```bash
# Binarios base
go build -mod=readonly -o autofirma ./cmd/autofirma
go build -mod=readonly -o autofirma-browser-bridge ./cmd/browser-bridge

# Frontend Qt wrapper (Go)
go build -mod=readonly -o autofirma-qt-bin ./cmd/qt

# Frontend Qt real (si aplica)
./scripts/build_qt_real_linux.sh ./autofirma-qt-real
```

### Windows (cross-compile desde Linux)
Requisitos:
- `go` 1.22+
- `makensis` en `PATH` para generar instalador `.exe`

Comandos:
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-H=windowsgui" -o autofirma.exe ./cmd/autofirma
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o autofirma-browser-bridge.exe ./cmd/browser-bridge
./packaging/windows/make_windows_release.sh
```

### macOS
En macOS nativo:
```bash
go build -mod=readonly -o autofirma ./cmd/autofirma
go build -mod=readonly -o autofirma-browser-bridge ./cmd/browser-bridge
./packaging/macos/make_macos_release.sh
```

Desde Linux con `osxcross`:
- Ver guía: `docs/OSXCROSS_BUILD.md`

## Uso CLI de `autofirma`
```bash
autofirma -ayuda-detallada
autofirma -version
autofirma -generate-certs
autofirma -install-trust
autofirma -trust-status
autofirma -server
autofirma -exportar-certs-java /ruta/directorio

# Modo CLI en castellano (alias compatibles)
autofirma -modo-cli -listar-certificados
autofirma -modo-cli -operacion firmar -entrada /ruta/doc.pdf -indice-certificado 0 -formato pades
autofirma -modo-cli -operacion verificar -entrada /ruta/firmado.pdf
autofirma -modo-cli -operacion informe-diagnostico -salida-json

# Modo REST en castellano (alias compatibles)
autofirma -servidor-rest -direccion-rest 127.0.0.1:63118 -token-rest secreto
```

## Empaquetado
- Linux: `./packaging/linux/make_linux_release.sh`
- Windows: `./packaging/windows/make_windows_release.sh`
- macOS: `./packaging/macos/make_macos_release.sh`

Si existe `../../DipgraExtension`, el empaquetado incluye automáticamente:
- `extensiones/chromium` y `extensiones/firefox`
- ZIPs de distribución: `dipgra-extension-chromium.zip` y `dipgra-extension-firefox.zip`

## Ultimos cambios (integracion extension + seguridad)
### Native Messaging unificado
- Nombre principal de host: `com.dipgra.autofirma`.
- Alias legacy mantenido: `com.autofirma.native`.
- Instalación Linux crea manifiestos para ambos nombres (compatibilidad retro).

### Allowlist de extensiones en host nativo
- El host `autofirma-browser-bridge` valida caller contra `native_messaging_allowlist.json`.
- Ubicación habitual: `/opt/autofirma-dipgra/native_messaging_allowlist.json` (Linux).
- Campos usados:
  - `chromium_ids`
  - `firefox_ids`
  - `require_match`

Variables de entorno soportadas:
- `AUTOFIRMA_CHROMIUM_EXTENSION_IDS=id1,id2`
- `AUTOFIRMA_FIREFOX_EXTENSION_IDS=id1,id2`
- `AUTOFIRMA_NATIVE_HOST_NAME=com.dipgra.autofirma`
- `AUTOFIRMA_NATIVE_HOST_ALIASES=com.autofirma.native`

### Extensión de Diputación integrada en releases
- Origen por defecto: `../../DipgraExtension`.
- Se empaqueta en Linux/Windows/macOS dentro de `extensiones/`.
- Se generan ZIPs de importación rápida para Chromium/Firefox.
- Se puede redefinir origen con:
  - `DIPGRA_EXTENSION_DIR=/ruta/DipgraExtension`

### Dominios AAPP de España permitidos por defecto
- La whitelist por defecto ya no está hardcodeada en código:
  - `config/dominios_firma_permitidos.txt`
  - `config/dominios_firma_autoconfiados.txt`
- Incluye sedes AAPP (Estado + CCAA principales), por ejemplo:
  - `*.gob.es`, `*.administracion.gob.es`, `*.junta-andalucia.es`, `*.xunta.gal`, `*.gva.es`, `*.generalitat.cat`, `*.euskadi.eus`, `*.jcyl.es`, `*.navarra.es`, `*.aragon.es`, `*.cantabria.es`, `*.asturias.es`, `*.extremadura.es`, `*.larioja.org`, `*.carm.es`, `*.canarias.org`, `*.caib.es`.
- También se marcan como auto-confiados para evitar prompt inicial en esos dominios.
- Override por entorno:
  - `AUTOFIRMA_DOMINIOS_FIRMA_PERMITIDOS`
  - `AUTOFIRMA_DOMINIOS_FIRMA_AUTOCONFIADOS`
  - `AUTOFIRMA_DOMINIOS_FIRMA_PERMITIDOS_ARCHIVO`
  - `AUTOFIRMA_DOMINIOS_FIRMA_AUTOCONFIADOS_ARCHIVO`
  - Compatibilidad:
  - `AUTOFIRMA_ALLOWED_SIGN_DOMAINS`
  - `AUTOFIRMA_AUTO_TRUST_SIGN_DOMAINS`
  - `AUTOFIRMA_ALLOWED_SIGN_DOMAINS_FILE`
  - `AUTOFIRMA_AUTO_TRUST_SIGN_DOMAINS_FILE`

Importación masiva desde fichero (uno por línea):
```bash
autofirma -modo-cli -operacion importar-dominios -fichero-dominios /ruta/dominios_aapp_es.txt
```

Empaquetado Linux con Qt nativo real incluido:
```bash
QT_REAL_BIN_PATH=/ruta/autofirma-qt-real BUILD_SELF_CONTAINED=0 ./packaging/linux/make_linux_release.sh
```

Empaquetado Linux con runtime Qt incluido:
```bash
QT_REAL_BIN_PATH=/ruta/autofirma-qt-real \
QT_RUNTIME_DIR=/ruta/qt-runtime \
BUILD_SELF_CONTAINED=0 \
./packaging/linux/make_linux_release.sh
```

## Perfiles de instalación (Linux)
Perfiles disponibles en instalador `.run`:
- `completo` (por defecto): instala todo (GUI + integración de escritorio + handler `afirma://` + Native Messaging).
- `escritorio`: GUI + integración de escritorio + handler `afirma://`, sin registro Native Messaging.
- `minimo`: binarios y comandos, sin integración de escritorio ni Native Messaging.

Subperfil de escritorio (para `escritorio` y `completo`):
- `fyne` (por defecto)
- `gio`
- `qt`

Nota sobre `qt`:
- El lanzador `qt` usa `autofirma-qt-bin`.
- Si existe un binario Qt nativo real, puede indicarse con `AUTOFIRMA_QT_BIN_REAL=/ruta/autofirma-qt-real`.
- Mientras no exista ese binario, el instalador deja fallback temporal a Fyne para no bloquear el uso.

El instalador genera lanzadores directos:
- `autofirma-dipgra-fyne`
- `autofirma-dipgra-gio`
- `autofirma-dipgra-qt`
- `autofirma-dipgra` (apunta al subperfil elegido)

Ejemplos:
```bash
./release/linux/AutofirmaDipgra-linux-installer.run --perfil completo
./release/linux/AutofirmaDipgra-linux-installer.run --perfil escritorio
./release/linux/AutofirmaDipgra-linux-installer.run --perfil minimo
./release/linux/AutofirmaDipgra-linux-installer.run --perfil escritorio --subperfil-escritorio qt
```

## Instalacion y prueba rapida de lo ultimo (Linux)
```bash
# 1) Generar instalador actualizado
BUILD_SELF_CONTAINED=0 ./packaging/linux/make_linux_release.sh

# 2) Instalar
sudo ./release/linux/AutofirmaDipgra-linux-installer.run --perfil completo

# 3) Verificar host nativo y allowlist
ls -l /opt/autofirma-dipgra/native_messaging_allowlist.json
ls -l /etc/opt/chrome/native-messaging-hosts/com.dipgra.autofirma.json
ls -l /etc/opt/chrome/native-messaging-hosts/com.autofirma.native.json
```

## Licencia
GPLv3. Ver `LICENSE`.
