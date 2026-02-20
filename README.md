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
go build -mod=readonly -o autofirma-host ./cmd/autofirma-host
go build -mod=readonly -o autofirma-desktop ./cmd/gui
```

## Uso CLI de `autofirma-desktop`
```bash
autofirma-desktop -ayuda-detallada
autofirma-desktop -version
autofirma-desktop -generate-certs
autofirma-desktop -install-trust
autofirma-desktop -trust-status
autofirma-desktop -server
autofirma-desktop -exportar-certs-java /ruta/directorio

# Modo CLI en castellano (alias compatibles)
autofirma-desktop -modo-cli -listar-certificados
autofirma-desktop -modo-cli -operacion firmar -entrada /ruta/doc.pdf -indice-certificado 0 -formato pades
autofirma-desktop -modo-cli -operacion verificar -entrada /ruta/firmado.pdf
autofirma-desktop -modo-cli -operacion informe-diagnostico -salida-json

# Modo REST en castellano (alias compatibles)
autofirma-desktop -servidor-rest -direccion-rest 127.0.0.1:63118 -token-rest secreto
```

## Empaquetado
- Linux: `./packaging/linux/make_linux_release.sh`
- Windows: `./packaging/windows/make_windows_release.sh`
- macOS: `./packaging/macos/make_macos_release.sh`

Empaquetado Linux con Qt nativo real incluido:
```bash
QT_REAL_BIN_PATH=/ruta/autofirma-desktop-qt-real BUILD_SELF_CONTAINED=0 ./packaging/linux/make_linux_release.sh
```

Empaquetado Linux con runtime Qt incluido:
```bash
QT_REAL_BIN_PATH=/ruta/autofirma-desktop-qt-real \
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
- El lanzador `qt` usa `autofirma-desktop-qt-bin`.
- Si existe un binario Qt nativo real, puede indicarse con `AUTOFIRMA_QT_BIN_REAL=/ruta/autofirma-desktop-qt-real`.
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

## Licencia
GPLv3. Ver `LICENSE`.
