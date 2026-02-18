# Scripts de Pruebas y Validación (Castellano)

## Objetivo
Este documento resume **qué script usar**, **cuándo usarlo** y **qué valida**.

Notas generales:
- Ejecutar siempre desde la raíz del proyecto (`work/native-host-src`).
- La mayoría de scripts ya fuerzan `GOFLAGS=-mod=readonly` para evitar problemas de vendor.
- Algunos scripts requieren utilidades externas (`jq`, `python3`, `sudo`) según el caso.

## Scripts de prueba funcional
### `scripts/test_active_go.sh`
- Cuándo usarlo: al empezar una sesión de desarrollo o antes de commit.
- Qué valida: `go test` de paquetes activos (`cmd/`, `pkg/`).
- Comando:
```bash
bash scripts/test_active_go.sh
```

### `scripts/smoke_native_host.sh`
- Cuándo usarlo: validación rápida del host nativo.
- Qué valida: `ping`, `getCertificates`, firma y verificación (`cades`, y opcional `pades/xades`).
- Comandos:
```bash
bash scripts/smoke_native_host.sh
bash scripts/smoke_native_host.sh --strict-formats
```

### `scripts/e2e_native_request.sh`
- Cuándo usarlo: comprobar framing Native Messaging y respuesta JSON mínima por acción.
- Qué valida: `ping`, certificados y firma CAdES simple.
- Comandos:
```bash
bash scripts/e2e_native_request.sh ping
bash scripts/e2e_native_request.sh getCertificates
bash scripts/e2e_native_request.sh sign-cades
```

### `scripts/smoke_large_payload.sh`
- Cuándo usarlo: pruebas de cargas grandes, chunking y robustez temporal.
- Qué valida: firma/verificación CAdES con payload grande.
- Comando:
```bash
PAYLOAD_MB=3 bash scripts/smoke_large_payload.sh
```

## Scripts de compatibilidad web/sede
### `scripts/run_web_compat_server.sh`
- Cuándo usarlo: pruebas de canal WebSocket/WSS con sedes compatibles.
- Qué valida: arranque/parada/estado del servidor web compat.
- Comandos:
```bash
bash scripts/run_web_compat_server.sh start
bash scripts/run_web_compat_server.sh status
bash scripts/run_web_compat_server.sh stop
```

### `scripts/ws_echo_client.py`
- Cuándo usarlo: comprobar handshake y eco WSS local.
- Qué valida: conectividad WSS con el servidor web compat.
- Comando:
```bash
python3 scripts/ws_echo_client.py
```

### `scripts/ws_send_afirma_uri.py`
- Cuándo usarlo: envío manual de URI `afirma://...` por WSS para depuración.
- Qué valida: parseo y respuesta de operaciones protocolarias por WebSocket.
- Uso: revisar argumentos en el propio script según la operación a probar.

### `scripts/smoke_sede_logcheck.sh`
- Cuándo usarlo: tras firma real en sede.
- Qué valida: evidencia de subida/resultado correcto y ausencia de errores protocolarios clave.
- Comando:
```bash
bash scripts/smoke_sede_logcheck.sh --log-file /ruta/log.log --since-minutes 180
```

### `scripts/run_sede_e2e.sh`
- Cuándo usarlo: ciclo completo de preparación/comprobación de pruebas reales con sede.
- Qué valida: arranque web compat, revisión de logs de launcher/web/host, consistencia de flujo.
- Comandos típicos:
```bash
bash scripts/run_sede_e2e.sh start
bash scripts/run_sede_e2e.sh check --since-minutes 180
bash scripts/run_sede_e2e.sh stop
```

## Validación integral
### `scripts/run_full_validation.sh`
- Cuándo usarlo: validación de bloque antes de entrega/release.
- Qué valida: tests activos, smoke nativo, trust, web compat, WSS, log de sede y reporte final.
- Comando:
```bash
bash scripts/run_full_validation.sh
```
- Opciones frecuentes:
```bash
bash scripts/run_full_validation.sh --strict-formats
bash scripts/run_full_validation.sh --skip-trust
bash scripts/run_full_validation.sh --skip-sede-logcheck
```

## Empaquetado/instalación y soporte
### `scripts/package_linux_artifact.sh`
- Cuándo usarlo: generar artefacto Linux del host.
- Comando:
```bash
bash scripts/package_linux_artifact.sh
```

### `scripts/install_and_trust_linux.sh`
- Cuándo usarlo: instalar y configurar confianza local (Linux).
- Requisitos: permisos `sudo`.
- Comando:
```bash
bash scripts/install_and_trust_linux.sh
```

### `scripts/rebuild_install_and_tail.sh`
- Cuándo usarlo: recompilar GUI, instalar en `/opt` y seguir logs.
- Requisitos: permisos `sudo` para instalación.
- Comando:
```bash
bash scripts/rebuild_install_and_tail.sh
```

### `scripts/launch_autofirma_desktop_software.sh`
- Cuándo usarlo: lanzar binario concreto con render por software (depuración gráfica).
- Comando:
```bash
bash scripts/launch_autofirma_desktop_software.sh
```

## Script documental
### `scripts/generate_parity_changelog.sh`
- Cuándo usarlo: regenerar `docs/CHANGELOG_PARIDAD.md` desde el plan maestro.
- Comando:
```bash
bash scripts/generate_parity_changelog.sh
```

## Integración en la app
Desde la GUI (modo experto) existe el **Panel de pruebas** que permite:
- Seleccionar una o varias pruebas.
- Ejecutar una prueba individual.
- Ejecutar todas las seleccionadas o todas las disponibles.
- Ver resultados en el panel de mensajes con scroll.

El panel está pensado para pruebas de desarrollo local y no sustituye la validación E2E real en sede.

## Equivalentes para Windows (PowerShell)
Scripts disponibles:
- `scripts/windows/test_active_go.ps1`
- `scripts/windows/smoke_native_host.ps1`
- `scripts/windows/e2e_native_request.ps1`
- `scripts/windows/run_web_compat_server.ps1`
- `scripts/windows/install_and_trust_windows.ps1`
- `scripts/windows/run_full_validation_windows.ps1`
- `scripts/windows/run_test_suite.ps1`

Ejemplos:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/test_active_go.ps1
powershell -ExecutionPolicy Bypass -File scripts/windows/smoke_native_host.ps1 -StrictFormats
powershell -ExecutionPolicy Bypass -File scripts/windows/e2e_native_request.ps1 -Action sign-cades
powershell -ExecutionPolicy Bypass -File scripts/windows/run_full_validation_windows.ps1 -SkipTrust
```

Referencia de compatibilidad por sistema operativo:
- `docs/SCRIPTS_COMPATIBILIDAD_SO.md`
