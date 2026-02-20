# Compatibilidad de Scripts por Sistema Operativo

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## Objetivo
Matriz rápida para saber qué script usar en Linux/macOS/Windows y su alternativa equivalente.

## Matriz
| Utilidad | Linux/macOS | Windows | Comentarios |
|---|---|---|---|
| Tests Go activos | `scripts/test_active_go.sh` | `scripts/windows/test_active_go.ps1` | Ejecuta `go test` en `cmd/` y `pkg/`. |
| Smoke host nativo | `scripts/smoke_native_host.sh` | `scripts/windows/smoke_native_host.ps1` | Validación funcional mínima del host. |
| E2E request host | `scripts/e2e_native_request.sh` | `scripts/windows/e2e_native_request.ps1` | Framing Native Messaging + acciones base. |
| Servidor web compat | `scripts/run_web_compat_server.sh` | `scripts/windows/run_web_compat_server.ps1` | Start/stop/status del servidor WSS local. |
| Trust local / certificados | `scripts/install_and_trust_linux.sh` | `scripts/windows/install_and_trust_windows.ps1` | En Windows se soporta con/sin instalador. |
| Validación completa | `scripts/run_full_validation.sh` | `scripts/windows/run_full_validation_windows.ps1` | Pipeline de verificación integral. |
| Wrapper de suite | `scripts/run_test_suite.sh` | `scripts/windows/run_test_suite.ps1` | Entrada recomendada por plataforma. |

## Criterios de uso
- Si trabajas en Windows nativo, usa scripts `.ps1` de `scripts/windows/`.
- Si trabajas en Linux/macOS, usa scripts `.sh`.
- En la GUI (modo experto), el panel de pruebas detecta el SO y muestra utilidades compatibles.

## Nota sobre dependencias
- Linux/macOS: `bash`, `jq`, `python3` según script.
- Windows: `PowerShell`, `go`; algunos flujos pueden requerir privilegios de administrador para trust/certificados.
