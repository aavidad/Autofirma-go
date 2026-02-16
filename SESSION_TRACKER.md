# Session Tracker - Migracion AutoFirma Java -> Go

Fecha base: 2026-02-13
Workspace: `AutoFirma_Dipgra/autofirma_migracion/work/native-host-src`

## Reglas operativas
- No tocar codigo fuera de este workspace.
- Antes de editar archivos preexistentes: crear backup en `backups/<timestamp>_<motivo>/`.
- Mantener trazabilidad por sesiones.

## Objetivo principal
Conseguir compatibilidad operativa con flujo de sede usando protocolo `afirma://` y firma de documentos (prioridad: CAdES/PAdES compatibles con sedes reales).

## Estado global
- [x] Host Go lanza por `afirma://sign`.
- [x] Descarga de peticion desde `RetrieveService`.
- [x] Parse XML `<sign>` y extraccion de `stservlet`, `id`, `format`, `dat`.
- [x] Bucle activo `#WAIT` cada 10s durante firma.
- [x] Subida final a `StorageService` (no `RetrieveService`).
- [x] Formato `POST` estilo Java (`op=put&v=1_0&id=...&dat=...` cuerpo crudo).
- [x] Respuesta de upload validada por body (`OK` requerido).
- [x] Eliminada dependencia Node.js en firma/verificacion (CAdES/PAdES/XAdES en Go/OpenSSL).
- [x] Scripts de release/smoke ajustados a runtime Go puro.
- [x] Backup completo de trabajo creado.
- [x] Pipeline de empaquetado Linux+Windows con instaladores en carpetas separadas.

## Hitos recientes (cerrados)
- [x] Corregido error `ERR-01` por operacion no soportada.
- [x] Confirmado en logs: `java-style upload response ... body="OK"`.
- [x] Corregido CAdES signer para incluir atributos autenticados CMS:
  - `contentType`
  - `messageDigest`
  - `signingTime`

## Verificaciones pendientes en sede
- [x] Repetir prueba completa en sede con runtime Go puro (sin Node.js).
- [x] Confirmar desaparicion definitiva de `COD_103`.
- [x] Confirmar callback final de la sede sin mensaje de error de comunicacion.

## Riesgos abiertos
- Posible diferencia adicional entre CMS generado y esperado por backend de sede (cadena de certificados, atributos opcionales, algoritmo concreto).
- Confirmar en entorno real que no existen residuos de despliegues antiguos con `signers/*.js`.

## Siguiente bloque de trabajo (prioridad)
1. Consolidar pruebas repetibles (script de humo contra sede + parsing de logs).
2. Comparar ASN.1/CMS con AutoFirma Java original para eliminar riesgos residuales.
3. Ajustar signer CAdES para:
   - incluir cadena completa de certificados,
   - validar orden de atributos,
   - validar OIDs/algoritmos exactos.
4. Dejar script de comprobacion automatica de compatibilidad CMS.

## Artefactos clave
- Launcher: `scripts/launch_autofirma_desktop_software.sh`
- Binario: `dist/autofirma-desktop`
- Protocolo GUI: `cmd/gui/protocol.go`
- Flujo firma UI: `cmd/gui/ui.go`
- Selector de formatos y flujo de firma: `pkg/signer/signer.go`
- Signer CAdES (Go/OpenSSL): `pkg/signer/cades_openssl.go`
- Signer PAdES (Go): `pkg/signer/pades_go.go`
- Signer XAdES (Go): `pkg/signer/xades_go.go`
- Logs: `/tmp/autofirma-launcher.log`
- Smoke sede logs: `scripts/smoke_sede_logcheck.sh` (incluye deteccion de trazas Node)
- Packaging Linux: `packaging/linux/make_linux_release.sh`
- Packaging Windows: `packaging/windows/make_windows_release.sh`
- NSIS Windows: `packaging/windows/autofirma_windows_installer.nsi`

## Backups importantes
- Full backup:
  - `/home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/backups/native-host-src_full_20260213_140342`
- [X] Fix: Protocol sign requests now support manual file selection in minimalist mode.
- [X] Fix: WebSocket requests now bridge to the UI for cert selection.
- [X] Fix: Correctly handling multiple protocol URI aliases (id, stservlet, etc).
- [x] Task: Investigate system-wide trust for the local WebSocket TLS certificate on Linux.

## Avance sesion 2026-02-16
- [x] Añadidos flags GUI para TLS local:
  - `--install-trust`
  - `--trust-status`
- [x] Instalacion de confianza Linux implementada:
  - NSS usuario (Chrome/Chromium y perfiles Firefox detectados)
  - sistema (con root) via `update-ca-certificates` o `update-ca-trust`
- [x] Instalador Linux actualizado para aplicar confianza:
  - usuario (`AUTOFIRMA_TRUST_SKIP_SYSTEM=1`)
  - sistema en ejecucion root (`AUTOFIRMA_TRUST_SKIP_NSS=1`)
- [x] Guia web compat actualizada (`docs/WEB_COMPAT_TEST.md`) con pasos de confianza TLS.
