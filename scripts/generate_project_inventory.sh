#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_MD="${ROOT_DIR}/docs/INVENTARIO_PROYECTO.md"
OUT_MANIFEST="${ROOT_DIR}/docs/FILE_MANIFEST.txt"

cd "${ROOT_DIR}"

version_go="$(grep -m1 'CurrentVersion' pkg/version/version.go 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/' || true)"
version_txt="$(tr -d '[:space:]' < VERSION 2>/dev/null || true)"
generated_at="$(date '+%Y-%m-%d %H:%M:%S %z')"

script_desc() {
  case "$1" in
    scripts/build_and_install.sh) echo "Compila e instala en Linux (integración de escritorio, protocolo y Native Messaging)." ;;
    scripts/install.sh) echo "Instalador auxiliar de Linux usado por scripts/packaging." ;;
    scripts/install_desktop.sh) printf '%s\n' 'Instala integración de escritorio y handler `afirma://` en Linux.' ;;
    scripts/install_and_trust_linux.sh) echo "Instala y registra confianza TLS/certificados locales en Linux." ;;
    scripts/install_certificates.sh) echo "Instala certificados de confianza adicionales en el sistema/usuario." ;;
    scripts/install_tsa_extras.sh) echo "Instala extras de TSA/certificados para pruebas y entornos específicos." ;;
    scripts/instalar_lanzador_server.sh) echo "Instala lanzador/arranque del modo servidor (tray/websocket)." ;;
    scripts/run_autofirma.sh) echo "Lanzador de desarrollo para ejecutar la app/host con entorno local." ;;
    scripts/run_web_compat_server.sh) printf '%s\n' 'Arranca/para el servidor web-compat local (`cmd/autofirma`) para pruebas con sedes.' ;;
    scripts/run_sede_e2e.sh) echo "Orquesta pruebas E2E contra sedes (start/check/stop) con logs y validaciones." ;;
    scripts/smoke_sede_logcheck.sh) echo "Smoke test de logs de sede: detecta errores protocolarios comunes en trazas." ;;
    scripts/run_full_validation.sh) echo "Suite de validación amplia (tests Go + checks de integración/compatibilidad)." ;;
    scripts/run_test_suite.sh) echo "Wrapper de suite de pruebas de proyecto (rápida/completa según opciones)." ;;
    scripts/test_active_go.sh) printf '%s\n' 'Ejecuta tests Go activos (`./cmd/...`, `./pkg/...`) para ciclo rápido de desarrollo.' ;;
    scripts/test_websocket_cancel.sh) printf '%s\n' 'Test de integración para cancelación WebSocket y retorno `CANCEL` al navegador.' ;;
    scripts/smoke_native_host.sh) echo "Smoke test del host de Native Messaging." ;;
    scripts/smoke_large_payload.sh) echo "Prueba payloads grandes en WebSocket/Native Messaging para robustez." ;;
    scripts/test_ipc.sh) echo "Pruebas del canal IPC local (sin interfaz de usuario)." ;;
    scripts/test_ipc_sign.sh) echo "Prueba firma vía IPC con documento/certificado." ;;
    scripts/e2e_native_request.sh) echo "Simula peticiones Native Messaging completas (sign/cades/pades/etc.)." ;;
    scripts/ws_send_afirma_uri.py) printf '%s\n' 'Cliente WS para enviar una URI `afirma://...` al servidor local (diagnóstico).' ;;
    scripts/ws_echo_client.py) echo "Cliente WebSocket de eco/inspección para pruebas manuales." ;;
    scripts/test-websocket.js) echo "Cliente de prueba Node/JS para el servidor WebSocket local." ;;
    scripts/sniffer.js) echo "Sniffer de tráfico/protocolos web para depuración de compatibilidad." ;;
    scripts/interceptor-autofirma.js) echo "Script de inyección/interceptación para depurar llamadas web a AutoFirma." ;;
    scripts/inject_webservice_compat.js) echo "Inyecta capa de compatibilidad web en páginas de prueba/QA." ;;
    scripts/build_qt_real_linux.sh) echo "Compila la GUI Qt/QML nativa (C++/Qt6) en Linux." ;;
    scripts/reparar_qt_linux.sh) echo "Repara dependencias/plugins Qt en Linux (entorno de desarrollo/ejecución)." ;;
    scripts/arreglar_instalacion_qt.sh) echo "Ajusta rutas/instalación de Qt en Linux (compatibilidad de plugins/runtime)." ;;
    scripts/actualizar_qt_real.sh) echo "Actualiza/recompila el frontend Qt real y recursos asociados." ;;
    scripts/rebuild_install_and_tail.sh) echo "Recompila, reinstala y abre logs en tiempo real para depuración." ;;
    scripts/package_linux_artifact.sh) printf '%s\n' 'Genera artefacto Linux empaquetado desde `dist/`/`release`.' ;;
    scripts/build_macos_osxcross.sh) printf '%s\n' 'Compila para macOS desde Linux con `osxcross`.' ;;
    scripts/probar_iconos_systray.sh) echo "Pruebas manuales de iconos systray en Linux." ;;
    scripts/launch_autofirma_desktop_software.sh) echo "Lanzador de escritorio para pruebas con certificados software." ;;
    scripts/generate_parity_changelog.sh) echo "Genera changelog de paridad Java/Go." ;;
    scripts/process_ui.py) echo "Utilidad de procesado de UI/recursos (pipeline interno)." ;;
    scripts/rewrite_ui.py) echo "Reescritura/parcheo automatizado de archivos de UI (QML/otros)." ;;
    scripts/patch_ipc.py) echo "Parche/utilidad para ajustar el canal IPC o datos de prueba." ;;
    scripts/replace_global.py) echo "Reemplazos globales controlados en árbol de código." ;;
    scripts/test_install.sh) echo "Comprobación rápida de instalación/entorno local." ;;
    scripts/test_script.sh) echo "Script de pruebas varias/auxiliar (sandbox de desarrollo)." ;;
    scripts/windows/install_and_trust_windows.ps1) echo "Instalación y confianza TLS/certificados en Windows." ;;
    scripts/windows/run_web_compat_server.ps1) echo "Arranque/parada del web-compat server en Windows." ;;
    scripts/windows/run_full_validation_windows.ps1) echo "Suite de validación en Windows." ;;
    scripts/windows/run_test_suite.ps1) echo "Wrapper de pruebas del proyecto en Windows." ;;
    scripts/windows/test_active_go.ps1) echo "Tests Go activos en Windows." ;;
    scripts/windows/e2e_native_request.ps1) echo "Pruebas E2E Native Messaging en Windows." ;;
    scripts/windows/smoke_native_host.ps1) echo "Smoke test del host nativo en Windows." ;;
    scripts/macos/install_and_trust_macos.sh) echo "Instala y registra confianza TLS/certificados en macOS." ;;
    packaging/linux/make_linux_release.sh) printf '%s\n' 'Construye bundle e instalador Linux (`.run`/`.tar.gz`) con binarios, Qt runtime y extensiones.' ;;
    packaging/linux/build_and_install.sh) printf '%s\n' 'Build+install Linux desde carpeta `packaging/` (wrapper del flujo de despliegue).' ;;
    packaging/linux/install.sh) echo "Script de instalación Linux usado por el instalador/packaging." ;;
    packaging/windows/make_windows_release.sh) echo "Genera bundle Windows e instalador NSIS; integra Qt6 y extensiones Dipgra." ;;
    packaging/windows/autofirma_windows_installer.nsi) printf '%s\n' 'Script NSIS del instalador Windows (secciones, registro `afirma://`, accesos directos).' ;;
    packaging/macos/make_macos_release.sh) echo "Genera release/instalador para macOS." ;;
    packaging/macos/install.sh) echo "Instalador auxiliar de macOS para packaging." ;;
    packaging/build_all_releases.sh) echo "Orquestador multi-plataforma para generar releases de Linux/Windows/macOS." ;;
    scripts/README.md) echo "Guía manual de scripts (resumen funcional)." ;;
    *) echo "Utilidad del proyecto (revisar contenido/script para detalle específico)." ;;
  esac
}

exe_desc() {
  case "$1" in
    cmd/autofirma) printf '%s\n' 'Binario principal Go (`autofirma`): motor de firma, protocolo `afirma://`, WSS, REST local y frontends ligeros Fyne/Gio.' ;;
    cmd/browser-bridge) printf '%s\n' 'Host de Native Messaging (`autofirma-browser-bridge`) para Chrome/Firefox (stdin/stdout JSON).' ;;
    cmd/gui-qml) printf '%s\n' 'GUI de escritorio C++/Qt6/QML (`autofirma-gui-qml` / `autofirma-qt`). Cliente del core vía REST/IPC.' ;;
    cmd/gui-widgets) printf '%s\n' 'GUI clásica C++/Qt Widgets (`autofirma-gui-widgets`). Cliente del core vía REST.' ;;
    cmd/gui_backup_20251223_121308) echo "Copia histórica de una GUI Go anterior (backup de referencia; no forma parte del build actual)." ;;
    *) printf '%s\n' 'Componente ejecutable o fuente principal en `cmd/`.' ;;
  esac
}

top_level_summary() {
  git ls-files | awk -F/ '
    {
      top=$1;
      count[top]++
    }
    END {
      for (k in count) printf "%s\t%d\n", k, count[k]
    }' | sort
}

{
  echo "# Inventario del Proyecto AutoFirma Dipgra"
  echo
  echo "Generado automáticamente por \`scripts/generate_project_inventory.sh\`."
  echo
  echo "- Fecha: ${generated_at}"
  printf '%s\n' '- Versión (`pkg/version/version.go`): '"${version_go:-desconocida}"
  printf '%s\n' '- Versión (`VERSION`): '"${version_txt:-desconocida}"
  echo
  echo "## Objetivo"
  echo
  echo "Documento de referencia para conocer:"
  echo "- Qué ejecutables/componentes produce el proyecto."
  echo "- Qué scripts existen y para qué sirven."
  echo "- Qué áreas/directorios forman el repositorio."
  echo "- Dónde está el manifiesto exhaustivo de archivos trackeados."
  echo
  echo "## Ejecutables y Componentes en \`cmd/\`"
  echo
  echo "| Ruta | Función |"
  echo "|---|---|"
  find cmd -maxdepth 1 -mindepth 1 -type d | sort | while read -r d; do
    rel="${d#./}"
    [[ "${rel}" == "cmd" ]] && continue
    echo "| \`${rel}\` | $(exe_desc "${rel}") |"
  done
  echo
  printf '%s\n' '## Binarios de salida habituales (`dist/` y releases)'
  echo
  cat <<'EOF'
| Binario/artefacto | Origen | Uso |
|---|---|---|
| `dist/autofirma` | `cmd/autofirma` | Binario principal (protocolo, WSS, REST, frontends ligeros). |
| `dist/autofirma-browser-bridge` | `cmd/browser-bridge` | Host de Native Messaging. |
| `dist/autofirma-gui-qml` | `cmd/gui-qml` | GUI Qt6/QML. |
| `dist/autofirma-gui-widgets` | `cmd/gui-widgets` | GUI Qt Widgets. |
| `dist/qml/` | recursos QML | Recursos para frontend Qt. |
| `release/linux/*` | `packaging/linux/*` | Bundle/instalador Linux. |
| `release/windows/*` | `packaging/windows/*` | Bundle/instalador Windows (NSIS). |
| `release/macos/*` | `packaging/macos/*` | Artefactos macOS. |
EOF
  echo
  printf '%s\n' '## Scripts del Proyecto (incluye `scripts/` y `packaging/`)'
  echo
  echo "| Script/archivo | Propósito |"
  echo "|---|---|"
  {
    find scripts -type f | sort
    find packaging -type f \( -name '*.sh' -o -name '*.ps1' -o -name '*.nsi' -o -name '*.wxs' \) | sort
  } | while read -r f; do
    rel="${f#./}"
    echo "| \`${rel}\` | $(script_desc "${rel}") |"
  done
  echo
  echo "## Estructura del repositorio (resumen por área)"
  echo
  echo "| Ruta | Descripción |"
  echo "|---|---|"
  cat <<'EOF'
| `cmd/` | Ejecutables y frontends (core Go, bridge, Qt QML/Widgets). |
| `pkg/` | Librerías compartidas (firma, certificados, logs, TLS, versión, etc.). |
| `scripts/` | Scripts de build, pruebas, instalación y utilidades de desarrollo. |
| `packaging/` | Instaladores y empaquetado Linux/Windows/macOS. |
| `docs/` | Documentación técnica, compatibilidad, API REST, protocolo y guías de QA. |
| `config/` | Configuración estática (dominios permitidos/autoconfiados y otros). |
| `assets/` | Iconos y recursos gráficos. |
| `dist/` | Artefactos de compilación local (generados). |
| `release/` | Bundles/instaladores generados (release). |
| `clienteafirma-master/` | Referencia Java histórica/usada para paridad funcional. |
| `third_party/` | Dependencias de terceros embebidas/parcheadas. |
| `vendor/` | Dependencias vendorizadas de Go. |
| `backups/`, `backups_dev/`, `_backup_ediciones/` | Copias de seguridad y snapshots de trabajo. |
EOF
  echo
  echo "## Resumen de archivos trackeados por carpeta de primer nivel"
  echo
  echo "| Carpeta/archivo superior | Nº ficheros trackeados |"
  echo "|---|---:|"
  top_level_summary | while IFS=$'\t' read -r top count; do
    echo "| \`${top}\` | ${count} |"
  done
  echo
  echo "## Manifiesto exhaustivo de archivos"
  echo
  echo "Listado completo de ficheros trackeados del repositorio (uno por línea):"
  echo
  printf '%s\n' '- `docs/FILE_MANIFEST.txt`'
  echo
  echo "Se genera con el mismo script y sirve como inventario exhaustivo para auditoría/documentación."
} > "${OUT_MD}"

{
  echo "# FILE_MANIFEST - AutoFirma Dipgra"
  echo "# Generado: ${generated_at}"
  echo "# Script: scripts/generate_project_inventory.sh"
  echo "# Lista completa de ficheros trackeados (git ls-files)"
  git ls-files | sort
} > "${OUT_MANIFEST}"

echo "[ok] Generado ${OUT_MD}"
echo "[ok] Generado ${OUT_MANIFEST}"
