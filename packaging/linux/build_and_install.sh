#!/usr/bin/env bash
# =============================================================================
# AutoFirma Dipgra — Build + Install (Linux)
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputación de Granada
# =============================================================================
# Uso:
#   ./build_and_install.sh [--prefix /opt/autofirma-dipgra] [--no-build] [--uninstall]
#
# Variable de entorno:
#   AUTOFIRMA_PREFIX   — ruta de instalación (por defecto /opt/autofirma-dipgra)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─── Colores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[autofirma]${RESET} $*"; }
ok()      { echo -e "${GREEN}[autofirma]${RESET} ✓ $*"; }
warn()    { echo -e "${YELLOW}[autofirma]${RESET} ⚠ $*"; }
error()   { echo -e "${RED}[autofirma]${RESET} ✗ $*" >&2; }
banner()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; echo -e " $*"; echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}\n"; }

# ─── Configuración ────────────────────────────────────────────────────────────
VERSION="1.0.0"
APP_NAME="autofirma-dipgra"
PREFIX="${AUTOFIRMA_PREFIX:-/opt/autofirma-dipgra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DO_BUILD=1
DO_INSTALL=1
DO_UNINSTALL=0

# ─── Argumentos ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)       PREFIX="${2}"; shift 2 ;;
    --no-build)     DO_BUILD=0; shift ;;
    --no-install)   DO_INSTALL=0; shift ;;
    --uninstall)    DO_UNINSTALL=1; shift ;;
    --version)      VERSION="${2}"; shift 2 ;;
    -h|--help)
      echo "Uso: $0 [--prefix PATH] [--no-build] [--uninstall] [--version X.Y.Z]"
      exit 0 ;;
    *)
      error "Opción desconocida: $1"
      exit 1 ;;
  esac
done

# ─── Rutas ────────────────────────────────────────────────────────────────────
BIN_CORE="${PREFIX}/autofirma-desktop"       # Backend Go (core)
BIN_GUI="${PREFIX}/autofirma-qt"             # Frontend Qt
QML_DIR="${PREFIX}/qml"                      # Archivos QML
HOST_BIN="${PREFIX}/autofirma-host"          # Native messaging host
ASSETS_DIR="${PREFIX}/assets"                # Iconos, etc.
VERSION_FILE="${PREFIX}/VERSION"
DESKTOP_FILE="/usr/local/share/applications/${APP_NAME}.desktop"
SYMLINK_CORE="/usr/local/bin/autofirma-desktop"
SYMLINK_GUI="/usr/local/bin/${APP_NAME}"

# Native messaging
HOST_NAME="com.autofirma.native"
declare -a CHROMIUM_MANIFEST_DIRS=(
  "/etc/opt/chrome/native-messaging-hosts"
  "/etc/chromium/native-messaging-hosts"
  "/etc/opt/edge/native-messaging-hosts"
  "/etc/opt/brave.com/brave/native-messaging-hosts"
)
declare -a FIREFOX_MANIFEST_DIRS=(
  "/usr/lib/mozilla/native-messaging-hosts"
  "/usr/lib64/mozilla/native-messaging-hosts"
  "/etc/firefox/native-messaging-hosts"
)

# ─── Permisos ─────────────────────────────────────────────────────────────────
REAL_USER="${SUDO_USER:-${USER:-$(whoami)}}"
REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6 2>/dev/null || echo "${HOME}")"

# ─── Utilidades ───────────────────────────────────────────────────────────────
need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    error "Este paso requiere permisos de administrador."
    error "Ejecuta con: sudo $0 $*"
    exit 1
  fi
}

stop_processes() {
  info "Deteniendo procesos en ejecución..."
  local patterns=(
    "autofirma-desktop"
    "autofirma-qt"
    "${APP_NAME}"
  )
  local found=0
  for pat in "${patterns[@]}"; do
    local pids
    pids="$(pgrep -f "${pat}" 2>/dev/null || true)"
    if [[ -n "${pids}" ]]; then
      found=1
      warn "Deteniendo proceso: ${pat} (PIDs: $(echo "${pids}" | tr '\n' ' '))"
      echo "${pids}" | xargs -r kill -TERM 2>/dev/null || true
    fi
  done
  if [[ "${found}" -eq 1 ]]; then
    sleep 1
    for pat in "${patterns[@]}"; do
      local pids
      pids="$(pgrep -f "${pat}" 2>/dev/null || true)"
      [[ -n "${pids}" ]] && echo "${pids}" | xargs -r kill -KILL 2>/dev/null || true
    done
    ok "Procesos detenidos."
  else
    info "No había procesos en ejecución."
  fi
}

get_installed_version() {
  if [[ -f "${VERSION_FILE}" ]]; then
    cat "${VERSION_FILE}"
  else
    echo ""
  fi
}

# ─── DESINSTALACIÓN ───────────────────────────────────────────────────────────
uninstall() {
  banner "Desinstalando AutoFirma Dipgra"
  need_root

  local old_ver
  old_ver="$(get_installed_version)"
  if [[ -n "${old_ver}" ]]; then
    info "Versión encontrada: ${old_ver}"
  else
    warn "No se detectó versión instalada en ${PREFIX}. Limpiando igualmente..."
  fi

  stop_processes

  # Eliminar servicio systemd de usuario (si existe)
  local svc_file="${REAL_HOME}/.config/systemd/user/autofirma-backend.service"
  if [[ -f "${svc_file}" ]]; then
    info "Eliminando servicio systemd del usuario..."
    runuser -u "${REAL_USER}" -- systemctl --user stop autofirma-backend.service 2>/dev/null || true
    runuser -u "${REAL_USER}" -- systemctl --user disable autofirma-backend.service 2>/dev/null || true
    rm -f "${svc_file}"
    runuser -u "${REAL_USER}" -- systemctl --user daemon-reload 2>/dev/null || true
    ok "Servicio systemd eliminado."
  fi

  # Eliminar autostart GNOME/KDE
  local autostart_file="${REAL_HOME}/.config/autostart/autofirma-backend.desktop"
  [[ -f "${autostart_file}" ]] && rm -f "${autostart_file}" && info "Autostart eliminado."

  # Eliminar simlinks
  for link in "${SYMLINK_CORE}" "${SYMLINK_GUI}" \
      "/usr/local/bin/autofirma-dipgra" \
      "/usr/local/bin/autofirma-dipgra-fyne" \
      "/usr/local/bin/autofirma-dipgra-gio" \
      "/usr/local/bin/autofirma-dipgra-qt" \
      "/usr/local/bin/autofirma-host"; do
    [[ -L "${link}" || -f "${link}" ]] && rm -f "${link}" && info "Eliminado: ${link}"
  done

  # Eliminar .desktop y actualizar BD
  if [[ -f "${DESKTOP_FILE}" ]]; then
    rm -f "${DESKTOP_FILE}"
    rm -f "/usr/local/share/applications/${APP_NAME}.desktop"
    command -v update-desktop-database &>/dev/null && update-desktop-database /usr/local/share/applications 2>/dev/null || true
    ok "Entrada de escritorio eliminada."
  fi
  # Eliminar .desktop del usuario
  rm -f "${REAL_HOME}/.local/share/applications/${APP_NAME}.desktop" \
        "${REAL_HOME}/Desktop/${APP_NAME}.desktop" 2>/dev/null || true

  # Eliminar manifiestos Native Messaging
  for dir in "${CHROMIUM_MANIFEST_DIRS[@]}" "${FIREFOX_MANIFEST_DIRS[@]}"; do
    [[ -f "${dir}/${HOST_NAME}.json" ]] && rm -f "${dir}/${HOST_NAME}.json" && info "Manifest NM eliminado de ${dir}"
  done
  for ua_dir in \
      "${REAL_HOME}/.config/google-chrome/NativeMessagingHosts" \
      "${REAL_HOME}/.config/chromium/NativeMessagingHosts" \
      "${REAL_HOME}/.mozilla/native-messaging-hosts"; do
    [[ -f "${ua_dir}/${HOST_NAME}.json" ]] && rm -f "${ua_dir}/${HOST_NAME}.json" && info "Manifest NM usuario eliminado de ${ua_dir}"
  done

  # Eliminar certificados de sistema instalados por AutoFirma
  rm -f "/usr/local/share/ca-certificates/autofirma-dipgra-fnmt-accomp.crt" 2>/dev/null || true
  command -v update-ca-certificates &>/dev/null && update-ca-certificates &>/dev/null || true

  # Eliminar directorio de instalación
  if [[ -d "${PREFIX}" ]]; then
    rm -rf "${PREFIX}"
    ok "Directorio ${PREFIX} eliminado."
  fi

  ok "Desinstalación completa."
}

# ─── COMPILACIÓN ──────────────────────────────────────────────────────────────
build() {
  banner "Compilando AutoFirma Dipgra v${VERSION}"

  # Verificar dependencias de compilación
  local missing=()
  command -v go       &>/dev/null || missing+=("go")
  command -v qmake6   &>/dev/null || command -v qmake &>/dev/null || missing+=("qmake6 o qmake")
  command -v make     &>/dev/null || missing+=("make")
  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Faltan herramientas de compilación: ${missing[*]}"
    error "En Ubuntu/Debian: sudo apt install golang-go qt6-base-dev qt6-quick-dev make"
    exit 1
  fi

  local QMAKE="qmake6"
  command -v qmake6 &>/dev/null || QMAKE="qmake"

  # ── 1. Backend Go ──────────────────────────────────────────────────────────
  info "Compilando backend Go (autofirma-desktop)..."
  (
    cd "${ROOT_DIR}"
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" \
       -o "dist/autofirma-desktop" ./cmd/gui
  )
  ok "Backend Go compilado → dist/autofirma-desktop"

  # ── 2. Native messaging host ───────────────────────────────────────────────
  if [[ -d "${ROOT_DIR}/cmd/host" ]]; then
    info "Compilando native messaging host..."
    (
      cd "${ROOT_DIR}"
      go build -trimpath -ldflags="-s -w" \
         -o "dist/autofirma-host" ./cmd/host 2>/dev/null
    ) && ok "Native host compilado → dist/autofirma-host" || warn "No se encontró cmd/host, se omite."
  fi

  # ── 3. Frontend Qt ────────────────────────────────────────────────────────
  info "Compilando frontend Qt (autofirma-qt)..."
  (
    cd "${ROOT_DIR}/cmd/qt_real"
    # Limpiar build anterior
    [[ -f Makefile ]] && make clean &>/dev/null || true
    "${QMAKE}" qt_real.pro -spec linux-g++ CONFIG+=release &>/dev/null
    make -j"$(nproc)" 2>&1
  )
  cp "${ROOT_DIR}/cmd/qt_real/qt_real" "${ROOT_DIR}/dist/autofirma-qt"
  ok "Frontend Qt compilado → dist/autofirma-qt"

  # ── 4. Copiar QML y Assets ────────────────────────────────────────────────
  info "Copiando archivos QML y Assets..."
  mkdir -p "${ROOT_DIR}/dist/qml" "${ROOT_DIR}/dist/assets"
  cp -a "${ROOT_DIR}/cmd/qt_real/qml/." "${ROOT_DIR}/dist/qml/"
  [[ -d "${ROOT_DIR}/assets" ]] && cp -a "${ROOT_DIR}/assets/." "${ROOT_DIR}/dist/assets/" || true
  ok "QML y Assets copiados → dist/"

  # ── 5. Escribir VERSION ───────────────────────────────────────────────────
  echo "${VERSION}" > "${ROOT_DIR}/dist/VERSION"

  ok "\nCompilación completa. Artefactos en dist/"
  ls -lh "${ROOT_DIR}/dist/"
}

# ─── INSTALACIÓN ──────────────────────────────────────────────────────────────
install_app() {
  banner "Instalando AutoFirma Dipgra v${VERSION}"
  need_root

  # Verificar artefactos
  local dist_dir="${ROOT_DIR}/dist"
  if [[ ! -f "${dist_dir}/autofirma-desktop" ]]; then
    error "No se encuentran los binarios compilados en dist/"
    error "Compila primero con: $0  (sin --no-build)"
    exit 1
  fi

  # Detectar versión anterior
  local old_ver
  old_ver="$(get_installed_version)"
  if [[ -n "${old_ver}" ]]; then
    if [[ "${old_ver}" == "${VERSION}" ]]; then
      warn "Ya está instalada la versión ${VERSION}. Reinstalando..."
    else
      info "Actualizando de v${old_ver} → v${VERSION}"
    fi
    stop_processes
    # Limpiar binarios y QML antiguos (conservar configuración de usuario)
    rm -f "${BIN_CORE}" "${BIN_GUI}"
    rm -rf "${QML_DIR}"
    rm -f "${PREFIX}/autofirma-desktop-qt-real" \
          "${PREFIX}/autofirma-desktop-qt-bin" \
          "${PREFIX}/autofirma-desktop-gio" \
          "${PREFIX}/autofirma-desktop-fyne" \
          "${PREFIX}/autofirma-web-compat" 2>/dev/null || true
    ok "Archivos de versión anterior limpiados."
  else
    info "Instalación limpia en ${PREFIX}"
  fi

  # Crear directorio de instalación
  mkdir -p "${PREFIX}" "${ASSETS_DIR}"

  # Copiar binarios
  info "Instalando binarios..."
  install -m 0755 "${dist_dir}/autofirma-desktop" "${BIN_CORE}"
  install -m 0755 "${dist_dir}/autofirma-qt"      "${BIN_GUI}"
  if [[ -f "${dist_dir}/autofirma-host" ]]; then
    install -m 0755 "${dist_dir}/autofirma-host" "${HOST_BIN}"
  fi
  ok "Binarios instalados en ${PREFIX}"

  # Copiar QML y Assets
  info "Instalando archivos QML y Assets..."
  mkdir -p "${QML_DIR}" "${ASSETS_DIR}"
  cp -a "${dist_dir}/qml/." "${QML_DIR}/"
  [[ -d "${dist_dir}/assets" ]] && cp -a "${dist_dir}/assets/." "${ASSETS_DIR}/" || true
  ok "QML y Assets instalados en ${PREFIX}"

  # VERSION
  echo "${VERSION}" > "${VERSION_FILE}"

  # Crear wrapper script que lanza la GUI Qt con el core en la misma carpeta
  info "Creando script lanzador..."
  cat > "${PREFIX}/run-autofirma.sh" <<WRAPPER
#!/usr/bin/env bash
# AutoFirma Dipgra — lanzador principal
# El backend se inicia automáticamente desde el frontend Qt.
export AUTOFIRMA_QML_DIR="${QML_DIR}"
exec "${BIN_GUI}" "\$@"
WRAPPER
  chmod +x "${PREFIX}/run-autofirma.sh"

  # Symlinks globales
  info "Creando enlaces simbólicos..."
  mkdir -p /usr/local/bin
  ln -sf "${PREFIX}/run-autofirma.sh" "${SYMLINK_GUI}"
  ln -sf "${BIN_CORE}"                "${SYMLINK_CORE}"
  [[ -f "${HOST_BIN}" ]] && ln -sf "${HOST_BIN}" "/usr/local/bin/autofirma-host"
  # Compatibilidad con nombre antiguo
  ln -sf "${PREFIX}/run-autofirma.sh" "/usr/local/bin/autofirma-dipgra" 2>/dev/null || true
  ok "Comandos disponibles: autofirma-dipgra, autofirma-desktop"

  # Entrada de menú de escritorio
  info "Instalando entrada de escritorio..."
  mkdir -p /usr/local/share/applications
  cat > "${DESKTOP_FILE}" <<DESKTOP
[Desktop Entry]
Version=1.0
Name=AutoFirma Dipgra
Comment=Firma electrónica de documentos
Exec=${SYMLINK_GUI} %u
Icon=autofirma
Terminal=false
Type=Application
Categories=Office;Security;
MimeType=x-scheme-handler/afirma;
StartupNotify=false
DESKTOP
  chmod 0644 "${DESKTOP_FILE}"
  command -v update-desktop-database &>/dev/null && update-desktop-database /usr/local/share/applications 2>/dev/null || true
  command -v xdg-mime &>/dev/null && xdg-mime default "${APP_NAME}.desktop" x-scheme-handler/afirma 2>/dev/null || true
  ok "Entrada de escritorio instalada."

  # Asociación por usuario
  local user_apps="${REAL_HOME}/.local/share/applications"
  local user_mimeapps="${user_apps}/mimeapps.list"
  mkdir -p "${user_apps}"
  cp -f "${DESKTOP_FILE}" "${user_apps}/${APP_NAME}.desktop"
  chown "${REAL_USER}:$(id -gn "${REAL_USER}")" "${user_apps}/${APP_NAME}.desktop" 2>/dev/null || true

  if [[ ! -f "${user_mimeapps}" ]]; then
    printf '[Default Applications]\nx-scheme-handler/afirma=%s.desktop\n' "${APP_NAME}" > "${user_mimeapps}"
  elif ! grep -q "x-scheme-handler/afirma" "${user_mimeapps}"; then
    sed -i "/\[Default Applications\]/a x-scheme-handler/afirma=${APP_NAME}.desktop" "${user_mimeapps}"
  else
    sed -i "s|x-scheme-handler/afirma=.*|x-scheme-handler/afirma=${APP_NAME}.desktop|" "${user_mimeapps}"
  fi
  chown "${REAL_USER}:$(id -gn "${REAL_USER}")" "${user_mimeapps}" 2>/dev/null || true
  ok "Manejador afirma:// registrado para ${REAL_USER}."

  # Native Messaging (si existe autofirma-host)
  if [[ -f "${HOST_BIN}" ]]; then
    _install_native_messaging
  fi

  # Generar certificados TLS locales (best effort)
  info "Generando certificados TLS locales..."
  runuser -u "${REAL_USER}" -- "${BIN_CORE}" --generate-certs 2>/dev/null \
    && ok "Certificados TLS generados." \
    || warn "No se pudieron generar los certificados TLS automáticamente."
  runuser -u "${REAL_USER}" -- "${BIN_CORE}" --install-trust 2>/dev/null \
    && ok "Confianza TLS configurada." \
    || warn "No se pudo configurar la confianza TLS automáticamente."

  banner "✅ AutoFirma Dipgra v${VERSION} instalada correctamente"
  echo  "   Ejecuta:  autofirma-dipgra"
  echo  "   O abre:   AutoFirma Dipgra desde el menú de aplicaciones"
  echo  ""
  echo  "   Para instalar el servicio de usuario (arranque automático):"
  echo  "   Abre la app → Configuración → Instalar servicio"
  echo  ""
}

_install_native_messaging() {
  info "Instalando manifiestos Native Messaging..."
  local ext_id="${AUTOFIRMA_CHROMIUM_EXTENSION_IDS:-}"

  # Auto-detectar extensión instalada en Chrome/Chromium
  if [[ -z "${ext_id}" ]] && [[ -n "${REAL_HOME}" ]]; then
    for base in \
        "${REAL_HOME}/.config/google-chrome" \
        "${REAL_HOME}/.config/chromium" \
        "${REAL_HOME}/.config/BraveSoftware/Brave-Browser"; do
      [[ -d "${base}" ]] || continue
      while IFS= read -r manifest; do
        local id
        id="$(basename "$(dirname "$(dirname "${manifest}")")")"
        if [[ "${id}" =~ ^[a-p]{32}$ ]]; then
          ext_id="${id}"
          break 2
        fi
      done < <(find "${base}" -type f -path '*/Extensions/*/*/manifest.json' 2>/dev/null \
                | xargs grep -l '"nativeMessaging"' 2>/dev/null \
                | xargs grep -li 'autofirma' 2>/dev/null || true)
    done
  fi

  if [[ -z "${ext_id}" ]]; then
    warn "No se detectó ID de extensión Chromium. Skipping Native Messaging Chromium."
    warn "Configura: export AUTOFIRMA_CHROMIUM_EXTENSION_IDS=<id>"
  else
    local chromium_manifest
    chromium_manifest=$(cat <<JSON
{
  "name": "${HOST_NAME}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${HOST_BIN}",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://${ext_id}/"]
}
JSON
)
    for dir in "${CHROMIUM_MANIFEST_DIRS[@]}"; do
      mkdir -p "${dir}"
      echo "${chromium_manifest}" > "${dir}/${HOST_NAME}.json"
    done
    for user_dir in \
        "${REAL_HOME}/.config/google-chrome/NativeMessagingHosts" \
        "${REAL_HOME}/.config/chromium/NativeMessagingHosts" \
        "${REAL_HOME}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"; do
      mkdir -p "${user_dir}"
      echo "${chromium_manifest}" > "${user_dir}/${HOST_NAME}.json"
      chown -R "${REAL_USER}:" "${user_dir}" 2>/dev/null || true
    done
    ok "Manifest Chromium instalado para extensión: ${ext_id}"
  fi

  # Firefox
  local ff_id="${AUTOFIRMA_FIREFOX_EXTENSION_IDS:-}"
  if [[ -z "${ff_id}" ]]; then
    warn "Skipping Native Messaging Firefox. Configura: AUTOFIRMA_FIREFOX_EXTENSION_IDS=<id>"
  else
    local firefox_manifest
    firefox_manifest=$(cat <<JSON
{
  "name": "${HOST_NAME}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${HOST_BIN}",
  "type": "stdio",
  "allowed_extensions": ["${ff_id}"]
}
JSON
)
    for dir in "${FIREFOX_MANIFEST_DIRS[@]}"; do
      mkdir -p "${dir}"
      echo "${firefox_manifest}" > "${dir}/${HOST_NAME}.json"
    done
    local user_ff="${REAL_HOME}/.mozilla/native-messaging-hosts"
    mkdir -p "${user_ff}"
    echo "${firefox_manifest}" > "${user_ff}/${HOST_NAME}.json"
    chown -R "${REAL_USER}:" "${user_ff}" 2>/dev/null || true
    ok "Manifest Firefox instalado."
  fi
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
banner "AutoFirma Dipgra v${VERSION} — Instalador Linux"

if [[ "${DO_UNINSTALL}" -eq 1 ]]; then
  uninstall
  exit 0
fi

mkdir -p "${ROOT_DIR}/dist"

if [[ "${DO_BUILD}" -eq 1 ]]; then
  build
fi

if [[ "${DO_INSTALL}" -eq 1 ]]; then
  install_app
fi
