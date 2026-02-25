#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

PREFIX="/opt/autofirma-dipgra"
PROFILE="${AUTOFIRMA_INSTALL_PERFIL:-${AUTOFIRMA_INSTALL_PROFILE:-${AUTOFIRMA_PERFIL:-${AUTOFIRMA_PROFILE:-completo}}}}"
DESKTOP_SUBPROFILE="${AUTOFIRMA_SUBPERFIL_ESCRITORIO:-${AUTOFIRMA_DESKTOP_SUBPROFILE:-fyne}}"

# Compatibilidad retro: primer argumento posicional como prefix.
if [[ $# -gt 0 && "${1}" != --* ]]; then
  PREFIX="${1}"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="${2:-${PREFIX}}"
      shift 2 || true
      ;;
    --perfil|--profile)
      PROFILE="${2:-${PROFILE}}"
      shift 2 || true
      ;;
    --subperfil-escritorio|--subperfil-desktop|--subperfil)
      DESKTOP_SUBPROFILE="${2:-${DESKTOP_SUBPROFILE}}"
      shift 2 || true
      ;;
    -h|--help)
      echo "Uso: $0 [--prefix <ruta>] [--perfil minimo|escritorio|completo] [--subperfil-escritorio fyne|gio|qt]"
      exit 0
      ;;
    *)
      echo "[install] ERROR: opción no soportada: $1" >&2
      echo "[install] Uso: $0 [--prefix <ruta>] [--perfil minimo|escritorio|completo] [--subperfil-escritorio fyne|gio|qt]" >&2
      exit 1
      ;;
  esac
done

PROFILE="$(echo "${PROFILE}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
case "${PROFILE}" in
  min|minimo|minimal) PROFILE="minimo" ;;
  desk|desktop|escritorio) PROFILE="escritorio" ;;
  full|completo) PROFILE="completo" ;;
  *)
    echo "[install] ERROR: perfil inválido: ${PROFILE}" >&2
    echo "[install] perfiles válidos: minimo | escritorio | completo" >&2
    exit 1
    ;;
esac
ENABLE_DESKTOP_PROFILE=0
ENABLE_NATIVE_PROFILE=0
if [[ "${PROFILE}" == "escritorio" || "${PROFILE}" == "completo" ]]; then
  ENABLE_DESKTOP_PROFILE=1
fi
if [[ "${PROFILE}" == "completo" ]]; then
  ENABLE_NATIVE_PROFILE=1
fi
DESKTOP_SUBPROFILE="$(echo "${DESKTOP_SUBPROFILE}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
case "${DESKTOP_SUBPROFILE}" in
  fyne|gio|qt)
    ;;
  *)
    echo "[install] Aviso: subperfil de escritorio inválido (${DESKTOP_SUBPROFILE}), usando fyne."
    DESKTOP_SUBPROFILE="fyne"
    ;;
esac
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/AutofirmaDipgra"
FNMT_ACCOMP_CERT="${SCRIPT_DIR}/certs/fnmt-accomp.crt"
HOST_NAME="${AUTOFIRMA_NATIVE_HOST_NAME:-com.dipgra.autofirma}"
HOST_ALIASES_RAW="${AUTOFIRMA_NATIVE_HOST_ALIASES:-com.autofirma.native}"
CHROMIUM_IDS_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_IDS:-}"
FIREFOX_IDS_RAW="${AUTOFIRMA_FIREFOX_EXTENSION_IDS:-extension@dipgra.es}"
CHROMIUM_UPDATE_URL_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_UPDATE_URL:-}"

USER_NAME="${SUDO_USER:-}"
USER_HOME=""
if [[ -n "${USER_NAME}" ]]; then
  USER_HOME="$(getent passwd "${USER_NAME}" | cut -d: -f6 || true)"
fi

copy_java_compat_certs_to_prefix() {
  local certs_dir=""
  if [[ -n "${USER_HOME}" ]]; then
    certs_dir="${USER_HOME}/.config/AutofirmaDipgra/certs"
  else
    certs_dir="${HOME}/.config/AutofirmaDipgra/certs"
  fi
  local files=("autofirma.pfx" "Autofirma_ROOT.cer" "autofirma.cer")
  local f
  for f in "${files[@]}"; do
    if [[ -f "${certs_dir}/${f}" ]]; then
      cp -f "${certs_dir}/${f}" "${PREFIX}/${f}" || true
    fi
  done
}

install_fnmt_accomp_system_ca() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "[install] Aviso: se omite instalación de CA FNMT ACCOMP en sistema (requiere root)."
    return 0
  fi
  if [[ ! -f "${FNMT_ACCOMP_CERT}" ]]; then
    echo "[install] Aviso: no se encontró certificado FNMT ACCOMP en payload (${FNMT_ACCOMP_CERT})."
    return 0
  fi
  if ! openssl x509 -in "${FNMT_ACCOMP_CERT}" -noout >/dev/null 2>&1; then
    echo "[install] Aviso: certificado FNMT ACCOMP inválido, se omite instalación."
    return 0
  fi

  local target="/usr/local/share/ca-certificates/autofirma-dipgra-fnmt-accomp.crt"
  cp -f "${FNMT_ACCOMP_CERT}" "${target}"
  chmod 0644 "${target}"
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates >/dev/null 2>&1 || true
    echo "[install] CA FNMT ACCOMP instalada/actualizada en trust del sistema."
  elif command -v update-ca-trust >/dev/null 2>&1; then
    local rhel_target="/etc/pki/ca-trust/source/anchors/autofirma-dipgra-fnmt-accomp.crt"
    cp -f "${FNMT_ACCOMP_CERT}" "${rhel_target}"
    chmod 0644 "${rhel_target}"
    update-ca-trust >/dev/null 2>&1 || true
    echo "[install] CA FNMT ACCOMP instalada/actualizada en trust del sistema (update-ca-trust)."
  else
    echo "[install] Aviso: no se encontró update-ca-certificates/update-ca-trust para registrar FNMT ACCOMP."
  fi
}

install_system_dependencies() {
  if [[ "$(id -u)" -ne 0 ]]; then
    return 0
  fi

  echo "[install] Verificando e instalando dependencias del sistema..."

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    apt-get install -y -qq poppler-utils libnss3-tools || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q poppler-utils nss-tools || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q poppler-utils nss-tools || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper install -y poppler-utils mozilla-nss-tools || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm poppler nss || true
  fi
}

stop_running_instances() {
  echo "[install] Checking running Autofirma instances..."
  local patterns=(
    "/opt/autofirma-dipgra/autofirma-desktop"
    "/autofirma-web-compat"
    "/autofirma-desktop --server"
    "/autofirma-desktop afirma://websocket"
  )
  local found=0
  local pat pid_list
  for pat in "${patterns[@]}"; do
    pid_list="$(pgrep -f "${pat}" 2>/dev/null || true)"
    if [[ -n "${pid_list}" ]]; then
      found=1
      echo "[install] Stopping processes matching: ${pat}"
      while IFS= read -r pid; do
        [[ -n "${pid}" ]] || continue
        kill -TERM "${pid}" 2>/dev/null || true
      done <<< "${pid_list}"
    fi
  done
  if [[ "${found}" -eq 1 ]]; then
    sleep 1
    for pat in "${patterns[@]}"; do
      pid_list="$(pgrep -f "${pat}" 2>/dev/null || true)"
      if [[ -n "${pid_list}" ]]; then
        while IFS= read -r pid; do
          [[ -n "${pid}" ]] || continue
          kill -KILL "${pid}" 2>/dev/null || true
        done <<< "${pid_list}"
      fi
    done
  fi
}

append_unique() {
  local val="$1"
  shift || true
  local item
  for item in "$@"; do
    if [[ "${item}" == "${val}" ]]; then
      return 1
    fi
  done
  return 0
}

split_ids() {
  local raw="$1"
  raw="${raw//,/ }"
  for token in ${raw}; do
    token="$(echo "${token}" | tr -d '[:space:]')"
    [[ -n "${token}" ]] && printf '%s\n' "${token}"
  done
}

json_array() {
  printf '['
  local first=1
  local item esc
  for item in "$@"; do
    [[ -n "${item}" ]] || continue
    esc="${item//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    if [[ "${first}" -eq 0 ]]; then
      printf ','
    fi
    printf '"%s"' "${esc}"
    first=0
  done
  printf ']'
}

detect_chromium_extension_ids() {
  local home="$1"
  [[ -n "${home}" ]] || return 0

  local bases=(
    "${home}/.config/google-chrome"
    "${home}/.config/chromium"
    "${home}/.config/BraveSoftware/Brave-Browser"
    "${home}/.config/microsoft-edge"
  )
  local base manifest ext_id
  for base in "${bases[@]}"; do
    [[ -d "${base}" ]] || continue
    while IFS= read -r manifest; do
      if grep -qi '"nativeMessaging"' "${manifest}" && grep -qi 'autofirma' "${manifest}"; then
        ext_id="$(basename "$(dirname "$(dirname "${manifest}")")")"
        if [[ "${ext_id}" =~ ^[a-p]{32}$ ]]; then
          printf '%s\n' "${ext_id}"
        fi
      fi
    done < <(find "${base}" -type f -path '*/Extensions/*/*/manifest.json' 2>/dev/null)
  done
}

detect_firefox_extension_ids() {
  local home="$1"
  [[ -n "${home}" ]] || return 0
  local profiles_dir="${home}/.mozilla/firefox"
  [[ -d "${profiles_dir}" ]] || return 0

  local ext_json
  for ext_json in "${profiles_dir}"/*/extensions.json; do
    [[ -f "${ext_json}" ]] || continue
    if command -v jq >/dev/null 2>&1; then
      jq -r '.addons[]? | select((.defaultLocale.name // "" | ascii_downcase | contains("autofirma"))) | .id // empty' "${ext_json}" 2>/dev/null || true
    else
      grep -ioE '"id":"[^"]*autofirma[^"]*"' "${ext_json}" 2>/dev/null | sed -E 's/^"id":"([^"]*)"$/\1/' || true
    fi
  done
}

write_native_manifest() {
  local target="$1"
  local payload="$2"
  mkdir -p "$(dirname "${target}")"
  printf '%s\n' "${payload}" > "${target}"
}

install_browser_extensions_linux() {
  local ext_root="${PREFIX}/extensiones"
  local firefox_xpi="${ext_root}/dipgra-extension-firefox.xpi"
  local firefox_zip="${ext_root}/dipgra-extension-firefox.zip"
  local firefox_dir="${ext_root}/firefox"
  local firefox_id="extension@dipgra.es"

  if [[ -f "${firefox_xpi}" ]]; then
    :
  elif [[ -f "${firefox_zip}" ]]; then
    cp -f "${firefox_zip}" "${firefox_xpi}" || true
  elif [[ -d "${firefox_dir}" ]] && command -v zip >/dev/null 2>&1; then
    (
      cd "${ext_root}"
      rm -f "${firefox_xpi}" "${firefox_zip}"
      zip -qr "${firefox_zip}" firefox
      cp -f "${firefox_zip}" "${firefox_xpi}"
    ) || true
  fi

  if [[ -f "${firefox_xpi}" ]]; then
    declare -a ff_system_dirs=(
      "/usr/lib/firefox/distribution/extensions"
      "/usr/lib64/firefox/distribution/extensions"
      "/usr/lib/firefox-esr/distribution/extensions"
      "/usr/lib64/firefox-esr/distribution/extensions"
    )
    local ff_dir
    for ff_dir in "${ff_system_dirs[@]}"; do
      if [[ -d "${ff_dir%/extensions}" || "${ff_dir}" == "/usr/lib/firefox/distribution/extensions" || "${ff_dir}" == "/usr/lib/firefox-esr/distribution/extensions" ]]; then
        mkdir -p "${ff_dir}" 2>/dev/null || true
        cp -f "${firefox_xpi}" "${ff_dir}/${firefox_id}.xpi" 2>/dev/null || true
      fi
    done

    if [[ -n "${USER_HOME}" && -d "${USER_HOME}/.mozilla/firefox" ]]; then
      local prof
      for prof in "${USER_HOME}"/.mozilla/firefox/*; do
        [[ -d "${prof}" ]] || continue
        mkdir -p "${prof}/extensions" 2>/dev/null || true
        cp -f "${firefox_xpi}" "${prof}/extensions/${firefox_id}.xpi" 2>/dev/null || true
        chown "${USER_NAME}:${USER_NAME}" "${prof}/extensions/${firefox_id}.xpi" 2>/dev/null || true
      done
    fi
    echo "[install] Extensión Firefox instalada (ID ${firefox_id})."
  else
    echo "[install] Aviso: no se encontró paquete XPI de Firefox en ${ext_root}."
  fi

  local chromium_update_url
  chromium_update_url="$(echo "${CHROMIUM_UPDATE_URL_RAW}" | tr -d '[:space:]')"
  declare -a chromium_policy_ids=()
  local cid
  while IFS= read -r cid; do
    [[ -n "${cid}" ]] || continue
    if append_unique "${cid}" "${chromium_policy_ids[@]}"; then
      chromium_policy_ids+=("${cid}")
    fi
  done < <(split_ids "${CHROMIUM_IDS_RAW}")

  if [[ -n "${USER_HOME}" ]]; then
    while IFS= read -r cid; do
      [[ -n "${cid}" ]] || continue
      if append_unique "${cid}" "${chromium_policy_ids[@]}"; then
        chromium_policy_ids+=("${cid}")
      fi
    done < <(detect_chromium_extension_ids "${USER_HOME}")
  fi

  if [[ "${#chromium_policy_ids[@]}" -gt 0 && -n "${chromium_update_url}" ]]; then
    local forcelist_json="["
    local first=1
    for cid in "${chromium_policy_ids[@]}"; do
      if [[ "${first}" -eq 0 ]]; then
        forcelist_json+=","
      fi
      forcelist_json+="\"${cid};${chromium_update_url}\""
      first=0
    done
    forcelist_json+="]"
    local policy_payload
    policy_payload="$(cat <<JSON
{
  "ExtensionInstallForcelist": ${forcelist_json}
}
JSON
)"

    declare -a chromium_policy_dirs=(
      "/etc/opt/chrome/policies/managed"
      "/etc/chromium/policies/managed"
      "/etc/opt/edge/policies/managed"
      "/etc/brave/policies/managed"
      "/etc/opt/brave.com/brave/policies/managed"
    )
    local pdir
    for pdir in "${chromium_policy_dirs[@]}"; do
      mkdir -p "${pdir}" 2>/dev/null || true
      printf '%s\n' "${policy_payload}" > "${pdir}/autofirma-dipgra-extension.json" 2>/dev/null || true
    done
    echo "[install] Política Chromium/Edge/Brave instalada para extensión (force install)."
  elif [[ "${#chromium_policy_ids[@]}" -gt 0 ]]; then
    echo "[install] Aviso: faltó AUTOFIRMA_CHROMIUM_EXTENSION_UPDATE_URL; no se pudo forzar instalación automática en Chromium/Edge/Brave."
    echo "[install] La extensión Chromium queda en: ${ext_root}/chromium"
  else
    echo "[install] Aviso: no se detectaron IDs Chromium para instalación automática de extensión."
  fi
}

if [[ ! -d "${APP_SRC}" ]]; then
  echo "ERROR: payload not found at ${APP_SRC}" >&2
  exit 1
fi

stop_running_instances
install_system_dependencies

echo "[install] Installing into ${PREFIX} (perfil=${PROFILE})"
mkdir -p "${PREFIX}"
cp -a "${APP_SRC}/." "${PREFIX}/"
chmod +x "${PREFIX}/autofirma-desktop"
if [[ -f "${PREFIX}/autofirma-host" ]]; then
  chmod +x "${PREFIX}/autofirma-host"
fi
if [[ "${ENABLE_NATIVE_PROFILE}" -eq 1 ]]; then
  install_browser_extensions_linux
fi

# Copiar certificados de raíces públicas si existen
if [[ -d "${SCRIPT_DIR}/certs/public_roots" ]]; then
  mkdir -p "${PREFIX}/certs/public_roots"
  cp -rf "${SCRIPT_DIR}/certs/public_roots/." "${PREFIX}/certs/public_roots/"
  echo "[install] Certificados de raíces públicas copiados a ${PREFIX}/certs/public_roots"
  # Si somos root, intentamos instalarlos de oficio
  if [[ "$(id -u)" -eq 0 && -x "${PREFIX}/autofirma" ]]; then
    echo "[install] Instalando raíces de confianza de oficio..."
    "${PREFIX}/autofirma" --install-public-roots || true
  fi
fi

if [[ "${ENABLE_DESKTOP_PROFILE}" -eq 1 ]]; then
  # Generate local certificates for the installing user (best effort).
  if [[ -n "${USER_NAME}" ]] && command -v runuser >/dev/null 2>&1; then
    target_user_certs_dir="${USER_HOME:-${HOME}}/.config/AutofirmaDipgra/certs"
    runuser -u "${USER_NAME}" -- "${PREFIX}/autofirma-desktop" --generate-certs >/dev/null 2>&1 || true
    runuser -u "${USER_NAME}" -- env AUTOFIRMA_TRUST_SKIP_SYSTEM=1 "${PREFIX}/autofirma-desktop" --install-trust >/dev/null 2>&1 || true
    runuser -u "${USER_NAME}" -- "${PREFIX}/autofirma-desktop" --exportar-certs-java "${target_user_certs_dir}" >/dev/null 2>&1 || true
  else
    "${PREFIX}/autofirma-desktop" --generate-certs >/dev/null 2>&1 || true
    env AUTOFIRMA_TRUST_SKIP_SYSTEM=1 "${PREFIX}/autofirma-desktop" --install-trust >/dev/null 2>&1 || true
    "${PREFIX}/autofirma-desktop" --exportar-certs-java "${HOME}/.config/AutofirmaDipgra/certs" >/dev/null 2>&1 || true
  fi
  copy_java_compat_certs_to_prefix

  # System-wide trust (best effort, needs root)
  if [[ "$(id -u)" -eq 0 ]]; then
    env AUTOFIRMA_TRUST_SKIP_NSS=1 "${PREFIX}/autofirma-desktop" --install-trust >/dev/null 2>&1 || true
    install_fnmt_accomp_system_ca
  fi
else
  echo "[install] Perfil ${PROFILE}: se omite bootstrap de confianza/certificados de escritorio."
fi

mkdir -p /usr/local/bin

if [[ "${ENABLE_DESKTOP_PROFILE}" -eq 1 ]]; then
  # Evita sobrescribir el binario real si existían symlinks legacy
  # (p.ej. /usr/local/bin/autofirma-dipgra -> /opt/.../autofirma-desktop).
  rm -f /usr/local/bin/autofirma-dipgra /usr/local/bin/autofirma-dipgra-fyne /usr/local/bin/autofirma-dipgra-gio /usr/local/bin/autofirma-dipgra-qt /usr/local/bin/autofirma-dipgra-server

  if [[ "${DESKTOP_SUBPROFILE}" == "qt" && ! -x "${PREFIX}/autofirma-desktop-qt-bin" ]]; then
    echo "[install] Aviso: subperfil qt solicitado pero no se encontró ${PREFIX}/autofirma-desktop-qt-bin; se usará fyne."
    DESKTOP_SUBPROFILE="fyne"
  fi

  qt_env_base=""
  if [[ -d "${PREFIX}/qt-runtime" ]]; then
    qt_env_base="AUTOFIRMA_QT_RUNTIME_DIR=${PREFIX}/qt-runtime "
  fi
  qt_fallback_env=""
  if [[ ! -x "${PREFIX}/autofirma-desktop-qt-real" ]]; then
    qt_fallback_env="AUTOFIRMA_QT_FALLBACK_FYNE=1 "
  fi

  for frontend in fyne gio qt; do
    if [[ "${frontend}" == "qt" ]]; then
      cat > "/usr/local/bin/autofirma-dipgra-${frontend}" <<WRAP
#!/usr/bin/env bash
exec env ${qt_env_base}${qt_fallback_env}"${PREFIX}/autofirma-desktop" -frontend "${frontend}" "\$@"
WRAP
    else
      cat > "/usr/local/bin/autofirma-dipgra-${frontend}" <<WRAP
#!/usr/bin/env bash
exec "${PREFIX}/autofirma-desktop" -frontend "${frontend}" "\$@"
WRAP
    fi
    chmod 0755 "/usr/local/bin/autofirma-dipgra-${frontend}"
  done

  if [[ "${DESKTOP_SUBPROFILE}" == "qt" ]]; then
    cat > /usr/local/bin/autofirma-dipgra <<WRAP
#!/usr/bin/env bash
exec env ${qt_env_base}${qt_fallback_env}"${PREFIX}/autofirma-desktop" -frontend "${DESKTOP_SUBPROFILE}" "\$@"
WRAP
  else
    cat > /usr/local/bin/autofirma-dipgra <<WRAP
#!/usr/bin/env bash
exec "${PREFIX}/autofirma-desktop" -frontend "${DESKTOP_SUBPROFILE}" "\$@"
WRAP
  fi
  chmod 0755 /usr/local/bin/autofirma-dipgra

  cat > /usr/local/bin/autofirma-dipgra-server <<WRAP
#!/usr/bin/env bash
exec "${PREFIX}/autofirma-desktop" --server "\$@"
WRAP
  chmod 0755 /usr/local/bin/autofirma-dipgra-server
else
  ln -sf "${PREFIX}/autofirma-desktop" /usr/local/bin/autofirma-dipgra
  cat > /usr/local/bin/autofirma-dipgra-server <<WRAP
#!/usr/bin/env bash
exec "${PREFIX}/autofirma-desktop" --server "\$@"
WRAP
  chmod 0755 /usr/local/bin/autofirma-dipgra-server
fi

if [[ -f "${PREFIX}/autofirma-host" ]]; then
  ln -sf "${PREFIX}/autofirma-host" /usr/local/bin/autofirma-host
fi

if [[ "${ENABLE_DESKTOP_PROFILE}" -eq 1 ]]; then
mkdir -p /usr/local/share/applications
cat > /usr/local/share/applications/autofirma-dipgra.desktop <<DESKTOP
[Desktop Entry]
Name=Autofirma Dipgra
Comment=Firma electronica de documentos
Exec=/usr/local/bin/autofirma-dipgra %u
Terminal=false
Type=Application
Categories=Office;Security;
MimeType=x-scheme-handler/afirma;
DESKTOP

# Register afirma:// protocol handler in desktop DB if available
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/local/share/applications || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default autofirma-dipgra.desktop x-scheme-handler/afirma || true
fi
if command -v xdg-settings >/dev/null 2>&1; then
  xdg-settings set default-url-scheme-handler afirma autofirma-dipgra.desktop || true
fi

# Persist per-user association when installer is run with sudo.
if [[ -n "${USER_NAME}" ]]; then
  if [[ -n "${USER_HOME}" ]]; then
    USER_APPS_DIR="${USER_HOME}/.local/share/applications"
    USER_MIMEAPPS="${USER_APPS_DIR}/mimeapps.list"
    USER_DESKTOP_DIR="${USER_HOME}/Desktop"
    USER_DESKTOP_ENTRY="${USER_APPS_DIR}/autofirma-dipgra.desktop"
    USER_DESKTOP_SHORTCUT="${USER_DESKTOP_DIR}/autofirma-dipgra.desktop"
    mkdir -p "${USER_APPS_DIR}"
    mkdir -p "${USER_DESKTOP_DIR}"

    cp -f /usr/local/share/applications/autofirma-dipgra.desktop "${USER_DESKTOP_ENTRY}" || true
    chmod 0644 "${USER_DESKTOP_ENTRY}" || true

    cp -f "${USER_DESKTOP_ENTRY}" "${USER_DESKTOP_SHORTCUT}" || true
    chmod +x "${USER_DESKTOP_SHORTCUT}" || true

    if [[ ! -f "${USER_MIMEAPPS}" ]]; then
      cat > "${USER_MIMEAPPS}" <<MIMEAPPS
[Default Applications]
x-scheme-handler/afirma=autofirma-dipgra.desktop
MIMEAPPS
    elif ! grep -q '^x-scheme-handler/afirma=' "${USER_MIMEAPPS}"; then
      awk '
        BEGIN { done=0 }
        /^\[Default Applications\]$/ { print; print "x-scheme-handler/afirma=autofirma-dipgra.desktop"; done=1; next }
        { print }
        END {
          if (done==0) {
            print "[Default Applications]"
            print "x-scheme-handler/afirma=autofirma-dipgra.desktop"
          }
        }
      ' "${USER_MIMEAPPS}" > "${USER_MIMEAPPS}.tmp" && mv "${USER_MIMEAPPS}.tmp" "${USER_MIMEAPPS}"
    else
      sed -i 's#^x-scheme-handler/afirma=.*#x-scheme-handler/afirma=autofirma-dipgra.desktop#' "${USER_MIMEAPPS}"
    fi
    chown "${USER_NAME}:${USER_NAME}" "${USER_MIMEAPPS}" || true
    chown "${USER_NAME}:${USER_NAME}" "${USER_DESKTOP_ENTRY}" || true
    chown "${USER_NAME}:${USER_NAME}" "${USER_DESKTOP_SHORTCUT}" || true
  fi
fi
else
  echo "[install] Perfil ${PROFILE}: sin integración de menú ni handler afirma://."
fi

# Native Messaging manifests for Chromium/Firefox.
if [[ "${ENABLE_NATIVE_PROFILE}" -ne 1 ]]; then
  echo "[install] Perfil ${PROFILE}: se omite registro Native Messaging."
elif [[ ! -x "${PREFIX}/autofirma-host" ]]; then
  echo "[install] Warning: autofirma-host not found in ${PREFIX}. Native Messaging will not be installed."
else
  declare -a host_manifest_names=("${HOST_NAME}")
  while IFS= read -r alias_name; do
    [[ -n "${alias_name}" ]] || continue
    if append_unique "${alias_name}" "${host_manifest_names[@]}"; then
      host_manifest_names+=("${alias_name}")
    fi
  done < <(split_ids "${HOST_ALIASES_RAW}")

  declare -a chromium_ids=()
  declare -a firefox_ids=()

  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    if append_unique "${id}" "${chromium_ids[@]}"; then
      chromium_ids+=("${id}")
    fi
  done < <(split_ids "${CHROMIUM_IDS_RAW}")

  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    if append_unique "${id}" "${firefox_ids[@]}"; then
      firefox_ids+=("${id}")
    fi
  done < <(split_ids "${FIREFOX_IDS_RAW}")

  if [[ -n "${USER_HOME}" ]]; then
    while IFS= read -r id; do
      [[ -n "${id}" ]] || continue
      if append_unique "${id}" "${chromium_ids[@]}"; then
        chromium_ids+=("${id}")
      fi
    done < <(detect_chromium_extension_ids "${USER_HOME}")

    while IFS= read -r id; do
      [[ -n "${id}" ]] || continue
      if append_unique "${id}" "${firefox_ids[@]}"; then
        firefox_ids+=("${id}")
      fi
    done < <(detect_firefox_extension_ids "${USER_HOME}")
  fi

  declare -a chromium_origins=()
  for id in "${chromium_ids[@]}"; do
    chromium_origins+=("chrome-extension://${id}/")
  done

  chromium_array="$(json_array "${chromium_origins[@]}")"
  firefox_array="$(json_array "${firefox_ids[@]}")"
  chromium_ids_array="$(json_array "${chromium_ids[@]}")"
  firefox_ids_array="$(json_array "${firefox_ids[@]}")"

  # Allowlist local para endurecer validación de caller en autofirma-host.
  allow_require="false"
  if [[ "${#chromium_ids[@]}" -gt 0 || "${#firefox_ids[@]}" -gt 0 ]]; then
    allow_require="true"
  fi
  cat > "${PREFIX}/native_messaging_allowlist.json" <<JSON
{
  "chromium_ids": ${chromium_ids_array},
  "firefox_ids": ${firefox_ids_array},
  "require_match": ${allow_require}
}
JSON
  chmod 0644 "${PREFIX}/native_messaging_allowlist.json"

  if [[ "${#chromium_origins[@]}" -gt 0 ]]; then
    declare -a chromium_manifest_dirs=(
      "/etc/opt/chrome/native-messaging-hosts"
      "/etc/chromium/native-messaging-hosts"
      "/etc/opt/edge/native-messaging-hosts"
      "/etc/opt/brave.com/brave/native-messaging-hosts"
    )
    for dir in "${chromium_manifest_dirs[@]}"; do
      for manifest_name in "${host_manifest_names[@]}"; do
        chromium_manifest="$(cat <<JSON
{
  "name": "${manifest_name}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${PREFIX}/autofirma-host",
  "type": "stdio",
  "allowed_origins": ${chromium_array}
}
JSON
)"
        write_native_manifest "${dir}/${manifest_name}.json" "${chromium_manifest}"
      done
    done

    if [[ -n "${USER_HOME}" ]]; then
      declare -a user_chromium_dirs=(
        "${USER_HOME}/.config/google-chrome/NativeMessagingHosts"
        "${USER_HOME}/.config/chromium/NativeMessagingHosts"
        "${USER_HOME}/.config/microsoft-edge/NativeMessagingHosts"
        "${USER_HOME}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
      )
      for dir in "${user_chromium_dirs[@]}"; do
        for manifest_name in "${host_manifest_names[@]}"; do
          chromium_manifest="$(cat <<JSON
{
  "name": "${manifest_name}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${PREFIX}/autofirma-host",
  "type": "stdio",
  "allowed_origins": ${chromium_array}
}
JSON
)"
          write_native_manifest "${dir}/${manifest_name}.json" "${chromium_manifest}"
          chown "${USER_NAME}:${USER_NAME}" "${dir}/${manifest_name}.json" 2>/dev/null || true
        done
      done
    fi
  else
    echo "[install] Warning: no Chromium extension IDs detected for Native Messaging."
    echo "[install] Set AUTOFIRMA_CHROMIUM_EXTENSION_IDS=id1,id2 to force registration."
  fi

  if [[ "${#firefox_ids[@]}" -gt 0 ]]; then
    declare -a firefox_manifest_dirs=(
      "/usr/lib/mozilla/native-messaging-hosts"
      "/usr/lib64/mozilla/native-messaging-hosts"
      "/etc/firefox/native-messaging-hosts"
    )
    for dir in "${firefox_manifest_dirs[@]}"; do
      for manifest_name in "${host_manifest_names[@]}"; do
        firefox_manifest="$(cat <<JSON
{
  "name": "${manifest_name}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${PREFIX}/autofirma-host",
  "type": "stdio",
  "allowed_extensions": ${firefox_array}
}
JSON
)"
        write_native_manifest "${dir}/${manifest_name}.json" "${firefox_manifest}"
      done
    done

    if [[ -n "${USER_HOME}" ]]; then
      user_firefox_dir="${USER_HOME}/.mozilla/native-messaging-hosts"
      for manifest_name in "${host_manifest_names[@]}"; do
        firefox_manifest="$(cat <<JSON
{
  "name": "${manifest_name}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${PREFIX}/autofirma-host",
  "type": "stdio",
  "allowed_extensions": ${firefox_array}
}
JSON
)"
        write_native_manifest "${user_firefox_dir}/${manifest_name}.json" "${firefox_manifest}"
        chown "${USER_NAME}:${USER_NAME}" "${user_firefox_dir}/${manifest_name}.json" 2>/dev/null || true
      done
    fi
  else
    echo "[install] Warning: no Firefox extension IDs detected for Native Messaging."
    echo "[install] Set AUTOFIRMA_FIREFOX_EXTENSION_IDS=id1,id2 to force registration."
  fi
fi

echo "[install] Done (perfil=${PROFILE})"
echo "[install] Binary: ${PREFIX}/autofirma-desktop"
echo "[install] Command: autofirma-dipgra"
if [[ "${ENABLE_DESKTOP_PROFILE}" -eq 1 ]]; then
  echo "[install] Integración de escritorio: habilitada"
  echo "[install] Subperfil escritorio por defecto: ${DESKTOP_SUBPROFILE}"
  echo "[install] Lanzadores: autofirma-dipgra-fyne | autofirma-dipgra-gio | autofirma-dipgra-qt | autofirma-dipgra-server"
else
  echo "[install] Integración de escritorio: omitida"
  echo "[install] Lanzador servidor: autofirma-dipgra-server"
fi
if [[ -x "${PREFIX}/autofirma-host" ]]; then
  echo "[install] Native host: ${PREFIX}/autofirma-host"
  echo "[install] Native host command: autofirma-host"
  if [[ -f "${PREFIX}/native_messaging_allowlist.json" ]]; then
    echo "[install] Allowlist Native Messaging: ${PREFIX}/native_messaging_allowlist.json"
  fi
  if [[ "${ENABLE_NATIVE_PROFILE}" -eq 1 ]]; then
    echo "[install] Native Messaging: habilitado"
  else
    echo "[install] Native Messaging: omitido"
  fi
fi
