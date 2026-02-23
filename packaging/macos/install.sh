#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

PREFIX="/Applications/AutofirmaDipgra"
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/AutofirmaDipgra"
FNMT_ACCOMP_CERT="${SCRIPT_DIR}/certs/fnmt-accomp.crt"
CHROMIUM_IDS_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_IDS:-}"
FIREFOX_IDS_RAW="${AUTOFIRMA_FIREFOX_EXTENSION_IDS:-extension@dipgra.es}"
CHROMIUM_UPDATE_URL_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_UPDATE_URL:-}"

if [[ ! -d "${APP_SRC}" ]]; then
  echo "ERROR: payload no encontrado en ${APP_SRC}" >&2
  exit 1
fi

install_fnmt_accomp_system_ca_macos() {
  if [[ ! -f "${FNMT_ACCOMP_CERT}" ]]; then
    echo "[install-mac] Aviso: no se encontró certificado FNMT ACCOMP en payload (${FNMT_ACCOMP_CERT})."
    return 0
  fi
  if ! openssl x509 -in "${FNMT_ACCOMP_CERT}" -noout >/dev/null 2>&1; then
    echo "[install-mac] Aviso: certificado FNMT ACCOMP inválido, se omite instalación."
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "[install-mac] Aviso: se omite instalación de CA FNMT ACCOMP en System.keychain (requiere root)."
    return 0
  fi
  security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain "${FNMT_ACCOMP_CERT}" >/dev/null 2>&1 || true
  echo "[install-mac] CA FNMT ACCOMP instalada/actualizada en System.keychain."
}

json_array_from_csv() {
  local raw="$1"
  local out="["
  local first=1
  local item trimmed escaped
  IFS=',' read -r -a parts <<<"${raw}"
  for item in "${parts[@]:-}"; do
    trimmed="$(echo "${item}" | xargs)"
    [[ -n "${trimmed}" ]] || continue
    escaped="${trimmed//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    if [[ ${first} -eq 0 ]]; then
      out+=", "
    fi
    out+="\"${escaped}\""
    first=0
  done
  out+="]"
  printf '%s' "${out}"
}

install_browser_extensions_macos() {
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
      rm -f "${firefox_zip}" "${firefox_xpi}"
      zip -qr "${firefox_zip}" firefox
      cp -f "${firefox_zip}" "${firefox_xpi}"
    ) || true
  fi

  if [[ -f "${firefox_xpi}" ]]; then
    mkdir -p "/Library/Application Support/Mozilla/Extensions" 2>/dev/null || true
    cp -f "${firefox_xpi}" "/Library/Application Support/Mozilla/Extensions/${firefox_id}.xpi" 2>/dev/null || true

    local uhome
    uhome="${HOME}"
    if [[ -n "${SUDO_USER:-}" ]]; then
      uhome="$(dscl . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "${HOME}")"
    fi
    if [[ -d "${uhome}/Library/Application Support/Firefox/Profiles" ]]; then
      local prof
      for prof in "${uhome}/Library/Application Support/Firefox/Profiles"/*; do
        [[ -d "${prof}" ]] || continue
        mkdir -p "${prof}/extensions" 2>/dev/null || true
        cp -f "${firefox_xpi}" "${prof}/extensions/${firefox_id}.xpi" 2>/dev/null || true
      done
    fi
    echo "[install-mac] Extensión Firefox instalada (ID ${firefox_id})."
  else
    echo "[install-mac] Aviso: no se encontró paquete XPI de Firefox."
  fi

  if [[ -n "${CHROMIUM_UPDATE_URL_RAW}" && -n "${CHROMIUM_IDS_RAW}" ]]; then
    echo "[install-mac] Aviso: política Chromium force-install en macOS requiere perfil MDM."
    echo "[install-mac] IDs configurados: ${CHROMIUM_IDS_RAW}"
    echo "[install-mac] update_url configurada: ${CHROMIUM_UPDATE_URL_RAW}"
  fi
}

echo "[install-mac] Instalando en ${PREFIX} (perfil=${PROFILE})"
mkdir -p "${PREFIX}"
cp -a "${APP_SRC}/." "${PREFIX}/"
chmod +x "${PREFIX}/autofirma-desktop" || true
[[ -f "${PREFIX}/autofirma-host" ]] && chmod +x "${PREFIX}/autofirma-host" || true
if [[ "${ENABLE_NATIVE_PROFILE}" -eq 1 ]]; then
  install_browser_extensions_macos
fi

chromium_ids_json="$(json_array_from_csv "${CHROMIUM_IDS_RAW}")"
firefox_ids_json="$(json_array_from_csv "${FIREFOX_IDS_RAW}")"
allow_require="false"
if [[ "${chromium_ids_json}" != "[]" || "${firefox_ids_json}" != "[]" ]]; then
  allow_require="true"
fi
cat > "${PREFIX}/native_messaging_allowlist.json" <<JSON
{
  "chromium_ids": ${chromium_ids_json},
  "firefox_ids": ${firefox_ids_json},
  "require_match": ${allow_require}
}
JSON
chmod 0644 "${PREFIX}/native_messaging_allowlist.json"

echo "[install-mac] Generando certificados locales..."
"${PREFIX}/autofirma-desktop" --generate-certs || true

echo "[install-mac] Instalando confianza local..."
"${PREFIX}/autofirma-desktop" --install-trust || true
install_fnmt_accomp_system_ca_macos

echo "[install-mac] Exportando certificados compatibles Java en ${PREFIX}..."
"${PREFIX}/autofirma-desktop" --exportar-certs-java "${PREFIX}" || true

echo "[install-mac] Estado de confianza local..."
"${PREFIX}/autofirma-desktop" --trust-status || true

mkdir -p /usr/local/bin

if [[ "${ENABLE_DESKTOP_PROFILE}" -eq 1 ]]; then
  for frontend in fyne gio qt; do
    cat > "/usr/local/bin/autofirma-dipgra-${frontend}" <<WRAP
#!/usr/bin/env bash
exec "${PREFIX}/autofirma-desktop" -frontend "${frontend}" "\$@"
WRAP
    chmod 0755 "/usr/local/bin/autofirma-dipgra-${frontend}"
  done

  cat > /usr/local/bin/autofirma-dipgra <<WRAP
#!/usr/bin/env bash
exec "${PREFIX}/autofirma-desktop" -frontend "${DESKTOP_SUBPROFILE}" "\$@"
WRAP
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

echo "[install-mac] Listo"
echo "[install-mac] Binario: ${PREFIX}/autofirma-desktop"
echo "[install-mac] Comandos: autofirma-dipgra | autofirma-dipgra-server"
echo "[install-mac] Allowlist Native Messaging: ${PREFIX}/native_messaging_allowlist.json"
echo "[install-mac] Certificados Java: ${PREFIX}/autofirma.pfx ${PREFIX}/Autofirma_ROOT.cer ${PREFIX}/autofirma.cer"
