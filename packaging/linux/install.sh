#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

PREFIX="${1:-/opt/autofirma-dipgra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/AutofirmaDipgra"
FNMT_ACCOMP_CERT="${SCRIPT_DIR}/certs/fnmt-accomp.crt"
HOST_NAME="${AUTOFIRMA_NATIVE_HOST_NAME:-com.autofirma.native}"
CHROMIUM_IDS_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_IDS:-}"
FIREFOX_IDS_RAW="${AUTOFIRMA_FIREFOX_EXTENSION_IDS:-}"

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

if [[ ! -d "${APP_SRC}" ]]; then
  echo "ERROR: payload not found at ${APP_SRC}" >&2
  exit 1
fi

stop_running_instances

echo "[install] Installing into ${PREFIX}"
mkdir -p "${PREFIX}"
cp -a "${APP_SRC}/." "${PREFIX}/"
chmod +x "${PREFIX}/autofirma-desktop"
if [[ -f "${PREFIX}/autofirma-host" ]]; then
  chmod +x "${PREFIX}/autofirma-host"
fi

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

mkdir -p /usr/local/bin
ln -sf "${PREFIX}/autofirma-desktop" /usr/local/bin/autofirma-dipgra
if [[ -f "${PREFIX}/autofirma-host" ]]; then
  ln -sf "${PREFIX}/autofirma-host" /usr/local/bin/autofirma-host
fi

mkdir -p /usr/local/share/applications
cat > /usr/local/share/applications/autofirma-dipgra.desktop <<DESKTOP
[Desktop Entry]
Name=Autofirma Dipgra
Comment=Firma electronica de documentos
Exec=${PREFIX}/autofirma-desktop %u
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

# Native Messaging manifests for Chromium/Firefox.
if [[ ! -x "${PREFIX}/autofirma-host" ]]; then
  echo "[install] Warning: autofirma-host not found in ${PREFIX}. Native Messaging will not be installed."
else
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

  if [[ "${#chromium_origins[@]}" -gt 0 ]]; then
    chromium_manifest="$(cat <<JSON
{
  "name": "${HOST_NAME}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${PREFIX}/autofirma-host",
  "type": "stdio",
  "allowed_origins": ${chromium_array}
}
JSON
)"

    declare -a chromium_manifest_dirs=(
      "/etc/opt/chrome/native-messaging-hosts"
      "/etc/chromium/native-messaging-hosts"
      "/etc/opt/edge/native-messaging-hosts"
      "/etc/opt/brave.com/brave/native-messaging-hosts"
    )
    for dir in "${chromium_manifest_dirs[@]}"; do
      write_native_manifest "${dir}/${HOST_NAME}.json" "${chromium_manifest}"
    done

    if [[ -n "${USER_HOME}" ]]; then
      declare -a user_chromium_dirs=(
        "${USER_HOME}/.config/google-chrome/NativeMessagingHosts"
        "${USER_HOME}/.config/chromium/NativeMessagingHosts"
        "${USER_HOME}/.config/microsoft-edge/NativeMessagingHosts"
        "${USER_HOME}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
      )
      for dir in "${user_chromium_dirs[@]}"; do
        write_native_manifest "${dir}/${HOST_NAME}.json" "${chromium_manifest}"
        chown "${USER_NAME}:${USER_NAME}" "${dir}/${HOST_NAME}.json" 2>/dev/null || true
      done
    fi
  else
    echo "[install] Warning: no Chromium extension IDs detected for Native Messaging."
    echo "[install] Set AUTOFIRMA_CHROMIUM_EXTENSION_IDS=id1,id2 to force registration."
  fi

  if [[ "${#firefox_ids[@]}" -gt 0 ]]; then
    firefox_manifest="$(cat <<JSON
{
  "name": "${HOST_NAME}",
  "description": "AutoFirma Native Messaging Host",
  "path": "${PREFIX}/autofirma-host",
  "type": "stdio",
  "allowed_extensions": ${firefox_array}
}
JSON
)"

    declare -a firefox_manifest_dirs=(
      "/usr/lib/mozilla/native-messaging-hosts"
      "/usr/lib64/mozilla/native-messaging-hosts"
      "/etc/firefox/native-messaging-hosts"
    )
    for dir in "${firefox_manifest_dirs[@]}"; do
      write_native_manifest "${dir}/${HOST_NAME}.json" "${firefox_manifest}"
    done

    if [[ -n "${USER_HOME}" ]]; then
      user_firefox_dir="${USER_HOME}/.mozilla/native-messaging-hosts"
      write_native_manifest "${user_firefox_dir}/${HOST_NAME}.json" "${firefox_manifest}"
      chown "${USER_NAME}:${USER_NAME}" "${user_firefox_dir}/${HOST_NAME}.json" 2>/dev/null || true
    fi
  else
    echo "[install] Warning: no Firefox extension IDs detected for Native Messaging."
    echo "[install] Set AUTOFIRMA_FIREFOX_EXTENSION_IDS=id1,id2 to force registration."
  fi
fi

echo "[install] Done"
echo "[install] Binary: ${PREFIX}/autofirma-desktop"
echo "[install] Command: autofirma-dipgra"
if [[ -x "${PREFIX}/autofirma-host" ]]; then
  echo "[install] Native host: ${PREFIX}/autofirma-host"
  echo "[install] Native host command: autofirma-host"
fi
