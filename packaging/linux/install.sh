#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

PREFIX="${1:-/opt/autofirma-dipgra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/AutofirmaDipgra"
HOST_NAME="${AUTOFIRMA_NATIVE_HOST_NAME:-com.autofirma.native}"
CHROMIUM_IDS_RAW="${AUTOFIRMA_CHROMIUM_EXTENSION_IDS:-}"
FIREFOX_IDS_RAW="${AUTOFIRMA_FIREFOX_EXTENSION_IDS:-}"

USER_NAME="${SUDO_USER:-}"
USER_HOME=""
if [[ -n "${USER_NAME}" ]]; then
  USER_HOME="$(getent passwd "${USER_NAME}" | cut -d: -f6 || true)"
fi

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

echo "[install] Installing into ${PREFIX}"
mkdir -p "${PREFIX}"
cp -a "${APP_SRC}/." "${PREFIX}/"
chmod +x "${PREFIX}/autofirma-desktop"
if [[ -f "${PREFIX}/autofirma-host" ]]; then
  chmod +x "${PREFIX}/autofirma-host"
fi

# Generate local certificates for the installing user (best effort).
if [[ -n "${USER_NAME}" ]] && command -v runuser >/dev/null 2>&1; then
  runuser -u "${USER_NAME}" -- "${PREFIX}/autofirma-desktop" --generate-certs >/dev/null 2>&1 || true
else
  "${PREFIX}/autofirma-desktop" --generate-certs >/dev/null 2>&1 || true
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
    mkdir -p "${USER_APPS_DIR}"
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
