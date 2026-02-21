#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REL_DIR="${ROOT_DIR}/release/linux"
BUNDLE_DIR="${REL_DIR}/bundle/AutofirmaDipgra"
PAYLOAD_DIR="${REL_DIR}/payload"
ARTIFACT_TGZ="${REL_DIR}/AutofirmaDipgra-linux-x64.tar.gz"
ARTIFACT_RUN="${REL_DIR}/AutofirmaDipgra-linux-installer.run"
BIN_PATH="${BUNDLE_DIR}/autofirma-desktop"
HOST_BIN_PATH="${BUNDLE_DIR}/autofirma-host"
QT_BIN_PATH="${BUNDLE_DIR}/autofirma-desktop-qt-bin"
QT_REAL_BUNDLE_PATH="${BUNDLE_DIR}/autofirma-desktop-qt-real"
CHECK_STATIC="${CHECK_STATIC:-1}"
BUILD_SELF_CONTAINED="${BUILD_SELF_CONTAINED:-1}"
QT_REAL_BIN_PATH="${QT_REAL_BIN_PATH:-}"
QT_RUNTIME_DIR="${QT_RUNTIME_DIR:-}"
QT_RUNTIME_FROM_SYSTEM="${QT_RUNTIME_FROM_SYSTEM:-0}"
BUILD_QT_REAL_FROM_SOURCE="${BUILD_QT_REAL_FROM_SOURCE:-1}"

mkdir -p "${REL_DIR}" "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
rm -rf "${BUNDLE_DIR}" "${PAYLOAD_DIR}"
mkdir -p "${BUNDLE_DIR}" "${PAYLOAD_DIR}"

echo "[linux] Building GUI binary..."
if [[ "${BUILD_SELF_CONTAINED}" == "1" ]]; then
  (
    cd "${ROOT_DIR}"
    set +e
    GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w" -o "${BIN_PATH}" ./cmd/gui
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "[linux] Error: no se pudo compilar en modo autocontenido (CGO_ENABLED=0)."
      echo "[linux] Con el GUI actual (Gio), Linux requiere CGO para backend grafico."
      echo "[linux] Acciones posibles:"
      echo "[linux]  1) Migrar GUI a una opcion 100% Go sin CGO en Linux."
      echo "[linux]  2) Build temporal con BUILD_SELF_CONTAINED=0 (acepta dependencias del sistema)."
      exit $rc
    fi
  )
else
  (
    cd "${ROOT_DIR}"
    GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags="-s -w" -o "${BIN_PATH}" ./cmd/gui
  )
fi

chmod +x "${BIN_PATH}"

echo "[linux] Building Qt frontend binary (preparación)..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "${QT_BIN_PATH}" ./cmd/qt
)
chmod +x "${QT_BIN_PATH}"

if [[ -n "${QT_REAL_BIN_PATH}" ]]; then
  if [[ ! -f "${QT_REAL_BIN_PATH}" ]]; then
    echo "[linux] Error: QT_REAL_BIN_PATH no existe: ${QT_REAL_BIN_PATH}" >&2
    exit 1
  fi
  cp -f "${QT_REAL_BIN_PATH}" "${QT_REAL_BUNDLE_PATH}"
  chmod +x "${QT_REAL_BUNDLE_PATH}"
  echo "[linux] Frontend Qt nativo incluido: ${QT_REAL_BIN_PATH}"
elif [[ "${BUILD_QT_REAL_FROM_SOURCE}" == "1" ]]; then
  echo "[linux] Compilando frontend Qt nativo desde fuente..."
  if "${ROOT_DIR}/scripts/build_qt_real_linux.sh" "${QT_REAL_BUNDLE_PATH}"; then
    echo "[linux] Frontend Qt nativo compilado e incluido."
  else
    echo "[linux] Aviso: no se pudo compilar qt-real automáticamente. Se continuará con fallback Qt->Fyne."
    rm -f "${QT_REAL_BUNDLE_PATH}"
  fi
fi

if [[ -n "${QT_RUNTIME_DIR}" ]]; then
  if [[ ! -d "${QT_RUNTIME_DIR}" ]]; then
    echo "[linux] Error: QT_RUNTIME_DIR no existe o no es directorio: ${QT_RUNTIME_DIR}" >&2
    exit 1
  fi
  rm -rf "${BUNDLE_DIR}/qt-runtime"
  mkdir -p "${BUNDLE_DIR}/qt-runtime"
  cp -a "${QT_RUNTIME_DIR}/." "${BUNDLE_DIR}/qt-runtime/"
  echo "[linux] Runtime Qt incluido desde: ${QT_RUNTIME_DIR}"
elif [[ "${QT_RUNTIME_FROM_SYSTEM}" == "1" ]]; then
  echo "[linux] Intentando incluir runtime Qt desde librerías del sistema..."
  rm -rf "${BUNDLE_DIR}/qt-runtime"
  mkdir -p "${BUNDLE_DIR}/qt-runtime/lib" "${BUNDLE_DIR}/qt-runtime/plugins"

  plugin_dir=""
  qml_dir=""
  for c in /usr/lib/*/qt5/plugins /usr/lib/qt5/plugins /usr/lib/*/qt6/plugins /usr/lib/qt6/plugins; do
    if [[ -d "${c}" ]]; then
      plugin_dir="${c}"
      break
    fi
  done
  for c in /usr/lib/*/qt5/qml /usr/lib/qt5/qml /usr/lib/*/qt6/qml /usr/lib/qt6/qml; do
    if [[ -d "${c}" ]]; then
      qml_dir="${c}"
      break
    fi
  done

  if [[ -n "${plugin_dir}" ]]; then
    echo "[linux] Usando plugins desde: ${plugin_dir}"
    # Conjunto más completo de plugins para Linux/X11 + TLS + Image Formats.
    declare -a plugin_groups=("platforms" "tls" "imageformats" "iconengines" "xcbglintegrations")
    for group in "${plugin_groups[@]}"; do
      if [[ -d "${plugin_dir}/${group}" ]]; then
        mkdir -p "${BUNDLE_DIR}/qt-runtime/plugins/${group}"
        cp -af "${plugin_dir}/${group}/." "${BUNDLE_DIR}/qt-runtime/plugins/${group}/"
      fi
    done
  fi

  if [[ -n "${qml_dir}" ]]; then
    echo "[linux] Usando QML desde: ${qml_dir}"
    mkdir -p "${BUNDLE_DIR}/qt-runtime/qml"
    # Copiamos solo los módulos necesarios para optimizar tamaño (QtQuick, QtQuick.Controls, etc)
    declare -a qml_modules=("QtQuick" "QtQuick.2" "QtQuick.Controls" "QtQuick.Controls.2" "QtQuick.Layouts" "QtQuick.Templates.2" "QtQuick.Window.2")
    for mod in "${qml_modules[@]}"; do
      # Convertimos punto a barra (ej. QtQuick.Controls -> QtQuick/Controls)
      mod_path="${mod//.//}"
      if [[ -d "${qml_dir}/${mod_path}" ]]; then
        mkdir -p "$(dirname "${BUNDLE_DIR}/qt-runtime/qml/${mod_path}")"
        cp -af "${qml_dir}/${mod_path}" "${BUNDLE_DIR}/qt-runtime/qml/${mod_path}"
      fi
    done
  fi
        mkdir -p "${BUNDLE_DIR}/qt-runtime/plugins/${rel_dir}"
        cp -f "${plugin_file}" "${BUNDLE_DIR}/qt-runtime/plugins/${rel_dir}/"
      fi
    done
  else
    echo "[linux] Aviso: no se encontró carpeta de plugins Qt6 del sistema."
  fi

  if command -v ldd >/dev/null 2>&1; then
    should_skip_core_lib() {
      case "$(basename "$1")" in
        linux-vdso.so*|ld-linux*.so*|libc.so*|libm.so*|libpthread.so*|librt.so*|libdl.so*|libgcc_s.so*|libstdc++.so*|libresolv.so*|libnsl.so*|libutil.so*)
          return 0
          ;;
        *)
          return 1
          ;;
      esac
    }

    queue_file() {
      [[ -f "$1" ]] && printf '%s\n' "$1" >> "${BUNDLE_DIR}/qt-runtime/.dep_queue"
    }

    : > "${BUNDLE_DIR}/qt-runtime/.dep_queue"
    : > "${BUNDLE_DIR}/qt-runtime/.dep_seen"

    [[ -f "${QT_REAL_BUNDLE_PATH}" ]] && queue_file "${QT_REAL_BUNDLE_PATH}"
    if [[ -n "${plugin_dir}" ]]; then
      find "${BUNDLE_DIR}/qt-runtime/plugins" -type f -name '*.so' -print0 2>/dev/null | while IFS= read -r -d '' p; do
        queue_file "${p}"
      done
    fi

    while IFS= read -r current; do
      [[ -n "${current}" ]] || continue
      if grep -Fxq "${current}" "${BUNDLE_DIR}/qt-runtime/.dep_seen"; then
        continue
      fi
      printf '%s\n' "${current}" >> "${BUNDLE_DIR}/qt-runtime/.dep_seen"

      while IFS= read -r dep; do
        [[ -f "${dep}" ]] || continue
        should_skip_core_lib "${dep}" && continue
        cp -n "${dep}" "${BUNDLE_DIR}/qt-runtime/lib/" 2>/dev/null || true
        if [[ "${dep}" == /usr/lib/* || "${dep}" == /lib/* ]]; then
          queue_file "${dep}"
        fi
      done < <(ldd "${current}" 2>/dev/null | awk '/=> \// {print $3} /^\/[^[:space:]]+[[:space:]]+\(/ {print $1}')
    done < "${BUNDLE_DIR}/qt-runtime/.dep_queue"

    rm -f "${BUNDLE_DIR}/qt-runtime/.dep_queue" "${BUNDLE_DIR}/qt-runtime/.dep_seen"
  else
    echo "[linux] Aviso: ldd no disponible; no se pudo calcular cierre mínimo de dependencias Qt."
  fi

  echo "[linux] Runtime Qt del sistema incluido."
fi

if [[ "${BUILD_SELF_CONTAINED}" == "1" && "${CHECK_STATIC}" == "1" ]]; then
  echo "[linux] Verifying binary is self-contained (no dynamic linker deps)..."

  if command -v readelf >/dev/null 2>&1; then
    if readelf -d "${BIN_PATH}" 2>/dev/null | grep -q '(NEEDED)'; then
      echo "[linux] Error: dynamic shared libraries detected via readelf."
      readelf -d "${BIN_PATH}" | sed 's/^/[linux] readelf: /'
      exit 1
    fi
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd_out="$(ldd "${BIN_PATH}" 2>&1 || true)"
    if ! grep -qiE 'not a dynamic executable|statically linked' <<<"${ldd_out}"; then
      echo "[linux] Error: ldd indicates dynamic dependencies:"
      printf '%s\n' "${ldd_out}" | sed 's/^/[linux] ldd: /'
      exit 1
    fi
  fi
fi

echo "[linux] Building Native Messaging host binary..."
(
  cd "${ROOT_DIR}"
  GOCACHE=/tmp/gocache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "${HOST_BIN_PATH}" ./cmd/autofirma-host
)

chmod +x "${HOST_BIN_PATH}"

cat > "${BUNDLE_DIR}/README.txt" <<README
Autofirma Dipgra Linux

Ejecutable:
  ./autofirma-desktop
Frontend Qt:
  ./autofirma-desktop-qt-bin
Frontend Qt nativo (opcional, si se incluyó):
  ./autofirma-desktop-qt-real
Host nativo:
  ./autofirma-host

Notas de compilacion:
  - Modo autocontenido activo: ${BUILD_SELF_CONTAINED}
  - Build con CGO desactivado solo en modo autocontenido
  - Validacion de binario no dinamico solo en modo autocontenido
  - Qt nativo incluido: $( [[ -n "${QT_REAL_BIN_PATH}" ]] && echo "sí" || echo "no" )
  - Runtime Qt incluido: $( [[ -n "${QT_RUNTIME_DIR}" || "${QT_RUNTIME_FROM_SYSTEM}" == "1" ]] && echo "sí" || echo "no" )
README

# Tarball portable
(
  cd "${REL_DIR}/bundle"
  tar -czf "${ARTIFACT_TGZ}" "AutofirmaDipgra"
)

# Installer payload
mkdir -p "${PAYLOAD_DIR}/AutofirmaDipgra"
cp -a "${BUNDLE_DIR}/." "${PAYLOAD_DIR}/AutofirmaDipgra/"
cp "${ROOT_DIR}/packaging/linux/install.sh" "${PAYLOAD_DIR}/install.sh"
cp -a "${ROOT_DIR}/packaging/linux/certs" "${PAYLOAD_DIR}/certs"
chmod +x "${PAYLOAD_DIR}/install.sh"

(
  cd "${PAYLOAD_DIR}"
  tar -czf payload.tar.gz AutofirmaDipgra install.sh certs
)

cat > "${ARTIFACT_RUN}" <<'HDR'
#!/usr/bin/env bash
set -euo pipefail

PREFIX="/opt/autofirma-dipgra"
PROFILE="${AUTOFIRMA_INSTALL_PERFIL:-${AUTOFIRMA_INSTALL_PROFILE:-completo}}"
SUBPROFILE_DESKTOP="${AUTOFIRMA_SUBPERFIL_ESCRITORIO:-${AUTOFIRMA_DESKTOP_SUBPROFILE:-fyne}}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="${2:-/opt/autofirma-dipgra}"
      shift 2 || true
      ;;
    --perfil|--profile)
      PROFILE="${2:-completo}"
      shift 2 || true
      ;;
    --subperfil-escritorio|--subperfil-desktop|--subperfil)
      SUBPROFILE_DESKTOP="${2:-fyne}"
      shift 2 || true
      ;;
    *)
      echo "Uso: $0 [--prefix <ruta>] [--perfil minimo|escritorio|completo] [--subperfil-escritorio fyne|gio|qt]" >&2
      exit 1
      ;;
  esac
done

SELF="$0"
MARKER="__ARCHIVE_BELOW__"
LINE="$(awk -v m="$MARKER" '$0==m {print NR+1; exit}' "$SELF")"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

tail -n +"$LINE" "$SELF" | tar -xz -C "$TMPDIR"

if [[ "$EUID" -ne 0 ]]; then
  echo "Este instalador necesita permisos de root. Reintentando con sudo..."
  exec sudo "$TMPDIR/install.sh" "$PREFIX" --perfil "$PROFILE" --subperfil-escritorio "$SUBPROFILE_DESKTOP"
else
  exec "$TMPDIR/install.sh" "$PREFIX" --perfil "$PROFILE" --subperfil-escritorio "$SUBPROFILE_DESKTOP"
fi

exit 0
__ARCHIVE_BELOW__
HDR

cat "${PAYLOAD_DIR}/payload.tar.gz" >> "${ARTIFACT_RUN}"
chmod +x "${ARTIFACT_RUN}"

echo "[linux] Done"
echo "[linux] Portable: ${ARTIFACT_TGZ}"
echo "[linux] Installer: ${ARTIFACT_RUN}"

# 5. Optional: Try to register CA in NSS DB (for Chrome/Firefox)
echo "Intentando registrar CA local en navegadores..."
CERTS_DIR="$HOME/.config/AutofirmaDipgra/certs"
if [ -f "$CERTS_DIR/rootCA.crt" ] && command -v certutil >/dev/null 2>&1; then
    certutil -d "sql:$HOME/.pki/nssdb" -A -t "CT,C,C" -n "Autofirma ROOT" -i "$CERTS_DIR/rootCA.crt" 2>/dev/null || true
    echo "CA registrada/intendada en NSS DB (best effort)."
else
    echo "No se pudo registrar la CA automáticamente (falta certutil o no se ha ejecutado la app aun)."
fi

echo "Instalación completada. Ejecuta 'AutoFirma Dipgra' desde tu menú de aplicaciones."
