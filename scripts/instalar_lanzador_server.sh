#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_PATH="${1:-/opt/autofirma-dipgra/autofirma-desktop}"
LAUNCHER_PATH="/usr/local/bin/autofirma-dipgra-server"

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "[ERROR] No existe o no es ejecutable: ${BIN_PATH}" >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

tmp_file="$(mktemp)"
cat > "${tmp_file}" <<EOF
#!/usr/bin/env bash
exec "${BIN_PATH}" --server "\$@"
EOF

${SUDO} install -m 0755 "${tmp_file}" "${LAUNCHER_PATH}"
rm -f "${tmp_file}"

echo "OK: lanzador instalado en ${LAUNCHER_PATH}"
echo "Uso: autofirma-dipgra-server --server-modo ambas --rest-token secreto"
