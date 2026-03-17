#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
echo "BASH_SOURCE: ${BASH_SOURCE[0]}"
echo "SCRIPT_DIR: ${SCRIPT_DIR}"
echo "ROOT_DIR: ${ROOT_DIR}"
echo "Testing: ${ROOT_DIR}/dist/autofirma"
if [[ -f "${ROOT_DIR}/dist/autofirma" ]]; then
  echo "Found it!"
else
  echo "Not found!"
fi
