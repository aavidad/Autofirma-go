#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${ROOT_DIR}/autofirma-host-smoke"
STRICT_FORMATS=0

for arg in "$@"; do
  case "$arg" in
    --strict-formats) STRICT_FORMATS=1 ;;
    *)
      echo "Uso: $0 [--strict-formats]" >&2
      exit 1
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: se requiere 'jq'" >&2
  exit 1
fi

if [[ " ${GOFLAGS:-} " != *" -mod="* ]]; then
  GOFLAGS="${GOFLAGS:-} -mod=readonly"
fi

build_bin() {
  echo "[smoke] compilando binario del host..."
  GOCACHE=/tmp/go-build GOFLAGS="${GOFLAGS}" go build -o "${BIN_PATH}" ./cmd/autofirma-host
}

send_req() {
  local payload="$1"
  local frames_count
  local frames
  frames="$(
    printf '%s' "${payload}" |
      perl -e 'local $/; my $m=<STDIN>; print pack("V", length($m)).$m;' |
      "${BIN_PATH}" |
      perl -e '
        while (read(STDIN, my $l, 4) == 4) {
          my $n = unpack("V", $l);
          read(STDIN, my $b, $n) == $n or die "short frame";
          print $b, "\n";
        }
      '
  )"

  frames_count="$(printf '%s\n' "${frames}" | sed '/^$/d' | wc -l)"
  if [[ "${frames_count}" -le 1 ]]; then
    printf '%s' "${frames}" | head -n 1
    return 0
  fi

  # Reassemble chunked responses (signature split across multiple frames).
  printf '%s\n' "${frames}" | jq -cs '
    sort_by(.chunk) as $arr |
    ($arr[0] + {
      signature: ($arr | map(.signature // "") | join("")),
      totalChunks: ($arr | length),
      chunk: 0
    })
  '
}

run_ping() {
  local resp
  resp="$(send_req '{"requestId":"1","action":"ping"}')"
  echo "[smoke] ping => ${resp}"
  [[ "$(printf '%s' "${resp}" | jq -r '.success')" == "true" ]]
}

run_get_certs() {
  local resp
  resp="$(send_req '{"requestId":"2","action":"getCertificates"}')"
  echo "[smoke] getCertificates => exito=$(printf '%s' "${resp}" | jq -r '.success') total=$(printf '%s' "${resp}" | jq '.certificates | length')" >&2
  [[ "$(printf '%s' "${resp}" | jq -r '.success')" == "true" ]]
  printf '%s' "${resp}" | jq -r '.certificates[0].id // empty'
}

run_sign_verify() {
  local cert_id="$1"
  local sign_req sign_resp sig verify_req verify_resp

  sign_req="$(jq -nc --arg cert_id "${cert_id}" '{requestId:"3",action:"sign",certificateId:$cert_id,data:"SG9sYQ==",format:"cades"}')"
  sign_resp="$(send_req "${sign_req}")"
  echo "[smoke] sign(cades) => success=$(printf '%s' "${sign_resp}" | jq -r '.success') len=$(printf '%s' "${sign_resp}" | jq -r '.signatureLen // 0')"
  [[ "$(printf '%s' "${sign_resp}" | jq -r '.success')" == "true" ]]

  sig="$(printf '%s' "${sign_resp}" | jq -r '.signature // empty')"
  if [[ -z "${sig}" ]]; then
    echo "ERROR: la respuesta de firma no incluye firma" >&2
    exit 1
  fi

  verify_req="$(jq -nc --arg sig "${sig}" '{requestId:"4",action:"verify",format:"cades",originalData:"SG9sYQ==",signatureData:$sig}')"
  verify_resp="$(send_req "${verify_req}")"
  echo "[smoke] verify(cades) => success=$(printf '%s' "${verify_resp}" | jq -r '.success') valid=$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')"
  [[ "$(printf '%s' "${verify_resp}" | jq -r '.success')" == "true" ]]
  [[ "$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')" == "true" ]]
}

run_sign_verify_pades() {
  local cert_id="$1"
  local pdf_file sign_req sign_resp signed_pdf_b64 verify_req verify_resp
  local data_file sig_file
  pdf_file="${ROOT_DIR}/testdata/original.pdf"
  if [[ ! -f "${pdf_file}" ]]; then
    echo "[smoke] pades => OMITIDO (falta ${pdf_file})"
    return 0
  fi

  data_file="$(mktemp)"
  sig_file="$(mktemp)"
  trap 'rm -f "${data_file}" "${sig_file}"' RETURN
  base64 -w 0 "${pdf_file}" > "${data_file}"

  sign_req="$(jq -nc --arg cert_id "${cert_id}" --rawfile data "${data_file}" '{requestId:"5",action:"sign",certificateId:$cert_id,data:$data,format:"pades"}')"
  sign_resp="$(send_req "${sign_req}")"
  echo "[smoke] sign(pades) => success=$(printf '%s' "${sign_resp}" | jq -r '.success') len=$(printf '%s' "${sign_resp}" | jq -r '.signatureLen // 0')"

  if [[ "$(printf '%s' "${sign_resp}" | jq -r '.success')" != "true" ]]; then
    if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
      echo "ERROR: la firma PAdES falló en modo estricto" >&2
      return 1
    fi
    echo "[smoke] pades => AVISO (modo no estricto)"
    return 0
  fi

  signed_pdf_b64="$(printf '%s' "${sign_resp}" | jq -r '.signature // empty')"
  if [[ -z "${signed_pdf_b64}" ]]; then
    if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
      echo "ERROR: la firma PAdES devolvió firma vacía en modo estricto" >&2
      return 1
    fi
    echo "[smoke] pades => AVISO (firma vacía en modo no estricto)"
    return 0
  fi

  printf '%s' "${signed_pdf_b64}" > "${sig_file}"
  verify_req="$(jq -nc --rawfile data "${sig_file}" '{requestId:"6",action:"verify",format:"pades",originalData:$data}')"
  verify_resp="$(send_req "${verify_req}")"
  echo "[smoke] verify(pades) => success=$(printf '%s' "${verify_resp}" | jq -r '.success') valid=$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')"

  if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
    [[ "$(printf '%s' "${verify_resp}" | jq -r '.success')" == "true" ]]
    [[ "$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')" == "true" ]]
  fi

  rm -f "${data_file}" "${sig_file}"
  trap - RETURN
}

run_sign_verify_xades() {
  local cert_id="$1"
  local xml_data_b64 sign_req sign_resp sig verify_req verify_resp
  xml_data_b64="$(printf '%s' '<root><value>hola</value></root>' | base64 -w 0)"
  sign_req="$(jq -nc --arg cert_id "${cert_id}" --arg data "${xml_data_b64}" '{requestId:"7",action:"sign",certificateId:$cert_id,data:$data,format:"xades"}')"
  sign_resp="$(send_req "${sign_req}")"
  echo "[smoke] sign(xades) => success=$(printf '%s' "${sign_resp}" | jq -r '.success')"

  if [[ "$(printf '%s' "${sign_resp}" | jq -r '.success')" != "true" ]]; then
    if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
      echo "ERROR: la firma XAdES falló en modo estricto" >&2
      return 1
    fi
    echo "[smoke] xades => AVISO (modo no estricto)"
    return 0
  fi

  sig="$(printf '%s' "${sign_resp}" | jq -r '.signature // empty')"
  verify_req="$(jq -nc --arg data "${xml_data_b64}" --arg sig "${sig}" '{requestId:"8",action:"verify",format:"xades",originalData:$data,signatureData:$sig}')"
  verify_resp="$(send_req "${verify_req}")"
  echo "[smoke] verify(xades) => success=$(printf '%s' "${verify_resp}" | jq -r '.success') valid=$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')"

  if [[ "${STRICT_FORMATS}" -eq 1 ]]; then
    [[ "$(printf '%s' "${verify_resp}" | jq -r '.success')" == "true" ]]
    [[ "$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')" == "true" ]]
  fi
}

main() {
  cd "${ROOT_DIR}"
  build_bin

  run_ping

  local cert_id
  cert_id="$(run_get_certs)"
  if [[ -z "${cert_id}" ]]; then
    echo "[smoke] AVISO: no hay certificados disponibles; se omite firma/verificación"
    echo "[smoke] OK (parcial)"
    exit 0
  fi

  run_sign_verify "${cert_id}"
  run_sign_verify_pades "${cert_id}"
  run_sign_verify_xades "${cert_id}"
  echo "[smoke] OK"
}

main "$@"
