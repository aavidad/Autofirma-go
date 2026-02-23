#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${ROOT_DIR}/autofirma-host-large"
PAYLOAD_MB="${PAYLOAD_MB:-3}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: 'jq' is required" >&2
  exit 1
fi

if [[ " ${GOFLAGS:-} " != *" -mod="* ]]; then
  GOFLAGS="${GOFLAGS:-} -mod=readonly"
fi

build_bin() {
  echo "[large] building host binary..."
  GOCACHE=/tmp/go-build GOFLAGS="${GOFLAGS}" go build -o "${BIN_PATH}" ./cmd/autofirma-host
}

send_req() {
  local payload="$1"
  local frames
  frames="$({
    printf '%s' "${payload}" |
      perl -e 'local $/; my $m=<STDIN>; print pack("V", length($m)).$m;' |
      "${BIN_PATH}" |
      perl -e 'while (read(STDIN,my $l,4)==4){my $n=unpack("V",$l);read(STDIN,my $b,$n)==$n or die "short frame"; print $b, "\n";}'
  })"

  if [[ "$(printf '%s\n' "${frames}" | sed '/^$/d' | wc -l)" -le 1 ]]; then
    printf '%s' "${frames}" | head -n1
    return 0
  fi

  printf '%s\n' "${frames}" | jq -cs '
    sort_by(.chunk) as $arr |
    ($arr[0] + {
      signature: ($arr | map(.signature // "") | join("")),
      totalChunks: ($arr | length),
      chunk: 0
    })
  '
}

main() {
  cd "${ROOT_DIR}"
  build_bin

  local cert_resp cert_id
  cert_resp="$(send_req '{"requestId":"200","action":"getCertificates"}')"
  cert_id="$(printf '%s' "${cert_resp}" | jq -r '.certificates[0].id // empty')"
  if [[ -z "${cert_id}" ]]; then
    echo "[large] ERROR: no certificates available"
    exit 2
  fi

  local tmp_data data_b64_file sig_file sign_req sign_resp verify_req verify_resp
  tmp_data="$(mktemp)"
  data_b64_file="${tmp_data}.b64"
  sig_file="$(mktemp)"
  cleanup() {
    if [[ -n "${tmp_data:-}" ]]; then rm -f "${tmp_data}"; fi
    if [[ -n "${data_b64_file:-}" ]]; then rm -f "${data_b64_file}"; fi
    if [[ -n "${sig_file:-}" ]]; then rm -f "${sig_file}"; fi
  }
  trap cleanup EXIT

  # deterministic payload (fast to generate, >2MB)
  dd if=/dev/zero of="${tmp_data}" bs=1M count="${PAYLOAD_MB}" status=none
  base64 -w 0 "${tmp_data}" > "${data_b64_file}"

  echo "[large] payload bytes=$(wc -c < "${tmp_data}")"
  sign_req="$(jq -nc --arg cid "${cert_id}" --rawfile data "${data_b64_file}" '{requestId:"201",action:"sign",certificateId:$cid,data:$data,format:"cades"}')"
  sign_resp="$(send_req "${sign_req}")"

  echo "[large] sign(cades) => success=$(printf '%s' "${sign_resp}" | jq -r '.success') signatureLen=$(printf '%s' "${sign_resp}" | jq -r '.signatureLen // 0')"
  [[ "$(printf '%s' "${sign_resp}" | jq -r '.success')" == "true" ]]

  printf '%s' "${sign_resp}" | jq -r '.signature // empty' > "${sig_file}"
  verify_req="$(jq -nc --rawfile data "${data_b64_file}" --rawfile sig "${sig_file}" '{requestId:"202",action:"verify",format:"cades",originalData:$data,signatureData:$sig}')"
  verify_resp="$(send_req "${verify_req}")"

  echo "[large] verify(cades) => success=$(printf '%s' "${verify_resp}" | jq -r '.success') valid=$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')"
  [[ "$(printf '%s' "${verify_resp}" | jq -r '.success')" == "true" ]]
  [[ "$(printf '%s' "${verify_resp}" | jq -r '.result.valid // false')" == "true" ]]

  echo "[large] PASS"
}

main "$@"
