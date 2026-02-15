#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/autofirma-host-e2e"
ACTION="${1:-ping}"

cd "${ROOT_DIR}"
GOCACHE=/tmp/go-build go build -o "${BIN}" ./cmd/autofirma-host

send_req() {
  local payload="$1"
  printf '%s' "${payload}" |
    perl -e 'local $/; my $m=<STDIN>; print pack("V", length($m)).$m;' |
    "${BIN}" |
    perl -e 'while(read(STDIN,my $l,4)==4){my $n=unpack("V",$l);read(STDIN,my $b,$n)==$n or die "short frame"; print $b, "\n";}'
}

case "${ACTION}" in
  ping)
    send_req '{"requestId":"100","action":"ping"}'
    ;;
  getCertificates)
    send_req '{"requestId":"101","action":"getCertificates"}'
    ;;
  sign-cades)
    CERT_JSON="$(send_req '{"requestId":"102","action":"getCertificates"}' | head -n1)"
    CERT_ID="$(printf '%s' "${CERT_JSON}" | jq -r '.certificates[0].id // empty')"
    if [[ -z "${CERT_ID}" ]]; then
      echo '{"success":false,"error":"No certificates available"}'
      exit 2
    fi
    REQ="$(jq -nc --arg cid "${CERT_ID}" '{requestId:"103",action:"sign",certificateId:$cid,data:"SG9sYQ==",format:"cades"}')"
    send_req "${REQ}"
    ;;
  *)
    echo "Usage: $0 [ping|getCertificates|sign-cades]" >&2
    exit 1
    ;;
esac
