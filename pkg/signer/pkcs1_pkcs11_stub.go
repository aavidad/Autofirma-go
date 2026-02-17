// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build !linux || !cgo
// +build !linux !cgo

package signer

import (
	"fmt"

	"autofirma-host/pkg/protocol"
)

func signPKCS1WithPKCS11(_ []byte, _ *protocol.Certificate, _ string, _ map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("firma PKCS11 directa no soportada en esta plataforma")
}
