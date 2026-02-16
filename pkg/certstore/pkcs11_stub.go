// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build !linux || !cgo
// +build !linux !cgo

package certstore

import "autofirma-host/pkg/protocol"

// getPKCS11Certificates is a no-op on non-Linux builds for now.
func getPKCS11Certificates() ([]protocol.Certificate, error) {
	return nil, nil
}
