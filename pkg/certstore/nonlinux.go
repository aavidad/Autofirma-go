// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build !linux && !windows
// +build !linux,!windows

package certstore

import "autofirma-host/pkg/protocol"

func getSystemCertificatesImpl() ([]protocol.Certificate, error) {
	return nil, nil
}
