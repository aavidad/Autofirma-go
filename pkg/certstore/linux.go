// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build linux
// +build linux

package certstore

import (
	"os"
	"path/filepath"

	"autofirma-host/pkg/protocol"
)

func getSystemCertificatesImpl() ([]protocol.Certificate, error) {
	var certs []protocol.Certificate

	// Try NSS databases (Chrome and all Firefox profiles)
	dbs := DiscoverFirefoxProfiles()

	// Also add default Chrome NSS DB
	chromeDB := filepath.Join(os.Getenv("HOME"), ".pki/nssdb")
	if _, err := os.Stat(chromeDB); err == nil {
		dbs = append(dbs, chromeDB)
	}

	for _, db := range dbs {
		nssCerts, err := getNSSCertificates(db)
		if err == nil {
			certs = append(certs, nssCerts...)
		}
	}

	return certs, nil
}
