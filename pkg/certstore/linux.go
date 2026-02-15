// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build linux
// +build linux

package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"autofirma-host/pkg/protocol"
)

func getSystemCertificatesImpl() ([]protocol.Certificate, error) {
	var certs []protocol.Certificate

	// Try NSS database (Firefox, Chrome on Linux)
	nssDB := filepath.Join(os.Getenv("HOME"), ".pki/nssdb")
	if _, err := os.Stat(nssDB); err == nil {
		nssCerts, err := getNSSCertificates(nssDB)
		if err == nil {
			certs = append(certs, nssCerts...)
		}
	}

	return certs, nil
}

func getNSSCertificates(dbPath string) ([]protocol.Certificate, error) {
	var certs []protocol.Certificate
	seen := make(map[string]bool) // Track fingerprints to avoid duplicates

	// Use certutil to list certificates with trust attributes
	cmd := exec.Command("certutil", "-L", "-d", "sql:"+dbPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("certutil failed: %v", err)
	}

	// Parse certutil output to get certificate nicknames
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		// Skip header lines
		if i < 2 || strings.TrimSpace(line) == "" {
			continue
		}

		// Extract nickname and trust attributes
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Trust attributes are the last field
		trustAttrs := parts[len(parts)-1]

		// Nickname is everything except the last part (trust attributes)
		nickname := strings.Join(parts[:len(parts)-1], " ")
		nickname = strings.TrimSpace(nickname)

		if nickname == "" || nickname == "(NULL)" {
			continue
		}

		// Filter: only include certificates with 'u' in trust attributes
		// 'u' means the certificate has a private key (user certificate)
		// CA certificates typically have 'C' or 'CT' without 'u'
		if !strings.Contains(trustAttrs, "u") {
			continue
		}

		// Get certificate details
		cert, err := getNSSCertificateByNickname(dbPath, nickname)
		if err == nil {
			// Skip if we've already seen this certificate (by fingerprint)
			if !seen[cert.Fingerprint] {
				seen[cert.Fingerprint] = true
				cert.Nickname = nickname // Save nickname for signing
				certs = append(certs, cert)
			}
		}
	}

	return certs, nil
}

func getNSSCertificateByNickname(dbPath, nickname string) (protocol.Certificate, error) {
	// Export certificate in PEM format
	cmd := exec.Command("certutil", "-L", "-d", "sql:"+dbPath, "-n", nickname, "-a")
	output, err := cmd.Output()
	if err != nil {
		return protocol.Certificate{}, fmt.Errorf("failed to export cert: %v", err)
	}

	// Parse PEM
	block, _ := pem.Decode(output)
	if block == nil {
		return protocol.Certificate{}, fmt.Errorf("failed to decode PEM")
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return protocol.Certificate{}, err
	}

	return ParseCertificate(cert, "system"), nil
}
