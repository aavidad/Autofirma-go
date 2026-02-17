// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build linux && cgo
// +build linux,cgo

package certstore

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"autofirma-host/pkg/protocol"

	"github.com/miekg/pkcs11"
)

// getPKCS11Certificates gets certificates from PKCS#11 devices (DNIe, smart cards)
func getPKCS11Certificates() ([]protocol.Certificate, error) {
	return getPKCS11CertificatesWithModules(nil)
}

func getPKCS11CertificatesWithModules(moduleHints []string) ([]protocol.Certificate, error) {
	var allCerts []protocol.Certificate

	modules := normalizePKCS11ModulePaths(moduleHints)

	for _, modulePath := range modules {
		if _, err := os.Stat(modulePath); err != nil {
			continue // Module not found, try next
		}

		certs, err := getCertsFromPKCS11Module(modulePath)
		if err == nil && len(certs) > 0 {
			allCerts = append(allCerts, certs...)
		}
	}

	return allCerts, nil
}

func normalizePKCS11ModulePaths(moduleHints []string) []string {
	if len(moduleHints) > 0 {
		out := make([]string, 0, len(moduleHints))
		seen := make(map[string]struct{}, len(moduleHints))
		for _, raw := range moduleHints {
			p := strings.TrimSpace(raw)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
		if len(out) > 0 {
			return out
		}
	}

	// Common PKCS#11 module paths
	return []string{
		"/usr/lib/opensc-pkcs11.so",                  // OpenSC (DNIe)
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // Ubuntu/Debian
		"/usr/lib64/opensc-pkcs11.so",                // Fedora/RHEL
		"/usr/lib/pkcs11/opensc-pkcs11.so",           // Generic
		"/usr/local/lib/opensc-pkcs11.so",            // Custom install
	}
}

func getCertsFromPKCS11Module(modulePath string) ([]protocol.Certificate, error) {
	var certs []protocol.Certificate

	// Initialize PKCS#11
	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}

	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %v", err)
	}
	defer p.Finalize()

	// Get slots with tokens
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %v", err)
	}

	for _, slot := range slots {
		// Get token info
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		// Open session
		session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			continue
		}
		defer p.CloseSession(session)

		// Find certificates
		if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}); err != nil {
			continue
		}

		objects, _, err := p.FindObjects(session, 100)
		if err != nil {
			p.FindObjectsFinal(session)
			continue
		}

		p.FindObjectsFinal(session)

		// Extract certificates
		for _, obj := range objects {
			cert, err := extractCertificateFromPKCS11(p, session, obj, tokenInfo.Label)
			if err == nil {
				certs = append(certs, cert)
			}
		}
	}

	return certs, nil
}

func extractCertificateFromPKCS11(p *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle, tokenLabel string) (protocol.Certificate, error) {
	// Get certificate value
	attrs, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	})
	if err != nil {
		return protocol.Certificate{}, err
	}

	// Parse X.509 certificate
	certDER := attrs[0].Value
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return protocol.Certificate{}, err
	}

	// Determine source (DNIe or generic smart card)
	source := "smartcard"
	if tokenLabel == "DNI electrónico (PIN1)" || tokenLabel == "DNIe" {
		source = "dnie"
	}

	return ParseCertificate(cert, source), nil
}
