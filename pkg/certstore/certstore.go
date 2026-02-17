// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package certstore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"autofirma-host/pkg/protocol"
)

// Options controls how certificate stores are queried.
type Options struct {
	// PKCS11ModulePaths optionally restricts PKCS#11 lookup to specific module paths.
	PKCS11ModulePaths []string
	// IncludePKCS11 controls whether PKCS#11 stores are queried.
	// Default should be true for compatibility.
	IncludePKCS11 bool
}

// GetSystemCertificates returns all certificates from system stores
// Platform-specific implementations in windows.go, linux.go, darwin.go
func GetSystemCertificates() ([]protocol.Certificate, error) {
	return GetSystemCertificatesWithOptions(Options{IncludePKCS11: true})
}

// GetSystemCertificatesWithOptions returns all certificates from system stores
// with optional source-specific hints.
func GetSystemCertificatesWithOptions(opts Options) ([]protocol.Certificate, error) {
	allCerts := make([]protocol.Certificate, 0, 16)
	seen := make(map[string]struct{}, 32)

	// Get certificates from platform-specific store
	systemCerts, err := getSystemCertificatesImpl()
	if err == nil {
		allCerts = appendUniqueCertificates(allCerts, seen, systemCerts)
	}

	// Get certificates from PKCS#11 devices (DNIe, smart cards)
	if opts.IncludePKCS11 {
		pkcs11Certs, err := getPKCS11CertificatesWithModules(opts.PKCS11ModulePaths)
		if err == nil {
			allCerts = appendUniqueCertificates(allCerts, seen, pkcs11Certs)
		}
	}

	return allCerts, nil
}

func appendUniqueCertificates(dst []protocol.Certificate, seen map[string]struct{}, src []protocol.Certificate) []protocol.Certificate {
	for _, c := range src {
		key := certificateUniqueKey(c)
		if key == "" {
			// Conservative behavior: if no stable key can be built, keep cert.
			dst = append(dst, c)
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, c)
	}
	return dst
}

func certificateUniqueKey(c protocol.Certificate) string {
	if fp := strings.TrimSpace(strings.ToLower(c.Fingerprint)); fp != "" {
		return "fp:" + fp
	}
	if len(c.Content) > 0 {
		sum := sha256.Sum256(c.Content)
		return "der:" + hex.EncodeToString(sum[:])
	}
	if pem := strings.TrimSpace(c.PEM); pem != "" {
		sum := sha256.Sum256([]byte(pem))
		return "pem:" + hex.EncodeToString(sum[:])
	}
	return ""
}

// ParseCertificate converts x509.Certificate to protocol.Certificate
func ParseCertificate(cert *x509.Certificate, source string) protocol.Certificate {
	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	canSign, signIssue := evaluateSignCapability(cert)

	// Parse subject
	subject := make(map[string]string)
	if cert.Subject.CommonName != "" {
		subject["CN"] = cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		subject["O"] = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		subject["OU"] = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Country) > 0 {
		subject["C"] = cert.Subject.Country[0]
	}

	// Parse issuer
	issuer := make(map[string]string)
	if cert.Issuer.CommonName != "" {
		issuer["CN"] = cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		issuer["O"] = cert.Issuer.Organization[0]
	}

	// Convert to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return protocol.Certificate{
		ID:           hex.EncodeToString(fingerprint[:16]), // First 16 bytes as ID
		Subject:      subject,
		Issuer:       issuer,
		SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
		ValidFrom:    cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		ValidTo:      cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Fingerprint:  hex.EncodeToString(fingerprint[:]),
		Source:       source,
		PEM:          string(certPEM),
		CanSign:      canSign,
		SignIssue:    signIssue,
		Content:      cert.Raw,
	}
}

func evaluateSignCapability(cert *x509.Certificate) (bool, string) {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false, "certificado aun no valido"
	}
	if now.After(cert.NotAfter) {
		return false, "certificado caducado"
	}
	if cert.IsCA {
		return false, "certificado de autoridad (CA)"
	}

	// If KeyUsage is present, require a signing-compatible usage.
	if cert.KeyUsage != 0 {
		digitalSignature := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		contentCommitment := cert.KeyUsage&x509.KeyUsageContentCommitment != 0
		if !digitalSignature && !contentCommitment {
			return false, "uso de clave no permite firma"
		}
	}

	// If EKU is present, require at least one compatible purpose.
	if len(cert.ExtKeyUsage) > 0 {
		allowed := false
		for _, eku := range cert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageAny,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageCodeSigning:
				allowed = true
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return false, "EKU no permite firma"
		}
	}

	return true, ""
}
