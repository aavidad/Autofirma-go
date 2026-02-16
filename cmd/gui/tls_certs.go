// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func ensureLocalTLSCerts() (string, string, error) {
	dir, err := localTLSCertsDir()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("creating cert dir: %w", err)
	}

	rootCAKeyPath := filepath.Join(dir, "rootCA.key")
	rootCACertPath := filepath.Join(dir, "rootCA.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	serverCertPath := filepath.Join(dir, "server.crt")

	if fileExists(rootCAKeyPath) && fileExists(rootCACertPath) && fileExists(serverKeyPath) && fileExists(serverCertPath) {
		return serverCertPath, serverKeyPath, nil
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generating root key: %w", err)
	}

	rootSerial, err := randomSerialNumber()
	if err != nil {
		return "", "", err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "Autofirma Dipgra Local Root CA",
			Organization: []string{"Diputacion de Granada"},
			Country:      []string{"ES"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return "", "", fmt.Errorf("creating root cert: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generating server key: %w", err)
	}
	serverSerial, err := randomSerialNumber()
	if err != nil {
		return "", "", err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName:   "127.0.0.1",
			Organization: []string{"Autofirma Dipgra Local Server"},
			Country:      []string{"ES"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return "", "", fmt.Errorf("parsing root cert: %w", err)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, rootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		return "", "", fmt.Errorf("creating server cert: %w", err)
	}

	rootKeyDER, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		return "", "", fmt.Errorf("encoding root key: %w", err)
	}
	if err := writePEMFile(rootCAKeyPath, "PRIVATE KEY", rootKeyDER, 0o600); err != nil {
		return "", "", err
	}
	if err := writePEMFile(rootCACertPath, "CERTIFICATE", rootDER, 0o644); err != nil {
		return "", "", err
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return "", "", fmt.Errorf("encoding server key: %w", err)
	}
	if err := writePEMFile(serverKeyPath, "PRIVATE KEY", serverKeyDER, 0o600); err != nil {
		return "", "", err
	}
	if err := writePEMFile(serverCertPath, "CERTIFICATE", serverDER, 0o644); err != nil {
		return "", "", err
	}

	return serverCertPath, serverKeyPath, nil
}

func localTLSCertsDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil || cfgDir == "" {
		tmp := filepath.Join(os.TempDir(), "AutofirmaDipgra")
		return filepath.Join(tmp, "certs"), nil
	}
	return filepath.Join(cfgDir, "AutofirmaDipgra", "certs"), nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("creating serial number: %w", err)
	}
	return n, nil
}

func writePEMFile(path string, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
