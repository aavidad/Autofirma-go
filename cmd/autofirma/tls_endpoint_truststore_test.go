// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEndpointTrustStoreSaveAppendAndClear(t *testing.T) {
	origXDG := os.Getenv("XDG_CONFIG_HOME")
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	defer os.Setenv("XDG_CONFIG_HOME", origXDG)

	cert, err := makeTestCert("pruebas.dipgra.local")
	if err != nil {
		t.Fatalf("makeTestCert: %v", err)
	}

	saved, lines, err := saveEndpointCertificates("pruebas.dipgra.local", []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("saveEndpointCertificates: %v", err)
	}
	if saved != 1 {
		t.Fatalf("saved=%d, want 1", saved)
	}
	if len(lines) == 0 {
		t.Fatalf("expected status lines")
	}

	dir, count := endpointTrustStoreStatus()
	if count < 1 {
		t.Fatalf("endpointTrustStoreStatus count=%d, want >=1", count)
	}
	if dir == "" {
		t.Fatalf("endpointTrustStoreStatus dir empty")
	}

	pool := x509.NewCertPool()
	loaded := appendEndpointTrustStoreCerts(pool)
	if loaded < 1 {
		t.Fatalf("appendEndpointTrustStoreCerts loaded=%d, want >=1", loaded)
	}

	removed, err := clearEndpointTrustStore()
	if err != nil {
		t.Fatalf("clearEndpointTrustStore: %v", err)
	}
	if removed < 1 {
		t.Fatalf("clearEndpointTrustStore removed=%d, want >=1", removed)
	}
	if _, err := os.Stat(filepath.Join(dir)); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected dir stat error: %v", err)
	}
}

func makeTestCert(cn string) (*x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
