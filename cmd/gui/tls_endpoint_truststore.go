// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func endpointTLSCertsDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(cfgDir) == "" {
		return filepath.Join(os.TempDir(), "AutofirmaDipgra", "certs", "endpoints"), nil
	}
	return filepath.Join(cfgDir, "AutofirmaDipgra", "certs", "endpoints"), nil
}

func saveEndpointCertificates(host string, certs []*x509.Certificate) (int, []string, error) {
	lines := []string{}
	if len(certs) == 0 {
		return 0, lines, nil
	}
	dir, err := endpointTLSCertsDir()
	if err != nil {
		return 0, lines, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, lines, fmt.Errorf("creando almacén TLS local: %w", err)
	}

	hostTag := sanitizeEndpointHostTag(host)
	if hostTag == "" {
		hostTag = "manual"
	}
	saved := 0
	for _, cert := range certs {
		if cert == nil || len(cert.Raw) == 0 {
			continue
		}
		sum := sha1.Sum(cert.Raw)
		fp := strings.ToLower(hex.EncodeToString(sum[:]))
		name := hostTag + "-" + fp + ".crt"
		path := filepath.Join(dir, name)
		if fileExists(path) {
			lines = append(lines, "[TLS] Ya presente en almacén local: "+name)
			continue
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		data := pem.EncodeToMemory(block)
		if len(data) == 0 {
			continue
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return saved, lines, fmt.Errorf("guardando certificado TLS local %s: %w", name, err)
		}
		lines = append(lines, "[TLS] Guardado en almacén local: "+name)
		saved++
	}
	return saved, lines, nil
}

func appendEndpointTrustStoreCerts(pool *x509.CertPool) int {
	if pool == nil {
		return 0
	}
	dir, err := endpointTLSCertsDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(e.Name()))
		if !(strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cer") || strings.HasSuffix(name, ".pem")) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			loaded++
		}
	}
	return loaded
}

func sanitizeEndpointHostTag(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	host = strings.ReplaceAll(host, ":", "_")
	host = strings.ReplaceAll(host, "/", "_")
	host = strings.ReplaceAll(host, "\\", "_")
	host = strings.ReplaceAll(host, " ", "_")
	host = strings.Trim(host, "._-")
	if len(host) > 64 {
		host = host[:64]
	}
	return host
}

func endpointTrustStoreStatus() (string, int) {
	dir, err := endpointTLSCertsDir()
	if err != nil {
		return "", 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return dir, 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(e.Name()))
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cer") || strings.HasSuffix(name, ".pem") {
			count++
		}
	}
	return dir, count
}

func clearEndpointTrustStore() (int, error) {
	dir, err := endpointTLSCertsDir()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(e.Name()))
		if !(strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cer") || strings.HasSuffix(name, ".pem")) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
