// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const localRootCANickname = "Autofirma Dipgra Local Root CA"

func installLocalTLSTrust() ([]string, error) {
	lines := []string{}
	if runtime.GOOS != "linux" {
		lines = append(lines, "[Trust] Instalacion de confianza automatica disponible solo en Linux.")
		return lines, nil
	}

	rootCAPath, err := localRootCACertPath()
	if err != nil {
		return lines, err
	}
	if !fileExists(rootCAPath) {
		return lines, fmt.Errorf("no existe CA local en %s (ejecute --generate-certs)", rootCAPath)
	}
	lines = append(lines, fmt.Sprintf("[Trust] CA local: %s", rootCAPath))

	skipNSS := envBool("AUTOFIRMA_TRUST_SKIP_NSS", false)
	skipSystem := envBool("AUTOFIRMA_TRUST_SKIP_SYSTEM", false)

	if !skipNSS {
		nssLines, nssErr := installTrustInNSSDatabases(rootCAPath)
		lines = append(lines, nssLines...)
		if nssErr != nil {
			return lines, nssErr
		}
	} else {
		lines = append(lines, "[Trust] NSS de usuario omitido por AUTOFIRMA_TRUST_SKIP_NSS=1.")
	}

	if !skipSystem {
		sysLine, sysErr := installSystemTrustLinux(rootCAPath)
		lines = append(lines, sysLine)
		if sysErr != nil {
			return lines, sysErr
		}
	} else {
		lines = append(lines, "[Trust] Almacen del sistema omitido por AUTOFIRMA_TRUST_SKIP_SYSTEM=1.")
	}

	return lines, nil
}

func localTLSTrustStatus() ([]string, error) {
	lines := []string{}
	rootCAPath, err := localRootCACertPath()
	if err != nil {
		return lines, err
	}
	lines = append(lines, fmt.Sprintf("[Trust] CA local esperada: %s", rootCAPath))
	if !fileExists(rootCAPath) {
		lines = append(lines, "[Trust] CA local no encontrada (ejecute --generate-certs).")
		return lines, nil
	}

	if runtime.GOOS != "linux" {
		lines = append(lines, "[Trust] Comprobacion detallada disponible solo en Linux.")
		return lines, nil
	}

	if _, err := exec.LookPath("certutil"); err != nil {
		lines = append(lines, "[Trust] certutil no disponible; no se puede verificar NSS de usuario.")
	} else {
		dbs := discoverNSSDBs()
		if len(dbs) == 0 {
			lines = append(lines, "[Trust] No se encontraron bases NSS de usuario.")
		} else {
			for _, dbPath := range dbs {
				if isCertInNSS(dbPath, localRootCANickname) {
					lines = append(lines, fmt.Sprintf("[Trust] NSS OK: %s", dbPath))
				} else {
					lines = append(lines, fmt.Sprintf("[Trust] NSS FALTA: %s", dbPath))
				}
			}
		}
	}

	sysLine, _ := checkSystemTrustLinux(rootCAPath)
	lines = append(lines, sysLine)
	return lines, nil
}

func localRootCACertPath() (string, error) {
	dir, err := localTLSCertsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rootCA.crt"), nil
}

func installTrustInNSSDatabases(rootCAPath string) ([]string, error) {
	lines := []string{}
	if _, err := exec.LookPath("certutil"); err != nil {
		lines = append(lines, "[Trust] certutil no disponible; omitiendo instalacion NSS (instale libnss3-tools/nss-tools).")
		return lines, nil
	}

	dbs := discoverNSSDBs()
	if len(dbs) == 0 {
		lines = append(lines, "[Trust] No se encontraron bases NSS (Chrome/Firefox) para instalar la CA.")
		return lines, nil
	}

	trustedOrInstalled := 0
	for _, dbPath := range dbs {
		if isCertInNSS(dbPath, localRootCANickname) {
			lines = append(lines, fmt.Sprintf("[Trust] NSS ya confiado: %s", dbPath))
			trustedOrInstalled++
			continue
		}
		out, err := exec.Command("certutil", "-d", "sql:"+dbPath, "-A", "-t", "C,,", "-n", localRootCANickname, "-i", rootCAPath).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			low := strings.ToLower(msg)
			if strings.Contains(low, "sec_error_read_only") || strings.Contains(low, "read-only") {
				lines = append(lines, fmt.Sprintf("[Trust] NSS sin cambios (solo lectura): %s", dbPath))
				continue
			}
			if strings.Contains(low, "sec_error_adding_cert") && isCertInNSS(dbPath, localRootCANickname) {
				lines = append(lines, fmt.Sprintf("[Trust] NSS ya confiado: %s", dbPath))
				trustedOrInstalled++
				continue
			}
			return lines, fmt.Errorf("fallo instalando CA en NSS %s: %v (%s)", dbPath, err, msg)
		}
		lines = append(lines, fmt.Sprintf("[Trust] NSS instalado: %s", dbPath))
		trustedOrInstalled++
	}
	if trustedOrInstalled == 0 {
		return lines, fmt.Errorf("no se pudo instalar/verificar la CA en NSS. Cierre navegador y reintente --install-trust")
	}
	return lines, nil
}

func discoverNSSDBs() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}

	dbs := map[string]struct{}{}
	for _, base := range []string{
		filepath.Join(home, ".pki", "nssdb"),
		filepath.Join(home, "snap", "chromium", "current", ".pki", "nssdb"),
		filepath.Join(home, ".var", "app", "org.chromium.Chromium", "config", "chromium", "Default", "nssdb"),
	} {
		if fileExists(filepath.Join(base, "cert9.db")) {
			dbs[base] = struct{}{}
		}
	}

	for _, pattern := range []string{
		filepath.Join(home, ".mozilla", "firefox", "*", "cert9.db"),
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox", "*", "cert9.db"),
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox", "*", "cert9.db"),
	} {
		matches, _ := filepath.Glob(pattern)
		for _, certDB := range matches {
			dbs[filepath.Dir(certDB)] = struct{}{}
		}
	}

	out := make([]string, 0, len(dbs))
	for db := range dbs {
		out = append(out, db)
	}
	sort.Strings(out)
	return out
}

func isCertInNSS(dbPath string, nickname string) bool {
	cmd := exec.Command("certutil", "-d", "sql:"+dbPath, "-L", "-n", nickname)
	return cmd.Run() == nil
}

func installSystemTrustLinux(rootCAPath string) (string, error) {
	if os.Geteuid() != 0 {
		return "[Trust] Sistema: omitido (requiere root para instalar CA global).", nil
	}

	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		target := "/usr/local/share/ca-certificates/autofirma-dipgra-local-root-ca.crt"
		if err := copyFile(rootCAPath, target, 0o644); err != nil {
			return "", err
		}
		out, err := exec.Command("update-ca-certificates").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("fallo en update-ca-certificates: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return "[Trust] Sistema: CA instalada con update-ca-certificates.", nil
	}

	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		target := "/etc/pki/ca-trust/source/anchors/autofirma-dipgra-local-root-ca.crt"
		if err := copyFile(rootCAPath, target, 0o644); err != nil {
			return "", err
		}
		out, err := exec.Command("update-ca-trust").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("fallo en update-ca-trust: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return "[Trust] Sistema: CA instalada con update-ca-trust.", nil
	}

	return "[Trust] Sistema: no se encontro update-ca-certificates ni update-ca-trust.", nil
}

func checkSystemTrustLinux(rootCAPath string) (string, error) {
	targets := []string{
		"/usr/local/share/ca-certificates/autofirma-dipgra-local-root-ca.crt",
		"/etc/pki/ca-trust/source/anchors/autofirma-dipgra-local-root-ca.crt",
	}
	present := false
	for _, t := range targets {
		if fileExists(t) {
			present = true
			break
		}
	}

	caBundle := ""
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
	} {
		if fileExists(p) {
			caBundle = p
			break
		}
	}

	if caBundle == "" {
		if present {
			return "[Trust] Sistema: CA copiada pero no se encontro bundle para verificar.", nil
		}
		return "[Trust] Sistema: CA no detectada.", nil
	}

	if _, err := exec.LookPath("openssl"); err != nil {
		if present {
			return fmt.Sprintf("[Trust] Sistema: CA presente en rutas conocidas (sin openssl para verificar, bundle=%s).", caBundle), nil
		}
		return "[Trust] Sistema: CA no detectada.", nil
	}

	cmd := exec.Command("openssl", "verify", "-CAfile", caBundle, rootCAPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		return fmt.Sprintf("[Trust] Sistema OK (bundle=%s).", caBundle), nil
	}
	if present {
		return fmt.Sprintf("[Trust] Sistema parcial: CA copiada pero no validada contra bundle (%s).", caBundle), nil
	}
	return "[Trust] Sistema: CA no detectada.", nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("leyendo %s: %w", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("creando directorio destino %s: %w", filepath.Dir(dst), err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("escribiendo %s: %w", dst, err)
	}
	return nil
}

func envBool(name string, def bool) bool {
	val := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if val == "" {
		return def
	}
	switch val {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	default:
		return def
	}
}
