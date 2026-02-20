// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const localRootCANickname = "Autofirma ROOT"

func installLocalTLSTrust() ([]string, error) {
	lines := []string{}
	rootCAPath, err := localRootCACertPath()
	if err != nil {
		return lines, err
	}
	if !fileExists(rootCAPath) {
		return lines, fmt.Errorf("no existe CA local en %s (ejecute --generate-certs)", rootCAPath)
	}
	lines = append(lines, fmt.Sprintf("[Trust] CA local: %s", rootCAPath))

	if runtime.GOOS == "windows" {
		winLines, winErr := installTrustWindows(rootCAPath)
		lines = append(lines, winLines...)
		return lines, winErr
	}
	if runtime.GOOS == "darwin" {
		macLines, macErr := installTrustMacOS(rootCAPath)
		lines = append(lines, macLines...)
		return lines, macErr
	}

	if runtime.GOOS != "linux" {
		lines = append(lines, "[Trust] Instalacion de confianza automatica disponible solo en Linux, Windows y macOS.")
		return lines, nil
	}

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

	if runtime.GOOS == "windows" {
		winLines, winErr := localTLSTrustStatusWindows(rootCAPath)
		lines = append(lines, winLines...)
		return lines, winErr
	}
	if runtime.GOOS == "darwin" {
		macLines, macErr := localTLSTrustStatusMacOS(rootCAPath)
		lines = append(lines, macLines...)
		return lines, macErr
	}

	if runtime.GOOS != "linux" {
		lines = append(lines, "[Trust] Comprobacion detallada disponible solo en Linux, Windows y macOS.")
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

func installTrustWindows(rootCAPath string) ([]string, error) {
	lines := []string{}
	thumb, err := localCAThumbprint(rootCAPath)
	if err != nil {
		return lines, err
	}
	lines = append(lines, fmt.Sprintf("[Trust] Windows thumbprint CA local: %s", thumb))

	skipSystem := envBool("AUTOFIRMA_TRUST_SKIP_SYSTEM", false)

	userOK, err := windowsStoreHasThumbprint("CurrentUser", thumb)
	if err != nil {
		return lines, fmt.Errorf("error comprobando CurrentUser\\Root: %w", err)
	}
	if userOK {
		lines = append(lines, "[Trust] Windows CurrentUser\\Root: ya confiado.")
	} else {
		if err := windowsImportRootCA("CurrentUser", rootCAPath); err != nil {
			return lines, fmt.Errorf("error instalando en CurrentUser\\Root: %w", err)
		}
		lines = append(lines, "[Trust] Windows CurrentUser\\Root: instalado.")
	}

	if skipSystem {
		lines = append(lines, "[Trust] Windows LocalMachine\\Root omitido por AUTOFIRMA_TRUST_SKIP_SYSTEM=1.")
		return lines, nil
	}

	machineOK, err := windowsStoreHasThumbprint("LocalMachine", thumb)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] Windows LocalMachine\\Root: no verificado (%v).", err))
		return lines, nil
	}
	if machineOK {
		lines = append(lines, "[Trust] Windows LocalMachine\\Root: ya confiado.")
		return lines, nil
	}
	if err := windowsImportRootCA("LocalMachine", rootCAPath); err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] Windows LocalMachine\\Root: omitido (%v).", err))
		return lines, nil
	}
	lines = append(lines, "[Trust] Windows LocalMachine\\Root: instalado.")
	return lines, nil
}

func localTLSTrustStatusWindows(rootCAPath string) ([]string, error) {
	lines := []string{}
	thumb, err := localCAThumbprint(rootCAPath)
	if err != nil {
		return lines, err
	}
	lines = append(lines, fmt.Sprintf("[Trust] Windows thumbprint CA local: %s", thumb))

	userOK, err := windowsStoreHasThumbprint("CurrentUser", thumb)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] Windows CurrentUser\\Root: ERROR (%v).", err))
	} else if userOK {
		lines = append(lines, "[Trust] Windows CurrentUser\\Root: OK.")
	} else {
		lines = append(lines, "[Trust] Windows CurrentUser\\Root: FALTA.")
	}

	machineOK, err := windowsStoreHasThumbprint("LocalMachine", thumb)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] Windows LocalMachine\\Root: no verificable (%v).", err))
	} else if machineOK {
		lines = append(lines, "[Trust] Windows LocalMachine\\Root: OK.")
	} else {
		lines = append(lines, "[Trust] Windows LocalMachine\\Root: FALTA.")
	}

	return lines, nil
}

func localCAThumbprint(rootCAPath string) (string, error) {
	data, err := os.ReadFile(rootCAPath)
	if err != nil {
		return "", fmt.Errorf("leyendo CA local: %w", err)
	}

	var cert *x509.Certificate
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parsing CA local PEM: %w", err)
		}
	} else {
		cert, err = x509.ParseCertificate(data)
		if err != nil {
			return "", fmt.Errorf("parsing CA local DER: %w", err)
		}
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func windowsStoreHasThumbprint(scope string, thumbprint string) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, nil
	}
	thumb := strings.ToUpper(strings.TrimSpace(thumbprint))
	if thumb == "" {
		return false, nil
	}
	cmd := "$t='" + psQuotePS(thumb) + "'; " +
		"$hit=Get-ChildItem Cert:\\" + scope + "\\Root | Where-Object { $_.Thumbprint -eq $t }; " +
		"if ($hit) { Write-Output 'FOUND' }"
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return strings.Contains(string(out), "FOUND"), nil
}

func windowsImportRootCA(scope string, rootCAPath string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	path := psQuotePS(rootCAPath)
	cmd := "Import-Certificate -FilePath '" + path + "' -CertStoreLocation Cert:\\" + scope + "\\Root | Out-Null"
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func psQuotePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func installTrustMacOS(rootCAPath string) ([]string, error) {
	lines := []string{}
	thumb, err := localCAThumbprint(rootCAPath)
	if err != nil {
		return lines, err
	}
	lines = append(lines, fmt.Sprintf("[Trust] macOS huella CA local: %s", thumb))

	userOK, err := macOSKeychainHasThumbprint(thumb, macOSLoginKeychainPath())
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] macOS login keychain: no verificable (%v).", err))
	} else if userOK {
		lines = append(lines, "[Trust] macOS login keychain: ya confiado.")
	} else {
		if err := macOSImportRootCA(rootCAPath, macOSLoginKeychainPath()); err != nil {
			return lines, fmt.Errorf("error instalando en login keychain: %w", err)
		}
		lines = append(lines, "[Trust] macOS login keychain: instalado.")
	}

	if envBool("AUTOFIRMA_TRUST_SKIP_SYSTEM", false) {
		lines = append(lines, "[Trust] macOS System.keychain omitido por AUTOFIRMA_TRUST_SKIP_SYSTEM=1.")
		return lines, nil
	}
	if os.Geteuid() != 0 {
		lines = append(lines, "[Trust] macOS System.keychain: omitido (requiere root).")
		return lines, nil
	}

	systemPath := "/Library/Keychains/System.keychain"
	systemOK, err := macOSKeychainHasThumbprint(thumb, systemPath)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] macOS System.keychain: no verificable (%v).", err))
		return lines, nil
	}
	if systemOK {
		lines = append(lines, "[Trust] macOS System.keychain: ya confiado.")
		return lines, nil
	}
	if err := macOSImportRootCA(rootCAPath, systemPath); err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] macOS System.keychain: omitido (%v).", err))
		return lines, nil
	}
	lines = append(lines, "[Trust] macOS System.keychain: instalado.")
	return lines, nil
}

func localTLSTrustStatusMacOS(rootCAPath string) ([]string, error) {
	lines := []string{}
	thumb, err := localCAThumbprint(rootCAPath)
	if err != nil {
		return lines, err
	}
	lines = append(lines, fmt.Sprintf("[Trust] macOS huella CA local: %s", thumb))

	loginPath := macOSLoginKeychainPath()
	loginOK, err := macOSKeychainHasThumbprint(thumb, loginPath)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] macOS login keychain: no verificable (%v).", err))
	} else if loginOK {
		lines = append(lines, "[Trust] macOS login keychain: OK.")
	} else {
		lines = append(lines, "[Trust] macOS login keychain: FALTA.")
	}

	systemPath := "/Library/Keychains/System.keychain"
	systemOK, err := macOSKeychainHasThumbprint(thumb, systemPath)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[Trust] macOS System.keychain: no verificable (%v).", err))
	} else if systemOK {
		lines = append(lines, "[Trust] macOS System.keychain: OK.")
	} else {
		lines = append(lines, "[Trust] macOS System.keychain: FALTA.")
	}
	return lines, nil
}

func macOSLoginKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "login.keychain-db"
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db")
}

func macOSKeychainHasThumbprint(thumb string, keychainPath string) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, nil
	}
	cmd := exec.Command("security", "find-certificate", "-a", "-Z", keychainPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	want := strings.ToUpper(strings.TrimSpace(thumb))
	for _, line := range strings.Split(string(out), "\n") {
		up := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(up, "SHA-1 HASH:") {
			got := strings.TrimSpace(strings.TrimPrefix(up, "SHA-1 HASH:"))
			got = strings.ReplaceAll(got, " ", "")
			if got == want {
				return true, nil
			}
		}
	}
	return false, nil
}

func macOSImportRootCA(rootCAPath string, keychainPath string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	cmd := exec.Command(
		"security",
		"add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", keychainPath,
		rootCAPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
