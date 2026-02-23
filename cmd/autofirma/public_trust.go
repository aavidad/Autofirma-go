// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PublicAdminCert represents a certificate to be installed
type PublicAdminCert struct {
	Name string
	URL  string
}

var publicAdminCerts = []PublicAdminCert{
	{"Camerfirma TSA 2016", "https://www.camerfirma.com/wp-content/uploads/2021/06/AC_CAMERFIRMA_TSA-2016.crt"},
	{"Camerfirma TSA II 2014", "https://www.camerfirma.com/wp-content/uploads/2021/06/Camerfirma_TSA_II-2014.crt"},
	{"Camerfirma TSU 2022", "https://www.camerfirma.com/wp-content/uploads/2021/06/AC_CAMERFIRMA_TSU-2022.crt"},
	{"Camerfirma Root CA", "https://www.camerfirma.com/wp-content/uploads/2021/06/Camerfirma_Root_CA.cer"},
	{"FNMT AC Raiz SHA256", "https://www.cert.fnmt.es/documents/104459/434351/AC_Raiz_FNMT-RCM_SHA256.cer"},
	{"ACCV Raiz 1", "https://www.accv.es/wp-content/uploads/cert/accv_raiz1.crt"},
	{"CATCert AOC Arrel G3", "https://vids.aoc.cat/aoc/AC_Arrel_AOC_G3.cer"},
	{"CATCert AOC EC-ACC G3", "https://vids.aoc.cat/aoc/EC-ACC_G3.cer"},
	{"Izenpe Root CA", "https://www.izenpe.eus/descargas/certificados/izenpe_raiz.crt"},
}

func installPublicAdminRoots() ([]string, error) {
	lines := []string{"[Trust] Iniciando instalación de raíces de Administraciones Públicas..."}

	tempDir, err := os.MkdirTemp("", "autofirma-tsa-certs-*")
	if err != nil {
		return lines, fmt.Errorf("error creando directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	downloadedCerts := []string{}
	for _, c := range publicAdminCerts {
		path := filepath.Join(tempDir, filepath.Base(c.URL))
		if strings.HasSuffix(strings.ToLower(path), ".cer") || strings.HasSuffix(strings.ToLower(path), ".crt") {
			// okay
		} else {
			path += ".crt"
		}

		log.Printf("[Trust] Descargando %s desde %s", c.Name, c.URL)
		if err := downloadFile(c.URL, path); err != nil {
			lines = append(lines, fmt.Sprintf("[Trust] ⚠️ No se pudo descargar %s: %v", c.Name, err))
			continue
		}
		downloadedCerts = append(downloadedCerts, path)
		lines = append(lines, fmt.Sprintf("[Trust] Descargado: %s", c.Name))
	}

	if len(downloadedCerts) == 0 {
		return lines, fmt.Errorf("no se pudo descargar ningún certificado")
	}

	// Instalación según OS
	switch runtime.GOOS {
	case "windows":
		for _, certPath := range downloadedCerts {
			name := filepath.Base(certPath)
			if err := windowsImportRootCA("CurrentUser", certPath); err != nil {
				lines = append(lines, fmt.Sprintf("[Trust] ❌ Error en Windows (User) para %s: %v", name, err))
			} else {
				lines = append(lines, fmt.Sprintf("[Trust] ✅ Instalado en Windows (User): %s", name))
			}
		}
	case "darwin":
		loginKP := macOSLoginKeychainPath()
		for _, certPath := range downloadedCerts {
			name := filepath.Base(certPath)
			if err := macOSImportRootCA(certPath, loginKP); err != nil {
				lines = append(lines, fmt.Sprintf("[Trust] ❌ Error en macOS (Login) para %s: %v", name, err))
			} else {
				lines = append(lines, fmt.Sprintf("[Trust] ✅ Instalado en macOS (Login): %s", name))
			}
		}
	case "linux":
		// NSS es común en Linux para navegadores
		for _, certPath := range downloadedCerts {
			name := filepath.Base(certPath)
			nssLines, nssErr := installCertInNSS(certPath, "AutoFirma TSA - "+name)
			lines = append(lines, nssLines...)
			if nssErr != nil {
				log.Printf("[Trust] Error NSS para %s: %v", name, nssErr)
			}
		}

		// Sistema Linux (requiere sudo/root)
		if os.Geteuid() == 0 {
			for _, certPath := range downloadedCerts {
				name := filepath.Base(certPath)
				if err := installSystemCertLinux(certPath, "autofirma-tsa-"+name); err != nil {
					lines = append(lines, fmt.Sprintf("[Trust] ❌ Error sistema Linux para %s: %v", name, err))
				} else {
					lines = append(lines, fmt.Sprintf("[Trust] ✅ Instalado en sistema Linux: %s", name))
				}
			}
		} else {
			lines = append(lines, "[Trust] Instalación en almacén del sistema Linux omitida (no es root).")
		}
	}

	return lines, nil
}

func downloadFile(url string, dest string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status código no OK: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// installCertInNSS es una versión adaptada de installTrustInNSSDatabases para un certificado genérico
func installCertInNSS(certPath string, nickname string) ([]string, error) {
	lines := []string{}
	if _, err := exec.LookPath("certutil"); err != nil {
		return lines, nil // No certutil, skip silently
	}

	dbs := discoverNSSDBs()
	if len(dbs) == 0 {
		return lines, nil
	}

	for _, dbPath := range dbs {
		// No comprobamos si ya existe para simplificar, o usamos un nickname único
		out, err := exec.Command("certutil", "-d", "sql:"+dbPath, "-A", "-t", "C,,", "-n", nickname, "-i", certPath).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(strings.ToLower(msg), "already exists") {
				continue
			}
			lines = append(lines, fmt.Sprintf("[Trust] NSS Error (%s): %v", dbPath, msg))
			continue
		}
		lines = append(lines, fmt.Sprintf("[Trust] NSS OK: %s (DB: %s)", nickname, filepath.Base(dbPath)))
	}
	return lines, nil
}

func installSystemCertLinux(certPath string, baseName string) error {
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		target := "/usr/local/share/ca-certificates/" + baseName + ".crt"
		if err := copyFile(certPath, target, 0o644); err != nil {
			return err
		}
		return exec.Command("update-ca-certificates").Run()
	}

	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		target := "/etc/pki/ca-trust/source/anchors/" + baseName + ".crt"
		if err := copyFile(certPath, target, 0o644); err != nil {
			return err
		}
		return exec.Command("update-ca-trust").Run()
	}

	return fmt.Errorf("no se encontró cargador de confianza del sistema")
}
