// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package certstore

import (
	"autofirma-host/pkg/protocol"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ImportP12ToSystem imports a PKCS#12 file into the system's default certificate store.
func ImportP12ToSystem(p12Path, password string) error {
	switch runtime.GOOS {
	case "linux":
		// Chrome's NSS DB
		chromeDB := filepath.Join(os.Getenv("HOME"), ".pki/nssdb")
		if _, err := os.Stat(chromeDB); err == nil {
			if err := ImportP12ToNSS(chromeDB, p12Path, password); err != nil {
				log.Printf("[Import] Error importing to Chrome NSS: %v", err)
			}
		}
	case "windows":
		if err := ImportP12ToWindows(p12Path, password); err != nil {
			return err
		}
	case "darwin":
		if err := ImportP12ToMac(p12Path, password); err != nil {
			return err
		}
	}

	// Also try all Firefox profiles on all platforms
	firefoxProfiles := DiscoverFirefoxProfiles()
	for _, profile := range firefoxProfiles {
		log.Printf("[Import] Trying to import to Firefox profile: %s", profile)
		if err := ImportP12ToNSS(profile, p12Path, password); err != nil {
			log.Printf("[Import] Error importing to Firefox profile %s: %v", profile, err)
		}
	}

	return nil
}

// ImportP12ToNSS imports a PKCS#12 file into an NSS database using pk12util.
func ImportP12ToNSS(dbPath, p12Path, password string) error {
	// Escribir password en fichero temporal (evita exposición en argv / /proc)
	pwFile, err := os.CreateTemp("", "autofirma-pw-*")
	if err != nil {
		return fmt.Errorf("fallo al crear fichero de password temporal: %v", err)
	}
	pwPath := pwFile.Name()
	defer os.Remove(pwPath)
	os.Chmod(pwPath, 0600)
	if _, err := pwFile.WriteString(password); err != nil {
		pwFile.Close()
		return fmt.Errorf("fallo al escribir password temporal: %v", err)
	}
	pwFile.Close()

	// -i: input file, -d: database, -w: fichero con password del P12
	args := []string{"pk12util", "-i", p12Path, "-d", "sql:" + dbPath, "-w", pwPath}

	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try without sql: prefix if it failed (older certutil/pk12util versions or legacy DBs)
		args[3] = dbPath
		cmd = exec.Command(args[0], args[1:]...)
		_, err2 := cmd.CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("pk12util failed: %v (Output: %s)", err, string(output))
		}
	}
	log.Printf("[Import] NSS import success for %s", dbPath)
	return nil
}

// ImportP12ToWindows imports a PKCS#12 file into the Windows MY store using PowerShell.
func ImportP12ToWindows(p12Path, password string) error {
	// Import-PfxCertificate -FilePath "path.p12" -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword
	ps := fmt.Sprintf("$sec = ConvertTo-SecureString '%s' -AsPlainText -Force; Import-PfxCertificate -FilePath '%s' -CertStoreLocation Cert:\\CurrentUser\\My -Password $sec",
		strings.ReplaceAll(password, "'", "''"),
		strings.ReplaceAll(p12Path, "'", "''"))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PowerShell Import-PfxCertificate failed: %v (Output: %s)", err, string(output))
	}
	log.Printf("[Import] Windows system store import success")
	return nil
}

// ImportP12ToMac imports a PKCS#12 file into the macOS login keychain using security import.
func ImportP12ToMac(p12Path, password string) error {
	// security import "path.p12" -k ~/Library/Keychains/login.keychain -P "password" -T /usr/bin/codesign ...
	// We use -A to allow all applications to access it, similar to how FNMT installers do it?
	// Or maybe just -T to specify known apps.
	args := []string{"security", "import", p12Path, "-P", password}

	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("security import failed: %v (Output: %s)", err, string(output))
	}
	log.Printf("[Import] macOS Keychain import success")
	return nil
}

// DiscoverFirefoxProfiles returns a list of paths to Firefox profile NSS databases.
func DiscoverFirefoxProfiles() []string {
	var base string
	switch runtime.GOOS {
	case "linux":
		base = filepath.Join(os.Getenv("HOME"), ".mozilla/firefox")
	case "windows":
		base = filepath.Join(os.Getenv("APPDATA"), "Mozilla/Firefox/Profiles")
	case "darwin":
		base = filepath.Join(os.Getenv("HOME"), "Library/Application Support/Firefox/Profiles")
	default:
		return nil
	}

	if _, err := os.Stat(base); os.IsNotExist(err) {
		return nil
	}

	// In newer versions, Firefox has profiles in the base dir if we are lucky, or in profile folders
	var profiles []string

	// Check if base itself is a profile (unlikely) or list subdirs
	files, err := os.ReadDir(base)
	if err != nil {
		return nil
	}

	for _, f := range files {
		if f.IsDir() {
			profilePath := filepath.Join(base, f.Name())
			// Check if it contains cert9.db (SQLite) or cert8.db (Berkeley DB)
			if _, err := os.Stat(filepath.Join(profilePath, "cert9.db")); err == nil {
				profiles = append(profiles, profilePath)
			} else if _, err := os.Stat(filepath.Join(profilePath, "cert8.db")); err == nil {
				profiles = append(profiles, profilePath)
			}
		}
	}

	return profiles
}

// getNSSCertificates uses certutil to list user certificates in an NSS database.
func getNSSCertificates(dbPath string) ([]protocol.Certificate, error) {
	var certs []protocol.Certificate
	seen := make(map[string]bool)

	cmd := exec.Command("certutil", "-L", "-d", "sql:"+dbPath)
	output, err := cmd.Output()
	if err != nil {
		// Try without sql: prefix
		cmd = exec.Command("certutil", "-L", "-d", dbPath)
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("certutil failed: %v", err)
		}
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i < 2 || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		trustAttrs := parts[len(parts)-1]
		nickname := strings.Join(parts[:len(parts)-1], " ")
		nickname = strings.TrimSpace(nickname)

		if nickname == "" || nickname == "(NULL)" {
			continue
		}
		if !strings.Contains(trustAttrs, "u") {
			continue
		}

		cert, err := getNSSCertificateByNickname(dbPath, nickname)
		if err == nil {
			if !seen[cert.Fingerprint] {
				seen[cert.Fingerprint] = true
				cert.Nickname = nickname
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}

func getNSSCertificateByNickname(dbPath, nickname string) (protocol.Certificate, error) {
	cmd := exec.Command("certutil", "-L", "-d", "sql:"+dbPath, "-n", nickname, "-a")
	output, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("certutil", "-L", "-d", dbPath, "-n", nickname, "-a")
		output, err = cmd.Output()
		if err != nil {
			return protocol.Certificate{}, fmt.Errorf("failed to export cert: %v", err)
		}
	}

	block, _ := pem.Decode(output)
	if block == nil {
		return protocol.Certificate{}, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return protocol.Certificate{}, err
	}

	return ParseCertificate(cert, "nss"), nil
}
