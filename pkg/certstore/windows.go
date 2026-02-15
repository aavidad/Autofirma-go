// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build windows
// +build windows

package certstore

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"autofirma-host/pkg/protocol"
)

type windowsStoreCert struct {
	Thumbprint   string `json:"Thumbprint"`
	Subject      string `json:"Subject"`
	Issuer       string `json:"Issuer"`
	SerialNumber string `json:"SerialNumber"`
	NotBefore    string `json:"NotBefore"`
	NotAfter     string `json:"NotAfter"`
	RawData      string `json:"RawData"`
}

func getSystemCertificatesImpl() ([]protocol.Certificate, error) {
	// Read personal certificates that have private key in CurrentUser store.
	ps := `$ErrorActionPreference='Stop'; ` +
		`$certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -eq $true } | ` +
		`Select-Object Thumbprint,Subject,Issuer,SerialNumber,NotBefore,NotAfter,@{Name='RawData';Expression={[System.Convert]::ToBase64String($_.RawData)}}; ` +
		`$certs | ConvertTo-Json -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("powershell certificate query failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	data := strings.TrimSpace(string(out))
	if data == "" || data == "null" {
		return []protocol.Certificate{}, nil
	}

	storeCerts, err := parseWindowsStoreJSON(data)
	if err != nil {
		return nil, err
	}

	result := make([]protocol.Certificate, 0, len(storeCerts))
	for _, sc := range storeCerts {
		der, err := base64.StdEncoding.DecodeString(sc.RawData)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		pc := ParseCertificate(cert, "windows")
		pc.Nickname = normalizeThumbprint(sc.Thumbprint)

		// Keep explicit serial/times from store if available.
		if strings.TrimSpace(sc.SerialNumber) != "" {
			pc.SerialNumber = strings.TrimSpace(sc.SerialNumber)
		}
		if t, ok := parseWindowsDate(sc.NotBefore); ok {
			pc.ValidFrom = t.Format("2006-01-02T15:04:05Z")
		}
		if t, ok := parseWindowsDate(sc.NotAfter); ok {
			pc.ValidTo = t.Format("2006-01-02T15:04:05Z")
		}

		// Subject/issuer are already in parsed certificate; keep those canonical values.
		result = append(result, pc)
	}

	return result, nil
}

func parseWindowsStoreJSON(raw string) ([]windowsStoreCert, error) {
	// ConvertTo-Json returns object when there is a single item.
	var many []windowsStoreCert
	if err := json.Unmarshal([]byte(raw), &many); err == nil {
		return many, nil
	}

	var one windowsStoreCert
	if err := json.Unmarshal([]byte(raw), &one); err == nil {
		return []windowsStoreCert{one}, nil
	}

	return nil, fmt.Errorf("unable to parse windows certificate store JSON")
}

func normalizeThumbprint(v string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), " ", ""))
}

func parseWindowsDate(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	// Most PowerShell date serializations map to RFC3339 when compressed.
	t, err := time.Parse(time.RFC3339, v)
	if err == nil {
		return t, true
	}
	return time.Time{}, false
}
