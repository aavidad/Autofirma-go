// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SignPKCS1 signs arbitrary pre-sign data with the selected certificate private key.
// It returns the PKCS#1 signature encoded in standard Base64.
func SignPKCS1(preSignData []byte, certificateID string, algorithm string) (string, error) {
	if len(preSignData) == 0 {
		return "", fmt.Errorf("datos de prefirma vacios")
	}
	cert, nickname, err := getCertificateByID(strings.TrimSpace(certificateID))
	if err != nil || cert == nil {
		return "", fmt.Errorf("certificado no encontrado: %v", err)
	}

	tmpPassword := fmt.Sprintf("auto-pk1-%d-%d", time.Now().UnixNano(), os.Getpid())
	p12Path, err := exportCertificateToP12(nickname, tmpPassword)
	if err != nil {
		return "", fmt.Errorf("fallo al exportar certificado: %v", err)
	}
	defer os.Remove(p12Path)

	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pk1-in-%d.bin", time.Now().UnixNano()))
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pk1-out-%d.bin", time.Now().UnixNano()))
	keyPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pk1-key-%d.pem", time.Now().UnixNano()))
	defer os.Remove(inFile)
	defer os.Remove(outFile)
	defer os.Remove(keyPEM)

	if err := os.WriteFile(inFile, preSignData, 0o600); err != nil {
		return "", fmt.Errorf("fallo al escribir datos de entrada: %v", err)
	}

	timeout := timeoutForBytes(int64(len(preSignData)), "AUTOFIRMA_SIGN_TIMEOUT_SMALL_SEC", "AUTOFIRMA_SIGN_TIMEOUT_LARGE_SEC", defaultSignTimeoutSmallSec, defaultSignTimeoutLargeSec)
	retries := retriesForBytes(int64(len(preSignData)))
	passArg := "pass:" + tmpPassword
	if _, err := runCommandWithRetry(
		[]string{"openssl", "pkcs12", "-in", p12Path, "-passin", passArg, "-nocerts", "-nodes", "-out", keyPEM},
		timeout,
		retries,
		"openssl pkcs12 key pkcs1",
	); err != nil {
		return "", fmt.Errorf("fallo extrayendo clave privada: %v", err)
	}

	digest := resolveDigestName(map[string]interface{}{"algorithm": algorithm}, "sha256")
	if _, err := runCommandWithRetry(
		[]string{"openssl", "dgst", "-" + digest, "-sign", keyPEM, "-out", outFile, inFile},
		timeout,
		retries,
		"openssl dgst pkcs1",
	); err != nil {
		return "", fmt.Errorf("fallo generando PKCS#1: %v", err)
	}

	sig, err := os.ReadFile(outFile)
	if err != nil {
		return "", fmt.Errorf("fallo leyendo firma PKCS#1: %v", err)
	}
	if len(sig) == 0 {
		return "", fmt.Errorf("firma PKCS#1 vacia")
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
