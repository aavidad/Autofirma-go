// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func coSignCadesOpenSSL(inputSignature []byte, p12Path, p12Password string, options map[string]interface{}) ([]byte, error) {
	certPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cert-%d.pem", time.Now().UnixNano()))
	keyPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-key-%d.pem", time.Now().UnixNano()))
	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cades-in-%d.p7s", time.Now().UnixNano()))
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cades-out-%d.p7s", time.Now().UnixNano()))
	defer os.Remove(certPEM)
	defer os.Remove(keyPEM)
	defer os.Remove(inFile)
	defer os.Remove(outFile)

	if err := os.WriteFile(inFile, inputSignature, 0o600); err != nil {
		return nil, fmt.Errorf("no se pudo escribir firma de entrada: %v", err)
	}

	passArg := "pass:" + p12Password
	timeout := timeoutForBytes(
		int64(len(inputSignature)),
		"AUTOFIRMA_SIGN_TIMEOUT_SMALL_SEC",
		"AUTOFIRMA_SIGN_TIMEOUT_LARGE_SEC",
		defaultSignTimeoutSmallSec,
		defaultSignTimeoutLargeSec,
	)
	retries := retriesForBytes(int64(len(inputSignature)))

	if _, err := runCommandWithRetry(
		[]string{"openssl", "pkcs12", "-in", p12Path, "-passin", passArg, "-clcerts", "-nokeys", "-out", certPEM},
		timeout,
		retries,
		"openssl pkcs12 cert",
	); err != nil {
		return nil, err
	}
	if _, err := runCommandWithRetry(
		[]string{"openssl", "pkcs12", "-in", p12Path, "-passin", passArg, "-nocerts", "-nodes", "-out", keyPEM},
		timeout,
		retries,
		"openssl pkcs12 key",
	); err != nil {
		return nil, err
	}

	args := []string{
		"openssl", "cms",
		"-resign",
		"-binary",
		"-inform", "DER",
		"-in", inFile,
		"-signer", certPEM,
		"-inkey", keyPEM,
		"-outform", "DER",
		"-out", outFile,
		"-md", resolveDigestName(options, "sha256"),
	}
	if _, err := runCommandWithRetry(args, timeout, retries, "openssl cms resign"); err != nil {
		return nil, err
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer cofirma CAdES generada: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("cofirma CAdES vacia")
	}
	return out, nil
}
