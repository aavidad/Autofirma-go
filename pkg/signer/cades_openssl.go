// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autofirma-host/pkg/protocol"
)

func signCadesDetachedOpenSSL(inputFile, p12Path, p12Password string, options map[string]interface{}) ([]byte, error) {
	certPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cert-%d.pem", time.Now().UnixNano()))
	keyPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-key-%d.pem", time.Now().UnixNano()))
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cades-%d.p7s", time.Now().UnixNano()))
	defer os.Remove(certPEM)
	defer os.Remove(keyPEM)
	defer os.Remove(outFile)

	passArg := "pass:" + p12Password
	timeout := timeoutForBytes(
		fileSize(inputFile),
		"AUTOFIRMA_SIGN_TIMEOUT_SMALL_SEC",
		"AUTOFIRMA_SIGN_TIMEOUT_LARGE_SEC",
		defaultSignTimeoutSmallSec,
		defaultSignTimeoutLargeSec,
	)
	retries := retriesForBytes(fileSize(inputFile))

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
		"-sign",
		"-binary",
		"-in", inputFile,
		"-signer", certPEM,
		"-inkey", keyPEM,
		"-outform", "DER",
		"-out", outFile,
		"-md", resolveDigestName(options, "sha256"),
	}
	if strings.EqualFold(optionString(options, "mode", ""), "implicit") {
		args = append(args, "-nodetach")
	}
	if _, err := runCommandWithRetry(
		args,
		timeout,
		retries,
		"openssl cms sign",
	); err != nil {
		return nil, err
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer firma CAdES generada: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("firma CAdES vacia")
	}
	return out, nil
}

func verifyCadesDetachedOpenSSL(originalFile, signatureFile string) (*protocol.VerifyResult, error) {
	totalSize := fileSize(originalFile) + fileSize(signatureFile)
	timeout := timeoutForBytes(
		totalSize,
		"AUTOFIRMA_VERIFY_TIMEOUT_SMALL_SEC",
		"AUTOFIRMA_VERIFY_TIMEOUT_LARGE_SEC",
		defaultVerifyTimeoutSmallSec,
		defaultVerifyTimeoutLargeSec,
	)
	retries := retriesForBytes(totalSize)

	_, err := runCommandWithRetry(
		[]string{
			"openssl", "cms",
			"-verify",
			"-binary",
			"-inform", "DER",
			"-in", signatureFile,
			"-content", originalFile,
			"-noverify",
			"-out", os.DevNull,
		},
		timeout,
		retries,
		"openssl cms verify",
	)
	if err != nil {
		return nil, err
	}

	return &protocol.VerifyResult{
		Valid:     true,
		Format:    "cades",
		Algorithm: "sha256WithRSA",
		Reason:    strings.TrimSpace("Verificacion CAdES correcta con OpenSSL"),
	}, nil
}
