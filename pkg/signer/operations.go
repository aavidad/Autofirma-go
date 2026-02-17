// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"autofirma-host/pkg/applog"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

var signDataCompatFallbackFunc = SignData

// CoSignData performs a best-effort local co-sign operation.
// Current native support is implemented for CAdES signatures.
func CoSignData(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
	format = normalizeSignFormat(format)
	log.Printf("[Signer] CoSign start cert=%s format=%s pin_set=%t opts=%s %s",
		applog.MaskID(certificateID),
		format,
		strings.TrimSpace(pin) != "",
		applog.OptionKeys(options),
		applog.SecretMeta("dataB64", dataB64),
	)

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", fmt.Errorf("datos base64 inválidos: %v", err)
	}
	format = resolveSignFormat(format, data)
	if !strings.EqualFold(format, "cades") {
		log.Printf("[Signer] CoSign fallback to SignData for format=%s", format)
		return signDataCompatFallbackFunc(dataB64, certificateID, pin, format, options)
	}
	cert, nickname, err := getCertificateByID(certificateID, options)
	if err != nil {
		return "", fmt.Errorf("certificado no encontrado: %v", err)
	}

	tempPassword := fmt.Sprintf("auto-%d-%d", time.Now().UnixNano(), os.Getpid())
	p12Path, err := exportCertificateToP12(nickname, tempPassword)
	if err != nil {
		if runtime.GOOS == "windows" && isNonExportableKeyError(err) {
			return "", fmt.Errorf("el certificado seleccionado no permite exportar su clave privada")
		}
		return "", fmt.Errorf("fallo al exportar certificado: %v", err)
	}
	defer os.Remove(p12Path)

	signedData, err := coSignCadesOpenSSL(data, p12Path, tempPassword, options)
	if err != nil {
		return "", fmt.Errorf("cofirma CAdES fallida (openssl): %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(signedData)
	log.Printf("[Signer] CoSign success cert=%s format=%s %s", applog.MaskID(cert.ID), format, applog.SecretMeta("signatureB64", sig))
	return sig, nil
}

// CounterSignData keeps explicit behavior while countersign native backend is pending.
func CounterSignData(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
	format = normalizeSignFormat(format)

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", fmt.Errorf("datos base64 inválidos: %v", err)
	}
	format = resolveSignFormat(format, data)
	if !strings.EqualFold(format, "cades") {
		log.Printf("[Signer] CounterSign fallback to SignData for format=%s", format)
		return signDataCompatFallbackFunc(dataB64, certificateID, pin, format, options)
	}
	cert, _, err := getCertificateByID(certificateID, options)
	if err != nil {
		return "", fmt.Errorf("certificado no encontrado: %v", err)
	}
	algorithm := optionString(options, "algorithm", "SHA256withRSA")
	target := optionString(options, "target", "")
	targetSigners := optionString(options, "targets", "")
	if targetSigners == "" {
		targetSigners = optionString(options, "signers", "")
	}
	countersigned, err := counterSignCadesDER(data, cert, certificateID, algorithm, target, targetSigners)
	if err != nil {
		return "", fmt.Errorf("contrafirma CAdES fallida (go): %v", err)
	}
	return base64.StdEncoding.EncodeToString(countersigned), nil
}
