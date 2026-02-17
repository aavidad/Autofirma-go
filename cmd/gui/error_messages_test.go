// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildAfirmaUploadErrorMessageHTTP503(t *testing.T) {
	err := errors.New("java-style upload HTTP error: 503 service unavailable")
	msg := buildAfirmaUploadErrorMessage(err, "https://afirma.ejemplo.es/storage", "")
	if !strings.Contains(strings.ToLower(msg), "incidencia temporal") {
		t.Fatalf("mensaje inesperado para HTTP 503: %q", msg)
	}
	if !strings.Contains(msg, "afirma.ejemplo.es") {
		t.Fatalf("debe incluir endpoint de @firma: %q", msg)
	}
}

func TestBuildAfirmaUploadErrorMessageDNS(t *testing.T) {
	err := errors.New("java-style upload failed: Post \"https://afirma.invalid\": dial tcp: lookup afirma.invalid: no such host")
	msg := buildAfirmaUploadErrorMessage(err, "https://afirma.invalid/storage", "")
	if !strings.Contains(strings.ToLower(msg), "dns") {
		t.Fatalf("mensaje inesperado para DNS: %q", msg)
	}
}

func TestBuildUserSignErrorMessageAuthToken(t *testing.T) {
	err := errors.New("pkcs11 token login failed: PIN incorrect")
	msg := buildUserSignErrorMessage(err, "cades")
	if !strings.Contains(strings.ToLower(msg), "no se pudo autenticar el certificado") {
		t.Fatalf("mensaje inesperado para fallo de autenticacion token: %q", msg)
	}
}

func TestBuildUserSignErrorMessageCertNotFound(t *testing.T) {
	err := errors.New("certificado no encontrado: certificado no encontrado")
	msg := buildUserSignErrorMessage(err, "pades")
	if !strings.Contains(strings.ToLower(msg), "certificado seleccionado") {
		t.Fatalf("mensaje inesperado para certificado no encontrado: %q", msg)
	}
}
