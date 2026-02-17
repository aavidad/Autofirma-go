// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	pdfsign "github.com/digitorus/pdfsign/sign"
)

func TestBuildPadesVisibleSignatureTextIncludesCNAndFNMT(t *testing.T) {
	ts := time.Date(2026, 2, 17, 13, 45, 59, 0, time.Local)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "Juan Perez"}}

	got := buildPadesVisibleSignatureText(cert, ts)
	if !strings.Contains(got, "CN=Juan Perez") {
		t.Fatalf("texto visible sin CN esperado: %q", got)
	}
	if !strings.Contains(got, "Firmado el 17/02/2026 13:45:59 por un certificado de la FNMT") {
		t.Fatalf("texto visible sin linea de firma FNMT esperada: %q", got)
	}
}

func TestApplyPadesAppearanceOptionsSetsVisibleText(t *testing.T) {
	ts := time.Date(2026, 2, 17, 13, 45, 59, 0, time.Local)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "CN Prueba"}}
	sd := &pdfsign.SignData{}

	applyPadesAppearanceOptions(sd, map[string]interface{}{
		"visibleSignature": true,
		"page":             uint32(1),
		"x":                100.0,
		"y":                200.0,
		"width":            220.0,
		"height":           80.0,
	}, cert, ts)

	if !sd.Appearance.Visible {
		t.Fatalf("firma visible no activada")
	}
	if !strings.Contains(sd.Appearance.Text, "CN=CN Prueba") || !strings.Contains(sd.Appearance.Text, "FNMT") {
		t.Fatalf("texto visible inesperado: %q", sd.Appearance.Text)
	}
}
