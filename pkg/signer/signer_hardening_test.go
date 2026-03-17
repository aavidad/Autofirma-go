// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"strings"
	"testing"
	"time"

	"autofirma-host/pkg/protocol"
)

func TestNewTemporaryPasswordHexLength(t *testing.T) {
	t.Parallel()

	password, err := newTemporaryPassword()
	if err != nil {
		t.Fatalf("newTemporaryPassword error: %v", err)
	}
	if len(password) != 48 {
		t.Fatalf("longitud inesperada: got=%d want=48", len(password))
	}
	if _, err := sanitizeWindowsThumbprint(password); err != nil {
		t.Fatalf("la contraseña temporal debe ser hex válida: %v", err)
	}
}

func TestSanitizeWindowsThumbprintNormalizaYValida(t *testing.T) {
	t.Parallel()

	got, err := sanitizeWindowsThumbprint("ab:cd ef 01")
	if err != nil {
		t.Fatalf("sanitizeWindowsThumbprint error: %v", err)
	}
	if got != "ABCDEF01" {
		t.Fatalf("thumbprint normalizado inesperado: %q", got)
	}

	if _, err := sanitizeWindowsThumbprint("ZZ:11"); err == nil {
		t.Fatal("se esperaba error con thumbprint no hexadecimal")
	}
}

func TestParseCertificateNotAfterDesdeValidTo(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	got, ok := parseCertificateNotAfter(&protocol.Certificate{
		ValidTo: want.Format(time.RFC3339),
	})
	if !ok {
		t.Fatal("se esperaba parsear ValidTo")
	}
	if !got.Equal(want) {
		t.Fatalf("fecha inesperada: got=%s want=%s", got, want)
	}

	if _, ok := parseCertificateNotAfter(&protocol.Certificate{ValidTo: strings.Repeat("x", 4)}); ok {
		t.Fatal("no se esperaba parsear una fecha inválida")
	}
}
