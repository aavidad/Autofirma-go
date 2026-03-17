// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"testing"
)

func TestBuildCertificateDialogLabelsUnique(t *testing.T) {
	certs := []protocol.Certificate{
		{ID: "a1", Subject: map[string]string{"CN": "Juan Perez"}, CanSign: true},
		{ID: "b2", Subject: map[string]string{"CN": "Juan Perez"}, CanSign: true},
	}
	got := buildCertificateDialogLabels(certs)
	if len(got) != 2 {
		t.Fatalf("número de etiquetas inesperado: %d", len(got))
	}
	if got[0] == got[1] {
		t.Fatalf("las etiquetas deben quedar desambiguadas cuando se repiten: %q", got)
	}
}

func TestBuildCertificateDialogLabelsFallback(t *testing.T) {
	certs := []protocol.Certificate{
		{ID: "certificado-interno", CanSign: true},
	}
	got := buildCertificateDialogLabels(certs)
	if len(got) != 1 {
		t.Fatalf("número de etiquetas inesperado: %d", len(got))
	}
	if got[0] == "" {
		t.Fatalf("la etiqueta no puede quedar vacía")
	}
}
