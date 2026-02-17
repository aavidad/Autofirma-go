// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package certstore

import (
	"autofirma-host/pkg/protocol"
	"testing"
)

func TestAppendUniqueCertificatesDeduplicatesByFingerprint(t *testing.T) {
	seen := map[string]struct{}{}
	dst := make([]protocol.Certificate, 0, 4)

	src := []protocol.Certificate{
		{ID: "a", Fingerprint: "ABCDEF", Content: []byte{0x01}},
		{ID: "b", Fingerprint: "abcdef", Content: []byte{0x02}}, // same fp, different case
		{ID: "c", Fingerprint: "123456", Content: []byte{0x03}},
	}

	got := appendUniqueCertificates(dst, seen, src)
	if len(got) != 2 {
		t.Fatalf("se esperaban 2 certificados unicos por fingerprint, obtenido=%d (%#v)", len(got), got)
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Fatalf("orden/seleccion inesperada tras deduplicar por fingerprint: %#v", got)
	}
}

func TestAppendUniqueCertificatesDeduplicatesByDERHashWhenNoFingerprint(t *testing.T) {
	seen := map[string]struct{}{}
	dst := make([]protocol.Certificate, 0, 4)

	src := []protocol.Certificate{
		{ID: "a", Content: []byte{0x30, 0x82, 0x01}},
		{ID: "b", Content: []byte{0x30, 0x82, 0x01}}, // same DER
		{ID: "c", Content: []byte{0x30, 0x82, 0x02}},
	}

	got := appendUniqueCertificates(dst, seen, src)
	if len(got) != 2 {
		t.Fatalf("se esperaban 2 certificados unicos por DER hash, obtenido=%d (%#v)", len(got), got)
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Fatalf("orden/seleccion inesperada tras deduplicar por DER hash: %#v", got)
	}
}
