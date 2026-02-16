// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto"
	"testing"
)

func TestResolveDigestFromOptions(t *testing.T) {
	tests := []struct {
		name     string
		options  map[string]interface{}
		wantName string
		wantHash crypto.Hash
	}{
		{
			name:     "sha1withrsa",
			options:  map[string]interface{}{"algorithm": "SHA1withRSA"},
			wantName: "sha1",
			wantHash: crypto.SHA1,
		},
		{
			name:     "sha512withecdsa",
			options:  map[string]interface{}{"algorithm": "SHA512withECDSA"},
			wantName: "sha512",
			wantHash: crypto.SHA512,
		},
		{
			name:     "precalculated",
			options:  map[string]interface{}{"precalculatedHashAlgorithm": "SHA384"},
			wantName: "sha384",
			wantHash: crypto.SHA384,
		},
		{
			name:     "unsupported",
			options:  map[string]interface{}{"algorithm": "MD5withRSA"},
			wantName: "",
			wantHash: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotHash := resolveDigestFromOptions(tt.options)
			if gotName != tt.wantName || gotHash != tt.wantHash {
				t.Fatalf("resultado inesperado: name=%q hash=%v", gotName, gotHash)
			}
		})
	}
}

func TestResolveDigestOID(t *testing.T) {
	if got := resolveDigestOID(map[string]interface{}{"algorithm": "SHA1withRSA"}, "fallback"); got != "1.3.14.3.2.26" {
		t.Fatalf("OID SHA1 inesperado: %s", got)
	}
	if got := resolveDigestOID(map[string]interface{}{"algorithm": "SHA512withRSA"}, "fallback"); got != "2.16.840.1.101.3.4.2.3" {
		t.Fatalf("OID SHA512 inesperado: %s", got)
	}
	if got := resolveDigestOID(map[string]interface{}{"algorithm": "MD5"}, "fallback"); got != "fallback" {
		t.Fatalf("fallback OID inesperado: %s", got)
	}
}
