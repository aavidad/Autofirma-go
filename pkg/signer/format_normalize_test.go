// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import "testing"

func TestNormalizeSignFormat(t *testing.T) {
	cases := map[string]string{
		"CAdEStri":            "cades",
		"PAdEStri":            "pades",
		"XAdEStri":            "xades",
		"PDF":                 "pades",
		"XMLDSIG Enveloped":   "xades",
		"CAdES-ASiC-S":        "cades",
		"AUTO":                "auto",
		"custom-format":       "custom-format",
	}
	for in, want := range cases {
		if got := normalizeSignFormat(in); got != want {
			t.Fatalf("normalizeSignFormat(%q)=%q want=%q", in, got, want)
		}
	}
}

func TestResolveSignFormatAuto(t *testing.T) {
	cases := []struct {
		name   string
		format string
		data   []byte
		want   string
	}{
		{name: "auto pdf", format: "AUTO", data: []byte("%PDF-1.7 body"), want: "pades"},
		{name: "auto xml", format: "auto", data: []byte("   <xml>body</xml>"), want: "xades"},
		{name: "auto fallback cades", format: "auto", data: []byte("binary-content"), want: "cades"},
		{name: "empty fallback cades", format: "", data: []byte(""), want: "cades"},
		{name: "explicit keeps format", format: "XAdES", data: []byte("%PDF-1.7 body"), want: "xades"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveSignFormat(tc.format, tc.data); got != tc.want {
				t.Fatalf("resolveSignFormat(%q)= %q want=%q", tc.format, got, tc.want)
			}
		})
	}
}
