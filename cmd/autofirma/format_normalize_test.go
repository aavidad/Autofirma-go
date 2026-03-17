// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestNormalizeProtocolFormat(t *testing.T) {
	cases := map[string]string{
		"CAdEStri":            "cades",
		"PAdEStri":            "pades",
		"XAdEStri":            "xades",
		"PDF":                 "pades",
		"XMLDSIG Detached":    "xades",
		"CAdES-ASiC-S":        "cades",
		"CAdES-ASiC-S-tri":    "cades",
		"unknown-custom-format": "unknown-custom-format",
	}
	for in, want := range cases {
		if got := normalizeProtocolFormat(in); got != want {
			t.Fatalf("normalizeProtocolFormat(%q)=%q want=%q", in, got, want)
		}
	}
}
