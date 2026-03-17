// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestIsRequestedVersionGreater(t *testing.T) {
	cases := []struct {
		req     string
		cur     string
		greater bool
	}{
		{req: "1.7.0", cur: "1.6.5", greater: true},
		{req: "1.6.5", cur: "1.6.5", greater: false},
		{req: "1.6.4", cur: "1.6.5", greater: false},
		{req: "1.7.0.1", cur: "1.7.0", greater: true},
		{req: "1.7 RC1", cur: "1.7", greater: false},
		{req: "1.7a", cur: "1.7", greater: true},
	}
	for _, tc := range cases {
		got, err := isRequestedVersionGreater(tc.req, tc.cur)
		if err != nil {
			t.Fatalf("error inesperado req=%q cur=%q: %v", tc.req, tc.cur, err)
		}
		if got != tc.greater {
			t.Fatalf("comparacion inesperada req=%q cur=%q -> %t (esperado %t)", tc.req, tc.cur, got, tc.greater)
		}
	}
}

func TestIsRequestedVersionGreaterInvalidInput(t *testing.T) {
	if _, err := isRequestedVersionGreater("1..2", "1.0"); err == nil {
		t.Fatalf("se esperaba error con version invalida")
	}
}
