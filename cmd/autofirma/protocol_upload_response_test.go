// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/base64"
	"testing"
)

func TestIsStorageUploadOKResponse(t *testing.T) {
	cases := []string{
		"OK",
		" ok ",
		"SAVE_OK",
		"1",
		"1)",
		base64.StdEncoding.EncodeToString([]byte("OK")),
		base64.StdEncoding.EncodeToString([]byte("SAVE_OK")),
	}
	for _, in := range cases {
		if !isStorageUploadOKResponse(in) {
			t.Fatalf("debería aceptar respuesta de éxito: %q", in)
		}
	}
}

func TestIsStorageUploadOKResponseRejectsUnexpected(t *testing.T) {
	cases := []string{
		"",
		"KO",
		"ERROR",
		"2)",
		"NOK",
		base64.StdEncoding.EncodeToString([]byte("ERROR")),
	}
	for _, in := range cases {
		if isStorageUploadOKResponse(in) {
			t.Fatalf("no debería aceptar respuesta: %q", in)
		}
	}
}

