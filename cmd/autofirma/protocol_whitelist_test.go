// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestValidateSigningServerURL_AllowAndDeny(t *testing.T) {
	t.Setenv("AUTOFIRMA_ALLOWED_SIGN_DOMAINS", "*.gob.es,*.dipgra.es,localhost,127.0.0.1")
	t.Setenv("AUTOFIRMA_DOMAIN_TRUST_AUTO_ALLOW", "1")

	if err := validateSigningServerURL("https://afirmasignature.sededgsfp.gob.es/afirma-signature-storage/StorageService", "stservlet"); err != nil {
		t.Fatalf("debería permitir host gob.es: %v", err)
	}
	if err := validateSigningServerURL("https://autofirma.dipgra.es/version.json", "stservlet"); err != nil {
		t.Fatalf("debería permitir host dipgra.es: %v", err)
	}
	if err := validateSigningServerURL("http://localhost:63117/StorageService", "stservlet"); err != nil {
		t.Fatalf("debería permitir localhost en http: %v", err)
	}
	if err := validateSigningServerURL("https://evil.example.com/StorageService", "stservlet"); err == nil {
		t.Fatalf("debería bloquear host fuera de lista blanca")
	}
}

func TestValidateSigningServerURL_RequireHTTPSForRemote(t *testing.T) {
	t.Setenv("AUTOFIRMA_ALLOWED_SIGN_DOMAINS", "*.gob.es")
	t.Setenv("AUTOFIRMA_DOMAIN_TRUST_AUTO_ALLOW", "1")
	if err := validateSigningServerURL("http://afirmasignature.sededgsfp.gob.es/StorageService", "stservlet"); err == nil {
		t.Fatalf("debería exigir https para host remoto")
	}
}
