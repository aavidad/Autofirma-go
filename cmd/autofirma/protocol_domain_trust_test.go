// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"path/filepath"
	"testing"
)

func resetTrustedDomainsForTest() {
	trustedSigningDomainsState.mu.Lock()
	trustedSigningDomainsState.loaded = false
	trustedSigningDomainsState.items = nil
	trustedSigningDomainsState.mu.Unlock()
}

func TestEnsureTrustedSigningDomain_FirstUseAndRemember(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AUTOFIRMA_DOMAIN_TRUST_AUTO_ALLOW", "")

	resetTrustedDomainsForTest()
	orig := confirmFirstDomainUseFunc
	defer func() {
		confirmFirstDomainUseFunc = orig
		resetTrustedDomainsForTest()
	}()

	calls := 0
	confirmFirstDomainUseFunc = func(host string) (bool, error) {
		calls++
		return true, nil
	}

	host := "afirmasignature.sededgsfp.gob.es"
	if err := ensureTrustedSigningDomain(host); err != nil {
		t.Fatalf("fallo inesperado primera confianza: %v", err)
	}
	if calls != 1 {
		t.Fatalf("se esperaba 1 diálogo de confianza, obtenido=%d", calls)
	}
	if err := ensureTrustedSigningDomain(host); err != nil {
		t.Fatalf("fallo inesperado dominio ya confiado: %v", err)
	}
	if calls != 1 {
		t.Fatalf("no debería volver a pedir confianza, calls=%d", calls)
	}
	if path := trustedSigningDomainsPath(); path == "" {
		t.Fatalf("ruta de dominios confiados vacía")
	} else if filepath.Base(path) != "trusted_sign_domains.json" {
		t.Fatalf("ruta inesperada de dominios confiados: %s", path)
	}
}

func TestEnsureTrustedSigningDomain_Reject(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AUTOFIRMA_DOMAIN_TRUST_AUTO_ALLOW", "")
	resetTrustedDomainsForTest()
	orig := confirmFirstDomainUseFunc
	defer func() {
		confirmFirstDomainUseFunc = orig
		resetTrustedDomainsForTest()
	}()

	confirmFirstDomainUseFunc = func(host string) (bool, error) {
		return false, nil
	}
	if err := ensureTrustedSigningDomain("rechazado.sededgsfp.gob.es"); err == nil {
		t.Fatalf("se esperaba error por rechazo del usuario")
	}
}
