// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"testing"
)

func TestGetCertificateByIDUsesStoreOptionsForLookup(t *testing.T) {
	origDefault := getSystemCertificatesFunc
	origOpts := getSystemCertificatesWithOptionsFunc
	defer func() {
		getSystemCertificatesFunc = origDefault
		getSystemCertificatesWithOptionsFunc = origOpts
	}()

	withOptionsCalled := false
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return nil, nil
	}
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		withOptionsCalled = true
		if opts.IncludePKCS11 {
			t.Fatalf("con default store MOZ_UNI debe omitirse PKCS11")
		}
		return []protocol.Certificate{{
			ID:       "cert-1",
			Nickname: "nick-1",
		}}, nil
	}

	_, nick, err := getCertificateByID("cert-1", map[string]interface{}{
		"_defaultKeyStore": "MOZ_UNI",
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !withOptionsCalled {
		t.Fatalf("se esperaba lookup con opciones de almacén")
	}
	if nick != "nick-1" {
		t.Fatalf("nickname inesperado: %q", nick)
	}
}

func TestGetCertificateByIDFallsBackToNicknameCertificate(t *testing.T) {
	origDefault := getSystemCertificatesFunc
	origOpts := getSystemCertificatesWithOptionsFunc
	defer func() {
		getSystemCertificatesFunc = origDefault
		getSystemCertificatesWithOptionsFunc = origOpts
	}()

	const certID = "cert-2"
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		return []protocol.Certificate{{
			ID:          certID,
			Fingerprint: "ABCDEF",
			Content:     []byte{0x01, 0x02, 0x03},
			Source:      "smartcard",
		}}, nil
	}
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{
			ID:          certID,
			Fingerprint: "ABCDEF",
			Content:     []byte{0x01, 0x02, 0x03},
			Nickname:    "nss-nick",
			Source:      "system",
		}}, nil
	}

	_, nick, err := getCertificateByID(certID, map[string]interface{}{
		"_defaultKeyStore": "PKCS11",
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if nick != "nss-nick" {
		t.Fatalf("se esperaba fallback por nickname en lookup por defecto, obtenido=%q", nick)
	}
}

func TestResolveCertstoreOptionsPKCS11Hints(t *testing.T) {
	store, hints, includePKCS11, hasOverride := resolveCertstoreOptions(map[string]interface{}{
		"_defaultKeyStore":    "PKCS11",
		"_defaultKeyStoreLib": "/opt/lib/a.so;/opt/lib/b.so,/opt/lib/a.so",
	})
	if store != "PKCS11" {
		t.Fatalf("store inesperado: %q", store)
	}
	if !includePKCS11 {
		t.Fatalf("PKCS11 debe permanecer habilitado")
	}
	if !hasOverride {
		t.Fatalf("debe marcar override cuando hay pistas de almacén")
	}
	if len(hints) != 2 || hints[0] != "/opt/lib/a.so" || hints[1] != "/opt/lib/b.so" {
		t.Fatalf("hints inesperados: %#v", hints)
	}
}

func TestResolveCertstoreOptionsDisableExternalStoresBoolDisablesPKCS11(t *testing.T) {
	store, hints, includePKCS11, hasOverride := resolveCertstoreOptions(map[string]interface{}{
		"_disableOpeningExternalStores": true,
	})
	if store != "" {
		t.Fatalf("store inesperado: %q", store)
	}
	if len(hints) != 0 {
		t.Fatalf("hints inesperados: %#v", hints)
	}
	if includePKCS11 {
		t.Fatalf("disableOpeningExternalStores=true debe desactivar PKCS11")
	}
	if !hasOverride {
		t.Fatalf("se esperaba override por disableOpeningExternalStores")
	}
}

func TestResolveCertstoreOptionsDisableExternalStoresDoesNotOverrideExplicitPKCS11(t *testing.T) {
	store, hints, includePKCS11, hasOverride := resolveCertstoreOptions(map[string]interface{}{
		"_defaultKeyStore":              "PKCS11",
		"_disableOpeningExternalStores": true,
	})
	if store != "PKCS11" {
		t.Fatalf("store inesperado: %q", store)
	}
	if len(hints) != 0 {
		t.Fatalf("hints inesperados: %#v", hints)
	}
	if !includePKCS11 {
		t.Fatalf("defaultKeyStore=PKCS11 debe prevalecer frente a disableOpeningExternalStores")
	}
	if !hasOverride {
		t.Fatalf("se esperaba override por defaultKeyStore explicito")
	}
}

func TestGetCertificatesForSignOptionsPKCS11HintsWithoutTokenFallbacksToDefaultDiscovery(t *testing.T) {
	origDefault := getSystemCertificatesFunc
	origOpts := getSystemCertificatesWithOptionsFunc
	defer func() {
		getSystemCertificatesFunc = origDefault
		getSystemCertificatesWithOptionsFunc = origOpts
	}()

	defaultCalls := 0
	optionsCalls := 0
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		optionsCalls++
		// Simulate hints path returning only system certs.
		return []protocol.Certificate{{ID: "sys", Source: "system", Nickname: "n1"}}, nil
	}
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		defaultCalls++
		return []protocol.Certificate{{ID: "pk", Source: "smartcard", Nickname: "n2"}}, nil
	}

	certs, err := getCertificatesForSignOptions(map[string]interface{}{
		"_defaultKeyStore":    "PKCS11",
		"_defaultKeyStoreLib": "/opt/lib/nonworking-p11.so",
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if optionsCalls != 1 {
		t.Fatalf("se esperaba un intento con options loader, obtenidos=%d", optionsCalls)
	}
	if defaultCalls != 1 {
		t.Fatalf("se esperaba fallback a descubrimiento por defecto, obtenidos=%d", defaultCalls)
	}
	if len(certs) != 1 || certs[0].Source != "smartcard" {
		t.Fatalf("fallback inesperado, certs=%#v", certs)
	}
}
