// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"autofirma-host/pkg/protocol"
	"encoding/base64"
	"errors"
	"testing"
)

func TestSignPKCS1WithOptionsFallsBackToPKCS11DirectSign(t *testing.T) {
	origLookup := lookupCertificateByIDFunc
	origExport := exportCertificateToP12Func
	origPKCS11 := signPKCS1PKCS11Func
	defer func() {
		lookupCertificateByIDFunc = origLookup
		exportCertificateToP12Func = origExport
		signPKCS1PKCS11Func = origPKCS11
	}()

	lookupCertificateByIDFunc = func(certificateID string, options map[string]interface{}) (*protocol.Certificate, string, error) {
		return &protocol.Certificate{
			ID:      "c1",
			Source:  "smartcard",
			Content: []byte{0x30, 0x82, 0x01},
		}, "", nil
	}
	exportCertificateToP12Func = func(nickname, password string) (string, error) {
		return "", errors.New("pk12util failed")
	}
	signPKCS1PKCS11Func = func(preSignData []byte, cert *protocol.Certificate, algorithm string, options map[string]interface{}) ([]byte, error) {
		if got := optionString(options, "_pin", ""); got != "1234" {
			t.Fatalf("pin no propagado al fallback PKCS11: %q", got)
		}
		return []byte("PK1SIG"), nil
	}

	out, err := SignPKCS1WithOptions([]byte("pre"), "c1", "SHA256withRSA", map[string]interface{}{
		"_defaultKeyStore": "PKCS11",
		"_pin":             "1234",
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("PK1SIG"))
	if out != want {
		t.Fatalf("firma inesperada: got=%q want=%q", out, want)
	}
}

func TestShouldTryPKCS11DirectSign(t *testing.T) {
	if !shouldTryPKCS11DirectSign(&protocol.Certificate{Source: "smartcard"}, nil) {
		t.Fatalf("smartcard debe activar fallback PKCS11 directo")
	}
	if !shouldTryPKCS11DirectSign(&protocol.Certificate{Source: "system"}, map[string]interface{}{
		"_defaultKeyStore": "PKCS11",
	}) {
		t.Fatalf("defaultKeyStore=PKCS11 debe activar fallback PKCS11 directo")
	}
	if shouldTryPKCS11DirectSign(&protocol.Certificate{Source: "system"}, nil) {
		t.Fatalf("source=system sin store PKCS11 no debe activar fallback PKCS11 directo")
	}
}
