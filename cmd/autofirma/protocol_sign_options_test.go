// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestBuildProtocolSignOptionsFromProperties(t *testing.T) {
	props := "signReason=Motivo\n" +
		"signatureProductionCity=Granada\n" +
		"signerContact=test@example.com\n" +
		"tsaURL=https://tsa.example.org\n" +
		"algorithm=SHA512withRSA\n" +
		"signaturePage=2\n" +
		"signaturePositionOnPageLowerLeftX=100\n" +
		"signaturePositionOnPageLowerLeftY=200\n" +
		"signaturePositionOnPageUpperRightX=250\n" +
		"signaturePositionOnPageUpperRightY=260\n"
	state := &ProtocolState{
		Params: url.Values{
			"properties": []string{base64.StdEncoding.EncodeToString([]byte(props))},
		},
	}

	opts := buildProtocolSignOptions(state, "pades")
	if opts == nil {
		t.Fatalf("se esperaban opciones de firma")
	}
	if got := opts["reason"]; got != "Motivo" {
		t.Fatalf("reason inesperado: %#v", got)
	}
	if got := opts["location"]; got != "Granada" {
		t.Fatalf("location inesperado: %#v", got)
	}
	if got := opts["contactInfo"]; got != "test@example.com" {
		t.Fatalf("contactInfo inesperado: %#v", got)
	}
	if got := opts["tsaURL"]; got != "https://tsa.example.org" {
		t.Fatalf("tsaURL inesperado: %#v", got)
	}
	if got := opts["algorithm"]; got != "SHA512withRSA" {
		t.Fatalf("algorithm inesperado: %#v", got)
	}
	if got, ok := opts["page"].(uint32); !ok || got != 2 {
		t.Fatalf("page inesperado: %#v", opts["page"])
	}
	if got, ok := opts["x"].(float64); !ok || got != 100 {
		t.Fatalf("x inesperado: %#v", opts["x"])
	}
	if got, ok := opts["y"].(float64); !ok || got != 200 {
		t.Fatalf("y inesperado: %#v", opts["y"])
	}
	if got, ok := opts["width"].(float64); !ok || got != 150 {
		t.Fatalf("width inesperado: %#v", opts["width"])
	}
	if got, ok := opts["height"].(float64); !ok || got != 60 {
		t.Fatalf("height inesperado: %#v", opts["height"])
	}
	if got, ok := opts["visibleSignature"].(bool); !ok || !got {
		t.Fatalf("visibleSignature inesperado: %#v", opts["visibleSignature"])
	}
}

func TestBuildProtocolSignOptionsParamsOverrideProperties(t *testing.T) {
	props := "signReason=DesdeProperties\nsignaturePage=2\n"
	state := &ProtocolState{
		Params: url.Values{
			"properties": []string{base64.StdEncoding.EncodeToString([]byte(props))},
			"signReason": []string{"DesdeParams"},
			"page":       []string{"4"},
		},
	}

	opts := buildProtocolSignOptions(state, "pades")
	if got := opts["reason"]; got != "DesdeParams" {
		t.Fatalf("se esperaba reason desde params, obtenido: %#v", got)
	}
	if got, ok := opts["page"].(uint32); !ok || got != 4 {
		t.Fatalf("se esperaba page=4 desde params, obtenido: %#v", opts["page"])
	}
}

func TestMergeSignOptions(t *testing.T) {
	base := map[string]interface{}{
		"reason": "A",
		"x":      10.0,
	}
	overlay := map[string]interface{}{
		"reason": "B",
		"y":      20.0,
	}
	merged := mergeSignOptions(base, overlay)
	if merged["reason"] != "B" {
		t.Fatalf("el overlay debe sobrescribir reason")
	}
	if merged["x"] != 10.0 || merged["y"] != 20.0 {
		t.Fatalf("merge incorrecto: %#v", merged)
	}
}

func TestBuildProtocolSignOptionsExpPolicyAGE18ByFormat(t *testing.T) {
	props := "expPolicy=FirmaAGE18\n"
	state := &ProtocolState{
		Params: url.Values{
			"properties": []string{base64.StdEncoding.EncodeToString([]byte(props))},
		},
	}

	optsX := buildProtocolSignOptions(state, "xades")
	if optsX["policyIdentifierHash"] != "V8lVVNGDCPen6VELRD1Ja8HARFk=" {
		t.Fatalf("hash XAdES inesperado: %#v", optsX["policyIdentifierHash"])
	}

	optsP := buildProtocolSignOptions(state, "pades")
	if optsP["policyIdentifierHash"] != "7SxX3erFuH31TvAw9LZ70N7p1vA=" {
		t.Fatalf("hash PAdES inesperado: %#v", optsP["policyIdentifierHash"])
	}

	optsC := buildProtocolSignOptions(state, "cades")
	if optsC["policyIdentifierHash"] != "7SxX3erFuH31TvAw9LZ70N7p1vA=" {
		t.Fatalf("hash CAdES inesperado: %#v", optsC["policyIdentifierHash"])
	}
	if optsC["policyIdentifier"] != "urn:oid:2.16.724.1.3.1.1.2.1.8" {
		t.Fatalf("policyIdentifier inesperado: %#v", optsC["policyIdentifier"])
	}
}

func TestBuildProtocolSignOptionsCanonicalizesCounterSignAndDigestKeys(t *testing.T) {
	props := "" +
		"target=signers\n" +
		"targets=CN=Firmante 1\n" +
		"signers=CN=Firmante 2\n" +
		"precalculatedhashalgorithm=SHA384\n"
	state := &ProtocolState{
		Params: url.Values{
			"properties": []string{base64.StdEncoding.EncodeToString([]byte(props))},
		},
	}

	opts := buildProtocolSignOptions(state, "cades")
	if got := opts["target"]; got != "signers" {
		t.Fatalf("target inesperado: %#v", got)
	}
	if got := opts["targets"]; got != "CN=Firmante 1" {
		t.Fatalf("targets inesperado: %#v", got)
	}
	if got := opts["signers"]; got != "CN=Firmante 2" {
		t.Fatalf("signers inesperado: %#v", got)
	}
	if got := opts["precalculatedHashAlgorithm"]; got != "SHA384" {
		t.Fatalf("precalculatedHashAlgorithm inesperado: %#v", got)
	}
}

func TestBuildProtocolSignOptionsPropagatesStoreHintsForSigner(t *testing.T) {
	props := "filter=disableopeningexternalstores\n"
	state := &ProtocolState{
		Params: url.Values{
			"properties":         []string{base64.StdEncoding.EncodeToString([]byte(props))},
			"defaultKeyStore":    []string{"PKCS11"},
			"defaultKeyStoreLib": []string{"/opt/lib/p11a.so;/opt/lib/p11b.so"},
		},
	}

	opts := buildProtocolSignOptions(state, "cades")
	if got := opts["_defaultKeyStore"]; got != "PKCS11" {
		t.Fatalf("defaultKeyStore no propagado: %#v", got)
	}
	if got := opts["_defaultKeyStoreLib"]; got != "/opt/lib/p11a.so;/opt/lib/p11b.so" {
		t.Fatalf("defaultKeyStoreLib no propagado: %#v", got)
	}
	if got, ok := opts["_disableOpeningExternalStores"].(bool); !ok || !got {
		t.Fatalf("disableopeningexternalstores no propagado: %#v", opts["_disableOpeningExternalStores"])
	}
}

func TestBuildProtocolSignOptionsReadsPropertiesCaseInsensitiveParam(t *testing.T) {
	props := "signReason=DesdePropertiesMayus\n"
	state := &ProtocolState{
		Params: url.Values{
			"Properties": []string{base64.StdEncoding.EncodeToString([]byte(props))},
		},
	}

	opts := buildProtocolSignOptions(state, "cades")
	if got := opts["reason"]; got != "DesdePropertiesMayus" {
		t.Fatalf("properties case-insensitive no aplicado: %#v", got)
	}
}

func TestBuildProtocolSignOptionsPropagatesPINForSigner(t *testing.T) {
	state := &ProtocolState{
		Params: url.Values{
			"pin": []string{"1234"},
		},
	}

	opts := buildProtocolSignOptions(state, "cades")
	if got := opts["_pin"]; got != "1234" {
		t.Fatalf("pin no propagado: %#v", got)
	}
}

func TestApplyStrictCompatDefaultsAddsConservativeDefaults(t *testing.T) {
	opts := applyStrictCompatDefaults(nil, "pades")
	if opts["algorithm"] != "SHA256withRSA" {
		t.Fatalf("algorithm por defecto inesperado: %#v", opts["algorithm"])
	}
	if opts["mode"] != "implicit" {
		t.Fatalf("mode por defecto inesperado: %#v", opts["mode"])
	}
	if opts["signatureSubFilter"] != "adbe.pkcs7.detached" {
		t.Fatalf("signatureSubFilter por defecto inesperado: %#v", opts["signatureSubFilter"])
	}
}

func TestApplyStrictCompatDefaultsDoesNotOverrideExistingValues(t *testing.T) {
	input := map[string]interface{}{
		"algorithm":        "SHA512withRSA",
		"mode":             "explicit",
		"signatureSubFilter": "ETSI.CAdES.detached",
	}
	opts := applyStrictCompatDefaults(input, "pades")
	if opts["algorithm"] != "SHA512withRSA" {
		t.Fatalf("algorithm no debe sobrescribirse: %#v", opts["algorithm"])
	}
	if opts["mode"] != "explicit" {
		t.Fatalf("mode no debe sobrescribirse: %#v", opts["mode"])
	}
	if opts["signatureSubFilter"] != "ETSI.CAdES.detached" {
		t.Fatalf("signatureSubFilter no debe sobrescribirse: %#v", opts["signatureSubFilter"])
	}
}

func TestApplyStrictCompatDefaultsPadesOnlyAddsSubFilter(t *testing.T) {
	opts := applyStrictCompatDefaults(nil, "xades")
	if _, ok := opts["signatureSubFilter"]; ok {
		t.Fatalf("signatureSubFilter no debe forzarse fuera de pades")
	}
}
