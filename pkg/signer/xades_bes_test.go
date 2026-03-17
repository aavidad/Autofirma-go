// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"autofirma-host/pkg/protocol"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

func TestSignXadesElementEnvelopedAddsSignedQualifyingProperties(t *testing.T) {
	t.Parallel()

	signerKey, cert := testGenerateSignerAndXadesCert(t, "Firmante BES")
	root := etree.NewElement("Documento")
	root.CreateAttr("ID", "doc-1")
	root.CreateElement("Contenido").SetText("hola")

	baseCtx, err := dsig.NewSigningContext(signerKey, [][]byte{cert.Raw})
	if err != nil {
		t.Fatalf("NewSigningContext error: %v", err)
	}
	baseCtx.Prefix = "ds"
	baseCtx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()
	baseRoot, err := baseCtx.SignEnveloped(root)
	if err != nil {
		t.Fatalf("SignEnveloped base error: %v", err)
	}
	assertSignedXMLValid(t, baseRoot)

	signedRoot, err := signXadesElementEnveloped(root, signerKey, [][]byte{cert.Raw}, nil)
	if err != nil {
		t.Fatalf("signXadesElementEnveloped error: %v", err)
	}

	if findElementByLocalName(signedRoot, "QualifyingProperties") == nil {
		t.Fatal("falta xades:QualifyingProperties")
	}
	if el := findElementByLocalName(signedRoot, "SigningTime"); el == nil || el.Text() == "" {
		t.Fatal("falta xades:SigningTime")
	}
	if el := findElementByLocalName(signedRoot, "SigningCertificate"); el == nil {
		t.Fatal("falta xades:SigningCertificate")
	}
	if !hasSignedPropertiesReference(signedRoot) {
		t.Fatal("falta ds:Reference a SignedProperties")
	}
	assertSignedInfoRSAValid(t, signedRoot, cert)
	assertReferenceDigestsMatch(t, signedRoot)

	out, err := documentBytes(signedRoot)
	if err != nil {
		t.Fatalf("documentBytes error: %v", err)
	}

	result, err := verifyResultForElement(signedRoot)
	if err != nil {
		t.Fatalf("verifyResultForElement error: %v", err)
	}
	if result == nil || !result.Valid {
		t.Fatalf("la firma XAdES generada debe ser válida: %#v\nXML=%s", result, string(out))
	}
}

func testGenerateSignerAndXadesCert(t *testing.T, cn string) (crypto.Signer, *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          testSerialNumber(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return priv, cert
}

func testSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	return big.NewInt(time.Now().UnixNano())
}

func findElementByLocalName(root *etree.Element, localName string) *etree.Element {
	var found *etree.Element
	walkElements(root, func(el *etree.Element) {
		if found != nil {
			return
		}
		if xmlLocalName(el.Tag) == localName {
			found = el
		}
	})
	return found
}

func hasSignedPropertiesReference(root *etree.Element) bool {
	var found bool
	walkElements(root, func(el *etree.Element) {
		if found || xmlLocalName(el.Tag) != "Reference" {
			return
		}
		if el.SelectAttrValue("Type", "") == "http://uri.etsi.org/01903#SignedProperties" {
			found = true
		}
	})
	return found
}

func assertSignedXMLValid(t *testing.T, root *etree.Element) {
	t.Helper()
	result, err := verifyResultForElement(root)
	if err != nil {
		t.Fatalf("verifyResultForElement error: %v", err)
	}
	if result == nil || !result.Valid {
		out, _ := documentBytes(root)
		t.Fatalf("la firma base debe ser válida: %#v\nXML=%s", result, string(out))
	}
}

func verifyResultForElement(root *etree.Element) (*protocol.VerifyResult, error) {
	out, err := documentBytes(root)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "xades-bes-*.xml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return verifyXadesWithGo(tmp.Name())
}

func documentBytes(root *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(root)
	return doc.WriteToBytes()
}

func assertSignedInfoRSAValid(t *testing.T, root *etree.Element, cert *x509.Certificate) {
	t.Helper()

	sig := findElementByLocalName(root, "Signature")
	if sig == nil {
		t.Fatal("falta Signature")
	}
	signedInfo := findDirectChildByLocalName(sig, "SignedInfo")
	if signedInfo == nil {
		t.Fatal("falta SignedInfo")
	}
	signatureValue := findDirectChildByLocalName(sig, "SignatureValue")
	if signatureValue == nil {
		t.Fatal("falta SignatureValue")
	}

	rootNSCtx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		t.Fatalf("NSBuildParentContext error: %v", err)
	}
	rootCtx, err := rootNSCtx.SubContext(root)
	if err != nil {
		t.Fatalf("root SubContext error: %v", err)
	}
	sigCtx, err := rootCtx.SubContext(sig)
	if err != nil {
		t.Fatalf("sig SubContext error: %v", err)
	}
	detachedSignedInfo, err := etreeutils.NSDetatch(sigCtx, signedInfo)
	if err != nil {
		t.Fatalf("NSDetatch error: %v", err)
	}
	canonicalizer := dsig.MakeC14N10RecCanonicalizer()
	canonicalSignedInfo, err := canonicalizer.Canonicalize(detachedSignedInfo)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}
	decodedSignature, err := base64.StdEncoding.DecodeString(signatureValue.Text())
	if err != nil {
		t.Fatalf("Decode signature error: %v", err)
	}
	if err := cert.CheckSignature(x509.SHA256WithRSA, canonicalSignedInfo, decodedSignature); err != nil {
		t.Fatalf("la firma RSA de SignedInfo no valida: %v", err)
	}
}

func assertReferenceDigestsMatch(t *testing.T, root *etree.Element) {
	t.Helper()

	sig := findElementByLocalName(root, "Signature")
	if sig == nil {
		t.Fatal("falta Signature")
	}
	signedInfo := findDirectChildByLocalName(sig, "SignedInfo")
	if signedInfo == nil {
		t.Fatal("falta SignedInfo")
	}

	refs := make([]*etree.Element, 0)
	for _, child := range signedInfo.ChildElements() {
		if xmlLocalName(child.Tag) == "Reference" {
			refs = append(refs, child)
		}
	}
	if len(refs) < 2 {
		t.Fatalf("se esperaban al menos 2 referencias, obtenidas=%d", len(refs))
	}

	rootDigestValue := findElementByLocalName(refs[0], "DigestValue")
	if rootDigestValue == nil {
		t.Fatal("falta DigestValue de la referencia principal")
	}
	rootWithoutSig := root.Copy()
	for i, child := range rootWithoutSig.ChildElements() {
		if xmlLocalName(child.Tag) == "Signature" {
			rootWithoutSig.RemoveChildAt(i)
			break
		}
	}
	rootDigest, err := digestXMLElement(dsig.MakeC14N10RecCanonicalizer(), crypto.SHA256, rootWithoutSig)
	if err != nil {
		t.Fatalf("digest principal error: %v", err)
	}
	if base64.StdEncoding.EncodeToString(rootDigest) != strings.TrimSpace(rootDigestValue.Text()) {
		t.Fatalf("digest principal no coincide")
	}

	propsDigestValue := findElementByLocalName(refs[1], "DigestValue")
	if propsDigestValue == nil {
		t.Fatal("falta DigestValue de SignedProperties")
	}
	signedProperties := findElementByLocalName(sig, "SignedProperties")
	if signedProperties == nil {
		t.Fatal("falta SignedProperties")
	}
	rootNSCtx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		t.Fatalf("NSBuildParentContext error: %v", err)
	}
	rootCtx, err := rootNSCtx.SubContext(root)
	if err != nil {
		t.Fatalf("root SubContext error: %v", err)
	}
	sigCtx, err := rootCtx.SubContext(sig)
	if err != nil {
		t.Fatalf("sig SubContext error: %v", err)
	}
	propsDigest, err := digestXMLElementWithContext(dsig.MakeC14N10RecCanonicalizer(), crypto.SHA256, sigCtx, signedProperties)
	if err != nil {
		t.Fatalf("digest SignedProperties error: %v", err)
	}
	if base64.StdEncoding.EncodeToString(propsDigest) != strings.TrimSpace(propsDigestValue.Text()) {
		t.Fatalf("digest de SignedProperties no coincide")
	}
}
