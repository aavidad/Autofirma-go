// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestCollectXadesSignatureElements(t *testing.T) {
	root := etree.NewElement("root")
	sig1 := root.CreateElement("ds:Signature")
	_ = sig1.CreateElement("ds:SignedInfo")
	container := root.CreateElement("child")
	_ = container.CreateElement("xades:Signature")

	sigs := collectXadesSignatureElements(root)
	if len(sigs) != 2 {
		t.Fatalf("numero inesperado de Signature en XML: %d", len(sigs))
	}
}

func TestFilterLeafSignatureElements(t *testing.T) {
	root := etree.NewElement("root")
	parent := root.CreateElement("ds:Signature")
	_ = parent.CreateElement("ds:Signature")
	leaf := root.CreateElement("xades:Signature")

	sigs := collectXadesSignatureElements(root)
	leafs := filterLeafSignatureElements(sigs)
	if len(leafs) != 2 {
		t.Fatalf("se esperaban 2 firmas hoja, obtenido: %d", len(leafs))
	}

	foundParent := false
	foundNested := false
	foundLeaf := false
	for _, s := range leafs {
		if s == parent {
			foundParent = true
		}
		if s != nil && s.Parent() == parent {
			foundNested = true
		}
		if s == leaf {
			foundLeaf = true
		}
	}
	if foundParent {
		t.Fatalf("la firma padre no debe considerarse hoja")
	}
	if !foundNested || !foundLeaf {
		t.Fatalf("firmas hoja no detectadas correctamente")
	}
}

func TestXMLLocalName(t *testing.T) {
	if got := xmlLocalName("ds:Signature"); got != "Signature" {
		t.Fatalf("local name inesperado: %q", got)
	}
	if got := xmlLocalName("Signature"); got != "Signature" {
		t.Fatalf("local name inesperado sin prefijo: %q", got)
	}
}

func TestFilterSignerTargetSignatureElementsByCNAndSHA1(t *testing.T) {
	cert := testGenerateXadesCert(t, "Firmante XAdES")
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
	sha1fp := testNormalizeCandidateValue(t, testSHA1Hex(cert.Raw))

	root := etree.NewElement("root")
	s1 := root.CreateElement("ds:Signature")
	keyInfo := s1.CreateElement("ds:KeyInfo")
	x509Data := keyInfo.CreateElement("ds:X509Data")
	x509Cert := x509Data.CreateElement("ds:X509Certificate")
	x509Cert.SetText(certB64)
	_ = root.CreateElement("ds:Signature")

	sigs := collectXadesSignatureElements(root)
	if len(sigs) != 2 {
		t.Fatalf("firmas inesperadas en setup: %d", len(sigs))
	}

	byCN := filterSignerTargetSignatureElements(sigs, "Firmante XAdES")
	if len(byCN) != 1 || byCN[0] != s1 {
		t.Fatalf("target por CN no selecciona la firma esperada")
	}

	bySHA1 := filterSignerTargetSignatureElements(sigs, sha1fp)
	if len(bySHA1) != 1 || bySHA1[0] != s1 {
		t.Fatalf("target por SHA1 no selecciona la firma esperada")
	}
}

func testGenerateXadesCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2026021701),
		Subject: pkix.Name{
			CommonName: cn,
		},
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
	return cert
}

func testSHA1Hex(b []byte) string {
	return fmt.Sprintf("%x", sha1.Sum(b))
}

func testNormalizeCandidateValue(t *testing.T, v string) string {
	t.Helper()
	m := buildCounterSignerMatcher(v)
	if len(m.selectors) != 1 {
		t.Fatalf("selector normalizado inesperado: %#v", m.selectors)
	}
	return m.selectors[0]
}
