// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"autofirma-host/pkg/protocol"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
)

func TestCounterSignCadesDERAddsCounterSignatureAttr(t *testing.T) {
	priv, cert := testGenerateSelfSignedRSACert(t)
	input := testBuildDetachedCAdES(t, cert, priv)

	out, err := counterSignCadesDERWithSigner(
		input,
		&protocol.Certificate{Content: cert.Raw},
		"c1",
		"SHA256withRSA",
		"",
		"",
		func(preSignData []byte, certificateID, algorithm string) (string, error) {
			h := crypto.SHA256.New()
			h.Write(preSignData)
			digest := h.Sum(nil)
			sig, sigErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
			if sigErr != nil {
				return "", sigErr
			}
			return base64.StdEncoding.EncodeToString(sig), nil
		},
	)
	if err != nil {
		t.Fatalf("counterSignCadesDERWithSigner error: %v", err)
	}

	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(out, &ci); err != nil {
		t.Fatalf("resultado no es CMS valido: %v", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("resultado no es SignedData valido: %v", err)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("se esperaba un signerinfo top-level, obtenido: %d", len(sd.SignerInfos))
	}

	var csInfo *cmsSignerInfo
	for _, attr := range sd.SignerInfos[0].UnauthenticatedAttributes {
		if attr.Type.Equal(oidAttrCounterSignature) {
			var parsed cmsSignerInfo
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &parsed); err != nil {
				t.Fatalf("counterSignature attribute invalido: %v", err)
			}
			csInfo = &parsed
			break
		}
	}
	if csInfo == nil {
		t.Fatalf("no se encontro atributo countersignature en unsignedAttrs")
	}

	hasMsgDigest := false
	hasContentType := false
	for _, a := range csInfo.AuthenticatedAttributes {
		if a.Type.Equal(oidAttrMessageDigest) {
			hasMsgDigest = true
		}
		if a.Type.Equal(oidContentTypeData) {
			hasContentType = true
		}
	}
	if !hasMsgDigest {
		t.Fatalf("la countersignature no incluye messageDigest")
	}
	if hasContentType {
		t.Fatalf("la countersignature no debe incluir contentType")
	}
}

func TestCounterSignCadesDERTargetLeafsOnlySignsLeaves(t *testing.T) {
	priv, cert := testGenerateSelfSignedRSACert(t)
	input := testBuildDetachedCAdES(t, cert, priv)

	first, err := counterSignCadesDERWithSigner(
		input,
		&protocol.Certificate{Content: cert.Raw},
		"c1",
		"SHA256withRSA",
		"tree",
		"",
		func(preSignData []byte, certificateID, algorithm string) (string, error) {
			h := crypto.SHA256.New()
			h.Write(preSignData)
			d := h.Sum(nil)
			sig, sigErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
			if sigErr != nil {
				return "", sigErr
			}
			return base64.StdEncoding.EncodeToString(sig), nil
		},
	)
	if err != nil {
		t.Fatalf("primera contrafirma tree fallo: %v", err)
	}
	second, err := counterSignCadesDERWithSigner(
		first,
		&protocol.Certificate{Content: cert.Raw},
		"c1",
		"SHA256withRSA",
		"leafs",
		"",
		func(preSignData []byte, certificateID, algorithm string) (string, error) {
			h := crypto.SHA256.New()
			h.Write(preSignData)
			d := h.Sum(nil)
			sig, sigErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
			if sigErr != nil {
				return "", sigErr
			}
			return base64.StdEncoding.EncodeToString(sig), nil
		},
	)
	if err != nil {
		t.Fatalf("segunda contrafirma leafs fallo: %v", err)
	}

	rootCounterSigs := testCountRootCounterSignatures(t, second)
	if rootCounterSigs != 1 {
		t.Fatalf("en modo leafs no debe incrementarse countersig en raiz, obtenido: %d", rootCounterSigs)
	}
}

func TestCounterSignCadesDERTargetTreeSignsWholeTree(t *testing.T) {
	priv, cert := testGenerateSelfSignedRSACert(t)
	input := testBuildDetachedCAdES(t, cert, priv)

	first, err := counterSignCadesDERWithSigner(
		input,
		&protocol.Certificate{Content: cert.Raw},
		"c1",
		"SHA256withRSA",
		"tree",
		"",
		func(preSignData []byte, certificateID, algorithm string) (string, error) {
			h := crypto.SHA256.New()
			h.Write(preSignData)
			d := h.Sum(nil)
			sig, sigErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
			if sigErr != nil {
				return "", sigErr
			}
			return base64.StdEncoding.EncodeToString(sig), nil
		},
	)
	if err != nil {
		t.Fatalf("primera contrafirma tree fallo: %v", err)
	}
	second, err := counterSignCadesDERWithSigner(
		first,
		&protocol.Certificate{Content: cert.Raw},
		"c1",
		"SHA256withRSA",
		"tree",
		"",
		func(preSignData []byte, certificateID, algorithm string) (string, error) {
			h := crypto.SHA256.New()
			h.Write(preSignData)
			d := h.Sum(nil)
			sig, sigErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
			if sigErr != nil {
				return "", sigErr
			}
			return base64.StdEncoding.EncodeToString(sig), nil
		},
	)
	if err != nil {
		t.Fatalf("segunda contrafirma tree fallo: %v", err)
	}
	rootCounterSigs := testCountRootCounterSignatures(t, second)
	if rootCounterSigs < 2 {
		t.Fatalf("en modo tree debe incrementarse countersig en raiz, obtenido: %d", rootCounterSigs)
	}
}

func TestCounterSignCadesDERTargetSignersByCN(t *testing.T) {
	priv1, cert1 := testGenerateSelfSignedRSACert(t)
	priv2, cert2 := testGenerateSelfSignedRSACertWithCN(t, "Second Signer")
	input := testBuildDetachedCAdESWithSigners(t, cert1, priv1, cert2, priv2)

	out, err := counterSignCadesDERWithSigner(
		input,
		&protocol.Certificate{Content: cert1.Raw},
		"c1",
		"SHA256withRSA",
		"signers",
		"Second Signer",
		func(preSignData []byte, certificateID, algorithm string) (string, error) {
			h := crypto.SHA256.New()
			h.Write(preSignData)
			d := h.Sum(nil)
			sig, sigErr := rsa.SignPKCS1v15(rand.Reader, priv1, crypto.SHA256, d)
			if sigErr != nil {
				return "", sigErr
			}
			return base64.StdEncoding.EncodeToString(sig), nil
		},
	)
	if err != nil {
		t.Fatalf("contrafirma signers fallo: %v", err)
	}

	rootCounts := testCountRootCounterSignaturesPerSigner(t, out)
	if len(rootCounts) != 2 {
		t.Fatalf("se esperaban dos signerinfos top-level, obtenido: %d", len(rootCounts))
	}
	if rootCounts[0] != 0 && rootCounts[1] != 0 {
		t.Fatalf("se esperaba al menos un firmante sin contrafirma: %#v", rootCounts)
	}
	if rootCounts[0] != 1 && rootCounts[1] != 1 {
		t.Fatalf("se esperaba exactamente un firmante contrafirmado: %#v", rootCounts)
	}
}

func TestResolveSignatureAlgorithmOIDUnknownFallsBackToSHA256RSA(t *testing.T) {
	oid, err := resolveSignatureAlgorithmOID("SHA3withRSA")
	if err != nil {
		t.Fatalf("no se esperaba error para algoritmo desconocido: %v", err)
	}
	want := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	if !oid.Equal(want) {
		t.Fatalf("OID inesperado para fallback: got=%v want=%v", oid, want)
	}
}

func testGenerateSelfSignedRSACert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	return testGenerateSelfSignedRSACertWithCN(t, "Test CounterSigner")
}

func testGenerateSelfSignedRSACertWithCN(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
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

func testBuildDetachedCAdES(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) []byte {
	return testBuildDetachedCAdESWithSigners(t, cert, key)
}

func testBuildDetachedCAdESWithSigners(t *testing.T, certsAndKeys ...interface{}) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData([]byte("mensaje"))
	if err != nil {
		t.Fatalf("pkcs7.NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	for i := 0; i+1 < len(certsAndKeys); i += 2 {
		cert, _ := certsAndKeys[i].(*x509.Certificate)
		key, _ := certsAndKeys[i+1].(*rsa.PrivateKey)
		if cert == nil || key == nil {
			t.Fatalf("par cert/key invalido en posicion %d", i)
		}
		if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
			t.Fatalf("pkcs7.AddSigner: %v", err)
		}
	}
	sd.Detach()
	out, err := sd.Finish()
	if err != nil {
		t.Fatalf("pkcs7.Finish: %v", err)
	}
	return out
}

func testCountRootCounterSignaturesPerSigner(t *testing.T, cms []byte) []int {
	t.Helper()
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cms, &ci); err != nil {
		t.Fatalf("cms invalido: %v", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("signedData invalido: %v", err)
	}
	out := make([]int, 0, len(sd.SignerInfos))
	for _, si := range sd.SignerInfos {
		total := 0
		for _, attr := range si.UnauthenticatedAttributes {
			if !attr.Type.Equal(oidAttrCounterSignature) {
				continue
			}
			children, err := decodeCounterSignatureSignerInfos(attr)
			if err != nil {
				t.Fatalf("counterSignature invalido: %v", err)
			}
			total += len(children)
		}
		out = append(out, total)
	}
	return out
}

func testCountRootCounterSignatures(t *testing.T, cms []byte) int {
	t.Helper()
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(cms, &ci); err != nil {
		t.Fatalf("cms invalido: %v", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("signedData invalido: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		return 0
	}
	total := 0
	for _, attr := range sd.SignerInfos[0].UnauthenticatedAttributes {
		if !attr.Type.Equal(oidAttrCounterSignature) {
			continue
		}
		children, err := decodeCounterSignatureSignerInfos(attr)
		if err != nil {
			t.Fatalf("counterSignature invalido: %v", err)
		}
		total += len(children)
	}
	return total
}
