// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

// Implementacion manual de firma XAdES-BES (enveloped) conforme a ETSI EN 319 132.
// Se construye la estructura XMLDSig a mano para poder incluir la referencia a
// xades:SignedProperties en ds:SignedInfo antes de firmar. La libreria goxmldsig
// no permite añadir referencias adicionales, de ahi este enfoque.
//
// Estructura generada:
//   ds:Signature
//     ds:SignedInfo
//       ds:CanonicalizationMethod  (C14N 1.0 inclusive)
//       ds:SignatureMethod         (rsa-sha256 o equivalente)
//       ds:Reference URI=""        (documento, con transforms enveloped+c14n)
//       ds:Reference URI="#sp-ID"  (xades:SignedProperties, Type=SignedProperties)
//     ds:SignatureValue
//     ds:KeyInfo > ds:X509Data > ds:X509Certificate...
//     ds:Object > xades:QualifyingProperties
//       xades:SignedProperties Id="sp-ID"
//         xades:SignedSignatureProperties
//           xades:SigningTime
//           xades:SigningCertificate > xades:Cert (digest + IssuerSerial)

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	xmlDSigNS             = "http://www.w3.org/2000/09/xmldsig#"
	xadesV132NS           = "http://uri.etsi.org/01903/v1.3.2#"
	c14nInclusiveAlg      = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	envelopedSigTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	xadesSignedPropsType  = "http://uri.etsi.org/01903#SignedProperties"
)

// signXadesElementEnvelopedBES firma el elemento XML con XAdES-BES (enveloped).
// Añade ds:Signature como hijo de el y devuelve el elemento modificado.
func signXadesElementEnvelopedBES(el *etree.Element, signerKey crypto.Signer, certChain [][]byte, options map[string]interface{}) (*etree.Element, error) {
	if el == nil {
		return nil, fmt.Errorf("elemento XML nulo")
	}
	if signerKey == nil || len(certChain) == 0 {
		return nil, fmt.Errorf("signer y certChain obligatorios para XAdES-BES")
	}

	leaf, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, fmt.Errorf("certificado hoja invalido: %v", err)
	}

	hashAlg := resolveDigestHash(options, crypto.SHA256)
	switch hashAlg {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		// ok
	default:
		hashAlg = crypto.SHA256
	}

	c14n := dsig.MakeC14N10RecCanonicalizer()

	// IDs únicos para esta firma
	uid := xadesGenerateID()
	sigID := "Signature-" + uid
	spID := "SignedProperties-" + uid

	// 1. Construir xades:QualifyingProperties (todavía no adjunto al árbol)
	qualProps := xadesBuildQualifyingProperties("#"+sigID, spID, leaf, hashAlg)

	// 2. Canonicalizar y hashear xades:SignedProperties
	signedProps := xadesFindChildByLocalName(qualProps, "SignedProperties")
	if signedProps == nil {
		return nil, fmt.Errorf("xades:SignedProperties no encontrado en QualifyingProperties")
	}
	spBytes, err := c14n.Canonicalize(signedProps)
	if err != nil {
		return nil, fmt.Errorf("c14n xades:SignedProperties: %v", err)
	}
	spDigest, err := xadesHash(spBytes, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("hash xades:SignedProperties: %v", err)
	}

	// 3. Canonicalizar y hashear el documento (sin ds:Signature todavía)
	docBytes, err := c14n.Canonicalize(el)
	if err != nil {
		return nil, fmt.Errorf("c14n documento: %v", err)
	}
	docDigest, err := xadesHash(docBytes, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("hash documento: %v", err)
	}

	// 4. Construir ds:SignedInfo con ambas referencias
	digestAlgURI := xadesDigestAlgURI(hashAlg)
	sigAlgURI := xadesSigAlgURI(signerKey.Public(), hashAlg)
	signedInfo := xadesBuildSignedInfo(docDigest, spDigest, "#"+spID, sigAlgURI, digestAlgURI)

	// 5. Canonicalizar ds:SignedInfo y firmar
	siBytes, err := c14n.Canonicalize(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("c14n ds:SignedInfo: %v", err)
	}
	digest, err := xadesHash(siBytes, hashAlg)
	if err != nil {
		return nil, err
	}
	sigBytes, err := signerKey.Sign(rand.Reader, digest, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("error al firmar XMLDSig: %v", err)
	}

	// 6. Ensamblar ds:Signature
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", xmlDSigNS)
	sig.CreateAttr("Id", sigID)

	sig.AddChild(signedInfo)

	sigVal := etree.NewElement("ds:SignatureValue")
	sigVal.SetText(base64.StdEncoding.EncodeToString(sigBytes))
	sig.AddChild(sigVal)

	sig.AddChild(xadesBuildKeyInfo(certChain))

	dsObj := etree.NewElement("ds:Object")
	dsObj.AddChild(qualProps)
	sig.AddChild(dsObj)

	// 7. Añadir la firma como hijo del elemento original
	el.AddChild(sig)
	return el, nil
}

// xadesBuildQualifyingProperties construye el elemento xades:QualifyingProperties
// con xades:SignedSignatureProperties (SigningTime + SigningCertificate).
func xadesBuildQualifyingProperties(sigIDRef, spID string, leaf *x509.Certificate, hashAlg crypto.Hash) *etree.Element {
	qp := etree.NewElement("xades:QualifyingProperties")
	qp.CreateAttr("xmlns:xades", xadesV132NS)
	qp.CreateAttr("xmlns:ds", xmlDSigNS)
	qp.CreateAttr("Target", sigIDRef)

	// xades:SignedProperties — lleva xmlns propio para que sea canonicalizable de forma aislada
	sp := etree.NewElement("xades:SignedProperties")
	sp.CreateAttr("xmlns:xades", xadesV132NS)
	sp.CreateAttr("xmlns:ds", xmlDSigNS)
	sp.CreateAttr("Id", spID)
	qp.AddChild(sp)

	ssp := etree.NewElement("xades:SignedSignatureProperties")
	sp.AddChild(ssp)

	// xades:SigningTime en formato XSD dateTime UTC
	st := etree.NewElement("xades:SigningTime")
	st.SetText(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	ssp.AddChild(st)

	// xades:SigningCertificate (V1 — usa el certificado hoja)
	sc := etree.NewElement("xades:SigningCertificate")
	ssp.AddChild(sc)

	certEl := etree.NewElement("xades:Cert")
	sc.AddChild(certEl)

	certDigest := etree.NewElement("xades:CertDigest")
	certEl.AddChild(certDigest)

	dm := etree.NewElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", xadesDigestAlgURI(hashAlg))
	certDigest.AddChild(dm)

	certHash, _ := xadesHash(leaf.Raw, hashAlg)
	dv := etree.NewElement("ds:DigestValue")
	dv.SetText(base64.StdEncoding.EncodeToString(certHash))
	certDigest.AddChild(dv)

	is := etree.NewElement("xades:IssuerSerial")
	certEl.AddChild(is)

	xin := etree.NewElement("ds:X509IssuerName")
	xin.SetText(leaf.Issuer.String())
	is.AddChild(xin)

	xsn := etree.NewElement("ds:X509SerialNumber")
	xsn.SetText(leaf.SerialNumber.String())
	is.AddChild(xsn)

	return qp
}

// xadesBuildSignedInfo construye ds:SignedInfo con dos referencias:
// una al documento (URI="", transform enveloped+c14n) y otra a xades:SignedProperties.
func xadesBuildSignedInfo(docDigest, spDigest []byte, spURI, sigAlgURI, digestAlgURI string) *etree.Element {
	si := etree.NewElement("ds:SignedInfo")
	si.CreateAttr("xmlns:ds", xmlDSigNS)

	cm := etree.NewElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", c14nInclusiveAlg)
	si.AddChild(cm)

	sm := etree.NewElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", sigAlgURI)
	si.AddChild(sm)

	// Referencia al documento completo (transform enveloped-signature + c14n)
	ref1 := etree.NewElement("ds:Reference")
	ref1.CreateAttr("URI", "")
	si.AddChild(ref1)

	transforms1 := etree.NewElement("ds:Transforms")
	ref1.AddChild(transforms1)
	t1 := etree.NewElement("ds:Transform")
	t1.CreateAttr("Algorithm", envelopedSigTransform)
	transforms1.AddChild(t1)
	t2 := etree.NewElement("ds:Transform")
	t2.CreateAttr("Algorithm", c14nInclusiveAlg)
	transforms1.AddChild(t2)

	dm1 := etree.NewElement("ds:DigestMethod")
	dm1.CreateAttr("Algorithm", digestAlgURI)
	ref1.AddChild(dm1)
	dv1 := etree.NewElement("ds:DigestValue")
	dv1.SetText(base64.StdEncoding.EncodeToString(docDigest))
	ref1.AddChild(dv1)

	// Referencia a xades:SignedProperties
	ref2 := etree.NewElement("ds:Reference")
	ref2.CreateAttr("URI", spURI)
	ref2.CreateAttr("Type", xadesSignedPropsType)
	si.AddChild(ref2)

	transforms2 := etree.NewElement("ds:Transforms")
	ref2.AddChild(transforms2)
	t3 := etree.NewElement("ds:Transform")
	t3.CreateAttr("Algorithm", c14nInclusiveAlg)
	transforms2.AddChild(t3)

	dm2 := etree.NewElement("ds:DigestMethod")
	dm2.CreateAttr("Algorithm", digestAlgURI)
	ref2.AddChild(dm2)
	dv2 := etree.NewElement("ds:DigestValue")
	dv2.SetText(base64.StdEncoding.EncodeToString(spDigest))
	ref2.AddChild(dv2)

	return si
}

// xadesBuildKeyInfo construye ds:KeyInfo con la cadena de certificados.
func xadesBuildKeyInfo(certChain [][]byte) *etree.Element {
	ki := etree.NewElement("ds:KeyInfo")
	x509Data := etree.NewElement("ds:X509Data")
	ki.AddChild(x509Data)
	for _, certDER := range certChain {
		x509cert := etree.NewElement("ds:X509Certificate")
		x509cert.SetText(base64.StdEncoding.EncodeToString(certDER))
		x509Data.AddChild(x509cert)
	}
	return ki
}

// xadesDigestAlgURI devuelve la URI del algoritmo de digest para XAdES.
func xadesDigestAlgURI(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "http://www.w3.org/2000/09/xmldsig#sha1"
	case crypto.SHA384:
		return "http://www.w3.org/2001/04/xmldsig-more#sha384"
	case crypto.SHA512:
		return "http://www.w3.org/2001/04/xmlenc#sha512"
	default: // SHA256
		return "http://www.w3.org/2001/04/xmlenc#sha256"
	}
}

// xadesSigAlgURI devuelve la URI del algoritmo de firma (RSA o ECDSA + hash).
func xadesSigAlgURI(pub interface{}, h crypto.Hash) string {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA1:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
		case crypto.SHA384:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
		case crypto.SHA512:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
		default:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
		}
	default: // RSA (y cualquier otra clave)
		switch h {
		case crypto.SHA1:
			return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		case crypto.SHA384:
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
		case crypto.SHA512:
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
		default:
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		}
	}
}

// xadesHash aplica el algoritmo de hash indicado a data.
func xadesHash(data []byte, h crypto.Hash) ([]byte, error) {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(data)
		return s[:], nil
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:], nil
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:], nil
	default: // SHA256
		s := sha256.Sum256(data)
		return s[:], nil
	}
}

// xadesGenerateID genera un identificador aleatorio de 8 bytes en hexadecimal.
func xadesGenerateID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck — crypto/rand.Read falla solo ante fallo catastrofico del SO
	return fmt.Sprintf("%x", b)
}

// xadesFindChildByLocalName busca el primer hijo directo cuyo nombre local coincide.
func xadesFindChildByLocalName(el *etree.Element, localName string) *etree.Element {
	for _, child := range el.ChildElements() {
		if strings.EqualFold(xmlLocalName(child.Tag), localName) {
			return child
		}
	}
	return nil
}

// Asegurar que los paquetes de hash están enlazados (necesario para crypto.Hash.New()).
var _ = rsa.PublicKey{}
