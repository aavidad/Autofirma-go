// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"autofirma-host/pkg/protocol"
)

func signXadesWithGo(inputFile string, leaf *x509.Certificate, signer crypto.Signer, chains [][]*x509.Certificate, options map[string]interface{}) ([]byte, error) {
	xmlData, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("XML invalido: %v", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("XML sin elemento raiz")
	}

	if leaf == nil || signer == nil {
		return nil, fmt.Errorf("certificado y signer obligatorios para xades")
	}

	certChain := [][]byte{leaf.Raw}
	if len(chains) > 0 && len(chains[0]) > 1 {
		for _, c := range chains[0][1:] {
			certChain = append(certChain, c.Raw)
		}
	}

	op := strings.ToLower(strings.TrimSpace(optionString(options, "_operation", "operation")))
	if op == "countersign" {
		if err := counterSignXadesTree(root, signer, certChain, options); err != nil {
			return nil, err
		}
	} else {
		signedRoot, err := signXadesElementEnveloped(root, signer, certChain, options)
		if err != nil {
			return nil, err
		}
		doc.SetRoot(signedRoot)
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func signXadesElementEnveloped(el *etree.Element, signer crypto.Signer, certChain [][]byte, options map[string]interface{}) (*etree.Element, error) {
	if el == nil {
		return nil, fmt.Errorf("elemento XML nulo")
	}
	ctx, err := dsig.NewSigningContext(signer, certChain)
	if err != nil {
		return nil, err
	}
	digest := resolveDigestHash(options, crypto.SHA256)
	if digest == crypto.SHA1 || digest == crypto.SHA256 || digest == crypto.SHA384 || digest == crypto.SHA512 {
		ctx.Hash = digest
	}
	ctx.Prefix = "ds"
	ctx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()
	if len(certChain) == 0 {
		return nil, fmt.Errorf("cadena de certificados vacía para xades")
	}
	leaf, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, fmt.Errorf("certificado hoja inválido para xades: %w", err)
	}
	return constructXadesBesSignature(el, ctx, signer, leaf)
}

func constructXadesBesSignature(el *etree.Element, ctx *dsig.SigningContext, signer crypto.Signer, leaf *x509.Certificate) (*etree.Element, error) {
	signatureID := "xades-signature-" + mustRandomHex(8)
	signedPropsID := "xades-signed-properties-" + mustRandomHex(8)
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}
	sig.CreateAttr("Id", signatureID)
	sig.CreateAttr("ID", signatureID)

	signedInfo := findDirectChildByLocalName(sig, "SignedInfo")
	if signedInfo == nil {
		return nil, fmt.Errorf("firma XMLDSig sin SignedInfo")
	}
	signatureValue := findDirectChildByLocalName(sig, "SignatureValue")
	if signatureValue == nil {
		return nil, fmt.Errorf("firma XMLDSig sin SignatureValue")
	}

	objectEl := createNamespacedElement(sig, "ds", "Object")
	qualifyingProperties := createNamespacedElement(objectEl, "xades", "QualifyingProperties")
	qualifyingProperties.CreateAttr("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#")
	qualifyingProperties.CreateAttr("Target", "#"+signatureID)
	signedProperties := createNamespacedElement(qualifyingProperties, "xades", "SignedProperties")
	signedProperties.CreateAttr("Id", signedPropsID)
	signedProperties.CreateAttr("ID", signedPropsID)
	signedSigProps := createNamespacedElement(signedProperties, "xades", "SignedSignatureProperties")
	signingTime := createNamespacedElement(signedSigProps, "xades", "SigningTime")
	signingTime.SetText(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	signingCertificate := createNamespacedElement(signedSigProps, "xades", "SigningCertificate")
	certEl := createNamespacedElement(signingCertificate, "xades", "Cert")
	certDigest := createNamespacedElement(certEl, "xades", "CertDigest")
	certDigestMethod := createNamespacedElement(certDigest, "ds", "DigestMethod")
	certDigestMethod.CreateAttr("Algorithm", digestAlgorithmIdentifierSHA256)
	certDigestValue := createNamespacedElement(certDigest, "ds", "DigestValue")
	certDigestValue.SetText(sha256SumBase64(leaf.Raw))
	issuerSerial := createNamespacedElement(certEl, "xades", "IssuerSerial")
	x509IssuerName := createNamespacedElement(issuerSerial, "ds", "X509IssuerName")
	x509IssuerName.SetText(leaf.Issuer.String())
	x509SerialNumber := createNamespacedElement(issuerSerial, "ds", "X509SerialNumber")
	x509SerialNumber.SetText(leaf.SerialNumber.String())

	propsRef := createNamespacedElement(signedInfo, "ds", "Reference")
	propsRef.CreateAttr("URI", "#"+signedPropsID)
	propsRef.CreateAttr("Type", "http://uri.etsi.org/01903#SignedProperties")
	propsTransforms := createNamespacedElement(propsRef, "ds", "Transforms")
	propsC14NTransform := createNamespacedElement(propsTransforms, "ds", "Transform")
	propsC14NTransform.CreateAttr("Algorithm", string(ctx.Canonicalizer.Algorithm()))
	propsDigestMethod := createNamespacedElement(propsRef, "ds", "DigestMethod")
	propsDigestMethod.CreateAttr("Algorithm", ctx.GetDigestAlgorithmIdentifier())
	propsDigestValue := createNamespacedElement(propsRef, "ds", "DigestValue")

	rootNSCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	elNSCtx, err := rootNSCtx.SubContext(el)
	if err != nil {
		return nil, err
	}
	sigNSCtx, err := elNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	propsDigest, err := digestXMLElementWithContext(ctx.Canonicalizer, ctx.Hash, sigNSCtx, signedProperties)
	if err != nil {
		return nil, err
	}
	propsDigestValue.SetText(base64.StdEncoding.EncodeToString(propsDigest))

	detachedSignedInfo, err := etreeutils.NSDetatch(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}
	canonicalSignedInfo, err := ctx.Canonicalizer.Canonicalize(detachedSignedInfo)
	if err != nil {
		return nil, err
	}
	hash := ctx.Hash.New()
	if _, err := hash.Write(canonicalSignedInfo); err != nil {
		return nil, err
	}
	rawSignature, err := signer.Sign(rand.Reader, hash.Sum(nil), ctx.Hash)
	if err != nil {
		return nil, err
	}
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	ret := el.Copy()
	ret.AddChild(sig)
	return ret, nil
}

func mustRandomHex(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func newNamespacedElement(prefix, local string) *etree.Element {
	el := etree.NewElement(local)
	el.Space = prefix
	return el
}

func createNamespacedElement(parent *etree.Element, prefix, local string) *etree.Element {
	child := parent.CreateElement(local)
	child.Space = prefix
	return child
}

func findDirectChildByLocalName(parent *etree.Element, localName string) *etree.Element {
	if parent == nil {
		return nil
	}
	for _, child := range parent.ChildElements() {
		if xmlLocalName(child.Tag) == localName {
			return child
		}
	}
	return nil
}

func digestXMLElement(canonicalizer dsig.Canonicalizer, hash crypto.Hash, el *etree.Element) ([]byte, error) {
	canonical, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	if _, err := h.Write(canonical); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func digestXMLElementWithContext(canonicalizer dsig.Canonicalizer, hash crypto.Hash, ctx etreeutils.NSContext, el *etree.Element) ([]byte, error) {
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, err
	}
	return digestXMLElement(canonicalizer, hash, detached)
}

func counterSignXadesTree(root *etree.Element, signer crypto.Signer, certChain [][]byte, options map[string]interface{}) error {
	if root == nil {
		return fmt.Errorf("XML sin elemento raiz")
	}
	signatures := collectXadesSignatureElements(root)
	if len(signatures) == 0 {
		_, err := signXadesElementEnveloped(root, signer, certChain, options)
		return err
	}

	targetMode := normalizeCounterSignTarget(optionString(options, "target", ""))
	filtered := signatures
	switch targetMode {
	case "leafs":
		filtered = filterLeafSignatureElements(signatures)
	case "signers":
		filtered = filterSignerTargetSignatureElements(signatures, optionString(options, "targets", "signers"))
	default:
		// tree: keep all signatures
	}
	if len(filtered) == 0 {
		// Compatibility fallback: if selector doesn't match any existing signer, do not fail hard.
		_, err := signXadesElementEnveloped(root, signer, certChain, options)
		return err
	}

	for _, sig := range filtered {
		if _, err := signXadesElementEnveloped(sig, signer, certChain, options); err != nil {
			return err
		}
	}
	return nil
}

func collectXadesSignatureElements(root *etree.Element) []*etree.Element {
	out := make([]*etree.Element, 0)
	walkElements(root, func(el *etree.Element) {
		if isXMLSignatureElement(el) {
			out = append(out, el)
		}
	})
	return out
}

func filterLeafSignatureElements(in []*etree.Element) []*etree.Element {
	if len(in) == 0 {
		return nil
	}
	out := make([]*etree.Element, 0, len(in))
	for _, sig := range in {
		if sig == nil || hasNestedSignature(sig) {
			continue
		}
		out = append(out, sig)
	}
	return out
}

func filterSignerTargetSignatureElements(in []*etree.Element, rawTargets string) []*etree.Element {
	matcher := buildCounterSignerMatcher(rawTargets)
	if len(matcher.selectors) == 0 {
		return nil
	}
	out := make([]*etree.Element, 0, len(in))
	for _, sig := range in {
		cands := signatureMatchCandidates(sig)
		for _, sel := range matcher.selectors {
			matched := false
			for _, c := range cands {
				if c == sel {
					matched = true
					break
				}
			}
			if matched {
				out = append(out, sig)
				break
			}
		}
	}
	return out
}

func signatureMatchCandidates(sig *etree.Element) []string {
	if sig == nil {
		return nil
	}
	cands := []string{}
	cert := extractSignatureCertificateFromElement(sig)
	if cert != nil {
		sha1fp := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
		cands = append(cands,
			strings.ToLower(strings.TrimSpace(cert.Subject.CommonName)),
			strings.ToLower(strings.TrimSpace(cert.Subject.String())),
			strings.ToLower(strings.TrimSpace(cert.SerialNumber.String())),
			strings.ToLower(strings.TrimSpace(strings.ToUpper(cert.SerialNumber.Text(16)))),
			strings.ToLower(strings.TrimSpace(sha1fp)),
			strings.ToLower(strings.TrimSpace(fmt.Sprintf("%x", cert.Raw))),
		)
	}
	uniq := make(map[string]struct{}, len(cands))
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		c = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(c, ":", "")))
		if c == "" {
			continue
		}
		if _, ok := uniq[c]; ok {
			continue
		}
		uniq[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func extractSignatureCertificateFromElement(sig *etree.Element) *x509.Certificate {
	if sig == nil {
		return nil
	}
	var certB64 string
	walkElements(sig, func(el *etree.Element) {
		if certB64 != "" {
			return
		}
		if strings.EqualFold(xmlLocalName(el.Tag), "X509Certificate") {
			certB64 = strings.TrimSpace(el.Text())
		}
	})
	if certB64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certB64))
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil
	}
	return cert
}

func hasNestedSignature(sig *etree.Element) bool {
	if sig == nil {
		return false
	}
	for _, child := range sig.ChildElements() {
		if isXMLSignatureElement(child) {
			return true
		}
		if hasNestedSignature(child) {
			return true
		}
	}
	return false
}

func isXMLSignatureElement(el *etree.Element) bool {
	return el != nil && strings.EqualFold(xmlLocalName(el.Tag), "Signature")
}

func xmlLocalName(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	if i := strings.Index(tag, ":"); i >= 0 && i+1 < len(tag) {
		return tag[i+1:]
	}
	return tag
}

func verifyXadesWithGo(xmlFile string) (*protocol.VerifyResult, error) {
	xmlData, err := os.ReadFile(xmlFile)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return &protocol.VerifyResult{
			Valid:  false,
			Format: "xades",
			Reason: "XML invalido",
		}, nil
	}
	root := doc.Root()
	if root == nil {
		return &protocol.VerifyResult{
			Valid:  false,
			Format: "xades",
			Reason: "XML sin raiz",
		}, nil
	}

	cert, err := extractSignatureCertificate(root)
	if err != nil {
		return &protocol.VerifyResult{
			Valid:  false,
			Format: "xades",
			Reason: "No se encontro certificado en la firma XML",
		}, nil
	}

	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})

	if _, err := vc.Validate(root); err != nil {
		if customErr := verifyXadesBES(root, cert); customErr != nil {
			return &protocol.VerifyResult{
				Valid:      false,
				SignerName: cert.Subject.CommonName,
				Format:     "xades",
				Reason:     customErr.Error(),
			}, nil
		}
	}

	return &protocol.VerifyResult{
		Valid:      true,
		SignerName: cert.Subject.CommonName,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Format:     "xades",
		Algorithm:  "sha256WithRSA",
		Reason:     "Firma XML valida",
	}, nil
}

func extractSignatureCertificate(root *etree.Element) (*x509.Certificate, error) {
	var certB64 string
	walkElements(root, func(el *etree.Element) {
		if certB64 != "" {
			return
		}
		if strings.EqualFold(xmlLocalName(el.Tag), "X509Certificate") {
			certB64 = strings.TrimSpace(el.Text())
		}
	})
	if certB64 == "" {
		return nil, fmt.Errorf("falta x509certificate")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certB64))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw)
}

func verifyXadesBES(root *etree.Element, cert *x509.Certificate) error {
	sig := findFirstElementByLocalName(root, "Signature")
	if sig == nil {
		return fmt.Errorf("firma xades sin elemento Signature")
	}
	signedInfo := findDirectChildByLocalName(sig, "SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("firma xades sin SignedInfo")
	}
	signatureValue := findDirectChildByLocalName(sig, "SignatureValue")
	if signatureValue == nil {
		return fmt.Errorf("firma xades sin SignatureValue")
	}

	canonicalizer, err := canonicalizerForSignedInfo(signedInfo)
	if err != nil {
		return err
	}
	signatureMethod, err := signatureAlgorithmForSignedInfo(signedInfo)
	if err != nil {
		return err
	}
	canonicalSignedInfo, err := canonicalSignedInfoBytes(root, sig, signedInfo, canonicalizer)
	if err != nil {
		return err
	}
	decodedSignature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureValue.Text()))
	if err != nil {
		return fmt.Errorf("signaturevalue inválido: %w", err)
	}
	if err := cert.CheckSignature(signatureMethod, canonicalSignedInfo, decodedSignature); err != nil {
		return fmt.Errorf("Signature could not be verified")
	}

	if err := verifyRootReferenceDigest(root, signedInfo); err != nil {
		return err
	}
	if err := verifySignedPropertiesReferences(root, sig, signedInfo); err != nil {
		return err
	}
	return nil
}

func canonicalizerForSignedInfo(signedInfo *etree.Element) (dsig.Canonicalizer, error) {
	methodEl := findDirectChildByLocalName(signedInfo, "CanonicalizationMethod")
	if methodEl == nil {
		return nil, fmt.Errorf("SignedInfo sin CanonicalizationMethod")
	}
	switch methodEl.SelectAttrValue("Algorithm", "") {
	case string(dsig.CanonicalXML10ExclusiveAlgorithmId):
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), nil
	case string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId):
		return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""), nil
	case "http://www.w3.org/2006/12/xml-c14n11":
		return dsig.MakeC14N11Canonicalizer(), nil
	case "http://www.w3.org/2006/12/xml-c14n11#WithComments":
		return dsig.MakeC14N11WithCommentsCanonicalizer(), nil
	case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315":
		return dsig.MakeC14N10RecCanonicalizer(), nil
	case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
		return dsig.MakeC14N10WithCommentsCanonicalizer(), nil
	default:
		return nil, fmt.Errorf("canonicalización no soportada en XAdES")
	}
}

func signatureAlgorithmForSignedInfo(signedInfo *etree.Element) (x509.SignatureAlgorithm, error) {
	methodEl := findDirectChildByLocalName(signedInfo, "SignatureMethod")
	if methodEl == nil {
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("SignedInfo sin SignatureMethod")
	}
	switch methodEl.SelectAttrValue("Algorithm", "") {
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		return x509.SHA1WithRSA, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		return x509.SHA256WithRSA, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		return x509.SHA384WithRSA, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		return x509.SHA512WithRSA, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("algoritmo de firma XAdES no soportado")
	}
}

func canonicalSignedInfoBytes(root, sig, signedInfo *etree.Element, canonicalizer dsig.Canonicalizer) ([]byte, error) {
	rootNSCtx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return nil, err
	}
	rootCtx, err := rootNSCtx.SubContext(root)
	if err != nil {
		return nil, err
	}
	sigCtx, err := rootCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}
	detachedSignedInfo, err := etreeutils.NSDetatch(sigCtx, signedInfo)
	if err != nil {
		return nil, err
	}
	return canonicalizer.Canonicalize(detachedSignedInfo)
}

func verifyRootReferenceDigest(root, signedInfo *etree.Element) error {
	dataID := root.SelectAttrValue("ID", "")
	var rootRef *etree.Element
	for _, child := range signedInfo.ChildElements() {
		if xmlLocalName(child.Tag) != "Reference" {
			continue
		}
		uri := child.SelectAttrValue("URI", "")
		if uri == "" || strings.TrimPrefix(uri, "#") == dataID {
			rootRef = child
			break
		}
	}
	if rootRef == nil {
		return fmt.Errorf("Missing reference")
	}
	rootCopy := root.Copy()
	removeFirstSignatureChild(rootCopy)
	return verifyReferenceDigestValue(rootCopy, rootRef, etreeutils.EmptyNSContext, false)
}

func verifySignedPropertiesReferences(root, sig, signedInfo *etree.Element) error {
	rootNSCtx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return err
	}
	rootCtx, err := rootNSCtx.SubContext(root)
	if err != nil {
		return err
	}
	sigCtx, err := rootCtx.SubContext(sig)
	if err != nil {
		return err
	}
	for _, child := range signedInfo.ChildElements() {
		if xmlLocalName(child.Tag) != "Reference" {
			continue
		}
		if child.SelectAttrValue("Type", "") != "http://uri.etsi.org/01903#SignedProperties" {
			continue
		}
		targetID := strings.TrimPrefix(child.SelectAttrValue("URI", ""), "#")
		target := findElementByAnyID(sig, targetID)
		if target == nil {
			return fmt.Errorf("SignedProperties ausente")
		}
		if findFirstElementByLocalName(target, "SigningTime") == nil || findFirstElementByLocalName(target, "SigningCertificate") == nil {
			return fmt.Errorf("SignedProperties incompleto")
		}
		if err := verifyReferenceDigestValue(target, child, sigCtx, true); err != nil {
			return err
		}
	}
	return nil
}

func verifyReferenceDigestValue(target, ref *etree.Element, nsCtx etreeutils.NSContext, useNSCtx bool) error {
	if ref == nil {
		return fmt.Errorf("referencia XML ausente")
	}
	digestMethod := findFirstElementByLocalName(ref, "DigestMethod")
	digestValue := findFirstElementByLocalName(ref, "DigestValue")
	if digestMethod == nil || digestValue == nil {
		return fmt.Errorf("referencia XML incompleta")
	}
	hash, err := hashFromDigestMethod(digestMethod.SelectAttrValue("Algorithm", ""))
	if err != nil {
		return err
	}
	canonicalizer, err := canonicalizerFromReference(ref)
	if err != nil {
		return err
	}
	var computed []byte
	if useNSCtx {
		computed, err = digestXMLElementWithContext(canonicalizer, hash, nsCtx, target)
	} else {
		computed, err = digestXMLElement(canonicalizer, hash, target)
	}
	if err != nil {
		return err
	}
	if base64.StdEncoding.EncodeToString(computed) != strings.TrimSpace(digestValue.Text()) {
		return fmt.Errorf("Signature could not be verified")
	}
	return nil
}

func canonicalizerFromReference(ref *etree.Element) (dsig.Canonicalizer, error) {
	transforms := findFirstElementByLocalName(ref, "Transforms")
	if transforms == nil {
		return dsig.MakeNullCanonicalizer(), nil
	}
	var algorithm string
	for _, child := range transforms.ChildElements() {
		if xmlLocalName(child.Tag) != "Transform" {
			continue
		}
		candidate := child.SelectAttrValue("Algorithm", "")
		if candidate == dsig.EnvelopedSignatureAltorithmId.String() {
			continue
		}
		algorithm = candidate
	}
	if algorithm == "" {
		return dsig.MakeNullCanonicalizer(), nil
	}
	switch algorithm {
	case string(dsig.CanonicalXML10ExclusiveAlgorithmId):
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), nil
	case string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId):
		return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""), nil
	case "http://www.w3.org/2006/12/xml-c14n11":
		return dsig.MakeC14N11Canonicalizer(), nil
	case "http://www.w3.org/2006/12/xml-c14n11#WithComments":
		return dsig.MakeC14N11WithCommentsCanonicalizer(), nil
	case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315":
		return dsig.MakeC14N10RecCanonicalizer(), nil
	case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
		return dsig.MakeC14N10WithCommentsCanonicalizer(), nil
	default:
		return nil, fmt.Errorf("transformación XML no soportada")
	}
}

func hashFromDigestMethod(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		return crypto.SHA1, nil
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return crypto.SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return crypto.SHA384, nil
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("digest XML no soportado")
	}
}

func removeFirstSignatureChild(root *etree.Element) {
	if root == nil {
		return
	}
	for i, child := range root.ChildElements() {
		if xmlLocalName(child.Tag) == "Signature" {
			root.RemoveChildAt(i)
			return
		}
	}
}

func findElementByAnyID(root *etree.Element, id string) *etree.Element {
	var found *etree.Element
	walkElements(root, func(el *etree.Element) {
		if found != nil {
			return
		}
		if el.SelectAttrValue("Id", "") == id || el.SelectAttrValue("ID", "") == id {
			found = el
		}
	})
	return found
}

func findFirstElementByLocalName(root *etree.Element, localName string) *etree.Element {
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

const digestAlgorithmIdentifierSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

func sha256SumBase64(raw []byte) string {
	sum := sha256.Sum256(raw)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func walkElements(el *etree.Element, fn func(*etree.Element)) {
	if el == nil {
		return
	}
	fn(el)
	for _, child := range el.ChildElements() {
		walkElements(child, fn)
	}
}
