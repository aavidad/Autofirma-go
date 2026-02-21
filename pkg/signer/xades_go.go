// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

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
	ctx.Prefix = ""
	ctx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()
	return ctx.SignEnveloped(el)
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
		return &protocol.VerifyResult{
			Valid:      false,
			SignerName: cert.Subject.CommonName,
			Format:     "xades",
			Reason:     err.Error(),
		}, nil
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
		if strings.EqualFold(el.Tag, "X509Certificate") {
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

func walkElements(el *etree.Element, fn func(*etree.Element)) {
	if el == nil {
		return
	}
	fn(el)
	for _, child := range el.ChildElements() {
		walkElements(child, fn)
	}
}
