// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
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

func signXadesWithGo(inputFile, p12Path, p12Password string) ([]byte, error) {
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

	leaf, signer, chains, err := loadP12ForPades(p12Path, p12Password)
	if err != nil {
		return nil, err
	}

	certChain := [][]byte{leaf.Raw}
	if len(chains) > 0 && len(chains[0]) > 1 {
		for _, c := range chains[0][1:] {
			certChain = append(certChain, c.Raw)
		}
	}

	ctx, err := dsig.NewSigningContext(signer, certChain)
	if err != nil {
		return nil, err
	}
	ctx.Prefix = ""
	ctx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()

	signedRoot, err := ctx.SignEnveloped(root)
	if err != nil {
		return nil, err
	}

	doc.SetRoot(signedRoot)
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return out, nil
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
		return nil, fmt.Errorf("x509certificate missing")
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
