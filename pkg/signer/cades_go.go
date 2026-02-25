// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/digitorus/pkcs7"
)

func signCadesWithGo(data []byte, cert *x509.Certificate, signer crypto.Signer, chains [][]*x509.Certificate, options map[string]interface{}) ([]byte, error) {
	if cert == nil || signer == nil {
		return nil, fmt.Errorf("certificado y signer son obligatorios para CAdES en memoria")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("datos vacios para CAdES")
	}

	sd, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, fmt.Errorf("pkcs7.NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(resolveCadesDigestOID(options))

	parents := firstChainParents(chains, cert)
	if len(parents) > 0 {
		if err := sd.AddSignerChain(cert, signer, parents, pkcs7.SignerInfoConfig{}); err != nil {
			return nil, fmt.Errorf("pkcs7.AddSignerChain: %v", err)
		}
	} else {
		if err := sd.AddSigner(cert, signer, pkcs7.SignerInfoConfig{}); err != nil {
			return nil, fmt.Errorf("pkcs7.AddSigner: %v", err)
		}
	}

	if !strings.EqualFold(optionString(options, "mode", ""), "implicit") {
		sd.Detach()
	}

	out, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("pkcs7.Finish: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("firma CAdES vacia")
	}
	return out, nil
}

func resolveCadesDigestOID(options map[string]interface{}) asn1.ObjectIdentifier {
	switch strings.ToLower(strings.TrimSpace(resolveDigestName(options, "sha256"))) {
	case "sha1":
		return pkcs7.OIDDigestAlgorithmSHA1
	case "sha384":
		return pkcs7.OIDDigestAlgorithmSHA384
	case "sha512":
		return pkcs7.OIDDigestAlgorithmSHA512
	default:
		return pkcs7.OIDDigestAlgorithmSHA256
	}
}

func firstChainParents(chains [][]*x509.Certificate, leaf *x509.Certificate) []*x509.Certificate {
	if leaf == nil {
		return nil
	}
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		out := make([]*x509.Certificate, 0, len(chain))
		for _, c := range chain {
			if c == nil || c.Equal(leaf) {
				continue
			}
			out = append(out, c)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}
