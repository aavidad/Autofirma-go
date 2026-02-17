// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"autofirma-host/pkg/protocol"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	oidContentTypeData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentTypeSigned    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrCounterSignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type cmsSignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                cmsContentInfo
	Certificates               cmsRawCertificates     `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []cmsSignerInfo        `asn1:"set"`
}

type cmsSignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     cmsIssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []cmsAttribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []cmsAttribute `asn1:"optional,omitempty,tag:1"`
}

type cmsIssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type cmsAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type cmsRawCertificates struct {
	Raw asn1.RawContent
}

func counterSignCadesDER(data []byte, cert *protocol.Certificate, certID, algorithm, target, targetSigners string) ([]byte, error) {
	return counterSignCadesDERWithSigner(data, cert, certID, algorithm, target, targetSigners, SignPKCS1)
}

func counterSignCadesDERWithSigner(
	data []byte,
	cert *protocol.Certificate,
	certID, algorithm, target, targetSigners string,
	signPKCS1 func(preSignData []byte, certificateID string, algorithm string) (string, error),
) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("firma CMS vacia")
	}
	if cert == nil || len(cert.Content) == 0 {
		return nil, fmt.Errorf("certificado de contrafirma no disponible")
	}
	xc, err := x509.ParseCertificate(cert.Content)
	if err != nil {
		return nil, fmt.Errorf("certificado de contrafirma invalido: %v", err)
	}

	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil, fmt.Errorf("CMS invalido: %v", err)
	}
	if !ci.ContentType.Equal(oidContentTypeSigned) {
		return nil, fmt.Errorf("contenido CMS no es SignedData")
	}

	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData invalido: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, fmt.Errorf("SignedData sin firmantes")
	}
	signerCerts := parseCMSCertificates(sd.Certificates)
	matcher := buildCounterSignerMatcher(targetSigners)

	targetMode := normalizeCounterSignTarget(target)
	for i := range sd.SignerInfos {
		updated, err := applyCounterSignTarget(sd.SignerInfos[i], signerCerts, matcher, xc, certID, algorithm, targetMode, signPKCS1)
		if err != nil {
			return nil, err
		}
		sd.SignerInfos[i] = updated
	}

	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("no se pudo codificar SignedData de contrafirma: %v", err)
	}
	out, err := asn1.Marshal(cmsContentInfo{
		ContentType: oidContentTypeSigned,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	})
	if err != nil {
		return nil, fmt.Errorf("no se pudo codificar CMS de contrafirma: %v", err)
	}
	return out, nil
}

func applyCounterSignTarget(
	si cmsSignerInfo,
	signerCerts []*x509.Certificate,
	matcher counterSignerMatcher,
	xc *x509.Certificate,
	certID, algorithm, targetMode string,
	signPKCS1 func(preSignData []byte, certificateID string, algorithm string) (string, error),
) (cmsSignerInfo, error) {
	hasChildren := false
	for i := range si.UnauthenticatedAttributes {
		attr := si.UnauthenticatedAttributes[i]
		if !attr.Type.Equal(oidAttrCounterSignature) {
			continue
		}
		children, err := decodeCounterSignatureSignerInfos(attr)
		if err != nil {
			return si, err
		}
		if len(children) == 0 {
			continue
		}
		hasChildren = true
		for j := range children {
			updatedChild, err := applyCounterSignTarget(children[j], signerCerts, matcher, xc, certID, algorithm, targetMode, signPKCS1)
			if err != nil {
				return si, err
			}
			children[j] = updatedChild
		}
		si.UnauthenticatedAttributes[i] = encodeCounterSignatureSignerInfos(children)
	}

	shouldSign := targetMode == "tree" || (targetMode == "leafs" && !hasChildren)
	if targetMode == "signers" {
		shouldSign = matcher.matches(si, signerCerts)
	}
	if shouldSign {
		csInfo, err := buildCounterSignerInfo(si.EncryptedDigest, xc, certID, algorithm, signPKCS1)
		if err != nil {
			return si, err
		}
		si.UnauthenticatedAttributes = append(si.UnauthenticatedAttributes, encodeCounterSignatureSignerInfos([]cmsSignerInfo{csInfo}))
		sortCMSAttributes(si.UnauthenticatedAttributes)
	}
	return si, nil
}

func normalizeCounterSignTarget(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	switch t {
	case "signers":
		return "signers"
	case "tree", "arbol", "contrafirmar_arbol":
		return "tree"
	case "leafs", "leaves", "hojas", "contrafirmar_hojas", "":
		return "leafs"
	default:
		return "leafs"
	}
}

type counterSignerMatcher struct {
	selectors []string
}

func buildCounterSignerMatcher(raw string) counterSignerMatcher {
	parts := splitCounterSignerTargets(raw)
	norm := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.ToLower(strings.TrimSpace(p))
		if s == "" {
			continue
		}
		norm = append(norm, s)
	}
	return counterSignerMatcher{selectors: norm}
}

func splitCounterSignerTargets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replaced := strings.NewReplacer("|", ",", ";", ",", "\n", ",", "\r", ",").Replace(raw)
	parts := strings.Split(replaced, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m counterSignerMatcher) matches(si cmsSignerInfo, certs []*x509.Certificate) bool {
	if len(m.selectors) == 0 {
		return false
	}
	candidates := buildSignerMatchCandidates(si, certs)
	for _, sel := range m.selectors {
		for _, c := range candidates {
			if c == sel {
				return true
			}
		}
	}
	return false
}

func buildSignerMatchCandidates(si cmsSignerInfo, certs []*x509.Certificate) []string {
	cands := []string{
		strings.ToLower(strings.TrimSpace(si.IssuerAndSerialNumber.SerialNumber.String())),
		strings.ToLower(strings.TrimSpace(strings.ToUpper(si.IssuerAndSerialNumber.SerialNumber.Text(16)))),
	}
	cert := findCMSSignerCertificate(si, certs)
	if cert != nil {
		cands = append(cands,
			strings.ToLower(strings.TrimSpace(cert.Subject.CommonName)),
			strings.ToLower(strings.TrimSpace(cert.Subject.String())),
			strings.ToLower(strings.TrimSpace(cert.SerialNumber.String())),
			strings.ToLower(strings.TrimSpace(strings.ToUpper(cert.SerialNumber.Text(16)))),
			strings.ToLower(strings.TrimSpace(fmt.Sprintf("%x", sha1.Sum(cert.Raw)))),
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

func findCMSSignerCertificate(si cmsSignerInfo, certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if c == nil || c.SerialNumber == nil || si.IssuerAndSerialNumber.SerialNumber == nil {
			continue
		}
		if c.SerialNumber.Cmp(si.IssuerAndSerialNumber.SerialNumber) != 0 {
			continue
		}
		if bytes.Equal(c.RawIssuer, si.IssuerAndSerialNumber.IssuerName.FullBytes) {
			return c
		}
	}
	return nil
}

func parseCMSCertificates(raw cmsRawCertificates) []*x509.Certificate {
	if len(raw.Raw) == 0 {
		return nil
	}
	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil
	}
	certs, err := x509.ParseCertificates(val.Bytes)
	if err != nil {
		return nil
	}
	return certs
}

func decodeCounterSignatureSignerInfos(attr cmsAttribute) ([]cmsSignerInfo, error) {
	if !attr.Type.Equal(oidAttrCounterSignature) {
		return nil, nil
	}
	rest := attr.Value.Bytes
	out := make([]cmsSignerInfo, 0, 1)
	for len(rest) > 0 {
		var si cmsSignerInfo
		next, err := asn1.Unmarshal(rest, &si)
		if err != nil {
			return nil, fmt.Errorf("atributo countersignature invalido: %v", err)
		}
		out = append(out, si)
		rest = next
	}
	return out, nil
}

func encodeCounterSignatureSignerInfos(infos []cmsSignerInfo) cmsAttribute {
	raw := make([]byte, 0)
	for _, si := range infos {
		enc, err := asn1.Marshal(si)
		if err != nil {
			continue
		}
		raw = append(raw, enc...)
	}
	return cmsAttribute{
		Type:  oidAttrCounterSignature,
		Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: raw},
	}
}

func buildCounterSignerInfo(
	targetEncryptedDigest []byte,
	xc *x509.Certificate,
	certID, algorithm string,
	signPKCS1 func(preSignData []byte, certificateID string, algorithm string) (string, error),
) (cmsSignerInfo, error) {
	digestOID := resolveDigestOID(map[string]interface{}{"algorithm": algorithm}, "2.16.840.1.101.3.4.2.1")
	signOID, err := resolveSignatureAlgorithmOID(algorithm)
	if err != nil {
		return cmsSignerInfo{}, err
	}

	mdAttr, err := marshalCMSAttribute(oidAttrMessageDigest, digestBytesForAlgorithm(targetEncryptedDigest, algorithm))
	if err != nil {
		return cmsSignerInfo{}, err
	}
	stAttr, err := marshalCMSAttribute(oidAttrSigningTime, time.Now().UTC())
	if err != nil {
		return cmsSignerInfo{}, err
	}
	signedAttrs := []cmsAttribute{mdAttr, stAttr}
	sortCMSAttributes(signedAttrs)
	toSign, err := marshalCMSAttributesSet(signedAttrs)
	if err != nil {
		return cmsSignerInfo{}, err
	}
	pk1B64, err := signPKCS1(toSign, certID, algorithm)
	if err != nil {
		return cmsSignerInfo{}, fmt.Errorf("error firmando countersignature PKCS1: %v", err)
	}
	pk1, err := decodeAutoFirmaB64Local(strings.ReplaceAll(pk1B64, " ", "+"))
	if err != nil {
		return cmsSignerInfo{}, fmt.Errorf("firma PKCS1 de contrafirma invalida: %v", err)
	}

	return cmsSignerInfo{
		Version: 1,
		IssuerAndSerialNumber: cmsIssuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: xc.RawIssuer},
			SerialNumber: xc.SerialNumber,
		},
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: mustParseOID(digestOID)},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signOID},
		AuthenticatedAttributes:   signedAttrs,
		EncryptedDigest:           pk1,
	}, nil
}

func digestBytesForAlgorithm(data []byte, algorithm string) []byte {
	name := resolveDigestName(map[string]interface{}{"algorithm": algorithm}, "sha256")
	return digestBytesByName(data, name)
}

func digestBytesByName(data []byte, name string) []byte {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:]
	case "sha384":
		sum := sha512.Sum384(data)
		return sum[:]
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:]
	default:
		sum := sha256.Sum256(data)
		return sum[:]
	}
}

func resolveSignatureAlgorithmOID(algorithm string) (asn1.ObjectIdentifier, error) {
	l := strings.ToLower(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(l, "sha1"):
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}, nil
	case strings.Contains(l, "sha384"):
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, nil
	case strings.Contains(l, "sha512"):
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, nil
	case l == "" || strings.Contains(l, "sha256"):
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, nil
	default:
		log.Printf("[Signer] CounterSign unknown algorithm %q, fallback to SHA256withRSA OID", algorithm)
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, nil
	}
}

func marshalCMSAttribute(attrType asn1.ObjectIdentifier, value interface{}) (cmsAttribute, error) {
	enc, err := asn1.Marshal(value)
	if err != nil {
		return cmsAttribute{}, err
	}
	return cmsAttribute{
		Type:  attrType,
		Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: enc},
	}, nil
}

func marshalCMSAttributesSet(attrs []cmsAttribute) ([]byte, error) {
	enc, err := asn1.Marshal(struct {
		A []cmsAttribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(enc, &raw); err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

func sortCMSAttributes(attrs []cmsAttribute) {
	sort.Slice(attrs, func(i, j int) bool {
		ai, errI := asn1.Marshal(attrs[i])
		aj, errJ := asn1.Marshal(attrs[j])
		if errI != nil || errJ != nil {
			return i < j
		}
		return string(ai) < string(aj)
	})
}

func mustParseOID(s string) asn1.ObjectIdentifier {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
		}
		out = append(out, n)
	}
	return out
}

func decodeAutoFirmaB64Local(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("vacío")
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		out, err := enc.DecodeString(v)
		if err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}
