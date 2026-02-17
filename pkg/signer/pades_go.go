// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pdfsign "github.com/digitorus/pdfsign/sign"
	pdfverify "github.com/digitorus/pdfsign/verify"

	"autofirma-host/pkg/protocol"
)

type windowsStorePadesSigner struct {
	thumbprint string
	publicKey  crypto.PublicKey
}

func (s *windowsStorePadesSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *windowsStorePadesSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest vacio para firma PAdES")
	}
	hashName := "SHA256"
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA384:
			hashName = "SHA384"
		case crypto.SHA512:
			hashName = "SHA512"
		default:
			hashName = "SHA256"
		}
	}
	return signDigestWithWindowsStoreKey(s.thumbprint, digest, hashName, s.publicKey)
}

func signPadesWithGo(inputFile, p12Path, p12Password string, options map[string]interface{}) ([]byte, error) {
	cert, signer, chains, err := loadP12ForPades(p12Path, p12Password)
	if err != nil {
		return nil, err
	}

	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pades-%d.pdf", time.Now().UnixNano()))
	defer os.Remove(outFile)

	info := pdfsign.SignDataSignatureInfo{
		Name:        optionString(options, "signerName", ""),
		Location:    optionString(options, "location", buildCertificateLabel(options)),
		Reason:      optionString(options, "reason", "Firma electrónica avanzada"),
		ContactInfo: optionString(options, "contactInfo", optionString(options, "signerDNI", "")),
		Date:        time.Now().Local(),
	}

	signData := pdfsign.SignData{
		Signature: pdfsign.SignDataSignature{
			Info:       info,
			CertType:   pdfsign.ApprovalSignature,
			DocMDPPerm: pdfsign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            signer,
		DigestAlgorithm:   resolveDigestHash(options, crypto.SHA256),
		Certificate:       cert,
		CertificateChains: chains,
	}
	applyPadesAppearanceOptions(&signData, options, cert, info.Date)

	if tsaURL := strings.TrimSpace(optionString(options, "tsaURL", "")); tsaURL != "" {
		signData.TSA.URL = tsaURL
	}

	if err := pdfsign.SignFile(inputFile, outFile, signData); err != nil {
		return nil, err
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer PDF firmado: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("PDF firmado vacio")
	}
	return out, nil
}

func signPadesWithWindowsStoreGo(inputFile string, certInfo *protocol.Certificate, thumbprint string, options map[string]interface{}) ([]byte, error) {
	if certInfo == nil {
		return nil, fmt.Errorf("certificado Windows no disponible para PAdES")
	}
	if len(certInfo.Content) == 0 {
		return nil, fmt.Errorf("certificado Windows sin contenido DER")
	}
	leaf, err := x509.ParseCertificate(certInfo.Content)
	if err != nil {
		return nil, fmt.Errorf("no se pudo parsear certificado de Windows: %v", err)
	}

	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pades-winstore-%d.pdf", time.Now().UnixNano()))
	defer os.Remove(outFile)

	info := pdfsign.SignDataSignatureInfo{
		Name:        optionString(options, "signerName", ""),
		Location:    optionString(options, "location", buildCertificateLabel(options)),
		Reason:      optionString(options, "reason", "Firma electrónica avanzada"),
		ContactInfo: optionString(options, "contactInfo", optionString(options, "signerDNI", "")),
		Date:        time.Now().Local(),
	}

	signData := pdfsign.SignData{
		Signature: pdfsign.SignDataSignature{
			Info:       info,
			CertType:   pdfsign.ApprovalSignature,
			DocMDPPerm: pdfsign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:          &windowsStorePadesSigner{thumbprint: thumbprint, publicKey: leaf.PublicKey},
		DigestAlgorithm: resolveDigestHash(options, crypto.SHA256),
		Certificate:     leaf,
	}
	applyPadesAppearanceOptions(&signData, options, leaf, info.Date)

	if tsaURL := strings.TrimSpace(optionString(options, "tsaURL", "")); tsaURL != "" {
		signData.TSA.URL = tsaURL
	}

	if err := pdfsign.SignFile(inputFile, outFile, signData); err != nil {
		return nil, err
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer PDF firmado (Windows store): %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("PDF firmado vacio (Windows store)")
	}
	return out, nil
}

func signDigestWithWindowsStoreKey(thumbprint string, digest []byte, hashName string, publicKey crypto.PublicKey) ([]byte, error) {
	thumb := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(thumbprint), " ", ""))
	if thumb == "" {
		return nil, fmt.Errorf("thumbprint vacio para firma Windows store")
	}
	hashB64 := base64.StdEncoding.EncodeToString(digest)
	pubType := "rsa"
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		pubType = "ecdsa"
	case *rsa.PublicKey:
		pubType = "rsa"
	}

	ps := "$ErrorActionPreference='Stop'; " +
		"$thumb='" + psSingleQuote(thumb) + "'; " +
		"$hashB64='" + psSingleQuote(hashB64) + "'; " +
		"$hashName='" + psSingleQuote(hashName) + "'; " +
		"$pubType='" + psSingleQuote(pubType) + "'; " +
		"$cert=Get-Item ('Cert:\\CurrentUser\\My\\' + $thumb); " +
		"if ($null -eq $cert) { throw 'certificado no encontrado en CurrentUser\\\\My' }; " +
		"$hash=[System.Convert]::FromBase64String($hashB64); " +
		"if ($pubType -eq 'ecdsa') { " +
		"  $ecdsa=[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert); " +
		"  if ($null -eq $ecdsa) { throw 'clave ECDSA privada no disponible' }; " +
		"  $sig=$ecdsa.SignHash($hash) " +
		"} else { " +
		"  $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); " +
		"  if ($null -eq $rsa) { throw 'clave RSA privada no disponible' }; " +
		"  $sig=$rsa.SignHash($hash, [System.Security.Cryptography.HashAlgorithmName]::$hashName, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) " +
		"}; " +
		"[System.Convert]::ToBase64String($sig)"

	timeout := time.Duration(getEnvInt("AUTOFIRMA_SIGN_TIMEOUT_SMALL_SEC", defaultSignTimeoutSmallSec)) * time.Second
	retries := getEnvInt("AUTOFIRMA_RETRIES_SMALL", defaultRetriesSmall)
	out, err := runCommandWithRetry(
		[]string{"powershell", "-NoProfile", "-NonInteractive", "-Command", ps},
		timeout,
		retries,
		"WinStore PAdES SignHash",
	)
	if err != nil {
		return nil, err
	}

	sigB64 := strings.TrimSpace(string(out))
	if sigB64 == "" {
		return nil, fmt.Errorf("firma vacia devuelta por Windows store")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("firma Windows store en formato invalido: %v", err)
	}
	if len(sig) == 0 {
		return nil, fmt.Errorf("firma Windows store vacia")
	}
	return sig, nil
}

func verifyPadesWithGo(pdfFile string) (*protocol.VerifyResult, error) {
	f, err := os.Open(pdfFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	resp, err := pdfverify.VerifyFileWithOptions(f, pdfverify.DefaultVerifyOptions())
	if err != nil {
		return nil, err
	}
	if resp == nil || len(resp.Signers) == 0 {
		return &protocol.VerifyResult{
			Valid:  false,
			Format: "pades",
			Reason: "No se encontraron firmantes en el PDF",
		}, nil
	}

	first := resp.Signers[0]
	valid := false
	for _, s := range resp.Signers {
		if s.ValidSignature {
			valid = true
			break
		}
	}

	reason := first.Reason
	if !first.TrustedIssuer {
		if reason == "" {
			reason = "Firma criptografica valida, emisor no confiable en este entorno"
		} else {
			reason = reason + " (emisor no confiable en este entorno)"
		}
	}

	var ts string
	if first.SignatureTime != nil {
		ts = first.SignatureTime.Format(time.RFC3339)
	}

	return &protocol.VerifyResult{
		Valid:      valid,
		SignerName: first.Name,
		Timestamp:  ts,
		Format:     "pades",
		Algorithm:  "sha256WithRSA",
		Reason:     reason,
	}, nil
}

func loadP12ForPades(p12Path, password string) (*x509.Certificate, crypto.Signer, [][]*x509.Certificate, error) {
	certPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pades-cert-%d.pem", time.Now().UnixNano()))
	chainPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pades-chain-%d.pem", time.Now().UnixNano()))
	keyPEM := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-pades-key-%d.pem", time.Now().UnixNano()))
	defer os.Remove(certPEM)
	defer os.Remove(chainPEM)
	defer os.Remove(keyPEM)

	passArg := "pass:" + password
	timeout := time.Duration(getEnvInt("AUTOFIRMA_EXPORT_TIMEOUT_SEC", defaultExportTimeoutSec)) * time.Second
	retries := getEnvInt("AUTOFIRMA_EXPORT_RETRIES", defaultRetriesSmall)

	if _, err := runCommandWithRetry(
		[]string{"openssl", "pkcs12", "-in", p12Path, "-passin", passArg, "-clcerts", "-nokeys", "-out", certPEM},
		timeout,
		retries,
		"openssl pades cert",
	); err != nil {
		return nil, nil, nil, err
	}
	if _, err := runCommandWithRetry(
		[]string{"openssl", "pkcs12", "-in", p12Path, "-passin", passArg, "-cacerts", "-nokeys", "-out", chainPEM},
		timeout,
		retries,
		"openssl pades chain",
	); err != nil {
		log.Printf("[Signer] WARNING: no se pudo extraer cadena de certificados para PAdES: %v", err)
	}
	if _, err := runCommandWithRetry(
		[]string{"openssl", "pkcs12", "-in", p12Path, "-passin", passArg, "-nocerts", "-nodes", "-out", keyPEM},
		timeout,
		retries,
		"openssl pades key",
	); err != nil {
		return nil, nil, nil, err
	}

	certs, err := parsePEMCertificates(certPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	if chainCerts, err := parsePEMCertificates(chainPEM); err == nil && len(chainCerts) > 0 {
		certs = append(certs, chainCerts...)
	}
	signer, err := parseSignerFromPEMFile(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}

	if signer == nil {
		return nil, nil, nil, fmt.Errorf("no se encontro clave privada en P12")
	}
	if len(certs) == 0 {
		return nil, nil, nil, fmt.Errorf("no se encontro certificado en P12")
	}

	leaf := selectLeafForSigner(certs, signer)
	if leaf == nil {
		leaf = certs[0]
	}

	var chains [][]*x509.Certificate
	if ch, err := buildCertChains(leaf, certs); err == nil {
		chains = ch
	}

	return leaf, signer, chains, nil
}

func parseSignerFromPEMFile(path string) (crypto.Signer, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		signer, err := parseSignerFromPEMBlock(block)
		if err == nil {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("no se encontro clave privada compatible en %s", path)
}

func parseSignerFromPEMBlock(block *pem.Block) (crypto.Signer, error) {
	if block == nil {
		return nil, fmt.Errorf("bloque PEM nulo")
	}
	if keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := keyAny.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecKey, nil
	}
	return nil, fmt.Errorf("clave privada no soportada")
}

func parsePEMCertificates(path string) ([]*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no se encontraron certificados PEM en %s", path)
	}
	return certs, nil
}

func selectLeafForSigner(certs []*x509.Certificate, signer crypto.Signer) *x509.Certificate {
	if len(certs) == 0 || signer == nil {
		return nil
	}
	signerPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil
	}
	for _, c := range certs {
		certPub, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err == nil && bytes.Equal(certPub, signerPub) {
			return c
		}
	}
	return nil
}

func buildCertChains(leaf *x509.Certificate, certs []*x509.Certificate) ([][]*x509.Certificate, error) {
	if leaf == nil {
		return nil, fmt.Errorf("falta certificado hoja")
	}
	if len(certs) <= 1 {
		return nil, nil
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs {
		if c.Equal(leaf) {
			continue
		}
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   leaf.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}
	return chains, nil
}

func optionString(options map[string]interface{}, key, def string) string {
	if options == nil {
		return def
	}
	v, ok := options[key]
	if !ok || v == nil {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func optionBool(options map[string]interface{}, key string, def bool) bool {
	if options == nil {
		return def
	}
	v, ok := options[key]
	if !ok || v == nil {
		return def
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		s := strings.TrimSpace(strings.ToLower(b))
		if s == "true" || s == "1" || s == "yes" || s == "si" {
			return true
		}
		if s == "false" || s == "0" || s == "no" {
			return false
		}
	}
	return def
}

func optionFloat64(options map[string]interface{}, key string, def float64) float64 {
	if options == nil {
		return def
	}
	v, ok := options[key]
	if !ok || v == nil {
		return def
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		s := strings.TrimSpace(n)
		if s == "" {
			return def
		}
		if parsed, err := strconv.ParseFloat(s, 64); err == nil {
			return parsed
		}
	}
	return def
}

func optionUint32(options map[string]interface{}, key string, def uint32) uint32 {
	if options == nil {
		return def
	}
	v, ok := options[key]
	if !ok || v == nil {
		return def
	}
	switch n := v.(type) {
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case int:
		if n <= 0 {
			return def
		}
		return uint32(n)
	case int32:
		if n <= 0 {
			return def
		}
		return uint32(n)
	case int64:
		if n <= 0 {
			return def
		}
		return uint32(n)
	case float64:
		if n <= 0 {
			return def
		}
		return uint32(n)
	case string:
		s := strings.TrimSpace(n)
		if s == "" {
			return def
		}
		if parsed, err := strconv.Atoi(s); err == nil && parsed > 0 {
			return uint32(parsed)
		}
	}
	return def
}

func applyPadesAppearanceOptions(signData *pdfsign.SignData, options map[string]interface{}, cert *x509.Certificate, signingTime time.Time) {
	if signData == nil {
		return
	}

	visible := optionBool(options, "visibleSignature", false)
	if !visible {
		return
	}

	page := optionUint32(options, "page", 1)
	x := optionFloat64(options, "x", 0)
	y := optionFloat64(options, "y", 0)
	w := optionFloat64(options, "width", 0)
	h := optionFloat64(options, "height", 0)

	if w <= 0 || h <= 0 {
		return
	}

	signData.Appearance.Visible = true
	signData.Appearance.Page = page
	signData.Appearance.LowerLeftX = x
	signData.Appearance.LowerLeftY = y
	signData.Appearance.UpperRightX = x + w
	signData.Appearance.UpperRightY = y + h
	signData.Appearance.Text = buildPadesVisibleSignatureText(cert, signingTime)
}

func buildCertificateLabel(options map[string]interface{}) string {
	issuerOrg := strings.TrimSpace(optionString(options, "issuerOrg", ""))
	issuerName := strings.TrimSpace(optionString(options, "issuerName", ""))
	switch {
	case issuerOrg != "" && issuerName != "":
		return "Certificado: " + issuerOrg + " (" + issuerName + ")"
	case issuerOrg != "":
		return "Certificado: " + issuerOrg
	case issuerName != "":
		return "Certificado: " + issuerName
	default:
		return "Certificado digital cualificado"
	}
}

func buildPadesVisibleSignatureText(cert *x509.Certificate, signingTime time.Time) string {
	cn := "Desconocido"
	if cert != nil {
		if v := strings.TrimSpace(cert.Subject.CommonName); v != "" {
			cn = v
		}
	}
	return "CN=" + cn + "\nFirmado el " + signingTime.Format("02/01/2006 15:04:05") + " por un certificado de la FNMT"
}
