// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEvalRFC2254ExpressionBasic(t *testing.T) {
	attrs := map[string]string{
		"CN": "Juan Perez",
		"O":  "Dipgra",
	}
	if !evalRFC2254Expression("(CN=Juan*)", attrs) {
		t.Fatalf("se esperaba match de CN wildcard")
	}
	if !evalRFC2254Expression("(&(CN=Juan*)(O=Dipgra))", attrs) {
		t.Fatalf("se esperaba match AND")
	}
	if evalRFC2254Expression("(CN=Maria*)", attrs) {
		t.Fatalf("no se esperaba match con CN distinto")
	}
}

func TestMatchesPolicyID(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{
		subjectCN: "Juan Policy",
		policies:  []string{"1.2.3.4.5"},
	})
	if !matchesPolicyID(cert, "1.2.3.4.5,2.3.4.5.6") {
		t.Fatalf("se esperaba match policyid")
	}
	if matchesPolicyID(cert, "2.3.4.5.6") {
		t.Fatalf("no se esperaba match policyid")
	}
}

func TestMatchesKeyUsage(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{
		subjectCN: "Juan KU",
		keyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	})
	if !matchesKeyUsage(cert, "keyusage.digitalsignature:true") {
		t.Fatalf("se esperaba match digitalSignature")
	}
	if !matchesKeyUsage(cert, "keyusage.nonrepudiation:true") {
		t.Fatalf("se esperaba match nonRepudiation")
	}
	if matchesKeyUsage(cert, "keyusage.keyencipherment:true") {
		t.Fatalf("no se esperaba match keyEncipherment")
	}
	if !matchesKeyUsage(cert, "keyusage.keyencipherment:null") {
		t.Fatalf("keyusage:*:null debe no restringir (paridad Java)")
	}
}

func TestSigningCertFilterUsesNonRepudiationUsage(t *testing.T) {
	nonDnieDigitalSig := generateProtocolCert(t, certGenOpts{
		subjectCN: "Non DNIe DS",
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	dnieAuth := generateProtocolCert(t, certGenOpts{
		subjectCN: "DNIe Auth",
		issuerCN:  "AC DNIE 001",
		issuerOU:  "DNIE",
		issuerO:   "DIRECCION GENERAL DE LA POLICIA",
		issuerC:   "ES",
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	dnieSign := generateProtocolCert(t, certGenOpts{
		subjectCN: "DNIe Sign",
		issuerCN:  "AC DNIE 001",
		issuerOU:  "DNIE",
		issuerO:   "DIRECCION GENERAL DE LA POLICIA",
		issuerC:   "ES",
		keyUsage:  x509.KeyUsageContentCommitment,
	})
	if !certMatchesFilterToken(nonDnieDigitalSig, "signingcert:") {
		t.Fatalf("signingcert debe aceptar certificado no-DNIe aunque use digitalSignature")
	}
	if certMatchesFilterToken(dnieAuth, "signingcert:") {
		t.Fatalf("signingcert debe excluir certificado de autenticacion DNIe")
	}
	if !certMatchesFilterToken(dnieSign, "signingcert:") {
		t.Fatalf("signingcert debe aceptar certificado de firma DNIe")
	}
}

func TestMatchesPseudonymOnly(t *testing.T) {
	certWithPseudo := generateProtocolCert(t, certGenOpts{
		subjectCN:       "Pseudo",
		addPseudonymOID: true,
	})
	if !matchesPseudonym(certWithPseudo, "only") {
		t.Fatalf("se esperaba match pseudonym:only")
	}

	certWithoutPseudo := generateProtocolCert(t, certGenOpts{
		subjectCN: "NoPseudo",
	})
	if matchesPseudonym(certWithoutPseudo, "only") {
		t.Fatalf("no se esperaba match pseudonym:only")
	}
}

func TestMatchesDNIeAndAuthCert(t *testing.T) {
	dnieSignCert := generateProtocolCert(t, certGenOpts{
		subjectCN: "DNIe Sign",
		issuerCN:  "AC DNIE 001",
		issuerOU:  "DNIE",
		issuerO:   "DIRECCION GENERAL DE LA POLICIA",
		issuerC:   "ES",
		keyUsage:  x509.KeyUsageContentCommitment,
	})
	if !isSignatureDNIe(dnieSignCert) {
		t.Fatalf("se esperaba deteccion de certificado de firma DNIe")
	}
	if certMatchesFilterToken(dnieSignCert, "authcert:") {
		t.Fatalf("authcert no debe aceptar certificado de firma DNIe")
	}

	otherCert := generateProtocolCert(t, certGenOpts{
		subjectCN: "Otro Cert",
		issuerCN:  "Otra CA",
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	if isSignatureDNIe(otherCert) {
		t.Fatalf("no se esperaba deteccion DNIe para certificado generico")
	}
	if !certMatchesFilterToken(otherCert, "authcert:") {
		t.Fatalf("authcert debe aceptar certificado no-DNIe-firma")
	}
}

func TestQualifiedFilterMatchesSerial(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{
		subjectCN: "Qualified",
	})
	if !certMatchesFilterToken(cert, "qualified:"+cert.SerialNumber) {
		t.Fatalf("se esperaba match por serial exacto")
	}
	if certMatchesFilterToken(cert, "qualified:DEADBEEF") {
		t.Fatalf("no se esperaba match por serial distinto")
	}
}

func TestSSLFilterMatchesSerial(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{
		subjectCN: "SSL",
	})
	if !certMatchesFilterToken(cert, "ssl:"+cert.SerialNumber) {
		t.Fatalf("se esperaba match ssl por serial exacto")
	}
	if certMatchesFilterToken(cert, "ssl:ABCDEF") {
		t.Fatalf("no se esperaba match ssl por serial distinto")
	}
}

func TestThumbprintFilterSupportsJavaAlgorithmFirstFormat(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{subjectCN: "Thumb Java"})
	sum := sha1.Sum(cert.Content)
	thumb := hex.EncodeToString(sum[:])
	if !certMatchesFilterToken(cert, "thumbprint:SHA1:"+thumb) {
		t.Fatalf("formato Java thumbprint:SHA1:<hex> debe hacer match")
	}
}

func TestThumbprintFilterKeepsBackwardCompatibilityHexFirst(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{subjectCN: "Thumb Legacy"})
	sum := sha1.Sum(cert.Content)
	thumb := hex.EncodeToString(sum[:])
	if !certMatchesFilterToken(cert, "thumbprint:"+thumb+":sha1") {
		t.Fatalf("formato legacy thumbprint:<hex>:sha1 debe seguir haciendo match")
	}
}

func TestMatchesSSCD(t *testing.T) {
	certWithSSCD := generateProtocolCert(t, certGenOpts{
		subjectCN: "SSCD Cert",
		addSSCD:   true,
	})
	if !certMatchesFilterToken(certWithSSCD, "sscd:") {
		t.Fatalf("se esperaba match sscd")
	}

	certWithoutSSCD := generateProtocolCert(t, certGenOpts{
		subjectCN: "No SSCD",
	})
	if certMatchesFilterToken(certWithoutSSCD, "sscd:") {
		t.Fatalf("no se esperaba match sscd")
	}
}

func TestApplySelectCertFiltersPromotesDNIePairForSSL(t *testing.T) {
	auth := generateProtocolCert(t, certGenOpts{
		subjectCN:           "DNIe Auth",
		subjectSerialNumber: "12345678Z",
		issuerCN:            "AC DNIE 001",
		issuerOU:            "DNIE",
		issuerO:             "DIRECCION GENERAL DE LA POLICIA",
		issuerC:             "ES",
		keyUsage:            x509.KeyUsageDigitalSignature,
		notAfter:            time.Now().Add(365 * 24 * time.Hour),
	})
	sign := generateProtocolCert(t, certGenOpts{
		subjectCN:           "DNIe Sign",
		subjectSerialNumber: "12345678Z",
		issuerCN:            "AC DNIE 001",
		issuerOU:            "DNIE",
		issuerO:             "DIRECCION GENERAL DE LA POLICIA",
		issuerC:             "ES",
		keyUsage:            x509.KeyUsageContentCommitment,
		notAfter:            parseRFC3339OrPanic(t, auth.ValidTo),
	})
	state := &ProtocolState{
		Action: "selectcert",
		Params: mapToValues(map[string]string{
			"properties": mustB64("filter=ssl:" + auth.SerialNumber + "\n"),
		}),
	}
	if !certMatchesFilterToken(auth, "ssl:"+auth.SerialNumber) {
		t.Fatalf("el filtro ssl no selecciona el certificado auth base")
	}
	if certMatchesFilterToken(sign, "ssl:"+auth.SerialNumber) {
		t.Fatalf("el filtro ssl no deberia seleccionar directamente el cert de firma por serial auth")
	}
	if !isAuthenticationDNIe(auth) {
		t.Fatalf("el cert auth no se detecta como Authentication DNIe")
	}
	if !isSignatureDNIe(sign) {
		t.Fatalf("el cert sign no se detecta como Signature DNIe")
	}
	if _, ok := findAssociatedSignatureCert(auth, []protocol.Certificate{auth, sign}); !ok {
		t.Fatalf("no se encontro pareja de firma DNIe para el cert auth")
	}

	filtered, _ := applySelectCertFilters([]protocol.Certificate{auth, sign}, state)
	if len(filtered) != 1 || filtered[0].SerialNumber != sign.SerialNumber {
		t.Fatalf("se esperaba promocion al certificado de firma DNIe, obtenido: %#v", filtered)
	}
}

func TestApplySelectCertFiltersQualifiedKeepsNonDNIeWithoutPair(t *testing.T) {
	cert := generateProtocolCert(t, certGenOpts{
		subjectCN: "Cert Unico",
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	state := &ProtocolState{
		Action: "selectcert",
		Params: mapToValues(map[string]string{
			"properties": mustB64("filter=qualified:" + cert.SerialNumber + "\n"),
		}),
	}
	filtered, _ := applySelectCertFilters([]protocol.Certificate{cert}, state)
	if len(filtered) != 1 || filtered[0].SerialNumber != cert.SerialNumber {
		t.Fatalf("se esperaba conservar certificado no-DNIe sin pareja: %#v", filtered)
	}
}

func TestFindAssociatedSignatureCertRequiresSameIssuerDN(t *testing.T) {
	auth := generateProtocolCert(t, certGenOpts{
		subjectCN:           "Auth",
		subjectSerialNumber: "12345678Z",
		issuerCN:            "CA Igual",
		issuerOU:            "Unit",
		issuerO:             "Org",
		issuerC:             "ES",
		issuerL:             "Granada",
		keyUsage:            x509.KeyUsageDigitalSignature,
	})
	signDifferentIssuerDN := generateProtocolCert(t, certGenOpts{
		subjectCN:           "Sign",
		subjectSerialNumber: "12345678Z",
		issuerCN:            "CA Igual",
		issuerOU:            "Unit",
		issuerO:             "Org",
		issuerC:             "ES",
		issuerL:             "Madrid",
		keyUsage:            x509.KeyUsageContentCommitment,
		notAfter:            parseRFC3339OrPanic(t, auth.ValidTo),
	})
	if _, ok := findAssociatedSignatureCert(auth, []protocol.Certificate{auth, signDifferentIssuerDN}); ok {
		t.Fatalf("no debe emparejar certificados con issuer DN distinto aunque coincidan CN/O/OU/C")
	}
}

func TestApplySelectCertFiltersPseudonymAndOthersDropsEquivalentNormal(t *testing.T) {
	exp := time.Now().Add(365 * 24 * time.Hour)
	pseudo := generateProtocolCert(t, certGenOpts{
		subjectCN:       "PseudoIssuer",
		issuerCN:        "CA Pseudo",
		issuerO:         "ORG",
		issuerOU:        "UNIT",
		issuerC:         "ES",
		keyUsage:        x509.KeyUsageDigitalSignature,
		addPseudonymOID: true,
		notAfter:        exp,
	})
	normal := generateProtocolCert(t, certGenOpts{
		subjectCN: "PseudoIssuer",
		issuerCN:  "CA Pseudo",
		issuerO:   "ORG",
		issuerOU:  "UNIT",
		issuerC:   "ES",
		keyUsage:  x509.KeyUsageDigitalSignature,
		notAfter:  exp,
	})

	state := &ProtocolState{
		Action: "selectcert",
		Params: mapToValues(map[string]string{
			"properties": mustB64("filter=pseudonym:andothers\n"),
		}),
	}
	filtered, _ := applySelectCertFilters([]protocol.Certificate{pseudo, normal}, state)
	if len(filtered) != 1 || filtered[0].ID != pseudo.ID {
		t.Fatalf("se esperaba conservar solo el pseudonimo equivalente: %#v", filtered)
	}
}

func TestCertIsCurrentlyValidFallsBackToX509Dates(t *testing.T) {
	valid := generateProtocolCert(t, certGenOpts{
		subjectCN: "Valido",
		notAfter:  time.Now().Add(24 * time.Hour),
	})
	valid.ValidFrom = ""
	valid.ValidTo = ""
	valid.CanSign = false
	if !certIsCurrentlyValid(valid) {
		t.Fatalf("con fechas vacias en modelo, debe usar validez del X509 (valido)")
	}

	expired := generateProtocolCert(t, certGenOpts{
		subjectCN: "Caducado",
		notAfter:  time.Now().Add(-24 * time.Hour),
	})
	expired.ValidFrom = ""
	expired.ValidTo = ""
	expired.CanSign = true
	if certIsCurrentlyValid(expired) {
		t.Fatalf("con fechas vacias en modelo, debe usar validez del X509 (caducado)")
	}
}

type certGenOpts struct {
	subjectCN           string
	subjectSerialNumber string
	issuerCN            string
	issuerO             string
	issuerOU            string
	issuerC             string
	issuerL             string
	keyUsage            x509.KeyUsage
	policies            []string
	addPseudonymOID     bool
	addSSCD             bool
	notAfter            time.Time
}

func generateProtocolCert(t *testing.T, opts certGenOpts) protocol.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar clave: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("no se pudo generar serial: %v", err)
	}

	subject := pkix.Name{
		CommonName:   opts.subjectCN,
		Organization: []string{"Dipgra"},
		Country:      []string{"ES"},
	}
	if strings.TrimSpace(opts.subjectSerialNumber) != "" {
		subject.ExtraNames = append(subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 5},
			Value: strings.TrimSpace(opts.subjectSerialNumber),
		})
	}
	if opts.addPseudonymOID {
		subject.ExtraNames = append(subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 65},
			Value: "PSEUDO-123",
		})
	}

	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		Issuer: pkix.Name{
			CommonName:         firstOrDefault(opts.issuerCN, "CA Test"),
			Organization:       []string{firstOrDefault(opts.issuerO, "ACME")},
			OrganizationalUnit: []string{firstOrDefault(opts.issuerOU, "Unit")},
			Country:            []string{firstOrDefault(opts.issuerC, "ES")},
			Locality:           []string{firstOrDefault(opts.issuerL, "Granada")},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              opts.keyUsage,
		BasicConstraintsValid: true,
	}
	for _, oidStr := range opts.policies {
		oid, perr := parseOID(oidStr)
		if perr != nil {
			t.Fatalf("OID invalido %q: %v", oidStr, perr)
		}
		tpl.PolicyIdentifiers = append(tpl.PolicyIdentifiers, oid)
	}
	if len(opts.policies) > 0 {
		policySeq := make([]struct {
			PolicyIdentifier asn1.ObjectIdentifier
		}, 0, len(opts.policies))
		for _, oidStr := range opts.policies {
			oid, perr := parseOID(oidStr)
			if perr != nil {
				t.Fatalf("OID invalido %q: %v", oidStr, perr)
			}
			policySeq = append(policySeq, struct {
				PolicyIdentifier asn1.ObjectIdentifier
			}{PolicyIdentifier: oid})
		}
		polDER, merr := asn1.Marshal(policySeq)
		if merr != nil {
			t.Fatalf("no se pudo codificar extension de policy: %v", merr)
		}
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 32},
			Value: polDER,
		})
	}
	if opts.addSSCD {
		qcsSeq := []struct {
			StatementID asn1.ObjectIdentifier
		}{
			{StatementID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}},
		}
		qcsDER, qerr := asn1.Marshal(qcsSeq)
		if qerr != nil {
			t.Fatalf("no se pudo codificar extension QCStatements: %v", qerr)
		}
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3},
			Value: qcsDER,
		})
	}
	if tpl.KeyUsage == 0 {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("no se pudo crear certificado: %v", err)
	}

	subjectMap := map[string]string{"CN": opts.subjectCN, "O": "Dipgra"}
	if strings.TrimSpace(opts.subjectSerialNumber) != "" {
		subjectMap["SERIALNUMBER"] = strings.TrimSpace(opts.subjectSerialNumber)
	}

	return protocol.Certificate{
		ID:           "test-" + strings.ToLower(strings.TrimSpace(tpl.SerialNumber.Text(16))),
		Subject:      subjectMap,
		SerialNumber: strings.ToUpper(tpl.SerialNumber.Text(16)),
		Issuer: map[string]string{
			"CN": firstOrDefault(opts.issuerCN, "CA Test"),
			"O":  firstOrDefault(opts.issuerO, "ACME"),
			"OU": firstOrDefault(opts.issuerOU, "Unit"),
			"C":  firstOrDefault(opts.issuerC, "ES"),
			"L":  firstOrDefault(opts.issuerL, "Granada"),
		},
		ValidFrom: tpl.NotBefore.Format(time.RFC3339),
		ValidTo:   tpl.NotAfter.Format(time.RFC3339),
		CanSign:   true,
		Content:   der,
	}
}

func firstOrDefault(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func parseRFC3339OrPanic(t *testing.T, v string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatalf("fecha invalida %q: %v", v, err)
	}
	return tt
}

func mapToValues(m map[string]string) url.Values {
	out := make(url.Values, len(m))
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

func mustB64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var out asn1.ObjectIdentifier
	parts := strings.Split(s, ".")
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
