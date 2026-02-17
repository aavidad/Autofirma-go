// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/url"
	"strings"
	"time"
)

type selectCertFilterOptions struct {
	forceAutoSelection   bool
	autoSelectWhenSingle bool
	allowExternalStores  bool
}

func applySelectCertFilters(certs []protocol.Certificate, state *ProtocolState) ([]protocol.Certificate, selectCertFilterOptions) {
	rawProps := ""
	if state != nil {
		rawProps = getQueryParam(state.Params, "properties")
	}
	props := decodeProtocolProperties(rawProps)
	headless := isHeadlessMode(props)
	autoSingle := isMandatorySelectionDisabled(props)
	opts := selectCertFilterOptions{
		forceAutoSelection:   headless,
		autoSelectWhenSingle: autoSingle,
		allowExternalStores:  true,
	}

	filterGroups := extractFilterGroups(props)
	if len(filterGroups) == 0 {
		filterGroups = []string{"nonexpired:true"}
	}
	if containsDisableOpeningExternalStoresFilter(filterGroups) {
		opts.allowExternalStores = false
	}
	log.Printf("[SelectCertFilter] groups=%d force_auto=%t auto_single=%t", len(filterGroups), opts.forceAutoSelection, opts.autoSelectWhenSingle)

	filtered := make([]protocol.Certificate, 0, len(certs))
	for _, cert := range certs {
		if certMatchesAnyFilterGroup(cert, filterGroups) {
			filtered = append(filtered, cert)
		}
	}
	if containsPseudonymAndOthersFilter(filterGroups) {
		filtered = applyPseudonymAndOthersRule(filtered)
	}
	if containsPairedSerialFilter(filterGroups) {
		filtered = promoteAssociatedSignatureCerts(filtered, certs)
	}
	return filtered, opts
}

func decodeProtocolProperties(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]string{}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		normalized := strings.ReplaceAll(raw, " ", "+")
		b, err := enc.DecodeString(normalized)
		if err != nil {
			continue
		}
		return parseProperties(string(b))
	}
	decodedURL, err := url.QueryUnescape(raw)
	if err == nil && strings.TrimSpace(decodedURL) != "" {
		return parseProperties(strings.ReplaceAll(decodedURL, `\n`, "\n"))
	}
	return parseProperties(strings.ReplaceAll(raw, `\n`, "\n"))
}

func getProtocolProperty(props map[string]string, keys ...string) (string, bool) {
	if len(props) == 0 || len(keys) == 0 {
		return "", false
	}
	for _, k := range keys {
		if v, ok := props[k]; ok {
			return strings.TrimSpace(v), true
		}
	}
	for rawKey, rawVal := range props {
		for _, k := range keys {
			if strings.EqualFold(strings.TrimSpace(rawKey), strings.TrimSpace(k)) {
				return strings.TrimSpace(rawVal), true
			}
		}
	}
	return "", false
}

func parseProperties(body string) map[string]string {
	props := make(map[string]string)
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		sepIdx := strings.IndexAny(line, "=:")
		if sepIdx < 0 {
			props[strings.TrimSpace(line)] = ""
			continue
		}
		k := strings.TrimSpace(line[:sepIdx])
		v := strings.TrimSpace(line[sepIdx+1:])
		if k != "" {
			props[k] = v
		}
	}
	return props
}

func isHeadlessMode(props map[string]string) bool {
	v, _ := getProtocolProperty(props, "headless")
	return strings.EqualFold(v, "true")
}

func isMandatorySelectionDisabled(props map[string]string) bool {
	mandatorySelection, hasMandatory := getProtocolProperty(props, "mandatoryCertSelection")
	return hasMandatory && strings.EqualFold(mandatorySelection, "false")
}

func extractFilterGroups(props map[string]string) []string {
	if v, ok := getProtocolProperty(props, "filter"); ok && v != "" {
		return []string{v}
	}
	if v, ok := getProtocolProperty(props, "filters"); ok && v != "" {
		return []string{v}
	}
	out := make([]string, 0, 4)
	for i := 1; i <= 20; i++ {
		k := "filters." + strconvItoa(i)
		v, ok := getProtocolProperty(props, k)
		if !ok || v == "" {
			if i == 1 {
				continue
			}
			break
		}
		out = append(out, v)
	}
	return out
}

func certMatchesAnyFilterGroup(cert protocol.Certificate, groups []string) bool {
	for _, group := range groups {
		if certMatchesAllFilterTokens(cert, group) {
			return true
		}
	}
	return false
}

func certMatchesAllFilterTokens(cert protocol.Certificate, group string) bool {
	tokens := strings.Split(group, ";")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if !certMatchesFilterToken(cert, token) {
			return false
		}
	}
	return true
}

func certMatchesFilterToken(cert protocol.Certificate, token string) bool {
	lower := strings.ToLower(strings.TrimSpace(token))
	switch {
	case strings.HasPrefix(lower, "nonexpired:"):
		arg := strings.TrimSpace(token[len("nonexpired:"):])
		// Java: nonexpired:false means "show expired" (do not filter by date).
		if strings.EqualFold(arg, "false") {
			return true
		}
		return certIsCurrentlyValid(cert)
	case lower == "nonexpired":
		return certIsCurrentlyValid(cert)
	case strings.HasPrefix(lower, "subject.contains:"):
		q := strings.TrimSpace(token[len("subject.contains:"):])
		return containsInMapValues(cert.Subject, q)
	case strings.HasPrefix(lower, "issuer.contains:"):
		q := strings.TrimSpace(token[len("issuer.contains:"):])
		return containsInMapValues(cert.Issuer, q)
	case strings.HasPrefix(lower, "signingcert:"):
		// Java SigningCertificateFilter keeps all sign-capable certificates and
		// excludes known authentication-only certs (notably DNIe auth).
		return !isAuthenticationDNIe(cert)
	case strings.HasPrefix(lower, "thumbprint:"):
		spec := strings.TrimSpace(token[len("thumbprint:"):])
		return matchesThumbprint(cert, spec)
	case strings.HasPrefix(lower, "encodedcert:"):
		b64 := strings.TrimSpace(token[len("encodedcert:"):])
		return matchesEncodedCert(cert, b64)
	case strings.HasPrefix(lower, "qualified:"):
		sn := strings.TrimSpace(token[len("qualified:"):])
		return normalizeSerialHex(cert.SerialNumber) == normalizeSerialHex(sn)
	case strings.HasPrefix(lower, "ssl:"):
		sn := strings.TrimSpace(token[len("ssl:"):])
		return normalizeSerialHex(cert.SerialNumber) == normalizeSerialHex(sn)
	case strings.HasPrefix(lower, "sscd:"):
		return matchesSSCD(cert)
	case strings.HasPrefix(lower, "dnie:"):
		return isSignatureDNIe(cert)
	case strings.HasPrefix(lower, "authcert:"):
		return !isSignatureDNIe(cert)
	case strings.HasPrefix(lower, "policyid:"):
		spec := strings.TrimSpace(token[len("policyid:"):])
		return matchesPolicyID(cert, spec)
	case strings.HasPrefix(lower, "subject.rfc2254:"):
		expr := strings.TrimSpace(token[len("subject.rfc2254:"):])
		return evalRFC2254Expression(expr, cert.Subject)
	case strings.HasPrefix(lower, "issuer.rfc2254.recurse:"):
		expr := strings.TrimSpace(token[len("issuer.rfc2254.recurse:"):])
		// Recurse over chain is not available in current protocol cert model;
		// we apply the expression on direct issuer as best-effort behavior.
		return evalRFC2254Expression(expr, cert.Issuer)
	case strings.HasPrefix(lower, "issuer.rfc2254:"):
		expr := strings.TrimSpace(token[len("issuer.rfc2254:"):])
		return evalRFC2254Expression(expr, cert.Issuer)
	case strings.HasPrefix(lower, "keyusage."):
		return matchesKeyUsage(cert, lower)
	case strings.HasPrefix(lower, "pseudonym:"):
		mode := strings.TrimSpace(token[len("pseudonym:"):])
		return matchesPseudonym(cert, mode)
	case strings.HasPrefix(lower, "disableopeningexternalstores"):
		// UI-level behavior in Java (allow/disallow external stores opening).
		// Current Go implementation keeps this as a no-op in filtering stage.
		return true
	default:
		// Unsupported filter token: ignore (best-effort compatibility).
		return true
	}
}

func certIsCurrentlyValid(cert protocol.Certificate) bool {
	nb, errNB := time.Parse(time.RFC3339, strings.TrimSpace(cert.ValidFrom))
	na, errNA := time.Parse(time.RFC3339, strings.TrimSpace(cert.ValidTo))
	if errNB != nil || errNA != nil {
		if xc, err := parseProtocolX509(cert); err == nil {
			now := time.Now()
			return !now.Before(xc.NotBefore) && !now.After(xc.NotAfter)
		}
		return cert.CanSign
	}
	now := time.Now()
	return !now.Before(nb) && !now.After(na)
}

func containsInMapValues(m map[string]string, query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	for _, v := range m {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}

func matchesEncodedCert(cert protocol.Certificate, b64 string) bool {
	b64 = strings.TrimSpace(strings.ReplaceAll(b64, " ", "+"))
	if b64 == "" {
		return true
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		raw, err := enc.DecodeString(b64)
		if err == nil {
			return string(raw) == string(cert.Content)
		}
	}
	return false
}

func matchesThumbprint(cert protocol.Certificate, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	parts := strings.Split(spec, ":")
	want := ""
	algo := "sha256"
	if len(parts) >= 2 {
		p0 := strings.TrimSpace(parts[0])
		p1 := strings.TrimSpace(parts[1])
		// Java format: thumbprint:<algorithm>:<hex>
		if isThumbprintAlgorithm(p0) {
			algo = normalizeThumbprintAlgorithm(p0)
			want = normalizeHex(p1)
		} else {
			// Backward compatible fallback: thumbprint:<hex>:<algorithm>
			want = normalizeHex(p0)
			if p1 != "" {
				algo = normalizeThumbprintAlgorithm(p1)
			}
		}
	} else {
		want = normalizeHex(parts[0])
	}
	if want == "" {
		return true
	}
	switch normalizeThumbprintAlgorithm(algo) {
	case "sha1":
		sum := sha1.Sum(cert.Content)
		return normalizeHex(hex.EncodeToString(sum[:])) == want
	case "sha384":
		sum := sha512.Sum384(cert.Content)
		return normalizeHex(hex.EncodeToString(sum[:])) == want
	case "sha512":
		sum := sha512.Sum512(cert.Content)
		return normalizeHex(hex.EncodeToString(sum[:])) == want
	default:
		sum := sha256.Sum256(cert.Content)
		return normalizeHex(hex.EncodeToString(sum[:])) == want
	}
}

func isThumbprintAlgorithm(v string) bool {
	switch normalizeThumbprintAlgorithm(v) {
	case "sha1", "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

func normalizeThumbprintAlgorithm(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "")
	return v
}

func normalizeHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func normalizeSerialHex(s string) string {
	s = normalizeHex(s)
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}

func strconvItoa(n int) string {
	// tiny local helper to keep this file independent from strconv import.
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + (n % 10))
		n /= 10
	}
	return string(b[i:])
}

func parseProtocolX509(cert protocol.Certificate) (*x509.Certificate, error) {
	if len(cert.Content) == 0 {
		return nil, x509.CertificateInvalidError{}
	}
	return x509.ParseCertificate(cert.Content)
}

func matchesPolicyID(cert protocol.Certificate, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	allowed := make(map[string]struct{})
	for _, oid := range strings.Split(spec, ",") {
		oid = strings.TrimSpace(oid)
		if oid != "" {
			allowed[oid] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return true
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return false
	}
	policyOIDs := extractCertificatePolicyOIDs(xc)
	if len(policyOIDs) == 0 {
		return false
	}
	for _, oid := range policyOIDs {
		if _, ok := allowed[oid.String()]; !ok {
			return false
		}
	}
	return true
}

func extractCertificatePolicyOIDs(xc *x509.Certificate) []asn1.ObjectIdentifier {
	if xc == nil {
		return nil
	}
	if len(xc.PolicyIdentifiers) > 0 {
		return xc.PolicyIdentifiers
	}
	policyExtOID := asn1.ObjectIdentifier{2, 5, 29, 32}
	for _, ext := range xc.Extensions {
		if !ext.Id.Equal(policyExtOID) {
			continue
		}
		var seq []policyInformation
		if _, err := asn1.Unmarshal(ext.Value, &seq); err == nil {
			oids := make([]asn1.ObjectIdentifier, 0, len(seq))
			for _, pi := range seq {
				if len(pi.PolicyIdentifier) > 0 {
					oids = append(oids, pi.PolicyIdentifier)
				}
			}
			if len(oids) > 0 {
				return oids
			}
		}
	}
	return nil
}

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
}

func matchesSSCD(cert protocol.Certificate) bool {
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return false
	}
	qcStatementsOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	qcSSCDOID := asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	for _, ext := range xc.Extensions {
		if !ext.Id.Equal(qcStatementsOID) {
			continue
		}
		var seq []qcStatement
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			return false
		}
		for _, st := range seq {
			if st.StatementID.Equal(qcSSCDOID) {
				return true
			}
		}
	}
	return false
}

type qcStatement struct {
	StatementID asn1.ObjectIdentifier
	Info        asn1.RawValue `asn1:"optional"`
}

func matchesKeyUsage(cert protocol.Certificate, tokenLower string) bool {
	// tokenLower like "keyusage.digitalsignature:true"
	rest := strings.TrimPrefix(tokenLower, "keyusage.")
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return true
	}
	name := strings.TrimSpace(parts[0])
	want := true
	if len(parts) == 2 {
		raw := strings.TrimSpace(parts[1])
		// Java keyusage parser accepts "null" to leave this key-usage unconstrained.
		if strings.EqualFold(raw, "null") || raw == "" {
			return true
		}
		want = strings.EqualFold(raw, "true")
	}

	xc, err := parseProtocolX509(cert)
	if err != nil {
		return false
	}
	has := false
	switch name {
	case "digitalsignature":
		has = xc.KeyUsage&x509.KeyUsageDigitalSignature != 0
	case "nonrepudiation":
		has = xc.KeyUsage&x509.KeyUsageContentCommitment != 0
	case "keyencipherment":
		has = xc.KeyUsage&x509.KeyUsageKeyEncipherment != 0
	case "dataencipherment":
		has = xc.KeyUsage&x509.KeyUsageDataEncipherment != 0
	case "keyagreement":
		has = xc.KeyUsage&x509.KeyUsageKeyAgreement != 0
	case "keycertsign":
		has = xc.KeyUsage&x509.KeyUsageCertSign != 0
	case "crlsign":
		has = xc.KeyUsage&x509.KeyUsageCRLSign != 0
	case "encipheronly":
		has = xc.KeyUsage&x509.KeyUsageEncipherOnly != 0
	case "decipheronly":
		has = xc.KeyUsage&x509.KeyUsageDecipherOnly != 0
	default:
		return true
	}
	return has == want
}

func matchesPseudonym(cert protocol.Certificate, mode string) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "andothers" {
		return true
	}
	if mode != "only" {
		return true
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return false
	}
	pseudonymOID := asn1.ObjectIdentifier{2, 5, 4, 65}
	for _, atv := range xc.Subject.Names {
		if atv.Type.Equal(pseudonymOID) {
			return true
		}
	}
	for _, atv := range xc.Subject.ExtraNames {
		if atv.Type.Equal(pseudonymOID) {
			return true
		}
	}
	return false
}

func isSignatureDNIe(cert protocol.Certificate) bool {
	const dnieIssuerExpr = "(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))"
	issuerAttrs := cert.Issuer
	if len(issuerAttrs) == 0 {
		xc, err := parseProtocolX509(cert)
		if err != nil {
			return false
		}
		issuerAttrs = x509NameToAttrs(xc.Issuer)
	}
	if !evalRFC2254Expression(dnieIssuerExpr, issuerAttrs) {
		return false
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return false
	}
	return xc.KeyUsage&x509.KeyUsageContentCommitment != 0
}

func isAuthenticationDNIe(cert protocol.Certificate) bool {
	const dnieIssuerExpr = "(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))"
	issuerAttrs := cert.Issuer
	if len(issuerAttrs) == 0 {
		xc, err := parseProtocolX509(cert)
		if err != nil {
			return false
		}
		issuerAttrs = x509NameToAttrs(xc.Issuer)
	}
	if !evalRFC2254Expression(dnieIssuerExpr, issuerAttrs) {
		return false
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return false
	}
	return xc.KeyUsage&x509.KeyUsageDigitalSignature != 0
}

func x509NameToAttrs(name pkix.Name) map[string]string {
	out := map[string]string{}
	if name.CommonName != "" {
		out["CN"] = name.CommonName
	}
	if len(name.Organization) > 0 {
		out["O"] = name.Organization[0]
	}
	if len(name.OrganizationalUnit) > 0 {
		out["OU"] = name.OrganizationalUnit[0]
	}
	if len(name.Country) > 0 {
		out["C"] = name.Country[0]
	}
	if len(name.Locality) > 0 {
		out["L"] = name.Locality[0]
	}
	if len(name.Province) > 0 {
		out["ST"] = name.Province[0]
	}
	return out
}

func containsPairedSerialFilter(groups []string) bool {
	for _, group := range groups {
		for _, token := range strings.Split(group, ";") {
			lower := strings.ToLower(strings.TrimSpace(token))
			if strings.HasPrefix(lower, "qualified:") || strings.HasPrefix(lower, "ssl:") {
				return true
			}
		}
	}
	return false
}

func containsPseudonymAndOthersFilter(groups []string) bool {
	for _, group := range groups {
		for _, token := range strings.Split(group, ";") {
			lower := strings.ToLower(strings.TrimSpace(token))
			if strings.HasPrefix(lower, "pseudonym:andothers") || strings.EqualFold(lower, "pseudonym:") {
				return true
			}
		}
	}
	return false
}

func containsDisableOpeningExternalStoresFilter(groups []string) bool {
	for _, group := range groups {
		for _, token := range strings.Split(group, ";") {
			if strings.EqualFold(strings.TrimSpace(token), "disableopeningexternalstores") {
				return true
			}
		}
	}
	return false
}

func promoteAssociatedSignatureCerts(filtered []protocol.Certificate, all []protocol.Certificate) []protocol.Certificate {
	if len(filtered) == 0 {
		return filtered
	}
	out := make([]protocol.Certificate, 0, len(filtered))
	seen := make(map[string]struct{})

	for _, cert := range filtered {
		target := cert
		if !hasSignatureUsage(cert) {
			if paired, ok := findAssociatedSignatureCert(cert, all); ok {
				target = paired
			} else if isAuthenticationDNIe(cert) {
				// Java SSL/qualified behavior for DNIe auth cert:
				// if signature pair is not found, omit certificate.
				continue
			} else {
				// For other certs without associated signature pair, keep original.
				target = cert
			}
		}
		key := target.ID + "|" + normalizeSerialHex(target.SerialNumber)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, target)
	}
	return out
}

func findAssociatedSignatureCert(cert protocol.Certificate, all []protocol.Certificate) (protocol.Certificate, bool) {
	subjectSN := extractProtocolSubjectSerialNumber(cert)
	if subjectSN == "" {
		return protocol.Certificate{}, false
	}
	expire := certificateExpireDate(cert)

	for _, cand := range all {
		if cand.ID == cert.ID {
			continue
		}
		if !hasSignatureUsage(cand) {
			continue
		}
		if !sameIssuerForPairing(cert, cand) {
			continue
		}
		if extractProtocolSubjectSerialNumber(cand) != subjectSN {
			continue
		}
		if certificateExpireDate(cand) != expire {
			continue
		}
		return cand, true
	}
	return protocol.Certificate{}, false
}

func sameIssuerForPairing(a, b protocol.Certificate) bool {
	attrsA := issuerAttrsForPairing(a)
	attrsB := issuerAttrsForPairing(b)
	return attrsA["CN"] == attrsB["CN"] &&
		attrsA["O"] == attrsB["O"] &&
		attrsA["OU"] == attrsB["OU"] &&
		attrsA["C"] == attrsB["C"] &&
		attrsA["L"] == attrsB["L"] &&
		attrsA["ST"] == attrsB["ST"]
}

func issuerAttrsForPairing(cert protocol.Certificate) map[string]string {
	base := normalizeAttrs(protocolIssuerAttrs(cert))
	xc, err := parseProtocolX509(cert)
	if err != nil || xc == nil {
		return base
	}
	parsed := normalizeAttrs(x509NameToAttrs(xc.Issuer))
	for _, k := range []string{"CN", "O", "OU", "C", "L", "ST"} {
		if strings.TrimSpace(base[k]) == "" {
			base[k] = parsed[k]
		}
	}
	return base
}

func hasSignatureUsage(cert protocol.Certificate) bool {
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return cert.CanSign
	}
	return xc.KeyUsage&x509.KeyUsageContentCommitment != 0
}

func applyPseudonymAndOthersRule(certs []protocol.Certificate) []protocol.Certificate {
	if len(certs) <= 1 {
		return certs
	}
	type parsed struct {
		cert     protocol.Certificate
		x509     *x509.Certificate
		isPseudo bool
	}
	parsedCerts := make([]parsed, 0, len(certs))
	for _, c := range certs {
		xc, err := parseProtocolX509(c)
		if err != nil {
			parsedCerts = append(parsedCerts, parsed{cert: c, x509: nil, isPseudo: false})
			continue
		}
		parsedCerts = append(parsedCerts, parsed{
			cert:     c,
			x509:     xc,
			isPseudo: matchesPseudonym(c, "only"),
		})
	}

	drop := make(map[int]struct{})
	for i := range parsedCerts {
		if !parsedCerts[i].isPseudo || parsedCerts[i].x509 == nil {
			continue
		}
		for j := range parsedCerts {
			if i == j || parsedCerts[j].isPseudo || parsedCerts[j].x509 == nil {
				continue
			}
			if isPseudonymEquivalent(parsedCerts[i].x509, parsedCerts[j].x509) {
				drop[j] = struct{}{}
			}
		}
	}

	out := make([]protocol.Certificate, 0, len(certs))
	for i := range parsedCerts {
		if _, skip := drop[i]; skip {
			continue
		}
		out = append(out, parsedCerts[i].cert)
	}
	return out
}

func isPseudonymEquivalent(pseudo *x509.Certificate, normal *x509.Certificate) bool {
	if pseudo == nil || normal == nil {
		return false
	}
	if normalizeAttrs(x509NameToAttrs(pseudo.Issuer))["CN"] != normalizeAttrs(x509NameToAttrs(normal.Issuer))["CN"] ||
		normalizeAttrs(x509NameToAttrs(pseudo.Issuer))["O"] != normalizeAttrs(x509NameToAttrs(normal.Issuer))["O"] ||
		normalizeAttrs(x509NameToAttrs(pseudo.Issuer))["OU"] != normalizeAttrs(x509NameToAttrs(normal.Issuer))["OU"] ||
		normalizeAttrs(x509NameToAttrs(pseudo.Issuer))["C"] != normalizeAttrs(x509NameToAttrs(normal.Issuer))["C"] {
		return false
	}
	if !sameKeyUsage(pseudo.KeyUsage, normal.KeyUsage) {
		return false
	}
	delta := pseudo.NotAfter.Sub(normal.NotAfter)
	if delta < 0 {
		delta = -delta
	}
	return delta < 60*time.Second
}

func sameKeyUsage(a x509.KeyUsage, b x509.KeyUsage) bool {
	return a == b
}

func protocolIssuerAttrs(cert protocol.Certificate) map[string]string {
	if len(cert.Issuer) > 0 {
		return cert.Issuer
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return map[string]string{}
	}
	return x509NameToAttrs(xc.Issuer)
}

func extractProtocolSubjectSerialNumber(cert protocol.Certificate) string {
	if sn := strings.TrimSpace(cert.Subject["SERIALNUMBER"]); sn != "" {
		return sn
	}
	if sn := strings.TrimSpace(cert.Subject["SN"]); sn != "" {
		return sn
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return ""
	}
	return extractSubjectSerialNumber(xc)
}

func certificateExpireDate(cert protocol.Certificate) string {
	if ts := strings.TrimSpace(cert.ValidTo); ts != "" {
		if tt, err := time.Parse(time.RFC3339, ts); err == nil {
			return tt.Format("2006-01-02")
		}
	}
	xc, err := parseProtocolX509(cert)
	if err != nil {
		return ""
	}
	return xc.NotAfter.Format("2006-01-02")
}

func extractSubjectSerialNumber(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	snOID := asn1.ObjectIdentifier{2, 5, 4, 5}
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(snOID) {
			if s, ok := atv.Value.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	for _, atv := range cert.Subject.ExtraNames {
		if atv.Type.Equal(snOID) {
			if s, ok := atv.Value.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func evalRFC2254Expression(expr string, attrs map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	p := &rfc2254Parser{
		s:     expr,
		attrs: normalizeAttrs(attrs),
	}
	ok, next, parsed := p.parseExpr(0)
	if !parsed {
		// Java fallback on parser errors: keep certificate.
		return true
	}
	if !p.onlySpaces(next) {
		return true
	}
	return ok
}

type rfc2254Parser struct {
	s     string
	attrs map[string]string
}

func (p *rfc2254Parser) parseExpr(i int) (bool, int, bool) {
	i = p.skipSpaces(i)
	if i >= len(p.s) {
		return false, i, false
	}
	if p.s[i] != '(' {
		// Accept unwrapped simple attr expression (best-effort).
		end := i
		for end < len(p.s) && !isSpace(p.s[end]) {
			end++
		}
		return p.evalSimple(strings.TrimSpace(p.s[i:end])), end, true
	}
	i++
	i = p.skipSpaces(i)
	if i >= len(p.s) {
		return false, i, false
	}
	switch p.s[i] {
	case '&':
		i++
		val := true
		parsedAny := false
		for {
			i = p.skipSpaces(i)
			if i >= len(p.s) {
				return false, i, false
			}
			if p.s[i] == ')' {
				i++
				return val && parsedAny, i, true
			}
			child, ni, ok := p.parseExpr(i)
			if !ok {
				return false, ni, false
			}
			parsedAny = true
			val = val && child
			i = ni
		}
	case '|':
		i++
		val := false
		parsedAny := false
		for {
			i = p.skipSpaces(i)
			if i >= len(p.s) {
				return false, i, false
			}
			if p.s[i] == ')' {
				i++
				return val && parsedAny, i, true
			}
			child, ni, ok := p.parseExpr(i)
			if !ok {
				return false, ni, false
			}
			parsedAny = true
			val = val || child
			i = ni
		}
	case '!':
		i++
		child, ni, ok := p.parseExpr(i)
		if !ok {
			return false, ni, false
		}
		ni = p.skipSpaces(ni)
		if ni >= len(p.s) || p.s[ni] != ')' {
			return false, ni, false
		}
		return !child, ni + 1, true
	default:
		start := i
		for i < len(p.s) && p.s[i] != ')' {
			i++
		}
		if i >= len(p.s) {
			return false, i, false
		}
		return p.evalSimple(strings.TrimSpace(p.s[start:i])), i + 1, true
	}
}

func (p *rfc2254Parser) evalSimple(cond string) bool {
	if cond == "" {
		return true
	}
	eq := strings.Index(cond, "=")
	if eq < 1 {
		return true
	}
	attr := strings.ToUpper(strings.TrimSpace(cond[:eq]))
	pattern := strings.TrimSpace(cond[eq+1:])
	v, ok := p.attrs[attr]
	if !ok {
		return false
	}
	return wildcardMatchFold(pattern, v)
}

func normalizeAttrs(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[strings.ToUpper(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

func wildcardMatchFold(pattern string, value string) bool {
	p := strings.ToLower(pattern)
	v := strings.ToLower(value)
	if p == "*" {
		return true
	}
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return v == p
	}
	idx := 0
	if !strings.HasPrefix(p, "*") {
		if !strings.HasPrefix(v, parts[0]) {
			return false
		}
		idx = len(parts[0])
		parts = parts[1:]
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		pos := strings.Index(v[idx:], part)
		if pos < 0 {
			return false
		}
		idx += pos + len(part)
		if i == len(parts)-1 && !strings.HasSuffix(p, "*") && !strings.HasSuffix(v, part) {
			return false
		}
	}
	return true
}

func (p *rfc2254Parser) skipSpaces(i int) int {
	for i < len(p.s) && isSpace(p.s[i]) {
		i++
	}
	return i
}

func (p *rfc2254Parser) onlySpaces(i int) bool {
	return p.skipSpaces(i) >= len(p.s)
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
