// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/base64"
	"log"
	"net/url"
	"strconv"
	"strings"
)

func buildProtocolSignOptions(state *ProtocolState, format string) map[string]interface{} {
	if state == nil {
		return nil
	}

	opts := map[string]interface{}{}

	props := decodeProtocolProperties(getQueryParam(state.Params, "properties"))
	for k, v := range props {
		applyProtocolSignOption(opts, k, v)
	}

	for k, values := range state.Params {
		if len(values) == 0 {
			continue
		}
		applyProtocolSignOption(opts, k, values[len(values)-1])
	}

	applyProtocolVisibleGeometry(opts)
	expandProtocolPolicyOptions(opts, format)
	applyProtocolStoreHints(opts, state)
	if len(opts) == 0 {
		return nil
	}
	log.Printf("[Protocol] Sign options built format=%s keys=%s", format, protocolOptionKeys(opts))
	return opts
}

func applyProtocolStoreHints(opts map[string]interface{}, state *ProtocolState) {
	if state == nil {
		return
	}
	if store := strings.TrimSpace(getQueryParam(state.Params,
		"defaultkeystore", "defaultKeyStore", "keystore", "keyStore")); store != "" {
		opts["_defaultKeyStore"] = store
	}
	if lib := strings.TrimSpace(getQueryParam(state.Params,
		"defaultkeystorelib", "defaultKeyStoreLib", "keystorelib", "keyStoreLib")); lib != "" {
		opts["_defaultKeyStoreLib"] = lib
	}
	if shouldDisableExternalStoresInState(state) {
		opts["_disableOpeningExternalStores"] = true
	}
	if pin := strings.TrimSpace(getQueryParam(state.Params, "pin")); pin != "" {
		opts["_pin"] = pin
	}
}

func mergeSignOptions(base, overlay map[string]interface{}) map[string]interface{} {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	out := map[string]interface{}{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyProtocolSignOption(opts map[string]interface{}, rawKey, rawValue string) {
	key := strings.TrimSpace(rawKey)
	val := strings.TrimSpace(rawValue)
	if key == "" || val == "" {
		return
	}

	lowerKey := strings.ToLower(key)
	switch lowerKey {
	case "signreason", "reason":
		opts["reason"] = val
	case "signatureproductioncity", "location":
		opts["location"] = val
	case "signercontact", "contactinfo":
		opts["contactInfo"] = val
	case "tsaurl":
		opts["tsaURL"] = val
	case "algorithm":
		opts["algorithm"] = val
	case "signaturepage", "page":
		if n, ok := parseUint32OptionValue(val); ok {
			opts["page"] = n
		}
	case "signaturepositiononpagelowerleftx", "x":
		if f, ok := parseFloatOptionValue(val); ok {
			opts["x"] = f
		}
	case "signaturepositiononpagelowerlefty", "y":
		if f, ok := parseFloatOptionValue(val); ok {
			opts["y"] = f
		}
	case "signaturepositiononpageupperrightx":
		if f, ok := parseFloatOptionValue(val); ok {
			opts["_upperRightX"] = f
		}
	case "signaturepositiononpageupperrighty":
		if f, ok := parseFloatOptionValue(val); ok {
			opts["_upperRightY"] = f
		}
	case "width":
		if f, ok := parseFloatOptionValue(val); ok {
			opts["width"] = f
		}
	case "height":
		if f, ok := parseFloatOptionValue(val); ok {
			opts["height"] = f
		}
	case "visiblesignature":
		opts["visibleSignature"] = parseBoolParam(val)
	case "signername":
		opts["signerName"] = val
	case "issuername":
		opts["issuerName"] = val
	case "issuerorg":
		opts["issuerOrg"] = val
	case "signerdni":
		opts["signerDNI"] = val
	case "policyidentifier":
		opts["policyIdentifier"] = val
	case "policyidentifierhash":
		opts["policyIdentifierHash"] = val
	case "policyidentifierhashalgorithm":
		opts["policyIdentifierHashAlgorithm"] = val
	case "policyqualifier":
		opts["policyQualifier"] = val
	case "exppolicy":
		opts["expPolicy"] = val
	case "mode":
		opts["mode"] = val
	case "profile":
		opts["profile"] = val
	case "target":
		opts["target"] = val
	case "targets":
		opts["targets"] = val
	case "signers":
		opts["signers"] = val
	case "precalculatedhashalgorithm":
		opts["precalculatedHashAlgorithm"] = val
	case "signaturesubfilter":
		opts["signatureSubFilter"] = val
	case "pin":
		opts["_pin"] = val
	}
}

func applyProtocolVisibleGeometry(opts map[string]interface{}) {
	x, hasX := opts["x"].(float64)
	y, hasY := opts["y"].(float64)
	ux, hasUx := opts["_upperRightX"].(float64)
	uy, hasUy := opts["_upperRightY"].(float64)

	if hasX && hasUx && ux > x {
		opts["width"] = ux - x
	}
	if hasY && hasUy && uy > y {
		opts["height"] = uy - y
	}
	if hasX && hasY {
		if _, ok := opts["width"]; ok {
			if _, ok := opts["height"]; ok {
				opts["visibleSignature"] = true
			}
		}
	}
	delete(opts, "_upperRightX")
	delete(opts, "_upperRightY")
}

func expandProtocolPolicyOptions(opts map[string]interface{}, format string) {
	raw, ok := opts["expPolicy"]
	if !ok {
		return
	}
	policyID, ok := raw.(string)
	if !ok {
		return
	}
	p := strings.TrimSpace(policyID)
	if p == "" {
		return
	}

	type policyData struct {
		identifier string
		qualifier  string
		hashAlg    string
		hashCades  string
		hashPades  string
		hashXades  string
	}
	policies := map[string]policyData{
		"firmaage": {
			identifier: "urn:oid:2.16.724.1.3.1.1.2.1.9",
			qualifier:  "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
			hashAlg:    "http://www.w3.org/2000/09/xmldsig#sha1",
			hashCades:  "G7roucf600+f03r/o0bAOQ6WAs0=",
			hashPades:  "G7roucf600+f03r/o0bAOQ6WAs0=",
			hashXades:  "G7roucf600+f03r/o0bAOQ6WAs0=",
		},
		"firmaage19": {
			identifier: "urn:oid:2.16.724.1.3.1.1.2.1.9",
			qualifier:  "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
			hashAlg:    "http://www.w3.org/2000/09/xmldsig#sha1",
			hashCades:  "G7roucf600+f03r/o0bAOQ6WAs0=",
			hashPades:  "G7roucf600+f03r/o0bAOQ6WAs0=",
			hashXades:  "G7roucf600+f03r/o0bAOQ6WAs0=",
		},
		"firmaage18": {
			identifier: "urn:oid:2.16.724.1.3.1.1.2.1.8",
			qualifier:  "https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf",
			hashAlg:    "http://www.w3.org/2000/09/xmldsig#sha1",
			hashCades:  "7SxX3erFuH31TvAw9LZ70N7p1vA=",
			hashPades:  "7SxX3erFuH31TvAw9LZ70N7p1vA=",
			hashXades:  "V8lVVNGDCPen6VELRD1Ja8HARFk=",
		},
	}

	data, exists := policies[strings.ToLower(p)]
	if !exists {
		return
	}
	opts["policyIdentifier"] = data.identifier
	opts["policyQualifier"] = data.qualifier
	opts["policyIdentifierHashAlgorithm"] = data.hashAlg
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "xades":
		opts["policyIdentifierHash"] = data.hashXades
	case "pades":
		opts["policyIdentifierHash"] = data.hashPades
	default:
		opts["policyIdentifierHash"] = data.hashCades
	}
}

func parseFloatOptionValue(v string) (float64, bool) {
	n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseUint32OptionValue(v string) (uint32, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func protocolOptionKeys(opts map[string]interface{}) string {
	if len(opts) == 0 {
		return "[]"
	}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	return "[" + strings.Join(keys, ",") + "]"
}

func parsePropertiesFromBase64Param(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	decoded := ""
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		normalized := strings.ReplaceAll(raw, " ", "+")
		b, err := enc.DecodeString(normalized)
		if err == nil {
			decoded = string(b)
			break
		}
	}
	if decoded == "" {
		return nil
	}
	return parseProperties(decoded)
}

func mergePropertiesParam(params url.Values) map[string]string {
	props := map[string]string{}
	if params == nil {
		return props
	}
	for k, vs := range params {
		if len(vs) == 0 {
			continue
		}
		props[k] = vs[len(vs)-1]
	}
	for k, v := range parsePropertiesFromBase64Param(getQueryParam(params, "properties")) {
		props[k] = v
	}
	return props
}
