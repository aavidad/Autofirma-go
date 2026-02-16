// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"crypto"
	"strings"
)

func resolveDigestName(options map[string]interface{}, def string) string {
	name, _ := resolveDigestFromOptions(options)
	if name == "" {
		return strings.ToLower(def)
	}
	return name
}

func resolveDigestHash(options map[string]interface{}, def crypto.Hash) crypto.Hash {
	_, h := resolveDigestFromOptions(options)
	if h == 0 {
		return def
	}
	return h
}

func resolveDigestOID(options map[string]interface{}, def string) string {
	name := resolveDigestName(options, "")
	switch name {
	case "sha1":
		return "1.3.14.3.2.26"
	case "sha384":
		return "2.16.840.1.101.3.4.2.2"
	case "sha512":
		return "2.16.840.1.101.3.4.2.3"
	case "sha256":
		return "2.16.840.1.101.3.4.2.1"
	default:
		return def
	}
}

func resolveDigestFromOptions(options map[string]interface{}) (string, crypto.Hash) {
	if options == nil {
		return "", 0
	}
	var raw string
	if v, ok := options["algorithm"]; ok {
		raw = strings.TrimSpace(toString(v))
	}
	if raw == "" {
		if v, ok := options["precalculatedHashAlgorithm"]; ok {
			raw = strings.TrimSpace(toString(v))
		}
	}
	if raw == "" {
		return "", 0
	}
	l := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(l, "sha512"):
		return "sha512", crypto.SHA512
	case strings.Contains(l, "sha384"):
		return "sha384", crypto.SHA384
	case strings.Contains(l, "sha1"):
		return "sha1", crypto.SHA1
	case strings.Contains(l, "sha256"):
		return "sha256", crypto.SHA256
	default:
		return "", 0
	}
}

func toString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}
