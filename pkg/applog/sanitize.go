// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package applog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func MaskID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	if len(v) <= 10 {
		return v
	}
	return v[:6] + "..." + v[len(v)-4:]
}

func Digest12(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:12]
}

func SecretMeta(label string, raw string) string {
	return fmt.Sprintf("%s[len=%d sha12=%s]", label, len(raw), Digest12(raw))
}

func BytesMeta(label string, raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%s[len=%d sha12=%s]", label, len(raw), hex.EncodeToString(sum[:])[:12])
}

func OptionKeys(opts map[string]interface{}) string {
	if len(opts) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func SanitizeURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return truncate(raw, 180)
	}

	q := u.Query()
	sensitive := map[string]struct{}{
		"dat":           {},
		"data":          {},
		"signature":     {},
		"signaturedata": {},
		"sig":           {},
		"cert":          {},
		"key":           {},
		"pin":           {},
		"password":      {},
		"passwd":        {},
		"originaldata":  {},
	}
	for k, values := range q {
		lk := strings.ToLower(strings.TrimSpace(k))
		if _, ok := sensitive[lk]; ok {
			for i := range values {
				values[i] = "[REDACTED]"
			}
			q[k] = values
			continue
		}
		for i := range values {
			values[i] = truncate(values[i], 80)
		}
		q[k] = values
	}
	u.RawQuery = q.Encode()
	return truncate(u.String(), 220)
}

func SanitizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		la := strings.ToLower(a)
		if strings.Contains(a, "afirma://") {
			out = append(out, SanitizeURI(a))
			continue
		}
		if strings.Contains(la, "pin=") || strings.Contains(la, "key=") || strings.Contains(la, "password=") {
			out = append(out, "[REDACTED_ARG]")
			continue
		}
		out = append(out, truncate(a, 120))
	}
	return out
}

func truncate(v string, max int) string {
	if max < 8 {
		max = 8
	}
	if len(v) <= max {
		return v
	}
	return v[:max] + "...(trunc)"
}
