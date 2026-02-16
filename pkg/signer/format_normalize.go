// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"bytes"
	"strings"
)

func normalizeSignFormat(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "cades", "cadestri", "cades-tri", "cades_tri", "cades-asic-s", "cades-asic-s-tri":
		return "cades"
	case "pades", "padestri", "pades-tri", "pdf", "pdftri", "pdf-tri":
		return "pades"
	case "xades", "xadestri", "xades-tri", "xmldsig", "xmldsig detached", "xmldsig enveloped":
		return "xades"
	default:
		return f
	}
}

func resolveSignFormat(format string, data []byte) string {
	f := normalizeSignFormat(format)
	if f != "" && f != "auto" {
		return f
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) >= 4 && string(trimmed[:4]) == "%PDF" {
		return "pades"
	}
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return "xades"
	}
	return "cades"
}
