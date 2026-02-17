// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "strings"

func protocolSignOperation(
	action string,
	dataB64 string,
	certificateID string,
	pin string,
	format string,
	options map[string]interface{},
) (string, error) {
	if strings.TrimSpace(pin) == "" {
		pin = signOptionString(options, "_pin", "pin")
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "cosign":
		return coSignDataFunc(dataB64, certificateID, pin, format, options)
	case "countersign":
		return counterSignDataFunc(dataB64, certificateID, pin, format, options)
	default:
		return signDataFunc(dataB64, certificateID, pin, format, options)
	}
}

func signOptionString(options map[string]interface{}, keys ...string) string {
	if options == nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := options[key]
		if !ok || raw == nil {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			return s
		}
	}
	return ""
}
