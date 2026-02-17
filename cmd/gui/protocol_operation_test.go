// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestProtocolSignOperationDispatchSign(t *testing.T) {
	oldSign := signDataFunc
	oldCo := coSignDataFunc
	oldCounter := counterSignDataFunc
	t.Cleanup(func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCo
		counterSignDataFunc = oldCounter
	})

	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return "sign", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("coSignDataFunc no debe invocarse para action=sign")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("counterSignDataFunc no debe invocarse para action=sign")
		return "", nil
	}

	got, err := protocolSignOperation("sign", "ZGF0YQ==", "cert", "", "cades", nil)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if got != "sign" {
		t.Fatalf("resultado inesperado: %q", got)
	}
}

func TestProtocolSignOperationDispatchCoSign(t *testing.T) {
	oldSign := signDataFunc
	oldCo := coSignDataFunc
	oldCounter := counterSignDataFunc
	t.Cleanup(func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCo
		counterSignDataFunc = oldCounter
	})

	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("signDataFunc no debe invocarse para action=cosign")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return "cosign", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("counterSignDataFunc no debe invocarse para action=cosign")
		return "", nil
	}

	got, err := protocolSignOperation("cosign", "ZGF0YQ==", "cert", "", "cades", nil)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if got != "cosign" {
		t.Fatalf("resultado inesperado: %q", got)
	}
}

func TestProtocolSignOperationDispatchCounterSign(t *testing.T) {
	oldSign := signDataFunc
	oldCo := coSignDataFunc
	oldCounter := counterSignDataFunc
	t.Cleanup(func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCo
		counterSignDataFunc = oldCounter
	})

	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("signDataFunc no debe invocarse para action=countersign")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("coSignDataFunc no debe invocarse para action=countersign")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return "countersign", nil
	}

	got, err := protocolSignOperation("countersign", "ZGF0YQ==", "cert", "", "cades", nil)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if got != "countersign" {
		t.Fatalf("resultado inesperado: %q", got)
	}
}

func TestProtocolSignOperationTakesPinFromOptions(t *testing.T) {
	oldSign := signDataFunc
	oldCo := coSignDataFunc
	oldCounter := counterSignDataFunc
	t.Cleanup(func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCo
		counterSignDataFunc = oldCounter
	})

	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		if pin != "1234" {
			t.Fatalf("pin inesperado: %q", pin)
		}
		return "sign", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("coSignDataFunc no debe invocarse para action=sign")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("counterSignDataFunc no debe invocarse para action=sign")
		return "", nil
	}

	got, err := protocolSignOperation("sign", "ZGF0YQ==", "cert", "", "cades", map[string]interface{}{
		"_pin": "1234",
	})
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if got != "sign" {
		t.Fatalf("resultado inesperado: %q", got)
	}
}
