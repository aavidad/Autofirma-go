// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestStorageCheckReturnsOK(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, nil)
	req := httptest.NewRequest(http.MethodGet, "/afirma-signature-storage/StorageService?op=check", nil)
	rr := httptest.NewRecorder()

	s.handleStorageService(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status inesperado: %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "OK" {
		t.Fatalf("respuesta inesperada: %q", rr.Body.String())
	}
}

func TestRetrieveMissingIDReturnsErr06(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, nil)
	req := httptest.NewRequest(http.MethodGet, "/afirma-signature-retriever/RetrieveService?op=get&v=1_0&id=no-existe", nil)
	rr := httptest.NewRecorder()

	s.handleRetrieveService(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status inesperado: %d", rr.Code)
	}
	got := strings.TrimSpace(rr.Body.String())
	if !strings.HasPrefix(strings.ToLower(got), "err-06") {
		t.Fatalf("se esperaba ERR-06, obtenido: %q", got)
	}
}

func TestPutThenGetAndDelete(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, nil)

	form := url.Values{}
	form.Set("op", "put")
	form.Set("v", "1_0")
	form.Set("id", "abc123")
	form.Set("dat", "FIRMA_B64")

	putReq := httptest.NewRequest(http.MethodPost, "/afirma-signature-storage/StorageService", strings.NewReader(form.Encode()))
	putReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	putRR := httptest.NewRecorder()
	s.handleStorageService(putRR, putReq)

	if strings.TrimSpace(putRR.Body.String()) != "OK" {
		t.Fatalf("put no devolvio OK: %q", putRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/afirma-signature-retriever/RetrieveService?op=get&v=1_0&id=abc123", nil)
	getRR := httptest.NewRecorder()
	s.handleRetrieveService(getRR, getReq)
	if strings.TrimSpace(getRR.Body.String()) != "FIRMA_B64" {
		t.Fatalf("get devolvio valor inesperado: %q", getRR.Body.String())
	}

	getReq2 := httptest.NewRequest(http.MethodGet, "/afirma-signature-retriever/RetrieveService?op=get&v=1_0&id=abc123", nil)
	getRR2 := httptest.NewRecorder()
	s.handleRetrieveService(getRR2, getReq2)
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(getRR2.Body.String())), "err-06") {
		t.Fatalf("tras leer una vez, se esperaba ERR-06: %q", getRR2.Body.String())
	}
}
