// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestLegacyServiceSessionValidation(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "abc", nil)
	if got := s.processLegacyServicePayload("echo=-@EOFidsession=zzz"); !strings.HasPrefix(got, "SAF_46:") {
		t.Fatalf("se esperaba SAF_46 por idsession invalido, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("echo=-@EOFidsession=abc"); got != "OK" {
		t.Fatalf("se esperaba OK con idsession valido, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("echo=-@EOFidSession=abc"); got != "OK" {
		t.Fatalf("se esperaba OK con idSession valido, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if got != "1" {
		t.Fatalf("se esperaba total de partes=1 en cmd flow, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("se esperaba OK en parte unica de cmd flow, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdFlowUppercaseScheme(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "AFIRMA://WEBSOCKET?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if got != "1" {
		t.Fatalf("se esperaba total de partes=1 en cmd flow uppercase, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("se esperaba OK en parte unica de cmd flow uppercase, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdUppercaseCommandName(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("CMD=" + cmdB64 + "idsession=abc@EOF")
	if got != "1" {
		t.Fatalf("CMD= en mayusculas debe procesarse igual que cmd=, obtenido: %q", got)
	}
}

func TestLegacyServiceEchoUppercaseResetsState(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceFragments = []string{"a", "b"}
	s.serviceResponseParts = []string{"p1"}

	got := s.processLegacyServicePayload("ECHO=-idsession=abc@EOF")
	if got != "OK" {
		t.Fatalf("ECHO= en mayusculas debe devolver OK, obtenido: %q", got)
	}
	if len(s.serviceFragments) != 0 || len(s.serviceResponseParts) != 0 {
		t.Fatalf("ECHO=- debe resetear estado legacy")
	}
}

func TestLegacyServiceCmdFlowCamelCaseSessionSuffix(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + "idSession=abc@EOF HTTP/1.1")
	if got != "1" {
		t.Fatalf("se esperaba total de partes=1 en cmd flow con idSession, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idSession=abc@EOF"); got != "OK" {
		t.Fatalf("se esperaba OK en parte unica de cmd flow con idSession, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdSaveErrorMapsToSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://save?id=1"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if !strings.HasPrefix(got, "SAF_03:") {
		t.Fatalf("save en cmd con error debe mapear a SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentFirmSendFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))

	if got := s.processLegacyServicePayload("fragment=@1@1@" + chunk + "idsession=abc@EOF"); got != "OK" {
		t.Fatalf("fragment final debe devolver OK, obtenido: %q", got)
	}
	parts := s.processLegacyServicePayload("firm=idsession=abc@EOF")
	if parts != "1" {
		t.Fatalf("firm debe devolver numero de partes=1, obtenido: %q", parts)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("send de la parte 1 debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceUnsupportedCommandReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("foo=baridsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("comando legacy no soportado debe mapear a SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCommandPriorityCmdOverEcho(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	raw := "echo=-idsession=abc@EOFcmd=" + cmdB64 + "idsession=abc@EOF"
	got := s.processLegacyServicePayload(raw)
	if got != "1" {
		t.Fatalf("prioridad cmd sobre echo esperada (Java), obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentHTTPBodyFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))
	req := "POST /afirma HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"fragment=@1@1@" + chunk + "idsession=abc@EOF"
	if got := s.processLegacyServicePayload(req); got != "OK" {
		t.Fatalf("fragment HTTP body debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentAndSendWithCamelCaseSessionSuffix(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))
	if got := s.processLegacyServicePayload("fragment=@1@1@" + chunk + "idSession=abc@EOF"); got != "OK" {
		t.Fatalf("fragment con idSession debe devolver OK, obtenido: %q", got)
	}
	parts := s.processLegacyServicePayload("firm=idSession=abc@EOF")
	if parts != "1" {
		t.Fatalf("firm con idSession debe devolver numero de partes=1, obtenido: %q", parts)
	}
	if got := s.processLegacyServicePayload("send=@1@1idSession=abc@EOF"); got != "OK" {
		t.Fatalf("send con idSession debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceUppercaseFragmentFirmSendFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))

	if got := s.processLegacyServicePayload("FRAGMENT=@1@1@" + chunk + "idsession=abc@EOF"); got != "OK" {
		t.Fatalf("FRAGMENT en mayusculas debe devolver OK, obtenido: %q", got)
	}
	if parts := s.processLegacyServicePayload("FIRM=idsession=abc@EOF"); parts != "1" {
		t.Fatalf("FIRM en mayusculas debe devolver numero de partes=1, obtenido: %q", parts)
	}
	if got := s.processLegacyServicePayload("SEND=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("SEND en mayusculas debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceFirmWithoutFragmentsReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("firm=idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("firm sin fragmentos debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceFirmReturnsPreparedPartsCountOnRetry(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceResponseParts = []string{"P1", "P2"}
	got := s.processLegacyServicePayload("firm=idsession=abc@EOF")
	if got != "2" {
		t.Fatalf("firm con respuesta preparada debe devolver numero de partes, obtenido: %q", got)
	}
}

func TestLegacyServiceSendInvalidRangeReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceResponseParts = []string{"P1"}
	got := s.processLegacyServicePayload("send=@2@1idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("send fuera de rango debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceSendAllowsMismatchedTotalWhenPartExists(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceResponseParts = []string{"P1"}
	got := s.processLegacyServicePayload("send=@1@999idsession=abc@EOF")
	if got != "P1" {
		t.Fatalf("send debe devolver la parte aunque total no coincida (paridad Java), obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentInvalidReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("fragment=@x@1@YQ==idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("fragment invalido debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdInvalidBase64ReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("cmd=***idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("cmd base64 invalido debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdNonAfirmaURIReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdB64 := base64.StdEncoding.EncodeToString([]byte("https://example.com"))
	got := s.processLegacyServicePayload("cmd=" + cmdB64 + "idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("cmd no afirma:// debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdServiceURIReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdB64 := base64.StdEncoding.EncodeToString([]byte("afirma://service?ports=1"))
	got := s.processLegacyServicePayload("cmd=" + cmdB64 + "idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("cmd afirma://service debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestExtractLegacySessionID(t *testing.T) {
	if got := extractLegacySessionID("...idsession=abc@EOF..."); got != "abc" {
		t.Fatalf("idsession inesperado: %q", got)
	}
	if got := extractLegacySessionID("...idSession=def@EOF..."); got != "def" {
		t.Fatalf("idSession inesperado: %q", got)
	}
	if got := extractLegacySessionID("...idsession=abc&x=1..."); got != "abc" {
		t.Fatalf("idsession inesperado con &: %q", got)
	}
	if got := extractLegacySessionID("sin_idsession"); got != "" {
		t.Fatalf("idsession esperado vacio, obtenido: %q", got)
	}
}

func TestReadLegacySocketPayloadExtractsSessionAndTrimsEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("POST /afirma HTTP/1.1\r\nHost: localhost\r\n\r\nfragment=@1@1@YQ==idsession=abc@EOF"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idsession inesperado: %q", res.SessionID)
	}
	if !strings.Contains(res.RequestBody, "fragment=@1@1@YQ==") {
		t.Fatalf("payload inesperado: %q", res.RequestBody)
	}
	if strings.Contains(res.RequestBody, "idsession=") || strings.Contains(res.RequestBody, "@EOF") {
		t.Fatalf("payload debe venir sin idsession/@EOF: %q", res.RequestBody)
	}
}

func TestReadLegacySocketPayloadExtractsCamelCaseSession(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("POST /afirma HTTP/1.1\r\nHost: localhost\r\n\r\nfragment=@1@1@YQ==idSession=abc@EOF"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idSession inesperado: %q", res.SessionID)
	}
}

func TestReadLegacySocketPayloadSplitEOFAcrossChunks(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("echo=-idsession=abc@E"))
		_, _ = client.Write([]byte("OF"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idsession inesperado en EOF fragmentado: %q", res.SessionID)
	}
	if strings.Contains(res.RequestBody, "@EOF") {
		t.Fatalf("payload no debe incluir @EOF: %q", res.RequestBody)
	}
}

func TestReadLegacySocketPayloadLowercaseEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("echo=-idsession=abc@eof"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idsession inesperado con @eof: %q", res.SessionID)
	}
	if strings.Contains(strings.ToLower(res.RequestBody), "@eof") {
		t.Fatalf("payload no debe incluir @eof: %q", res.RequestBody)
	}
}
