// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestProcessProtocolRequestServiceRequiresPorts(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://service?idsession=abc"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("se esperaba SAF_03 en service sin puertos, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestServiceReturnsOK(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	oldStartLegacy := startLegacyServiceFunc
	startLegacyServiceFunc = func(_ *WebSocketServer, _ []int) error { return nil }
	defer func() { startLegacyServiceFunc = oldStartLegacy }()
	got := strings.TrimSpace(s.processProtocolRequest("afirma://service?idsession=abc&ports=64217,64218"))
	if got != "OK" {
		t.Fatalf("se esperaba OK en service valido, obtenido: %q", got)
	}
	if s.session != "abc" {
		t.Fatalf("idsession no fijada en servidor: %q", s.session)
	}
}

func TestProcessProtocolRequestServiceStartErrorReturnsSaf45(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	oldStartLegacy := startLegacyServiceFunc
	startLegacyServiceFunc = func(_ *WebSocketServer, _ []int) error { return fmt.Errorf("bind failed") }
	defer func() { startLegacyServiceFunc = oldStartLegacy }()

	got := strings.TrimSpace(s.processProtocolRequest("afirma://service?idsession=abc&ports=64217,64218"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_45:") {
		t.Fatalf("se esperaba SAF_45 en fallo de arranque service, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestWebSocketReturnsOK(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://websocket?idsession=xyz&ports=63117"))
	if got != "OK" {
		t.Fatalf("se esperaba OK en websocket valido, obtenido: %q", got)
	}
	if s.session != "xyz" {
		t.Fatalf("idsession no fijada en servidor: %q", s.session)
	}
}

func TestProcessProtocolRequestWebSocketLegacyPathAndAliasParams(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma:///websocket?idSession=xyz&port=63117"))
	if got != "OK" {
		t.Fatalf("se esperaba OK en websocket legacy path/alias, obtenido: %q", got)
	}
	if s.session != "xyz" {
		t.Fatalf("idSession no fijada en servidor: %q", s.session)
	}
}

func TestProcessProtocolRequestWebSocketActionInQueryOp(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://?op=websocket&idSession=xyz&port=63117"))
	if got != "OK" {
		t.Fatalf("se esperaba OK en websocket por op query, obtenido: %q", got)
	}
	if s.session != "xyz" {
		t.Fatalf("idSession no fijada en servidor: %q", s.session)
	}
}

func TestParsePortsList(t *testing.T) {
	ports, err := parsePortsList("63117, 63118")
	if err != nil || len(ports) != 2 || ports[0] != 63117 || ports[1] != 63118 {
		t.Fatalf("parsePortsList inesperado: ports=%v err=%v", ports, err)
	}
	if _, err := parsePortsList("0,70000"); err == nil {
		t.Fatalf("se esperaba error en puertos fuera de rango")
	}
}

func TestSplitLegacyResponse(t *testing.T) {
	parts := splitLegacyResponse(strings.Repeat("A", legacyResponseMaxSize+10))
	if len(parts) != 2 {
		t.Fatalf("se esperaban 2 partes, obtenido=%d", len(parts))
	}
	if len(parts[0]) != legacyResponseMaxSize || len(parts[1]) != 10 {
		t.Fatalf("tamano de partes inesperado: %d/%d", len(parts[0]), len(parts[1]))
	}
}

func TestExtractLegacyParam(t *testing.T) {
	raw := "GET /?cmd=YWZpcm1hOi8vc2lnbj9pZD0x HTTP/1.1\r\nHost: localhost\r\n\r\n"
	v, ok := extractLegacyParam(raw, "cmd=")
	if !ok || v != "YWZpcm1hOi8vc2lnbj9pZD0x" {
		t.Fatalf("extractLegacyParam inesperado: ok=%v val=%q", ok, v)
	}

	raw = "fragment=@1@1@YQ==idsession=abc@EOF"
	v, ok = extractLegacyParam(raw, "fragment=")
	if !ok || v != "@1@1@YQ==" {
		t.Fatalf("extractLegacyParam fragment inesperado: ok=%v val=%q", ok, v)
	}
}

func TestExtractLegacyPayload(t *testing.T) {
	raw := "POST /afirma HTTP/1.1\r\nHost: localhost\r\n\r\ncmd=abcidsession=abc@EOF"
	if got := extractLegacyPayload(raw); got != "cmd=abcidsession=abc@EOF" {
		t.Fatalf("payload HTTP inesperado: %q", got)
	}
}
