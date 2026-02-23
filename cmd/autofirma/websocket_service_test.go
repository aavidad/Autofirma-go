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
	if got := s.getServiceProtocolVersion(); got != 3 {
		t.Fatalf("version de servicio inesperada, obtenido=%d", got)
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
	got := strings.TrimSpace(s.processProtocolRequest("afirma://websocket?idsession=xyz&ports=63117&v=4"))
	if got != "OK" {
		t.Fatalf("se esperaba OK en websocket valido, obtenido: %q", got)
	}
	if s.session != "xyz" {
		t.Fatalf("idsession no fijada en servidor: %q", s.session)
	}
}

func TestProcessProtocolRequestWebSocketUnsupportedVersionReturnsSaf21(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://websocket?idsession=xyz&ports=63117&v=2"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_21:") {
		t.Fatalf("se esperaba SAF_21 en websocket con version no soportada, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestServiceUnsupportedVersionReturnsSaf21(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://service?idsession=abc&ports=64217&v=4"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_21:") {
		t.Fatalf("se esperaba SAF_21 en service con version no soportada, obtenido: %q", got)
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

func TestParseRequestedProtocolVersion(t *testing.T) {
	if v := parseRequestedProtocolVersion(nil); v != 1 {
		t.Fatalf("version por defecto inesperada: %d", v)
	}
	if v := parseRequestedProtocolVersion(map[string][]string{"v": []string{"4"}}); v != 4 {
		t.Fatalf("version parseada inesperada: %d", v)
	}
	if v := parseRequestedProtocolVersion(map[string][]string{"ver": []string{"3"}}); v != 3 {
		t.Fatalf("version parseada desde alias ver inesperada: %d", v)
	}
	if v := parseRequestedProtocolVersion(map[string][]string{"v": []string{"abc"}}); v != 1 {
		t.Fatalf("version invalida debe caer a 1, obtenido=%d", v)
	}
}

func TestEnsureProtocolVersionParam(t *testing.T) {
	got := ensureProtocolVersionParam("afirma://sign?id=1", 3)
	if !strings.Contains(got, "v=3") {
		t.Fatalf("debe inyectar v=3 en uri sin version, obtenido=%q", got)
	}

	got = ensureProtocolVersionParam("afirma://sign?id=1&v=4", 3)
	if !strings.Contains(got, "v=4") {
		t.Fatalf("no debe sobrescribir version existente, obtenido=%q", got)
	}

	got = ensureProtocolVersionParam("http://example.com", 3)
	if got != "http://example.com" {
		t.Fatalf("uri no afirma no debe alterarse, obtenido=%q", got)
	}

	got = ensureProtocolVersionParam("afirma://websocket?ports=63117", 3)
	if strings.Contains(got, "v=") {
		t.Fatalf("websocket launch no debe forzar v heredada, obtenido=%q", got)
	}
}

func TestParseJavaScriptVersionWithDefault(t *testing.T) {
	if v := parseJavaScriptVersionWithDefault(nil, 1); v != 1 {
		t.Fatalf("jvc por defecto inesperado: %d", v)
	}
	if v := parseJavaScriptVersionWithDefault(map[string][]string{"jvc": []string{"3"}}, 1); v != 3 {
		t.Fatalf("jvc parseado inesperado: %d", v)
	}
	if v := parseJavaScriptVersionWithDefault(map[string][]string{"jvc": []string{"x"}}, 1); v != 1 {
		t.Fatalf("jvc invalido debe caer a default, obtenido=%d", v)
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

func TestExtractLegacyParamPreservesInternalSpacesUntilHTTPMarker(t *testing.T) {
	raw := "GET /?cmd=AAA BBB CCC HTTP/1.1\r\nHost: localhost\r\n\r\n"
	v, ok := extractLegacyParam(raw, "cmd=")
	if !ok {
		t.Fatalf("extractLegacyParam debe detectar cmd en request HTTP")
	}
	if v != "AAA BBB CCC" {
		t.Fatalf("extractLegacyParam no debe truncar por espacios internos, obtenido=%q", v)
	}
}

func TestExtractLegacyPayload(t *testing.T) {
	raw := "POST /afirma HTTP/1.1\r\nHost: localhost\r\n\r\ncmd=abcidsession=abc@EOF"
	if got := extractLegacyPayload(raw); got != "cmd=abcidsession=abc@EOF" {
		t.Fatalf("payload HTTP inesperado: %q", got)
	}
}
