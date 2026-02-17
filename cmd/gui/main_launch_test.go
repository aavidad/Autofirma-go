// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestParseWebSocketLaunchURI(t *testing.T) {
	req, err := parseWebSocketLaunchURI("afirma://websocket?ports=63117,63118&idsession=abc123&v=4")
	if err != nil {
		t.Fatalf("error inesperado parseando websocket launch uri: %v", err)
	}
	if req == nil {
		t.Fatalf("request nil")
	}
	if req.Version != 4 {
		t.Fatalf("version inesperada: %d", req.Version)
	}
	if req.SessionID != "abc123" {
		t.Fatalf("idsession inesperada: %q", req.SessionID)
	}
	if len(req.Ports) != 2 || req.Ports[0] != 63117 || req.Ports[1] != 63118 {
		t.Fatalf("puertos inesperados: %v", req.Ports)
	}
}

func TestParseWebSocketLaunchURIAliasesAndDefaults(t *testing.T) {
	req, err := parseWebSocketLaunchURI("AFIRMA:///websocket?port=63119&idSession=sid01")
	if err != nil {
		t.Fatalf("error inesperado en aliases/defaults: %v", err)
	}
	if req.Version != 4 {
		t.Fatalf("sin v debe usar default 4, obtenido=%d", req.Version)
	}
	if req.SessionID != "sid01" {
		t.Fatalf("idSession no mapeada: %q", req.SessionID)
	}
	if len(req.Ports) != 1 || req.Ports[0] != 63119 {
		t.Fatalf("puerto inesperado: %v", req.Ports)
	}
}

func TestParseWebSocketLaunchURIActionInQueryOp(t *testing.T) {
	req, err := parseWebSocketLaunchURI("afirma://?op=websocket&portsList=63117&idSession=sid02")
	if err != nil {
		t.Fatalf("error inesperado en websocket por op query: %v", err)
	}
	if req.SessionID != "sid02" {
		t.Fatalf("idSession inesperada: %q", req.SessionID)
	}
	if len(req.Ports) != 1 || req.Ports[0] != 63117 {
		t.Fatalf("puertos inesperados: %v", req.Ports)
	}
}

func TestParseWebSocketLaunchURIUnsupportedVersion(t *testing.T) {
	if _, err := parseWebSocketLaunchURI("afirma://websocket?ports=63117&v=2"); err == nil {
		t.Fatalf("se esperaba error con version websocket no soportada")
	}
}

func TestParseWebSocketLaunchURIMissingPortsUsesDefault(t *testing.T) {
	req, err := parseWebSocketLaunchURI("afirma://websocket?idsession=abc&v=4")
	if err != nil {
		t.Fatalf("error inesperado sin puertos: %v", err)
	}
	if len(req.Ports) != 1 || req.Ports[0] != DefaultWebSocketPort {
		t.Fatalf("sin puertos debe usar default %d, obtenido=%v", DefaultWebSocketPort, req.Ports)
	}
}
