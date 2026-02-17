// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestLittleEndianHexIPv4(t *testing.T) {
	got := littleEndianHexIPv4("0101A8C0")
	want := "192.168.1.1"
	if got != want {
		t.Fatalf("ip convertida inesperada: got=%q want=%q", got, want)
	}
}

func TestLittleEndianHexIPv4Invalido(t *testing.T) {
	if got := littleEndianHexIPv4("ZZZZZZZZ"); got != "" {
		t.Fatalf("se esperaba cadena vacía para hex inválido, obtenido=%q", got)
	}
	if got := littleEndianHexIPv4("1234"); got != "" {
		t.Fatalf("se esperaba cadena vacía para longitud inválida, obtenido=%q", got)
	}
}

func TestParseDefaultGatewayFromProcRoute(t *testing.T) {
	raw := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	got := parseDefaultGatewayFromProcRoute(raw)
	want := "192.168.1.1"
	if got != want {
		t.Fatalf("gateway inesperado: got=%q want=%q", got, want)
	}
}

func TestWithSolutionNoDuplica(t *testing.T) {
	msg := "Error base\nPosible solución: prueba X"
	got := withSolution(msg, "otra cosa")
	if got != msg {
		t.Fatalf("withSolution no debe duplicar sugerencia, obtenido=%q", got)
	}
}
