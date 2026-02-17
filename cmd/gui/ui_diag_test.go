// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

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

func TestCertValidityStatusSinDatos(t *testing.T) {
	got := certValidityStatus("", "")
	if got != "sin datos" {
		t.Fatalf("estado de vigencia inesperado: %q", got)
	}
}

func TestCertValidityStatusCaducado(t *testing.T) {
	to := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")
	got := certValidityStatus("", to)
	if got == "" || got[:8] != "caducado" {
		t.Fatalf("se esperaba estado caducado, obtenido=%q", got)
	}
}

func TestSanitizeSensitiveTextNoCorrompeConEnvVacio(t *testing.T) {
	originalHome := os.Getenv("HOME")
	originalUserProfile := os.Getenv("USERPROFILE")
	t.Cleanup(func() {
		_ = os.Setenv("HOME", originalHome)
		_ = os.Setenv("USERPROFILE", originalUserProfile)
	})
	_ = os.Setenv("HOME", "")
	_ = os.Setenv("USERPROFILE", "")

	got := sanitizeSensitiveText("[WebSocket] Received: afirma://save?dat=ABC&id=123")
	if strings.Contains(got, "%USERPROFILE%") {
		t.Fatalf("no debe insertar marcador de USERPROFILE cuando variable vacía: %q", got)
	}
	if strings.HasPrefix(got, "%USERPROFILE%") {
		t.Fatalf("texto corrompido por reemplazo vacío: %q", got)
	}
}

func TestSanitizeSensitiveTextMascaraRutas(t *testing.T) {
	home, _ := os.UserHomeDir()
	if strings.TrimSpace(home) == "" {
		t.Skip("home no disponible en entorno de test")
	}
	raw := home + "/Trabajo/fichero.pdf"
	got := sanitizeSensitiveText(raw)
	if strings.Contains(got, home) {
		t.Fatalf("debe ocultar ruta HOME en reporte: %q", got)
	}
	if !strings.Contains(got, "~") {
		t.Fatalf("se esperaba marcador ~ en ruta saneada: %q", got)
	}
}

func TestOperationHistorySummaryEtiquetas(t *testing.T) {
	ui := &UI{
		OperationHistory: []OperationHistoryEntry{
			{At: "2026-02-18 00:00:00", Operation: "firmar", Format: "cades", Result: "ok"},
			{At: "2026-02-18 00:01:00", Operation: "verificar", Format: "pades", Result: "error"},
		},
	}
	got := ui.operationHistorySummary(2)
	if !strings.Contains(got, "[OK]") {
		t.Fatalf("se esperaba etiqueta OK en resumen: %q", got)
	}
	if !strings.Contains(got, "[ERROR]") {
		t.Fatalf("se esperaba etiqueta ERROR en resumen: %q", got)
	}
}
