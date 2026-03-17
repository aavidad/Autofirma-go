// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRESTMuxForTest(s *restServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRootConsole)
	mux.HandleFunc("/auth/challenge", s.handleAuthChallenge)
	mux.HandleFunc("/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/autenticacion/reto", s.handleAuthChallenge)
	mux.HandleFunc("/autenticacion/verificar", s.handleAuthVerify)
	mux.HandleFunc("/health", s.withAuth(s.handleHealth))
	mux.HandleFunc("/certificates", s.withAuth(s.handleCertificates))
	mux.HandleFunc("/sign", s.withAuth(s.handleSign))
	mux.HandleFunc("/verify", s.withAuth(s.handleVerify))
	mux.HandleFunc("/salud", s.withAuth(s.handleHealth))
	mux.HandleFunc("/certificados", s.withAuth(s.handleCertificates))
	mux.HandleFunc("/firmar", s.withAuth(s.handleSign))
	mux.HandleFunc("/verificar", s.withAuth(s.handleVerify))
	mux.HandleFunc("/diagnostics/report", s.withAuth(s.handleDiagnosticsReport))
	mux.HandleFunc("/security/domains", s.withAuth(s.handleSecurityDomains))
	mux.HandleFunc("/tls/clear-store", s.withAuth(s.handleTLSClearStore))
	mux.HandleFunc("/tls/trust-status", s.withAuth(s.handleTLSTrustStatus))
	mux.HandleFunc("/tls/install-trust", s.withAuth(s.handleTLSInstallTrust))
	mux.HandleFunc("/tls/generate-certs", s.withAuth(s.handleTLSGenerateCerts))
	mux.HandleFunc("/diagnostico/informe", s.withAuth(s.handleDiagnosticsReport))
	mux.HandleFunc("/seguridad/dominios", s.withAuth(s.handleSecurityDomains))
	mux.HandleFunc("/tls/limpiar-almacen", s.withAuth(s.handleTLSClearStore))
	mux.HandleFunc("/tls/estado-confianza", s.withAuth(s.handleTLSTrustStatus))
	mux.HandleFunc("/tls/instalar-confianza", s.withAuth(s.handleTLSInstallTrust))
	mux.HandleFunc("/tls/generar-certificados", s.withAuth(s.handleTLSGenerateCerts))
	return mux
}

func doRESTRequestForTest(mux *http.ServeMux, method, path, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestRESTNewEndpointsRequireAuth(t *testing.T) {
	s := &restServer{
		core:       NewCoreService(),
		token:      "secret",
		sessionTTL: 10 * time.Minute,
		challenges: map[string]restChallenge{},
		sessions:   map[string]restSession{},
	}
	mux := newRESTMuxForTest(s)

	tests := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/diagnostics/report"},
		{method: http.MethodGet, path: "/diagnostico/informe"},
		{method: http.MethodGet, path: "/security/domains"},
		{method: http.MethodGet, path: "/seguridad/dominios"},
		{method: http.MethodPost, path: "/security/domains"},
		{method: http.MethodPost, path: "/seguridad/dominios"},
		{method: http.MethodDelete, path: "/security/domains"},
		{method: http.MethodDelete, path: "/seguridad/dominios"},
		{method: http.MethodPost, path: "/tls/clear-store"},
		{method: http.MethodPost, path: "/tls/limpiar-almacen"},
		{method: http.MethodGet, path: "/tls/trust-status"},
		{method: http.MethodGet, path: "/tls/estado-confianza"},
		{method: http.MethodPost, path: "/tls/install-trust"},
		{method: http.MethodPost, path: "/tls/instalar-confianza"},
		{method: http.MethodPost, path: "/tls/generate-certs"},
		{method: http.MethodPost, path: "/tls/generar-certificados"},
	}
	for _, tc := range tests {
		rec := doRESTRequestForTest(mux, tc.method, tc.path, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status=%d, esperado=%d", tc.method, tc.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestRESTSecurityDomainsCRUD(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	resetTrustedDomainsForTest()
	defer resetTrustedDomainsForTest()

	s := &restServer{
		core:       NewCoreService(),
		token:      "secret",
		sessionTTL: 10 * time.Minute,
		challenges: map[string]restChallenge{},
		sessions:   map[string]restSession{},
	}
	mux := newRESTMuxForTest(s)

	rec := doRESTRequestForTest(mux, http.MethodGet, "/security/domains", "secret", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security/domains status=%d, esperado=%d", rec.Code, http.StatusOK)
	}
	var listResp restTrustedDomainsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("respuesta JSON inválida en GET inicial: %v", err)
	}
	if !listResp.OK {
		t.Fatalf("GET /security/domains ok=false")
	}
	if len(listResp.Domains) != 0 {
		t.Fatalf("se esperaban 0 dominios al inicio, obtenido=%d", len(listResp.Domains))
	}

	addBody := []byte(`{"domain":"https://firma.ejemplo.gob.es/portal"}`)
	rec = doRESTRequestForTest(mux, http.MethodPost, "/security/domains", "secret", addBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /security/domains status=%d, esperado=%d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("respuesta JSON inválida en POST: %v", err)
	}
	if len(listResp.Domains) != 1 || listResp.Domains[0] != "firma.ejemplo.gob.es" {
		t.Fatalf("dominios tras alta inesperados: %+v", listResp.Domains)
	}

	addBodyES := []byte(`{"dominio":"https://sede.grx.es/firma"}`)
	rec = doRESTRequestForTest(mux, http.MethodPost, "/seguridad/dominios", "secret", addBodyES)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /seguridad/dominios status=%d, esperado=%d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("respuesta JSON inválida en POST castellano: %v", err)
	}
	if len(listResp.Domains) != 2 {
		t.Fatalf("se esperaban 2 dominios tras alta castellano, obtenido=%d", len(listResp.Domains))
	}

	delBody := []byte(`{"domain":"firma.ejemplo.gob.es"}`)
	rec = doRESTRequestForTest(mux, http.MethodDelete, "/security/domains", "secret", delBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /security/domains status=%d, esperado=%d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("respuesta JSON inválida en DELETE: %v", err)
	}
	if len(listResp.Domains) != 1 {
		t.Fatalf("se esperaba 1 dominio tras borrar uno, obtenido=%d", len(listResp.Domains))
	}

	delBodyES := []byte(`{"dominio":"sede.grx.es"}`)
	rec = doRESTRequestForTest(mux, http.MethodDelete, "/seguridad/dominios", "secret", delBodyES)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /seguridad/dominios status=%d, esperado=%d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("respuesta JSON inválida en DELETE castellano: %v", err)
	}
	if len(listResp.Domains) != 0 {
		t.Fatalf("se esperaban 0 dominios tras borrar todo, obtenido=%d", len(listResp.Domains))
	}
}

func TestRESTTLSClearStore(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	storeDir, err := endpointTLSCertsDir()
	if err != nil {
		t.Fatalf("endpointTLSCertsDir: %v", err)
	}
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "one.crt"), []byte("dummy1"), 0o600); err != nil {
		t.Fatalf("write one.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "two.pem"), []byte("dummy2"), 0o600); err != nil {
		t.Fatalf("write two.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "note.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("write note.txt: %v", err)
	}

	s := &restServer{
		core:       NewCoreService(),
		token:      "secret",
		sessionTTL: 10 * time.Minute,
		challenges: map[string]restChallenge{},
		sessions:   map[string]restSession{},
	}
	mux := newRESTMuxForTest(s)
	rec := doRESTRequestForTest(mux, http.MethodPost, "/tls/clear-store", "secret", []byte(`{}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /tls/clear-store status=%d, esperado=%d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp restTLSClearStoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("respuesta JSON inválida: %v", err)
	}
	if !resp.OK {
		t.Fatalf("respuesta ok=false")
	}
	if resp.Removed != 2 {
		t.Fatalf("removed=%d, esperado=2", resp.Removed)
	}
	if resp.EndpointStoreCount != 0 {
		t.Fatalf("endpointStoreCount=%d, esperado=0", resp.EndpointStoreCount)
	}
	if _, err := os.Stat(filepath.Join(storeDir, "note.txt")); err != nil {
		t.Fatalf("note.txt debería mantenerse: %v", err)
	}
}

func TestRESTRootConsoleIncludesSecurityActions(t *testing.T) {
	s := &restServer{
		core:       NewCoreService(),
		token:      "secret",
		sessionTTL: 10 * time.Minute,
		challenges: map[string]restChallenge{},
		sessions:   map[string]restSession{},
	}
	mux := newRESTMuxForTest(s)
	rec := doRESTRequestForTest(mux, http.MethodGet, "/", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status=%d, esperado=%d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, marker := range []string{
		"/diagnostics/report",
		"/security/domains",
		"/tls/clear-store",
		"/tls/trust-status",
		"/tls/install-trust",
		"/tls/generate-certs",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("la consola web no contiene marcador %s", marker)
		}
	}
}

func TestRESTAliasNormalizationFunctions(t *testing.T) {
	signReq := restSignRequest{
		InputPathES:           "/tmp/in.pdf",
		OutputPathES:          "/tmp/out.pdf",
		CertificateIDES:       "cert-1",
		CertificateIndexES:    2,
		CertificateContainsES: "Juan",
		ActionES:              "sign",
		FormatES:              "pades",
		AllowInvalidPDFES:     true,
		StrictCompatES:        true,
		OverwriteES:           "force",
		ReturnSignatureB64ES:  true,
		VisibleSealES:         &restSignVisibleSeal{Page: 1, X: 0.1, Y: 0.1, W: 0.3, H: 0.1},
	}
	normalizeSignRequestAliases(&signReq)
	if signReq.InputPath == "" || signReq.OutputPath == "" || signReq.CertificateID == "" {
		t.Fatalf("normalización de aliases de firma incompleta: %+v", signReq)
	}
	if signReq.CertificateIndex != 2 || signReq.Action != "sign" || signReq.Format != "pades" {
		t.Fatalf("normalización de campos numéricos/texto incorrecta: %+v", signReq)
	}
	if !signReq.AllowInvalidPDF || !signReq.StrictCompat || !signReq.ReturnSignatureB64 || signReq.VisibleSeal == nil {
		t.Fatalf("normalización de bool/objeto incorrecta: %+v", signReq)
	}

	verifyReq := restVerifyRequest{
		InputPathES:     "/tmp/firmado.pdf",
		SignaturePathES: "/tmp/firma.csig",
		OriginalPathES:  "/tmp/original.bin",
		FormatES:        "cades",
	}
	normalizeVerifyRequestAliases(&verifyReq)
	if verifyReq.InputPath == "" || verifyReq.SignaturePath == "" || verifyReq.OriginalPath == "" || verifyReq.Format != "cades" {
		t.Fatalf("normalización de aliases de verificación incorrecta: %+v", verifyReq)
	}

	authReq := restAuthVerifyRequest{
		ChallengeIDES:    "reto-1",
		SignatureB64ES:   "ZmlybWE=",
		CertificatePEMES: "pem",
		CertificateB64ES: "b64",
	}
	normalizeAuthVerifyRequestAliases(&authReq)
	if authReq.ChallengeID == "" || authReq.SignatureB64 == "" || authReq.CertificatePEM == "" || authReq.CertificateB64 == "" {
		t.Fatalf("normalización de aliases de auth incorrecta: %+v", authReq)
	}
}
