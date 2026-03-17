// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"autofirma-host/pkg/version"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

type restServer struct {
	core         *CoreService
	token        string
	sessionTTL   time.Duration
	allowedCerts map[string]struct{}
	challenges   map[string]restChallenge
	sessions     map[string]restSession
	mu           sync.Mutex
}

type restError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type restHealthResponse struct {
	OK      bool   `json:"ok"`
	Service string `json:"service"`
	Version string `json:"version"`
}

type restCertificate struct {
	Index        int    `json:"index"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Nickname     string `json:"nickname,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	ValidFrom    string `json:"validFrom,omitempty"`
	ValidTo      string `json:"validTo,omitempty"`
	CanSign      bool   `json:"canSign"`
	SignIssue    string `json:"signIssue,omitempty"`
	Source       string `json:"source,omitempty"`
	SubjectName  string `json:"subjectName,omitempty"`
	IssuerName   string `json:"issuerName,omitempty"`
	Status       string `json:"status,omitempty"`
}

type restCertListResponse struct {
	OK           bool              `json:"ok"`
	Certificates []restCertificate `json:"certificates"`
}

type restSignVisibleSeal struct {
	Page     uint32  `json:"page"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	W        float64 `json:"w"`
	H        float64 `json:"h"`
	Rotation int     `json:"rotation"`
}

type restSignRequest struct {
	InputPath             string               `json:"inputPath"`
	InputPathES           string               `json:"rutaEntrada"`
	OutputPath            string               `json:"outputPath"`
	OutputPathES          string               `json:"rutaSalida"`
	CertificateID         string               `json:"certificateId"`
	CertificateIDES       string               `json:"idCertificado"`
	CertificateIndex      int                  `json:"certificateIndex"`
	CertificateIndexES    int                  `json:"indiceCertificado"`
	CertificateContains   string               `json:"certificateContains"`
	CertificateContainsES string               `json:"certificadoContiene"`
	Action                string               `json:"action"`
	ActionES              string               `json:"accion"`
	Format                string               `json:"format"`
	FormatES              string               `json:"formato"`
	AllowInvalidPDF       bool                 `json:"allowInvalidPDF"`
	AllowInvalidPDFES     bool                 `json:"permitirPDFInvalido"`
	StrictCompat          bool                 `json:"strictCompat"`
	StrictCompatES        bool                 `json:"compatibilidadEstricta"`
	Overwrite             string               `json:"overwrite"`
	OverwriteES           string               `json:"sobrescribir"`
	SaveToDisk            *bool                `json:"saveToDisk"`
	SaveToDiskES          *bool                `json:"guardarEnDisco"`
	ReturnSignatureB64    bool                 `json:"returnSignatureB64"`
	ReturnSignatureB64ES  bool                 `json:"devolverFirmaB64"`
	VisibleSeal           *restSignVisibleSeal `json:"visibleSeal"`
	VisibleSealES         *restSignVisibleSeal `json:"selloVisible"`
	TSAURL                string               `json:"tsaURL"`
	TSAURLES              string               `json:"urlTSA"`
	DataB64               string               `json:"dataB64"`
	DataB64ES             string               `json:"datosB64"`
}

type restCertImportRequest struct {
	P12B64     string `json:"p12B64"`
	P12B64ES   string `json:"datosP12"`
	Password   string `json:"password"`
	PasswordES string `json:"contrasena"`
}

type restSignResponse struct {
	OK            bool   `json:"ok"`
	Action        string `json:"action"`
	Format        string `json:"format"`
	OutputPath    string `json:"outputPath,omitempty"`
	Renamed       bool   `json:"renamed,omitempty"`
	Overwrote     bool   `json:"overwrote,omitempty"`
	CertificateID string `json:"certificateId"`
	SignatureB64  string `json:"signatureB64,omitempty"`
}

type restVerifyRequest struct {
	InputPath         string `json:"inputPath"`
	InputPathES       string `json:"rutaEntrada"`
	SignaturePath     string `json:"signaturePath"`
	SignaturePathES   string `json:"rutaFirma"`
	OriginalPath      string `json:"originalPath"`
	OriginalPathES    string `json:"rutaOriginal"`
	OriginalDataB64   string `json:"originalDataB64,omitempty"`
	OriginalDataB64ES string `json:"datosOriginalesB64,omitempty"`
	DataB64           string `json:"dataB64"`
	DataB64ES         string `json:"datosB64"`
	Format            string `json:"format"`
	FormatES          string `json:"formato"`
}

type restVerifyResponse struct {
	OK     bool                   `json:"ok"`
	Format string                 `json:"format"`
	Result *protocol.VerifyResult `json:"result"`
}

type restDiagnosticsReportResponse struct {
	OK                 bool     `json:"ok"`
	Service            string   `json:"service"`
	Version            string   `json:"version"`
	Timestamp          string   `json:"timestamp"`
	CertificateCount   int      `json:"certificateCount"`
	CanSignCount       int      `json:"canSignCount"`
	TrustedDomains     []string `json:"trustedDomains"`
	EndpointStoreDir   string   `json:"endpointStoreDir"`
	EndpointStoreCount int      `json:"endpointStoreCount"`
	TrustStatusLines   []string `json:"trustStatusLines"`
	TrustStatusError   string   `json:"trustStatusError,omitempty"`
	TokenEnabled       bool     `json:"tokenEnabled"`
	CertAuthEnabled    bool     `json:"certAuthEnabled"`
	AllowListCount     int      `json:"allowListCount"`
	SessionTTLSeconds  int64    `json:"sessionTTLSeconds"`
}

type restTrustedDomainsResponse struct {
	OK      bool     `json:"ok"`
	Domains []string `json:"domains"`
}

type restDomainUpdateRequest struct {
	Domain   string `json:"domain"`
	DomainES string `json:"dominio"`
}

type restTLSClearStoreResponse struct {
	OK                 bool   `json:"ok"`
	Removed            int    `json:"removed"`
	EndpointStoreDir   string `json:"endpointStoreDir"`
	EndpointStoreCount int    `json:"endpointStoreCount"`
}

type restTLSTrustStatusResponse struct {
	OK               bool     `json:"ok"`
	Lines            []string `json:"lines"`
	EndpointStoreDir string   `json:"endpointStoreDir"`
	EndpointStoreCnt int      `json:"endpointStoreCount"`
}

type restChallenge struct {
	Nonce     []byte
	ExpiresAt time.Time
}

type restSession struct {
	Token       string
	Subject     string
	Fingerprint string
	ExpiresAt   time.Time
}

type restChallengeResponse struct {
	OK           bool   `json:"ok"`
	ChallengeID  string `json:"challengeId"`
	ChallengeB64 string `json:"challengeB64"`
	ExpiresAt    string `json:"expiresAt"`
}

type restAuthVerifyRequest struct {
	ChallengeID      string `json:"challengeId"`
	ChallengeIDES    string `json:"idReto"`
	SignatureB64     string `json:"signatureB64"`
	SignatureB64ES   string `json:"firmaB64"`
	CertificatePEM   string `json:"certificatePEM"`
	CertificatePEMES string `json:"certificadoPEM"`
	CertificateB64   string `json:"certificateB64"`
	CertificateB64ES string `json:"certificadoB64"`
}

type restAuthVerifyResponse struct {
	OK           bool   `json:"ok"`
	SessionToken string `json:"sessionToken"`
	ExpiresAt    string `json:"expiresAt"`
	Subject      string `json:"subject"`
	Fingerprint  string `json:"fingerprint"`
}

func runRESTServer(addr string, token string, sessionTTL time.Duration, allowedFingerprintsCSV string, useTLS bool) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = "127.0.0.1:63118"
	}
	token = strings.TrimSpace(token)
	if sessionTTL <= 0 {
		sessionTTL = 10 * time.Minute
	}

	allowed := parseAllowedFingerprints(allowedFingerprintsCSV)
	s := &restServer{
		core:         NewCoreService(),
		token:        token,
		sessionTTL:   sessionTTL,
		allowedCerts: allowed,
		challenges:   map[string]restChallenge{},
		sessions:     map[string]restSession{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRootConsole)
	mux.HandleFunc("/auth/challenge", s.handleAuthChallenge)
	mux.HandleFunc("/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/autenticacion/reto", s.handleAuthChallenge)
	mux.HandleFunc("/autenticacion/verificar", s.handleAuthVerify)
	mux.HandleFunc("/sign", s.withAuth(s.handleSign))
	mux.HandleFunc("/verify", s.withAuth(s.handleVerify))
	mux.HandleFunc("/certificates/import", s.withAuth(s.handleCertificatesImport))
	mux.HandleFunc("/health", s.withAuth(s.handleHealth))
	mux.HandleFunc("/salud", s.withAuth(s.handleHealth))
	mux.HandleFunc("/certificados", s.withAuth(s.handleCertificates))
	mux.HandleFunc("/certificados/importar", s.withAuth(s.handleCertificatesImport))
	mux.HandleFunc("/firmar", s.withAuth(s.handleSign))
	mux.HandleFunc("/verificar", s.withAuth(s.handleVerify))
	mux.HandleFunc("/diagnostics/report", s.withAuth(s.handleDiagnosticsReport))
	mux.HandleFunc("/security/domains", s.withAuth(s.handleSecurityDomains))
	mux.HandleFunc("/tls/clear-store", s.withAuth(s.handleTLSClearStore))
	mux.HandleFunc("/tls/trust-status", s.withAuth(s.handleTLSTrustStatus))
	mux.HandleFunc("/tls/install-trust", s.withAuth(s.handleTLSInstallTrust))
	mux.HandleFunc("/tls/generate-certs", s.withAuth(s.handleTLSGenerateCerts))
	mux.HandleFunc("/trust/install-public-roots", s.withAuth(s.handleInstallPublicRoots))
	mux.HandleFunc("/diagnostico/informe", s.withAuth(s.handleDiagnosticsReport))
	mux.HandleFunc("/seguridad/dominios", s.withAuth(s.handleSecurityDomains))
	mux.HandleFunc("/confianza/instalar-raices-publicas", s.withAuth(s.handleInstallPublicRoots))
	mux.HandleFunc("/confianza/instalar", s.withAuth(s.handleInstallPublicRoots))
	mux.HandleFunc("/tls/limpiar-almacen", s.withAuth(s.handleTLSClearStore))
	mux.HandleFunc("/tls/estado-confianza", s.withAuth(s.handleTLSTrustStatus))
	mux.HandleFunc("/tls/instalar-confianza", s.withAuth(s.handleTLSInstallTrust))
	mux.HandleFunc("/tls/generar-certificados", s.withAuth(s.handleTLSGenerateCerts))
	// Service management
	mux.HandleFunc("/service/status", s.withAuth(s.handleServiceStatus))
	mux.HandleFunc("/service/install", s.withAuth(s.handleServiceInstall))
	mux.HandleFunc("/service/uninstall", s.withAuth(s.handleServiceUninstall))
	mux.HandleFunc("/service/start", s.withAuth(s.handleServiceStart))
	mux.HandleFunc("/service/stop", s.withAuth(s.handleServiceStop))
	mux.HandleFunc("/desktop/open", s.withAuth(s.handleDesktopOpen))
	mux.HandleFunc("/escritorio/abrir", s.withAuth(s.handleDesktopOpen))

	// User settings
	mux.HandleFunc("/settings", s.withAuth(s.handleSettings))
	mux.HandleFunc("/configuracion", s.withAuth(s.handleSettings))

	// PDF Helpers
	mux.HandleFunc("/pdf/preview", s.withAuth(s.handlePdfPreview))
	mux.HandleFunc("/pdf/previsualizar", s.withAuth(s.handlePdfPreview))

	if useTLS {
		certFile, keyFile, err := ensureLocalTLSCerts()
		if err != nil {
			return fmt.Errorf("error obteniendo certificados TLS: %w", err)
		}
		log.Printf("[REST] Servidor API REST local activo en https://%s (Cifrado habilitado)", addr)
		srv := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		return srv.ListenAndServeTLS(certFile, keyFile)
	}

	log.Printf("[REST] Servidor API REST local activo en http://%s", addr)
	log.Printf("[REST] Endpoints: / /auth/challenge /auth/verify /health /certificates /sign /verify /diagnostics/report /security/domains /tls/clear-store /tls/trust-status /tls/install-trust /tls/generate-certs")
	if token != "" {
		log.Printf("[REST] Autenticación por token: habilitada")
	}
	if len(allowed) > 0 {
		log.Printf("[REST] Autenticación por certificado: habilitada (lista blanca huellas SHA-256=%d, ttl=%s)", len(allowed), sessionTTL.String())
	} else {
		log.Printf("[REST] AVISO: sin lista blanca de certificados — cualquier titular de certificado puede autenticarse. Configura AUTOFIRMA_REST_ALLOWED_CERTS para restringir acceso.")
	}
	return (&http.Server{
		Addr:    addr,
		Handler: mux,
	}).ListenAndServe()
}

func runRESTServerOnSocket(socketPath string, token string, sessionTTL time.Duration, allowedFingerprintsCSV string) error {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = "/tmp/autofirma.sock"
	}
	// Limpieza previa del socket si existe
	os.Remove(socketPath)

	token = strings.TrimSpace(token)
	if sessionTTL <= 0 {
		sessionTTL = 10 * time.Minute
	}

	allowed := parseAllowedFingerprints(allowedFingerprintsCSV)
	s := &restServer{
		core:         NewCoreService(),
		token:        token,
		sessionTTL:   sessionTTL,
		allowedCerts: allowed,
		challenges:   map[string]restChallenge{},
		sessions:     map[string]restSession{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRootConsole)
	mux.HandleFunc("/auth/challenge", s.handleAuthChallenge)
	mux.HandleFunc("/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/sign", s.withAuth(s.handleSign))
	mux.HandleFunc("/verify", s.withAuth(s.handleVerify))
	mux.HandleFunc("/certificates/import", s.withAuth(s.handleCertificatesImport))
	mux.HandleFunc("/desktop/open", s.withAuth(s.handleDesktopOpen))
	mux.HandleFunc("/escritorio/abrir", s.withAuth(s.handleDesktopOpen))
	// Alias en castellano
	mux.HandleFunc("/salud", s.withAuth(s.handleHealth))
	mux.HandleFunc("/certificados", s.withAuth(s.handleCertificates))
	mux.HandleFunc("/certificados/importar", s.withAuth(s.handleCertificatesImport))
	mux.HandleFunc("/firmar", s.withAuth(s.handleSign))
	mux.HandleFunc("/verificar", s.withAuth(s.handleVerify))

	// User settings
	mux.HandleFunc("/settings", s.withAuth(s.handleSettings))
	mux.HandleFunc("/configuracion", s.withAuth(s.handleSettings))

	log.Printf("[REST-IPC] Servidor API REST activo en socket Unix: %s", socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	os.Chmod(socketPath, 0600)

	srv := &http.Server{
		Handler: mux,
	}
	return srv.Serve(l)
}

func (s *restServer) handleRootConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, "internal web fs error", http.StatusInternalServerError)
		return
	}

	http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
}

func (s *restServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !s.authOK(r) {
			writeJSON(w, http.StatusUnauthorized, restError{OK: false, Error: "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *restServer) authOK(r *http.Request) bool {
	s.cleanupExpiredAuthState()
	if s.allowLocalNoAuth(r) {
		return true
	}
	raw := authHeaderToken(r)
	if raw == "" {
		return false
	}
	if s.token != "" && subtle.ConstantTimeCompare([]byte(raw), []byte(s.token)) == 1 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[raw]
	if !ok {
		return false
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, raw)
		return false
	}
	return true
}

func (s *restServer) allowLocalNoAuth(r *http.Request) bool {
	if strings.TrimSpace(s.token) != "" {
		return false
	}
	if len(s.allowedCerts) > 0 {
		return false
	}
	if !isLoopbackRemoteAddr(r.RemoteAddr) {
		return false
	}
	log.Printf("[REST] Acceso local sin auth permitido (sin token/certs configurados) path=%s remote=%s", r.URL.Path, r.RemoteAddr)
	return true
}

func authHeaderToken(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		raw = strings.TrimSpace(raw[len("Bearer "):])
	}
	if raw == "" {
		raw = strings.TrimSpace(r.Header.Get("X-API-Token"))
	}
	return raw
}

func (s *restServer) cleanupExpiredAuthState() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, ch := range s.challenges {
		if now.After(ch.ExpiresAt) {
			delete(s.challenges, k)
		}
	}
	for k, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
}

func (s *restServer) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	challengeID, challengeRaw, err := newRandomTokenPair()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "no se pudo generar reto"})
		return
	}
	exp := time.Now().Add(2 * time.Minute)
	s.mu.Lock()
	s.challenges[challengeID] = restChallenge{Nonce: challengeRaw, ExpiresAt: exp}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, restChallengeResponse{
		OK:           true,
		ChallengeID:  challengeID,
		ChallengeB64: base64.StdEncoding.EncodeToString(challengeRaw),
		ExpiresAt:    exp.Format(time.RFC3339),
	})
}

func (s *restServer) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	var req restAuthVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "json inválido"})
		return
	}
	normalizeAuthVerifyRequestAliases(&req)
	challengeID := strings.TrimSpace(req.ChallengeID)
	signatureB64 := strings.TrimSpace(req.SignatureB64)
	if challengeID == "" || signatureB64 == "" {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "challengeId y signatureB64 son obligatorios"})
		return
	}

	s.cleanupExpiredAuthState()
	s.mu.Lock()
	ch, ok := s.challenges[challengeID]
	if ok {
		delete(s.challenges, challengeID)
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "challenge inválido o expirado"})
		return
	}

	cert, fp, err := parseAuthCertificate(strings.TrimSpace(req.CertificatePEM), strings.TrimSpace(req.CertificateB64))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
		return
	}
	if len(s.allowedCerts) > 0 {
		if _, found := s.allowedCerts[strings.ToLower(fp)]; !found {
			writeJSON(w, http.StatusForbidden, restError{OK: false, Error: "certificado no autorizado"})
			return
		}
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		writeJSON(w, http.StatusForbidden, restError{OK: false, Error: "certificado fuera de vigencia"})
		return
	}
	sigRaw, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "signatureB64 inválida"})
		return
	}
	if err := verifyChallengeSignature(cert, ch.Nonce, sigRaw); err != nil {
		writeJSON(w, http.StatusForbidden, restError{OK: false, Error: "firma de reto inválida"})
		return
	}

	sessionToken, _, err := newRandomTokenPair()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "no se pudo crear sesión"})
		return
	}
	exp := time.Now().Add(s.sessionTTL)
	subj := strings.TrimSpace(cert.Subject.String())
	s.mu.Lock()
	s.sessions[sessionToken] = restSession{
		Token:       sessionToken,
		Subject:     subj,
		Fingerprint: fp,
		ExpiresAt:   exp,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, restAuthVerifyResponse{
		OK:           true,
		SessionToken: sessionToken,
		ExpiresAt:    exp.Format(time.RFC3339),
		Subject:      subj,
		Fingerprint:  fp,
	})
}

func (s *restServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, restHealthResponse{
		OK:      true,
		Service: "autofirma-rest",
		Version: version.CurrentVersion,
	})
}

func (s *restServer) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	certs, err := s.core.LoadCertificates()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	check := strings.TrimSpace(r.URL.Query().Get("check"))
	if check == "" {
		check = strings.TrimSpace(r.URL.Query().Get("comprobar"))
	}
	if parseBoolParam(check) {
		certs, _, _ = s.core.CheckCertificates(certs)
	}
	out := make([]restCertificate, 0, len(certs))
	for i, c := range certs {
		out = append(out, restCertificate{
			Index:        i,
			ID:           c.ID,
			Name:         certificateBestDisplayName(c),
			Nickname:     c.Nickname,
			SerialNumber: c.SerialNumber,
			ValidFrom:    c.ValidFrom,
			ValidTo:      c.ValidTo,
			CanSign:      c.CanSign,
			SignIssue:    c.SignIssue,
			Source:       c.Source,
			SubjectName:  c.SubjectName,
			IssuerName:   c.IssuerName,
			Status:       c.Status,
		})
	}
	writeJSON(w, http.StatusOK, restCertListResponse{OK: true, Certificates: out})
}

func (s *restServer) handleCertificatesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	var req restCertImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "json inválido"})
		return
	}
	if req.P12B64ES != "" && req.P12B64 == "" {
		req.P12B64 = req.P12B64ES
	}
	if req.PasswordES != "" && req.Password == "" {
		req.Password = req.PasswordES
	}

	if req.P12B64 == "" {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "p12B64 es obligatorio"})
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.P12B64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "p12B64 no es base64 válido"})
		return
	}

	// Save to temp file to use ImportP12ToSystem
	tmpFile, err := os.CreateTemp("", "autofirma-import-*.p12")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error creando archivo temporal"})
		return
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error escribiendo archivo temporal"})
		return
	}
	tmpFile.Close()

	if err := certstore.ImportP12ToSystem(tmpFile.Name(), req.Password); err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *restServer) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	var req restSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "json inválido"})
		return
	}
	normalizeSignRequestAliases(&req)

	var tempFilePath string
	if req.DataB64 != "" {
		decodedContent, err := base64.StdEncoding.DecodeString(req.DataB64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "dataB64 no es base64 válido"})
			return
		}
		tmpF, err := os.CreateTemp("", "af_rest_in_*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error al guardar el contenido recibido"})
			return
		}
		if _, err := tmpF.Write(decodedContent); err != nil {
			_ = tmpF.Close()
			os.Remove(tmpF.Name())
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error al guardar el contenido recibido"})
			return
		}
		_ = tmpF.Close()
		tempFilePath = tmpF.Name()
		req.InputPath = tempFilePath
		defer os.Remove(tempFilePath) // Limpieza al terminar
	}

	if req.InputPath == "" {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "inputPath o dataB64 requerido"})
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "sign"
	}
	if action != "sign" && action != "cosign" && action != "countersign" {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "action no soportada"})
		return
	}

	certs, err := s.core.LoadCertificates()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	cert, err := selectCertificateForREST(certs, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
		return
	}

	signOpts := buildSignOptionsForREST(req)
	if req.StrictCompat {
		effectiveFormat := strings.TrimSpace(req.Format)
		if normalizeProtocolFormat(effectiveFormat) == "" || strings.EqualFold(effectiveFormat, "auto") {
			effectiveFormat = detectLocalSignFormat(strings.TrimSpace(req.InputPath))
		}
		signOpts = applyStrictCompatDefaults(signOpts, effectiveFormat)
	}

	saveToDisk := true
	if req.SaveToDisk != nil {
		saveToDisk = *req.SaveToDisk
	}
	coreReq := CoreSignRequest{
		FilePath:         strings.TrimSpace(req.InputPath),
		CertificateID:    cert.ID,
		Action:           action,
		Format:           strings.TrimSpace(req.Format),
		AllowInvalidPDF:  req.AllowInvalidPDF,
		SaveToDisk:       false,
		OverwritePolicy:  parseOverwritePolicyREST(req.Overwrite),
		SignatureOptions: signOpts,
	}
	signed, err := s.core.SignFile(coreReq)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
		return
	}

	if saveToDisk {
		outPath := strings.TrimSpace(req.OutputPath)
		if outPath == "" {
			outPath = buildLocalSignedOutputPath(strings.TrimSpace(req.InputPath), signed.Format)
		}
		resolved, renamed, overwrote, err := resolveOutputPathPolicy(outPath, parseOverwritePolicyREST(req.Overwrite))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
			return
		}
		raw, err := base64.StdEncoding.DecodeString(signed.SignatureB64)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error decodificando firma"})
			return
		}
		if err := os.WriteFile(resolved, raw, 0o644); err != nil {
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
			return
		}
		signed.OutputPath = resolved
		signed.Renamed = renamed
		signed.Overwrote = overwrote
	}

	resp := restSignResponse{
		OK:            true,
		Action:        action,
		Format:        signed.Format,
		OutputPath:    signed.OutputPath,
		Renamed:       signed.Renamed,
		Overwrote:     signed.Overwrote,
		CertificateID: cert.ID,
	}
	if req.ReturnSignatureB64 || !saveToDisk {
		resp.SignatureB64 = signed.SignatureB64
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *restServer) handlePdfPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	var params struct {
		Path      string `json:"path"`
		Page      int    `json:"page"`
		DataB64   string `json:"dataB64"`
		DataB64ES string `json:"datosB64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "invalid request body"})
		return
	}
	if strings.TrimSpace(params.DataB64) == "" && strings.TrimSpace(params.DataB64ES) != "" {
		params.DataB64 = params.DataB64ES
	}

	previewPath := strings.TrimSpace(params.Path)
	var tempFilePath string
	if previewPath == "" && strings.TrimSpace(params.DataB64) != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(params.DataB64))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "dataB64 no es base64 válido"})
			return
		}
		tmpF, err := os.CreateTemp("", "af_rest_pdf_preview_*.pdf")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error creando temporal de previsualización"})
			return
		}
		if _, err := tmpF.Write(raw); err != nil {
			_ = tmpF.Close()
			_ = os.Remove(tmpF.Name())
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error escribiendo temporal de previsualización"})
			return
		}
		_ = tmpF.Close()
		tempFilePath = tmpF.Name()
		previewPath = tempFilePath
		defer os.Remove(tempFilePath)
	}
	if previewPath == "" {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "path o dataB64 requerido"})
		return
	}

	b64, width, height, err := s.core.GeneratePdfPreview(previewPath, params.Page)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     true,
		"data":   b64,
		"width":  width,
		"height": height,
	})
}

func (s *restServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	var req restVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "json inválido"})
		return
	}
	normalizeVerifyRequestAliases(&req)

	var tempFilePath string
	if req.DataB64 != "" {
		decodedContent, err := base64.StdEncoding.DecodeString(req.DataB64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "dataB64 no es base64 válido"})
			return
		}
		tmpF, err := os.CreateTemp("", "af_rest_ver_*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error guardar el contenido recibido"})
			return
		}
		if _, err := tmpF.Write(decodedContent); err != nil {
			_ = tmpF.Close()
			os.Remove(tmpF.Name())
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: "error al guardar el contenido recibido"})
			return
		}
		_ = tmpF.Close()
		tempFilePath = tmpF.Name()
		req.InputPath = tempFilePath
		defer os.Remove(tempFilePath)
	}

	if req.InputPath == "" {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "inputPath o dataB64 requerido"})
		return
	}

	format := normalizeProtocolFormat(strings.TrimSpace(req.Format))
	if format == "" || strings.EqualFold(format, "auto") {
		if strings.TrimSpace(req.SignaturePath) != "" {
			format = detectLocalSignFormat(strings.TrimSpace(req.SignaturePath))
		} else {
			format = detectLocalSignFormat(strings.TrimSpace(req.InputPath))
		}
	}

	// For detached formats (e.g. CAdES), allow explicit signaturePath+originalPath.
	if strings.TrimSpace(req.SignaturePath) != "" || strings.TrimSpace(req.OriginalPath) != "" {
		sigPath := strings.TrimSpace(req.SignaturePath)
		if sigPath == "" {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "signaturePath requerido para verificación desacoplada"})
			return
		}
		sigRaw, err := os.ReadFile(sigPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "no se pudo leer signaturePath"})
			return
		}
		originalRaw := []byte{}
		if op := strings.TrimSpace(req.OriginalPath); op != "" {
			originalRaw, err = os.ReadFile(op)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "no se pudo leer originalPath"})
				return
			}
		}
		result, err := signer.VerifyData(
			base64.StdEncoding.EncodeToString(originalRaw),
			base64.StdEncoding.EncodeToString(sigRaw),
			format,
		)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, restVerifyResponse{
			OK:     true,
			Format: format,
			Result: result,
		})
		return
	}

	res, err := s.core.VerifyFile(strings.TrimSpace(req.InputPath), format)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restVerifyResponse{OK: true, Format: res.Format, Result: res.Result})
}

func (s *restServer) handleDiagnosticsReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	certs, err := s.core.LoadCertificates()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	certs, _, _ = s.core.CheckCertificates(certs)
	canSign := 0
	for _, c := range certs {
		if c.CanSign {
			canSign++
		}
	}
	storeDir, storeCount := endpointTrustStoreStatus()
	domains := trustedSigningDomainsSnapshot()
	trustLines, trustErr := localTLSTrustStatus()
	resp := restDiagnosticsReportResponse{
		OK:                 true,
		Service:            "autofirma-rest",
		Version:            version.CurrentVersion,
		Timestamp:          time.Now().Format(time.RFC3339),
		CertificateCount:   len(certs),
		CanSignCount:       canSign,
		TrustedDomains:     domains,
		EndpointStoreDir:   storeDir,
		EndpointStoreCount: storeCount,
		TrustStatusLines:   trustLines,
		TokenEnabled:       strings.TrimSpace(s.token) != "",
		CertAuthEnabled:    true,
		AllowListCount:     len(s.allowedCerts),
		SessionTTLSeconds:  int64(s.sessionTTL.Seconds()),
	}
	if trustErr != nil {
		resp.TrustStatusError = trustErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *restServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, struct {
			OK       bool         `json:"ok"`
			Settings UserSettings `json:"settings"`
		}{OK: true, Settings: LoadUserSettings()})
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var req UserSettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "json inválido"})
			return
		}
		if err := SaveUserSettings(req); err != nil {
			writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, struct {
			OK       bool         `json:"ok"`
			Settings UserSettings `json:"settings"`
		}{OK: true, Settings: req})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
}

func (s *restServer) handleSecurityDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, restTrustedDomainsResponse{OK: true, Domains: trustedSigningDomainsSnapshot()})
		return
	case http.MethodPost, http.MethodDelete:
		var req restDomainUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "json inválido"})
			return
		}
		if strings.TrimSpace(req.Domain) == "" {
			req.Domain = strings.TrimSpace(req.DomainES)
		}
		if strings.TrimSpace(req.Domain) == "" {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: "domain obligatorio"})
			return
		}
		var err error
		if r.Method == http.MethodPost {
			err = addTrustedSigningDomain(req.Domain)
		} else {
			err = removeTrustedSigningDomain(req.Domain)
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, restError{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, restTrustedDomainsResponse{OK: true, Domains: trustedSigningDomainsSnapshot()})
		return
	default:
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
}

func (s *restServer) handleTLSClearStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	removed, err := clearEndpointTrustStore()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	dir, count := endpointTrustStoreStatus()
	writeJSON(w, http.StatusOK, restTLSClearStoreResponse{
		OK:                 true,
		Removed:            removed,
		EndpointStoreDir:   dir,
		EndpointStoreCount: count,
	})
}

func (s *restServer) handleTLSTrustStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	lines, err := localTLSTrustStatus()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	dir, count := endpointTrustStoreStatus()
	writeJSON(w, http.StatusOK, restTLSTrustStatusResponse{
		OK:               true,
		Lines:            lines,
		EndpointStoreDir: dir,
		EndpointStoreCnt: count,
	})
}

func (s *restServer) handleTLSInstallTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	if _, _, err := ensureLocalTLSCerts(); err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	lines, err := installLocalTLSTrust()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restTLSTrustStatusResponse{OK: true, Lines: lines})
}

func (s *restServer) handleInstallPublicRoots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	lines, err := installPublicAdminRoots()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restTLSTrustStatusResponse{OK: true, Lines: lines})
}

func (s *restServer) handleTLSGenerateCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	certFile, keyFile, err := ensureLocalTLSCerts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"certFile": certFile,
		"keyFile":  keyFile,
	})
}

func normalizeAuthVerifyRequestAliases(req *restAuthVerifyRequest) {
	if req == nil {
		return
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		req.ChallengeID = strings.TrimSpace(req.ChallengeIDES)
	}
	if strings.TrimSpace(req.SignatureB64) == "" {
		req.SignatureB64 = strings.TrimSpace(req.SignatureB64ES)
	}
	if strings.TrimSpace(req.CertificatePEM) == "" {
		req.CertificatePEM = strings.TrimSpace(req.CertificatePEMES)
	}
	if strings.TrimSpace(req.CertificateB64) == "" {
		req.CertificateB64 = strings.TrimSpace(req.CertificateB64ES)
	}
}

func normalizeSignRequestAliases(req *restSignRequest) {
	if req == nil {
		return
	}
	if strings.TrimSpace(req.InputPath) == "" {
		req.InputPath = strings.TrimSpace(req.InputPathES)
	}
	if strings.TrimSpace(req.OutputPath) == "" {
		req.OutputPath = strings.TrimSpace(req.OutputPathES)
	}
	if strings.TrimSpace(req.CertificateID) == "" {
		req.CertificateID = strings.TrimSpace(req.CertificateIDES)
	}
	if req.CertificateIndex < 0 && req.CertificateIndexES >= 0 {
		req.CertificateIndex = req.CertificateIndexES
	} else if req.CertificateIndex == 0 && req.CertificateIndexES > 0 {
		req.CertificateIndex = req.CertificateIndexES
	}
	if strings.TrimSpace(req.CertificateContains) == "" {
		req.CertificateContains = strings.TrimSpace(req.CertificateContainsES)
	}
	if strings.TrimSpace(req.Action) == "" {
		req.Action = strings.TrimSpace(req.ActionES)
	}
	if strings.TrimSpace(req.Format) == "" {
		req.Format = strings.TrimSpace(req.FormatES)
	}
	if !req.AllowInvalidPDF && req.AllowInvalidPDFES {
		req.AllowInvalidPDF = true
	}
	if !req.StrictCompat && req.StrictCompatES {
		req.StrictCompat = true
	}
	if strings.TrimSpace(req.Overwrite) == "" {
		req.Overwrite = strings.TrimSpace(req.OverwriteES)
	}
	if req.SaveToDisk == nil && req.SaveToDiskES != nil {
		req.SaveToDisk = req.SaveToDiskES
	}
	if !req.ReturnSignatureB64 && req.ReturnSignatureB64ES {
		req.ReturnSignatureB64 = true
	}
	if req.VisibleSeal == nil && req.VisibleSealES != nil {
		req.VisibleSeal = req.VisibleSealES
	}
	if strings.TrimSpace(req.TSAURL) == "" {
		req.TSAURL = strings.TrimSpace(req.TSAURLES)
	}
	if strings.TrimSpace(req.DataB64) == "" {
		req.DataB64 = strings.TrimSpace(req.DataB64ES)
	}
}

func normalizeVerifyRequestAliases(req *restVerifyRequest) {
	if req == nil {
		return
	}
	if strings.TrimSpace(req.InputPath) == "" {
		req.InputPath = strings.TrimSpace(req.InputPathES)
	}
	if strings.TrimSpace(req.SignaturePath) == "" {
		req.SignaturePath = strings.TrimSpace(req.SignaturePathES)
	}
	if strings.TrimSpace(req.OriginalPath) == "" {
		req.OriginalPath = strings.TrimSpace(req.OriginalPathES)
	}
	if strings.TrimSpace(req.Format) == "" {
		req.Format = strings.TrimSpace(req.FormatES)
	}
	if req.OriginalDataB64ES != "" && req.OriginalDataB64 == "" {
		req.OriginalDataB64 = req.OriginalDataB64ES
	}
	if req.DataB64ES != "" && req.DataB64 == "" {
		req.DataB64 = req.DataB64ES
	}
}

func selectCertificateForREST(certs []protocol.Certificate, req restSignRequest) (protocol.Certificate, error) {
	if len(certs) == 0 {
		return protocol.Certificate{}, errors.New("no hay certificados disponibles")
	}
	id := strings.TrimSpace(req.CertificateID)
	if id != "" {
		for _, c := range certs {
			if c.ID == id {
				return c, nil
			}
		}
		return protocol.Certificate{}, fmt.Errorf("no se encontró certificado con ID %s", id)
	}
	if req.CertificateIndex >= 0 {
		if req.CertificateIndex >= len(certs) {
			return protocol.Certificate{}, fmt.Errorf("certificateIndex fuera de rango")
		}
		return certs[req.CertificateIndex], nil
	}
	contains := strings.ToLower(strings.TrimSpace(req.CertificateContains))
	if contains != "" {
		for _, c := range certs {
			name := strings.ToLower(certificateBestDisplayName(c))
			nick := strings.ToLower(strings.TrimSpace(c.Nickname))
			serial := strings.ToLower(strings.TrimSpace(c.SerialNumber))
			if strings.Contains(name, contains) || strings.Contains(nick, contains) || strings.Contains(serial, contains) {
				return c, nil
			}
		}
		return protocol.Certificate{}, fmt.Errorf("no se encontró certificado que contenga %s", contains)
	}
	return certs[0], nil
}

func buildSignOptionsForREST(req restSignRequest) map[string]interface{} {
	opts := map[string]interface{}{}
	if req.VisibleSeal != nil {
		opts["visibleSignature"] = true
		page := req.VisibleSeal.Page
		if page == 0 {
			page = 1
		}

		// Obtener dimensiones reales para el escalado
		pageW, pageH := 595.28, 841.89
		if req.InputPath != "" {
			if w, h, err := signer.GetPadesPageSize(req.InputPath, page); err == nil && w > 0 && h > 0 {
				pageW, pageH = w, h
				log.Printf("[REST] Dimensiones PDF detectadas: %.2f x %.2f", pageW, pageH)
			}
		}

		opts["x"] = clamp01(req.VisibleSeal.X) * pageW
		opts["y"] = clamp01(req.VisibleSeal.Y) * pageH
		opts["width"] = clamp01(req.VisibleSeal.W) * pageW
		opts["height"] = clamp01(req.VisibleSeal.H) * pageH
		opts["page"] = int(page)
		opts["rotation"] = req.VisibleSeal.Rotation
	}
	if req.TSAURL != "" {
		opts["tsaURL"] = req.TSAURL
	} else if req.TSAURLES != "" {
		opts["tsaURL"] = req.TSAURLES
	}

	if len(opts) == 0 {
		return nil
	}
	return opts
}

func parseOverwritePolicyREST(raw string) CoreOverwritePolicy {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fail", "error":
		return CoreOverwriteFail
	case "force", "overwrite":
		return CoreOverwriteForce
	default:
		return CoreOverwriteRename
	}
}

func parseAllowedFingerprints(csv string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(csv, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		v = strings.ReplaceAll(v, ":", "")
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func newRandomTokenPair() (string, []byte, error) {
	idRaw := make([]byte, 16)
	nonceRaw := make([]byte, 32)
	if _, err := rand.Read(idRaw); err != nil {
		return "", nil, err
	}
	if _, err := rand.Read(nonceRaw); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(idRaw), nonceRaw, nil
}

func parseAuthCertificate(certPEM string, certB64 string) (*x509.Certificate, string, error) {
	var der []byte
	switch {
	case strings.TrimSpace(certPEM) != "":
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, "", errors.New("certificatePEM inválido")
		}
		der = block.Bytes
	case strings.TrimSpace(certB64) != "":
		raw, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, "", errors.New("certificateB64 inválido")
		}
		der = raw
	default:
		return nil, "", errors.New("debe proporcionar certificatePEM o certificateB64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", errors.New("certificado X.509 inválido")
	}
	sum := sha256.Sum256(der)
	return cert, strings.ToLower(hex.EncodeToString(sum[:])), nil
}

func verifyChallengeSignature(cert *x509.Certificate, challenge []byte, signature []byte) error {
	digest := sha256.Sum256(challenge)
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return errors.New("invalid ecdsa signature")
		}
		return nil
	default:
		return fmt.Errorf("tipo de clave no soportado")
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
