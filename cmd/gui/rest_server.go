// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

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
	Page uint32  `json:"page"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	W    float64 `json:"w"`
	H    float64 `json:"h"`
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
	InputPath       string `json:"inputPath"`
	InputPathES     string `json:"rutaEntrada"`
	SignaturePath   string `json:"signaturePath"`
	SignaturePathES string `json:"rutaFirma"`
	OriginalPath    string `json:"originalPath"`
	OriginalPathES  string `json:"rutaOriginal"`
	Format          string `json:"format"`
	FormatES        string `json:"formato"`
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

func runRESTServer(addr string, token string, sessionTTL time.Duration, allowedFingerprintsCSV string) error {
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
	if token == "" && len(allowed) == 0 {
		return fmt.Errorf("debe configurar al menos --rest-token o --rest-cert-fingerprints")
	}
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
	// Service management
	mux.HandleFunc("/service/status", s.withAuth(s.handleServiceStatus))
	mux.HandleFunc("/service/install", s.withAuth(s.handleServiceInstall))
	mux.HandleFunc("/service/uninstall", s.withAuth(s.handleServiceUninstall))
	mux.HandleFunc("/service/start", s.withAuth(s.handleServiceStart))
	mux.HandleFunc("/service/stop", s.withAuth(s.handleServiceStop))

	log.Printf("[REST] Servidor API REST local activo en http://%s", addr)
	log.Printf("[REST] Endpoints: / /auth/challenge /auth/verify /health /certificates /sign /verify /diagnostics/report /security/domains /tls/clear-store /tls/trust-status /tls/install-trust /tls/generate-certs")
	if token != "" {
		log.Printf("[REST] Autenticación por token: habilitada")
	}
	if len(allowed) > 0 {
		log.Printf("[REST] Autenticación por certificado: habilitada (lista blanca huellas SHA-256=%d, ttl=%s)", len(allowed), sessionTTL.String())
	} else {
		log.Printf("[REST] Autenticación por certificado: habilitada (acepta cualquier certificado válido, ttl=%s)", sessionTTL.String())
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
	mux.HandleFunc("/health", s.withAuth(s.handleHealth))
	mux.HandleFunc("/certificates", s.withAuth(s.handleCertificates))
	mux.HandleFunc("/sign", s.withAuth(s.handleSign))
	mux.HandleFunc("/verify", s.withAuth(s.handleVerify))
	// Alias en castellano
	mux.HandleFunc("/salud", s.withAuth(s.handleHealth))
	mux.HandleFunc("/certificados", s.withAuth(s.handleCertificates))
	mux.HandleFunc("/firmar", s.withAuth(s.handleSign))
	mux.HandleFunc("/verificar", s.withAuth(s.handleVerify))

	log.Printf("[REST-IPC] Servidor API REST activo en socket Unix: %s", socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	os.Chmod(socketPath, 0666) // Permitir acceso al socket

	srv := &http.Server{
		Handler: mux,
	}
	return srv.Serve(l)
}

func (s *restServer) handleRootConsole(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, restError{OK: false, Error: "not found"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderRESTConsoleHTML()))
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
		opts["visibleSeal"] = true
		opts["visibleSealRectX"] = clamp01(req.VisibleSeal.X) * 595.28
		opts["visibleSealRectY"] = clamp01(req.VisibleSeal.Y) * 841.89
		opts["visibleSealRectW"] = clamp01(req.VisibleSeal.W) * 595.28
		opts["visibleSealRectH"] = clamp01(req.VisibleSeal.H) * 841.89
		page := req.VisibleSeal.Page
		if page == 0 {
			page = 1
		}
		opts["page"] = page
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

func renderRESTConsoleHTML() string {
	return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>AutoFirma REST Console</title>
<style>
:root { --bg:#f4f7fb; --fg:#1f2937; --muted:#6b7280; --card:#fff; --b:#d1d5db; --pri:#0b5fff; }
* { box-sizing: border-box; }
body { margin:0; font-family: "Segoe UI", Tahoma, sans-serif; background:var(--bg); color:var(--fg); }
.wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
h1 { margin: 0 0 8px; font-size: 22px; }
.muted { color: var(--muted); font-size: 13px; margin-bottom: 14px; }
.grid { display:grid; grid-template-columns: 1fr; gap: 12px; }
@media (min-width: 980px) { .grid { grid-template-columns: 1fr 1fr; } }
.card { background: var(--card); border:1px solid var(--b); border-radius: 10px; padding: 12px; }
.card h2 { margin: 0 0 10px; font-size: 16px; }
label { display:block; font-size: 12px; color: var(--muted); margin: 8px 0 3px; }
input, select, textarea, button { width:100%; padding: 8px 10px; border:1px solid var(--b); border-radius: 8px; font-size: 14px; }
textarea { min-height: 140px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
button { cursor:pointer; background: var(--pri); color:#fff; font-weight:600; border:none; margin-top: 10px; }
.row { display:grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
#out { min-height: 260px; white-space: pre-wrap; }
</style>
</head>
<body>
<div class="wrap">
  <h1>AutoFirma REST Console</h1>
  <div class="muted">API local en <span class="mono">127.0.0.1</span>. Puedes autenticarte con token o con certificado (reto firmado).</div>
  <div class="card">
    <label>Token de acceso activo (Bearer / X-API-Token)</label>
    <input id="token" type="password" placeholder="rest-token" />
  </div>
  <div class="grid">
    <div class="card">
      <h2>Login con certificado</h2>
      <div class="row">
        <button id="btnChallenge">GET /auth/challenge</button>
        <button id="btnVerifyAuth">POST /auth/verify</button>
      </div>
      <label>challengeId</label>
      <input id="authChallengeId" placeholder="id del reto" />
      <label>challengeB64</label>
      <input id="authChallengeB64" placeholder="texto a firmar (base64)" />
      <label>certificatePEM</label>
      <textarea id="authCertPem" placeholder="-----BEGIN CERTIFICATE----- ..."></textarea>
      <label>signatureB64 (firma SHA256 del challenge con clave privada del certificado)</label>
      <textarea id="authSigB64" placeholder="base64 de la firma"></textarea>
    </div>
    <div class="card">
      <h2>Estado y certificados</h2>
      <div class="row">
        <button id="btnHealth">GET /health</button>
        <button id="btnCerts">GET /certificates</button>
      </div>
      <label><input id="checkCerts" type="checkbox" style="width:auto"> check=true (probar capacidad de firma)</label>
    </div>
    <div class="card">
      <h2>Seguridad y diagnóstico</h2>
      <div class="row">
        <button id="btnDiagReport">GET /diagnostics/report</button>
        <button id="btnTLSClear">POST /tls/clear-store</button>
      </div>
      <div class="row">
        <button id="btnTLSStatus">GET /tls/trust-status</button>
        <button id="btnTLSGenerate">POST /tls/generate-certs</button>
      </div>
      <button id="btnTLSInstall">POST /tls/install-trust</button>
      <div class="row">
        <button id="btnDomainsGet">GET /security/domains</button>
        <button id="btnDomainAdd">POST /security/domains</button>
      </div>
      <button id="btnDomainDel">DELETE /security/domains</button>
      <label>domain</label>
      <input id="securityDomain" placeholder="firma.ejemplo.gob.es" />
    </div>
    <div class="card">
      <h2>Verificar</h2>
      <label>inputPath (PAdES típico)</label>
      <input id="verifyInputPath" placeholder="/ruta/firmado.pdf" />
      <label>signaturePath (CAdES/XAdES separado)</label>
      <input id="verifySigPath" placeholder="/ruta/firma.csig" />
      <label>originalPath (si aplica)</label>
      <input id="verifyOrigPath" placeholder="/ruta/original.bin" />
      <label>format</label>
      <select id="verifyFormat">
        <option value="">auto</option>
        <option value="pades">pades</option>
        <option value="cades">cades</option>
        <option value="xades">xades</option>
      </select>
      <button id="btnVerify">POST /verify</button>
    </div>
    <div class="card" style="grid-column: 1 / -1;">
      <h2>Firmar</h2>
      <div class="row">
        <div><label>inputPath</label><input id="signInputPath" placeholder="/ruta/entrada.pdf"/></div>
        <div><label>outputPath</label><input id="signOutputPath" placeholder="/ruta/salida.pdf"/></div>
      </div>
      <div class="row">
        <div><label>action</label><select id="signAction"><option>sign</option><option>cosign</option><option>countersign</option></select></div>
        <div><label>format</label><select id="signFormat"><option value="">auto</option><option>pades</option><option>cades</option><option>xades</option></select></div>
      </div>
      <div class="row">
        <div><label>certificateIndex</label><input id="signCertIndex" type="number" placeholder="0"/></div>
        <div><label>certificateId</label><input id="signCertID" placeholder="id exacto"/></div>
      </div>
      <div class="row">
        <div><label>certificateContains</label><input id="signCertContains" placeholder="texto parcial"/></div>
        <div><label>overwrite</label><select id="signOverwrite"><option>rename</option><option>fail</option><option>force</option></select></div>
      </div>
      <div class="row">
        <label><input id="signSave" type="checkbox" style="width:auto" checked> saveToDisk</label>
        <label><input id="signSigB64" type="checkbox" style="width:auto"> returnSignatureB64</label>
      </div>
      <div class="row">
        <label><input id="signStrict" type="checkbox" style="width:auto"> strictCompat</label>
        <label><input id="signAllowInvalid" type="checkbox" style="width:auto"> allowInvalidPDF</label>
      </div>
      <label><input id="signVisible" type="checkbox" style="width:auto"> visibleSeal (PAdES)</label>
      <div class="row">
        <div><label>seal page</label><input id="sealPage" type="number" value="1"></div>
        <div><label>seal x</label><input id="sealX" type="number" step="0.01" value="0.62"></div>
      </div>
      <div class="row">
        <div><label>seal y</label><input id="sealY" type="number" step="0.01" value="0.04"></div>
        <div><label>seal w</label><input id="sealW" type="number" step="0.01" value="0.34"></div>
      </div>
      <div class="row">
        <div><label>seal h</label><input id="sealH" type="number" step="0.01" value="0.12"></div>
      </div>
      <button id="btnSign">POST /sign</button>
    </div>
    <div class="card" style="grid-column: 1 / -1;">
      <h2>Salida</h2>
      <textarea id="out" readonly></textarea>
    </div>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
function out(obj) {
  const text = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  $('out').value = text;
}
async function call(path, method='GET', body=null, requireAuth=true) {
  const token = $('token').value.trim();
  const headers = {};
  if (requireAuth) {
    if (!token) { out('Falta token/sesión'); return; }
    headers['Authorization'] = 'Bearer ' + token;
  }
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const txt = await res.text();
  let payload = txt;
  try { payload = JSON.parse(txt); } catch {}
  out({ status: res.status, body: payload });
  return payload;
}
$('btnChallenge').onclick = async () => {
  const payload = await call('/auth/challenge', 'GET', null, false);
  if (!payload || !payload.challengeId) return;
  $('authChallengeId').value = payload.challengeId || '';
  $('authChallengeB64').value = payload.challengeB64 || '';
};
$('btnVerifyAuth').onclick = async () => {
  const body = {
    challengeId: $('authChallengeId').value.trim(),
    certificatePEM: $('authCertPem').value,
    signatureB64: $('authSigB64').value.trim()
  };
  const payload = await call('/auth/verify', 'POST', body, false);
  if (payload && payload.sessionToken) {
    $('token').value = payload.sessionToken;
  }
};
$('btnHealth').onclick = () => call('/health');
$('btnCerts').onclick = () => call('/certificates' + ($('checkCerts').checked ? '?check=1' : '?check=0'));
$('btnDiagReport').onclick = () => call('/diagnostics/report');
$('btnTLSClear').onclick = () => call('/tls/clear-store', 'POST', {});
$('btnTLSStatus').onclick = () => call('/tls/trust-status');
$('btnTLSGenerate').onclick = () => call('/tls/generate-certs', 'POST', {});
$('btnTLSInstall').onclick = () => call('/tls/install-trust', 'POST', {});
$('btnDomainsGet').onclick = () => call('/security/domains');
$('btnDomainAdd').onclick = () => {
  const domain = $('securityDomain').value.trim();
  call('/security/domains', 'POST', { domain });
};
$('btnDomainDel').onclick = () => {
  const domain = $('securityDomain').value.trim();
  call('/security/domains', 'DELETE', { domain });
};
$('btnVerify').onclick = () => {
  const body = {
    inputPath: $('verifyInputPath').value.trim(),
    signaturePath: $('verifySigPath').value.trim(),
    originalPath: $('verifyOrigPath').value.trim(),
    format: $('verifyFormat').value
  };
  call('/verify', 'POST', body);
};
$('btnSign').onclick = () => {
  const idxRaw = $('signCertIndex').value.trim();
  const body = {
    inputPath: $('signInputPath').value.trim(),
    outputPath: $('signOutputPath').value.trim(),
    certificateID: $('signCertID').value.trim(),
    certificateContains: $('signCertContains').value.trim(),
    action: $('signAction').value,
    format: $('signFormat').value,
    overwrite: $('signOverwrite').value,
    saveToDisk: $('signSave').checked,
    returnSignatureB64: $('signSigB64').checked,
    strictCompat: $('signStrict').checked,
    allowInvalidPDF: $('signAllowInvalid').checked
  };
  if (idxRaw !== '') body.certificateIndex = parseInt(idxRaw, 10);
  if ($('signVisible').checked) {
    body.visibleSeal = {
      page: parseInt($('sealPage').value || '1', 10),
      x: parseFloat($('sealX').value || '0.62'),
      y: parseFloat($('sealY').value || '0.04'),
      w: parseFloat($('sealW').value || '0.34'),
      h: parseFloat($('sealH').value || '0.12')
    };
  }
  call('/sign', 'POST', body);
};
</script>
</body>
</html>`
}
