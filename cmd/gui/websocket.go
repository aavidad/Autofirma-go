// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

const (
	DefaultWebSocketPort = 63117
	EchoRequestPrefix    = "echo="
	EchoOKResponse       = "OK"
	HeaderBatch1         = "afirma://batch?"
	HeaderBatch2         = "afirma://batch/?"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// AutoFirma Java server doesn't restrict origin, so we allow all
		return true
	},
}

var (
	getSystemCertificatesFunc            = certstore.GetSystemCertificates
	getSystemCertificatesWithOptionsFunc = certstore.GetSystemCertificatesWithOptions
	selectCertDialogFunc                 = protocolSelectCertDialog
	saveDialogFunc                       = protocolSaveDialog
	loadDialogFunc                       = protocolLoadDialog
	signDataFunc                         = signer.SignData
	coSignDataFunc                       = signer.CoSignData
	counterSignDataFunc                  = signer.CounterSignData
	signPKCS1Func                        = signer.SignPKCS1
	signPKCS1WithOptionsFunc             = signer.SignPKCS1WithOptions
)

type WebSocketServer struct {
	ports    []int
	session  string
	conn     *websocket.Conn
	connMux  sync.Mutex
	ui       *UI
	stopChan chan struct{}
	storeMux sync.Mutex
	store    map[string]string
	stickyID string

	serviceMux           sync.Mutex
	serviceListener      net.Listener
	serviceFragments     []string
	serviceResponseParts []string
	serviceProtocolVer   int
}

func NewWebSocketServer(ports []int, sessionID string, ui *UI) *WebSocketServer {
	return &WebSocketServer{
		ports:              ports,
		session:            strings.TrimSpace(sessionID),
		ui:                 ui,
		stopChan:           make(chan struct{}),
		store:              make(map[string]string),
		serviceProtocolVer: 1,
	}
}

func (s *WebSocketServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/afirma-signature-storage/StorageService", s.handleStorageService)
	mux.HandleFunc("/afirma-signature-retriever/RetrieveService", s.handleRetrieveService)
	// Compat paths used by some integraciones antiguas.
	mux.HandleFunc("/StorageService", s.handleStorageService)
	mux.HandleFunc("/RetrieveService", s.handleRetrieveService)

	var ln net.Listener
	var err error
	var port int

	// Try ports in order
	for _, p := range s.ports {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			port = p
			log.Printf("[WebSocket] Successfully bound to %s", addr)
			break
		}
		log.Printf("[WebSocket] Port %d not available: %v", p, err)
	}

	if ln == nil {
		return fmt.Errorf("failed to bind to any of the requested ports: %v", s.ports)
	}

	certFile, keyFile, err := ensureLocalTLSCerts()
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("failed to prepare local TLS certificates: %w", err)
	}

	go func() {
		// Setup HTTPS server
		srv := &http.Server{
			Handler: mux,
		}

		log.Printf("[WebSocket] Starting HTTPS/WSS server loop on port %d", port)
		if err := srv.ServeTLS(ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("[WebSocket] Server error: %v", err)
		}
	}()

	return nil
}

func (s *WebSocketServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	upgradeHdr := strings.ToLower(r.Header.Get("Upgrade"))
	connHdr := strings.ToLower(r.Header.Get("Connection"))
	if upgradeHdr == "websocket" && strings.Contains(connHdr, "upgrade") {
		s.handleWebSocket(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("AutoFirma local server running"))
}

func setCompatHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
}

func compatError(code, msg string) string {
	return code + ":=" + msg
}

func (s *WebSocketServer) handleStorageService(w http.ResponseWriter, r *http.Request) {
	setCompatHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := r.ParseForm(); err != nil {
		_, _ = w.Write([]byte(compatError("ERR-07", "Los datos solicitados o enviados son inválidos")))
		return
	}

	op := r.Form.Get("op")
	if op == "check" {
		_, _ = w.Write([]byte("OK"))
		return
	}
	if op == "" {
		_, _ = w.Write([]byte(compatError("ERR-00", "No se ha indicado código de operación")))
		return
	}
	if r.Form.Get("v") == "" {
		_, _ = w.Write([]byte(compatError("ERR-20", "No se ha indicado la versión de la sintaxis de la operación")))
		return
	}
	if op != "put" {
		_, _ = w.Write([]byte(compatError("ERR-01", "Código de operación no soportado")))
		return
	}

	id := r.Form.Get("id")
	if id == "" {
		_, _ = w.Write([]byte(compatError("ERR-05", "No se ha proporcionado un identificador para los datos")))
		return
	}
	data := r.Form.Get("dat")
	if data == "" {
		_, _ = w.Write([]byte(compatError("ERR-07", "Los datos solicitados o enviados son inválidos")))
		return
	}

	s.storeMux.Lock()
	s.store[id] = data
	s.storeMux.Unlock()
	_, _ = w.Write([]byte("OK"))
}

func (s *WebSocketServer) handleRetrieveService(w http.ResponseWriter, r *http.Request) {
	setCompatHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := r.ParseForm(); err != nil {
		_, _ = w.Write([]byte(compatError("ERR-07", "Los datos solicitados o enviados son inválidos")))
		return
	}

	op := r.Form.Get("op")
	if op == "check" {
		_, _ = w.Write([]byte("OK"))
		return
	}
	if op == "" {
		_, _ = w.Write([]byte(compatError("ERR-00", "No se ha indicado código de operación")))
		return
	}
	if r.Form.Get("v") == "" {
		_, _ = w.Write([]byte(compatError("ERR-20", "No se ha indicado la versión de la sintaxis de la operación")))
		return
	}
	if op != "get" {
		_, _ = w.Write([]byte(compatError("ERR-01", "Código de operación no soportado")))
		return
	}

	id := r.Form.Get("id")
	if id == "" {
		_, _ = w.Write([]byte(compatError("ERR-05", "No se ha proporcionado un identificador para los datos")))
		return
	}

	s.storeMux.Lock()
	data, ok := s.store[id]
	if ok {
		delete(s.store, id)
	}
	s.storeMux.Unlock()
	if !ok {
		_, _ = w.Write([]byte(compatError("ERR-06", "El identificador para los datos es inválido")))
		return
	}
	_, _ = w.Write([]byte(data))
}

func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRemoteAddr(r.RemoteAddr) {
		http.Error(w, "SAF_47: Peticion externa no permitida", http.StatusForbidden)
		log.Printf("[WebSocket] Rejected external remote addr: %s", r.RemoteAddr)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebSocket] Upgrade error: %v", err)
		return
	}

	s.connMux.Lock()
	s.conn = conn
	s.connMux.Unlock()

	log.Printf("[WebSocket] Client connected from %s", r.RemoteAddr)

	defer func() {
		conn.Close()
		s.connMux.Lock()
		s.conn = nil
		s.connMux.Unlock()
		log.Println("[WebSocket] Client disconnected")
	}()

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			errLower := strings.ToLower(err.Error())
			switch {
			case websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure):
				// Normal close path; no extra log noise.
			case websocket.IsCloseError(err, websocket.CloseAbnormalClosure) || strings.Contains(errLower, "unexpected eof"):
				log.Printf("[WebSocket] Client disconnected abruptly")
			default:
				log.Printf("[WebSocket] Read error: %v", err)
			}
			break
		}

		msg := string(message)
		// Don't log full echo message to keep logs clean, but log prefix
		if strings.HasPrefix(msg, EchoRequestPrefix) {
			// log.Printf("[WebSocket] Received echo: %s", msg)
		} else {
			log.Printf("[WebSocket] Received: %s", applog.SanitizeURI(msg))
		}

		if s.session != "" {
			msgSession := extractMessageSessionID(msg)
			if msgSession == "" || msgSession != s.session {
				_ = conn.WriteMessage(messageType, []byte("SAF_46: Id de sesion invalido"))
				log.Printf("[WebSocket] Invalid session id (expected=%s got=%s)", applog.MaskID(s.session), applog.MaskID(msgSession))
				continue
			}
		}

		// LOGIC FROM AfirmaWebSocketServer.java:
		// if (message.startsWith(ECHO_REQUEST_PREFIX)) { ... }
		// else { ... }

		if strings.HasPrefix(msg, EchoRequestPrefix) {
			// Respond with OK
			if err := conn.WriteMessage(messageType, []byte(EchoOKResponse)); err != nil {
				log.Printf("[WebSocket] Write error: %v", err)
				break
			}
			continue
		}

		// Handle normal operations (afirma://...)
		// Check for batch operations (AutoFirma sets timeout differently for these)
		isBatch := strings.HasPrefix(msg, HeaderBatch1) || strings.HasPrefix(msg, HeaderBatch2)
		if isBatch {
			log.Println("[WebSocket] Detected Batch Operation")
			// We effectively increase timeout by just continuing to process (we don't enforce strict timeouts here yet)
		}

		// In Java: broadcast(ProtocolInvocationLauncher.launch(message, protocolVersion, true), ...)
		// We implement that logic here:
		log.Printf("[WebSocket] Processing afirma protocol request: %s", applog.SanitizeURI(msg))
		result := s.processProtocolRequest(msg)

		// Send result back
		if err := conn.WriteMessage(messageType, []byte(result)); err != nil {
			log.Printf("[WebSocket] Write error: %v", err)
			break
		}
		upper := strings.ToUpper(result)
		log.Printf(
			"[WebSocket] Sent result len=%d protocol_error=%t",
			len(result),
			strings.HasPrefix(upper, "SAF_") || strings.HasPrefix(upper, "ERR-"),
		)
	}
}

func (s *WebSocketServer) processProtocolRequest(uriString string) string {
	// 1. Analyze URI and Download
	// Using our ProtocolState logic which mimics ProtocolInvocationLauncher

	// Basic check
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(uriString)), "afirma://") {
		return s.formatError("ERROR_INVALID_PROTOCOL", "")
	}
	// Java treats service/websocket launch independently from the standard sign URI parser.
	if u, perr := url.Parse(uriString); perr == nil {
		action := normalizeProtocolAction(extractProtocolAction(u))
		if action == "" {
			action = normalizeProtocolAction(getQueryParam(u.Query(), "op", "operation", "action"))
		}
		if action == "service" || action == "websocket" {
			state := &ProtocolState{
				IsActive:  true,
				SourceURL: uriString,
				Action:    action,
				Params:    u.Query(),
			}
			if action == "service" {
				return s.processServiceRequest(state)
			}
			return s.processWebSocketLaunchRequest(state)
		}
	}
	state, err := ParseProtocolURI(uriString)
	if err != nil {
		if errors.Is(err, errMinimumClientVersionNotSatisfied) {
			return s.formatError("ERROR_MINIMUM_VERSION_NOT_SATISFIED", err.Error())
		}
		if errors.Is(err, errUnsupportedProcedureVersion) {
			return s.formatError("ERROR_UNSUPPORTED_PROCEDURE", err.Error())
		}
		return s.formatError("ERROR_PARSING_URI", err.Error())
	}
	action := normalizeProtocolAction(state.Action)
	switch action {
	case "sign", "cosign", "countersign":
		// Supported path in current Go implementation (single interactive signing flow).
	case "selectcert":
		return s.processSelectCertRequest(state)
	case "save":
		return s.processSaveRequest(state)
	case "load":
		return s.processLoadRequest(state)
	case "signandsave":
		return s.processSignAndSaveRequest(state)
	case "batch":
		return s.processBatchRequest(state)
	case "service":
		return s.processServiceRequest(state)
	case "websocket":
		return s.processWebSocketLaunchRequest(state)
	default:
		return s.formatError("ERROR_UNSUPPORTED_OPERATION", "Codigo de operacion no soportado")
	}

	if s.ui == nil {
		return "SAF_09: Interfaz de firma no disponible"
	}

	// In Java: ProtocolInvocationLauncherSignAndSave.process(...)

	// Download file
	filePath, err := state.DownloadFile()
	if err != nil {
		return s.formatError("ERROR_DOWNLOAD", err.Error())
	}

	// Check if it's an AutoFirma XML request and extract data
	content, err := os.ReadFile(filePath)
	if err == nil && strings.HasPrefix(string(content), "<sign>") {
		actualData, format, err := parseAutoFirmaXML(content, state)
		if err != nil {
			return s.formatError("ERROR_PARSING_XML", err.Error())
		}

		// Save extracted data
		ext := ".bin"
		if format == "PAdES" {
			ext = ".pdf"
		} else if format == "XAdES" {
			ext = ".xml"
		}

		actualPath := strings.TrimSuffix(filePath, ".xml") + "_data" + ext
		if err := os.WriteFile(actualPath, actualData, 0644); err != nil {
			return s.formatError("ERROR_SAVING_DATA", err.Error())
		}

		filePath = actualPath
		state.SignFormat = format
	}

	// 4. Determine format
	format := normalizeProtocolFormat(state.SignFormat)
	if format == "" {
		format = "cades" // Default fallback
	}

	// 5. TRIGGER UI for user selection and signing
	s.ui.Protocol = state
	s.ui.InputFile.SetText(filePath)
	s.ui.StatusMsg = "Solicitud de firma recibida. Seleccione su certificado."
	s.ui.Window.Invalidate()

	// Wait for user to finish signing via UI
	log.Printf("[WebSocket] Waiting for user signature via UI...")
	s.ui.PendingWork.Add(1)
	defer s.ui.PendingWork.Done()
	sigResult := <-s.ui.SignatureDone
	log.Printf("[WebSocket] Signature received from UI.")

	sigBytes, _ := base64.StdEncoding.DecodeString(sigResult.SignatureB64)

	// Helper to encrypt/encode depending on 'key' param
	resp, err := s.buildResponse(sigResult.CertDER, sigBytes, state.Key, buildProtocolExtraInfo(state, filePath))
	if err != nil {
		return s.formatError("ERROR_BUILD_RESP", err.Error())
	}

	// Reset UI Status
	s.ui.StatusMsg = "¡Firma completada con éxito!"
	s.ui.Window.Invalidate()

	// Logging
	log.Printf("[WebSocket] Returning result (len=%d)", len(resp))

	return resp
}

func (s *WebSocketServer) processSelectCertRequest(state *ProtocolState) string {
	certs, err := loadCertificatesForState(state)
	if err != nil {
		return "SAF_08: Error accediendo al almacen de certificados"
	}
	certs, storeFilter := filterSelectCertByDefaultStore(certs, state)
	if len(certs) == 0 {
		return "SAF_19: No hay certificados disponibles"
	}

	resetSticky := parseBoolParam(getQueryParam(state.Params, "resetsticky", "resetSticky"))
	sticky := parseBoolParam(getQueryParam(state.Params, "sticky"))
	if resetSticky {
		s.stickyID = ""
		log.Printf("[WebSocket] selectcert resetsticky=true")
	}
	if sticky && s.stickyID != "" {
		if stickyIdx := findCertificateIndexByID(certs, s.stickyID); stickyIdx >= 0 {
			log.Printf("[WebSocket] selectcert sticky hit cert=%s", applog.MaskID(certs[stickyIdx].ID))
			resp, err := buildSelectCertResponse(certs[stickyIdx].Content, state.Key)
			if err != nil {
				return "SAF_12: Error preparando respuesta de certificado"
			}
			return resp
		}
		log.Printf("[WebSocket] selectcert sticky miss cert=%s", applog.MaskID(s.stickyID))
	}
	filtered, filterOpts := applySelectCertFilters(certs, state)
	log.Printf(
		"[WebSocket] selectcert candidates total=%d filtered=%d auto_selection=%t auto_single=%t sticky=%t allow_external_stores=%t store_filter=%s",
		len(certs),
		len(filtered),
		filterOpts.forceAutoSelection,
		filterOpts.autoSelectWhenSingle,
		sticky,
		filterOpts.allowExternalStores,
		storeFilter,
	)
	if len(filtered) == 0 {
		return "SAF_19: No hay certificados disponibles"
	}

	idx := findPreferredCertificateIndex(filtered)
	if idx < 0 {
		return "SAF_19: No hay certificados disponibles"
	}

	if s.ui != nil && !filterOpts.forceAutoSelection {
		if !(sticky && s.stickyID != "" && findCertificateIndexByID(certs, s.stickyID) >= 0) {
			// Java parity: mandatoryCertSelection=false omits the dialog only when
			// there is a single candidate after filtering.
			if !(filterOpts.autoSelectWhenSingle && len(filtered) == 1) {
				chosenIdx, canceled, selErr := selectCertDialogFunc(filtered)
				if canceled {
					return "CANCEL"
				}
				if selErr != nil {
					log.Printf("[WebSocket] selectcert dialog error: %v", selErr)
					return "SAF_08: Error accediendo al almacen de certificados"
				}
				if chosenIdx < 0 || chosenIdx >= len(filtered) || len(filtered[chosenIdx].Content) == 0 {
					return "SAF_19: No hay certificados disponibles"
				}
				idx = chosenIdx
			}
		}
	}
	if sticky && idx >= 0 && idx < len(filtered) {
		s.stickyID = filtered[idx].ID
		log.Printf("[WebSocket] selectcert sticky set cert=%s", applog.MaskID(s.stickyID))
	}

	resp, err := buildSelectCertResponse(filtered[idx].Content, state.Key)
	if err != nil {
		return "SAF_12: Error preparando respuesta de certificado"
	}
	return resp
}

func loadCertificatesForState(state *ProtocolState) ([]protocol.Certificate, error) {
	storePref := resolveDefaultKeyStorePreference(state)
	moduleHints := resolvePKCS11ModuleHints(state)
	includePKCS11 := shouldIncludePKCS11ForStore(storePref)
	if includePKCS11 && shouldDisableExternalStoresInState(state) && storePref != "PKCS11" {
		includePKCS11 = false
		log.Printf("[SelectCert] PKCS11 scan disabled by disableopeningexternalstores")
	}
	if len(moduleHints) == 0 && includePKCS11 {
		return getSystemCertificatesFunc()
	}
	if len(moduleHints) > 0 {
		log.Printf("[SelectCert] PKCS11 module hints requested (%d): %s", len(moduleHints), summarizeModuleHints(moduleHints))
	}
	if !includePKCS11 {
		log.Printf("[SelectCert] PKCS11 scan skipped by defaultKeyStore=%s", storePref)
	}
	certs, err := getSystemCertificatesWithOptionsFunc(certstore.Options{
		PKCS11ModulePaths: moduleHints,
		IncludePKCS11:     includePKCS11,
	})
	if err == nil {
		if len(moduleHints) > 0 && storePref == "PKCS11" && !hasPKCS11Certificates(certs) {
			log.Printf("[SelectCert] no PKCS11 certificates found using hints, retrying with default PKCS11 discovery")
			return getSystemCertificatesFunc()
		}
		log.Printf("[SelectCert] options loader returned %d certificates", len(certs))
		return certs, nil
	}
	log.Printf("[SelectCert] defaultKeyStoreLib hints failed, fallback to default loader: %v", err)
	return getSystemCertificatesFunc()
}

func resolvePKCS11ModuleHints(state *ProtocolState) []string {
	if state == nil {
		return nil
	}
	store := resolveDefaultKeyStorePreference(state)
	if store != "PKCS11" {
		return nil
	}
	raw := strings.TrimSpace(getQueryParam(state.Params,
		"defaultkeystorelib", "defaultKeyStoreLib", "keystorelib", "keyStoreLib"))
	if raw == "" {
		return nil
	}
	return splitStoreLibHints(raw)
}

func resolveDefaultKeyStorePreference(state *ProtocolState) string {
	if state == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(getQueryParam(state.Params,
		"defaultkeystore", "defaultKeyStore", "keystore", "keyStore")))
}

func shouldIncludePKCS11ForStore(store string) bool {
	store = strings.ToUpper(strings.TrimSpace(store))
	switch store {
	case "":
		return true
	case "PKCS11":
		return true
	case "MOZ_UNI", "SHARED_NSS", "MOZILLA", "WINDOWS", "WINADDRESSBOOK", "APPLE", "MACOS", "KEYCHAIN":
		return false
	default:
		return true
	}
}

func shouldDisableExternalStoresInState(state *ProtocolState) bool {
	if state == nil {
		return false
	}
	rawProps := getQueryParam(state.Params, "properties")
	props := decodeProtocolProperties(rawProps)
	groups := extractFilterGroups(props)
	return containsDisableOpeningExternalStoresFilter(groups)
}

func splitStoreLibHints(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' })
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func summarizeModuleHints(hints []string) string {
	if len(hints) == 0 {
		return "none"
	}
	max := len(hints)
	if max > 3 {
		max = 3
	}
	out := make([]string, 0, max+1)
	for i := 0; i < max; i++ {
		base := strings.TrimSpace(filepath.Base(hints[i]))
		if base == "" || base == "." || base == string(filepath.Separator) {
			base = "<unknown>"
		}
		out = append(out, base)
	}
	if len(hints) > max {
		out = append(out, fmt.Sprintf("+%d more", len(hints)-max))
	}
	return strings.Join(out, ",")
}

func hasPKCS11Certificates(certs []protocol.Certificate) bool {
	for _, c := range certs {
		src := strings.ToLower(strings.TrimSpace(c.Source))
		if src == "smartcard" || src == "dnie" {
			return true
		}
	}
	return false
}

func filterSelectCertByDefaultStore(certs []protocol.Certificate, state *ProtocolState) ([]protocol.Certificate, string) {
	if len(certs) == 0 || state == nil {
		return certs, "none"
	}
	store := resolveDefaultKeyStorePreference(state)
	if store == "" {
		return certs, "none"
	}

	// Best-effort compatibility: apply only when mapping is explicit.
	// Unknown values keep previous behavior (no filtering).
	switch store {
	case "PKCS11":
		filtered := make([]protocol.Certificate, 0, len(certs))
		for _, c := range certs {
			src := strings.ToLower(strings.TrimSpace(c.Source))
			if src == "smartcard" || src == "dnie" {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			return filtered, "pkcs11"
		}
		return certs, "pkcs11-empty-fallback"
	case "MOZ_UNI", "SHARED_NSS", "MOZILLA":
		filtered := make([]protocol.Certificate, 0, len(certs))
		for _, c := range certs {
			src := strings.ToLower(strings.TrimSpace(c.Source))
			if src == "system" {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			return filtered, "nss"
		}
		return certs, "nss-empty-fallback"
	case "WINDOWS", "WINADDRESSBOOK":
		filtered := make([]protocol.Certificate, 0, len(certs))
		for _, c := range certs {
			src := strings.ToLower(strings.TrimSpace(c.Source))
			if src == "windows" {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			return filtered, "windows"
		}
		return certs, "windows-empty-fallback"
	case "APPLE", "MACOS", "KEYCHAIN":
		filtered := make([]protocol.Certificate, 0, len(certs))
		for _, c := range certs {
			src := strings.ToLower(strings.TrimSpace(c.Source))
			if src == "system" {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			return filtered, "keychain"
		}
		return certs, "keychain-empty-fallback"
	default:
		return certs, "unknown-fallback"
	}
}

func buildSelectCertResponse(certDER []byte, key string) (string, error) {
	if len(certDER) == 0 {
		return "", fmt.Errorf("empty certificate")
	}
	if strings.TrimSpace(key) == "" {
		return base64.URLEncoding.EncodeToString(certDER), nil
	}
	return AutoFirmaEncryptAndFormat(certDER, []byte(key))
}

func (s *WebSocketServer) processSaveRequest(state *ProtocolState) string {
	raw := getQueryParam(state.Params, "dat", "data")
	if raw == "" {
		return "SAF_05: No se han proporcionado datos para guardar"
	}

	data, err := decodeAutoFirmaB64(raw)
	if err != nil {
		return "SAF_03: Datos de guardado invalidos"
	}

	targetPath, err := buildSaveTargetPath(
		getQueryParam(state.Params, "filename", "fileName"),
		getQueryParam(state.Params, "exts", "extensions"),
	)
	if err != nil {
		return "SAF_05: No se pudo determinar ruta de guardado"
	}
	if s.ui != nil {
		selectedPath, canceled, selErr := saveDialogFunc(targetPath, getQueryParam(state.Params, "exts", "extensions"))
		if canceled {
			return "CANCEL"
		}
		if selErr != nil {
			log.Printf("[WebSocket] save dialog error: %v", selErr)
			return "SAF_05: No se pudo guardar el fichero"
		}
		if strings.TrimSpace(selectedPath) != "" {
			targetPath = strings.TrimSpace(selectedPath)
		}
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "SAF_05: No se pudo crear carpeta de destino"
	}
	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return "SAF_05: No se pudo guardar el fichero"
	}

	log.Printf("[WebSocket] save completed file=%s bytes=%d", targetPath, len(data))
	return "SAVE_OK"
}

func decodeAutoFirmaB64(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty")
	}
	// Legacy web invocations may arrive with '+' converted to space after query parsing.
	normalized := strings.ReplaceAll(v, " ", "+")
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		out, err := enc.DecodeString(normalized)
		if err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func buildSaveTargetPath(filename string, exts string) (string, error) {
	filename = strings.TrimSpace(filename)
	exts = strings.TrimSpace(exts)
	if filename == "" {
		filename = "autofirma_guardado"
	}
	filename = filepath.Base(filename)
	filename = strings.ReplaceAll(filename, "..", "_")
	if filename == "." || filename == "" || filename == "/" {
		filename = "autofirma_guardado"
	}

	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(filename)))
	if ext == "" && exts != "" {
		parts := strings.Split(exts, ",")
		if len(parts) > 0 {
			cand := strings.TrimSpace(parts[0])
			cand = strings.TrimPrefix(cand, ".")
			if cand != "" {
				ext = "." + cand
			}
		}
	}
	if ext == "" {
		ext = ".bin"
	}
	if filepath.Ext(filename) == "" {
		filename += ext
	}

	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("home not available")
	}
	return filepath.Join(home, "Descargas", filename), nil
}

func (s *WebSocketServer) processLoadRequest(state *ProtocolState) string {
	filePathRaw := getQueryParam(state.Params, "filePath", "filepath", "file", "fileName")

	var paths []string
	if s.ui != nil {
		multiload := parseBoolParam(
			getQueryParam(state.Params, "multiload", "multiLoad", "multiple", "multi"),
		)
		loadedPaths, canceled, loadErr := loadDialogFunc(filePathRaw, getQueryParam(state.Params, "exts", "extensions"), multiload)
		if canceled {
			return "CANCEL"
		}
		if loadErr != nil {
			log.Printf("[WebSocket] load dialog error: %v", loadErr)
			return "SAF_25: No se pudo cargar el fichero"
		}
		paths = loadedPaths
	} else {
		paths = splitLoadPaths(filePathRaw)
	}

	if len(paths) == 0 {
		return "SAF_25: No se ha indicado la ruta del fichero"
	}

	items := make([]string, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return "SAF_25: No se pudo cargar el fichero"
		}
		name := filepath.Base(p)
		b64 := base64.URLEncoding.EncodeToString(data)
		items = append(items, name+":"+b64)
	}
	return strings.Join(items, "|")
}

func findPreferredCertificateIndex(certs []protocol.Certificate) int {
	for i := range certs {
		if certs[i].CanSign && len(certs[i].Content) > 0 {
			return i
		}
	}
	for i := range certs {
		if len(certs[i].Content) > 0 {
			return i
		}
	}
	return -1
}

func findCertificateIndexByID(certs []protocol.Certificate, id string) int {
	id = strings.TrimSpace(id)
	if id == "" {
		return -1
	}
	for i := range certs {
		if certs[i].ID == id && len(certs[i].Content) > 0 {
			return i
		}
	}
	return -1
}

func parseBoolParam(values ...string) bool {
	for _, v := range values {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "si":
			return true
		}
	}
	return false
}

func splitLoadPaths(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *WebSocketServer) processSignAndSaveRequest(state *ProtocolState) string {
	raw := getQueryParam(state.Params, "dat", "data")
	if raw == "" {
		return "SAF_44: Operacion de firma sin datos"
	}
	data, err := decodeAutoFirmaB64(raw)
	if err != nil {
		return "SAF_30: Datos de firma invalidos"
	}
	if s.ui == nil {
		return "SAF_09: Interfaz de firma no disponible"
	}

	format := getQueryParam(state.Params, "format", "signFormat")
	if format == "" {
		format = "CAdES"
	}
	format = normalizeProtocolFormat(format)
	tmpExt := ".bin"
	switch format {
	case "pades":
		tmpExt = ".pdf"
	case "xades":
		tmpExt = ".xml"
	case "cades":
		tmpExt = ".csig"
	}
	tmpFile, err := os.CreateTemp("", "autofirma-signandsave-*"+tmpExt)
	if err != nil {
		return "SAF_05: No se pudo preparar el fichero temporal"
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return "SAF_05: No se pudo preparar el fichero temporal"
	}

	s.ui.Protocol = &ProtocolState{
		IsActive:   true,
		Action:     "signandsave",
		Params:     state.Params,
		SignFormat: format,
	}
	s.ui.InputFile.SetText(tmpPath)
	s.ui.StatusMsg = "Solicitud de firma y guardado recibida. Seleccione su certificado."
	s.ui.Window.Invalidate()

	log.Printf("[WebSocket] Waiting for user signature (signandsave) via UI...")
	s.ui.PendingWork.Add(1)
	defer s.ui.PendingWork.Done()
	sigResult := <-s.ui.SignatureDone
	log.Printf("[WebSocket] Signature received from UI (signandsave).")

	sigBytes, err := base64.StdEncoding.DecodeString(sigResult.SignatureB64)
	if err != nil {
		return "SAF_09: Error al procesar la firma generada"
	}

	targetPath, err := buildSaveTargetPath(getQueryParam(state.Params, "filename", "fileName"), "")
	if err != nil {
		return "SAF_05: No se pudo determinar ruta de guardado"
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "SAF_05: No se pudo crear carpeta de destino"
	}
	if err := os.WriteFile(targetPath, sigBytes, 0o644); err != nil {
		return "SAF_05: No se pudo guardar el fichero firmado"
	}

	log.Printf("[WebSocket] signandsave completed file=%s bytes=%d", targetPath, len(sigBytes))
	return "SAVE_OK"
}

func buildProtocolExtraInfo(state *ProtocolState, filePath string) []byte {
	if state == nil || state.ProtocolVersion < 3 {
		return nil
	}
	name := strings.TrimSpace(filepath.Base(filePath))
	if name == "" || name == "." || name == "/" {
		return nil
	}
	raw, err := json.Marshal(map[string]string{"filename": name})
	if err != nil {
		return nil
	}
	return raw
}

func (s *WebSocketServer) buildResponse(certDER []byte, sigBytes []byte, key string, extraInfo []byte) (string, error) {
	// If key is present, encrypt.
	if key != "" {
		// We need to encrypt.
		// See protocol.go for decryptDES. We need the inverse.
		// Since we can't easily import "encryptDES" from protocol.go (it's in main package, this is too),
		// we should ensure we have access or duplicate/move logic.
		// For now, let's try to reuse or implement locally.

		// Move encrypt/decrypt to a utility if possible, but for this edit:
		keyBytes := []byte(key)
		cCert, err := AutoFirmaEncryptAndFormat(certDER, keyBytes)
		if err != nil {
			return "", err
		}
		cSig, err := AutoFirmaEncryptAndFormat(sigBytes, keyBytes)
		if err != nil {
			return "", err
		}
		if len(extraInfo) == 0 {
			return cCert + "|" + cSig, nil
		}
		cExtra, err := AutoFirmaEncryptAndFormat(extraInfo, keyBytes)
		if err != nil {
			return "", err
		}
		return cCert + "|" + cSig + "|" + cExtra, nil
	}
	// No key -> Plain URL Safe Base64 (Standard Java AutoFirma behavior)
	out := base64.URLEncoding.EncodeToString(certDER) + "|" + base64.URLEncoding.EncodeToString(sigBytes)
	if len(extraInfo) == 0 {
		return out, nil
	}
	return out + "|" + base64.URLEncoding.EncodeToString(extraInfo), nil
}

func (s *WebSocketServer) formatError(code string, message string) string {
	// WebSocket protocol errors follow Java SAF_* family.
	errCode := "SAF_03"
	defaultMsg := "Parametros incorrectos"
	switch code {
	case "ERROR_INVALID_PROTOCOL":
		errCode = "SAF_02"
		defaultMsg = "Protocolo no soportado"
	case "ERROR_PARSING_URI":
		errCode = "SAF_03"
		defaultMsg = "Parametros incorrectos"
	case "ERROR_DOWNLOAD":
		errCode = "SAF_16"
		defaultMsg = "Error recuperando los datos"
	case "ERROR_PARSING_XML":
		errCode = "SAF_03"
		defaultMsg = "Parametros incorrectos"
	case "ERROR_SAVING_DATA":
		errCode = "SAF_05"
		defaultMsg = "Error guardando los datos"
	case "ERROR_BUILD_RESP":
		errCode = "SAF_12"
		defaultMsg = "Error preparando la respuesta"
	case "ERROR_UNSUPPORTED_OPERATION":
		errCode = "SAF_04"
		defaultMsg = "Codigo de operacion no soportado"
	case "ERROR_SIGNATURE_FAILED":
		errCode = "SAF_09"
		defaultMsg = "Error en la operacion de firma"
	case "ERROR_CANNOT_ACCESS_KEYSTORE":
		errCode = "SAF_08"
		defaultMsg = "Error accediendo al almacen de certificados"
	case "ERROR_NO_CERTIFICATES_SYSTEM":
		errCode = "SAF_10"
		defaultMsg = "No hay certificados disponibles"
	case "ERROR_NO_CERTIFICATES_KEYSTORE":
		errCode = "SAF_19"
		defaultMsg = "No hay certificados disponibles"
	case "ERROR_LOCAL_BATCH_SIGN":
		errCode = "SAF_20"
		defaultMsg = "Error en firma local de lote"
	case "ERROR_CONTACT_BATCH_SERVICE":
		errCode = "SAF_26"
		defaultMsg = "Error contactando servicio de lote"
	case "ERROR_BATCH_SIGNATURE":
		errCode = "SAF_27"
		defaultMsg = "Error en firma de lote"
	case "ERROR_UNSUPPORTED_PROCEDURE":
		errCode = "SAF_21"
		defaultMsg = "Version de protocolo no soportada"
	case "ERROR_MINIMUM_VERSION_NOT_SATISFIED":
		errCode = "SAF_41"
		defaultMsg = "Se requiere una version mas reciente de la aplicacion"
	case "ERROR_CANNOT_OPEN_SOCKET":
		errCode = "SAF_45"
		defaultMsg = "No se pudo abrir el socket"
	case "ERROR_INVALID_SESSION_ID":
		errCode = "SAF_46"
		defaultMsg = "Id de sesion invalido"
	case "ERROR_EXTERNAL_REQUEST_TO_SOCKET":
		errCode = "SAF_47"
		defaultMsg = "Peticion externa no permitida"
	}
	if strings.TrimSpace(message) == "" {
		message = defaultMsg
	}
	return errCode + ": " + message
}

func (s *WebSocketServer) Stop() {
	close(s.stopChan)
	s.connMux.Lock()
	if s.conn != nil {
		s.conn.Close()
	}
	s.connMux.Unlock()
	s.serviceMux.Lock()
	if s.serviceListener != nil {
		_ = s.serviceListener.Close()
		s.serviceListener = nil
	}
	s.serviceMux.Unlock()
}

func extractMessageSessionID(message string) string {
	lower := strings.ToLower(message)
	idx := strings.Index(lower, "idsession=")
	if idx < 0 {
		return ""
	}
	start := idx + len("idsession=")
	end := strings.Index(message[start:], "&")
	if end < 0 {
		id := message[start:]
		id = strings.TrimSuffix(id, "@EOF")
		return strings.TrimSpace(id)
	}
	return strings.TrimSpace(message[start : start+end])
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseProtocolVersion(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 4
	}
	return n
}
