// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/signer"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
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

type WebSocketServer struct {
	ports    []int
	conn     *websocket.Conn
	connMux  sync.Mutex
	ui       *UI
	stopChan chan struct{}
	storeMux sync.Mutex
	store    map[string]string
}

func NewWebSocketServer(ports []int, ui *UI) *WebSocketServer {
	return &WebSocketServer{
		ports:    ports,
		ui:       ui,
		stopChan: make(chan struct{}),
		store:    make(map[string]string),
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

	go func() {
		// Use TLS for WSS
		certFile := "server.crt"
		keyFile := "server.key"

		// Load keys for TLS config to use with Serve
		// We use http.ServeTLS on the listener
		// Note: http.Serve(ln) is for plaintext. We need ServeTLS with files or config.
		// Since we have files, we can use a server with TLSConfig.

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
			// Normal closure or error
			if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[WebSocket] Read error: %v", err)
			}
			break
		}

		msg := string(message)
		// Don't log full echo message to keep logs clean, but log prefix
		if strings.HasPrefix(msg, EchoRequestPrefix) {
			// log.Printf("[WebSocket] Received echo: %s", msg)
		} else {
			log.Printf("[WebSocket] Received: %s", msg)
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
		log.Printf("[WebSocket] Processing afirma protocol request: %s", msg)
		result := s.processProtocolRequest(msg)

		// Send result back
		if err := conn.WriteMessage(messageType, []byte(result)); err != nil {
			log.Printf("[WebSocket] Write error: %v", err)
			break
		}
		log.Printf("[WebSocket] Sent result: %s", result)
	}
}

func (s *WebSocketServer) processProtocolRequest(uriString string) string {
	// 1. Analyze URI and Download
	// Using our ProtocolState logic which mimics ProtocolInvocationLauncher

	// Basic check
	if !strings.HasPrefix(uriString, "afirma://") {
		return s.formatError("ERROR_INVALID_PROTOCOL", "URI must start with afirma://")
	}

	state, err := ParseProtocolURI(uriString)
	if err != nil {
		return s.formatError("ERROR_PARSING_URI", err.Error())
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

	// Read file to sign
	data, err := os.ReadFile(filePath)
	if err != nil {
		return s.formatError("ERROR_READING_FILE", err.Error())
	}

	// Get certificate (use first available for WebSocket mode)
	// AutoFirma Java uses a UI selection dialog or defaults if pre-selected.
	// We default to first system cert for now.
	certs, err := certstore.GetSystemCertificates()
	if err != nil || len(certs) == 0 {
		return s.formatError("ERROR_NO_CERTIFICATES", "No certificates available")
	}

	certID := certs[0].ID

	// Determine format
	format := strings.ToLower(state.SignFormat)
	if format == "" {
		format = "cades" // Default fallback
	}

	// Sign
	dataB64 := base64.StdEncoding.EncodeToString(data)

	// Extract signature options if provided (for PDF)
	var signatureOptions map[string]interface{}

	signatureB64, err := signer.SignData(dataB64, certID, "", format, signatureOptions)
	if err != nil {
		return s.formatError("ERROR_SIGNING", err.Error())
	}

	// Decode signature back to bytes to handle flexible formatting if needed,
	// but signer.SignData returns Base64.
	// We need raw bytes for formatting if we were to re-encode or encrypt.
	// But formatResponse takes bytes.
	sigBytes, _ := base64.StdEncoding.DecodeString(signatureB64)

	// Get the cert raw bytes (DER)
	// We need to fetch the cert again by ID or keep it from before.
	// Use the certificate object we already have
	certObj := certs[0]

	// Helper to encrypt/encode
	resp, err := s.buildResponse(certObj.Content, sigBytes, state.Key)
	if err != nil {
		return s.formatError("ERROR_BUILD_RESP", err.Error())
	}

	// Logging
	log.Printf("[WebSocket] Returning format: Cert|Signature (len=%d)", len(resp))

	return resp
}

func (s *WebSocketServer) buildResponse(certDER []byte, sigBytes []byte, key string) (string, error) {
	// If key is present, encrypt.
	if key != "" {
		// We need to encrypt.
		// See protocol.go for decryptDES. We need the inverse.
		// Since we can't easily import "encryptDES" from protocol.go (it's in main package, this is too),
		// we should ensure we have access or duplicate/move logic.
		// For now, let's try to reuse or implement locally.

		// Move encrypt/decrypt to a utility if possible, but for this edit:
		cCert, err := encryptDES(certDER, []byte(key))
		if err != nil {
			return "", err
		}

		cSig, err := encryptDES(sigBytes, []byte(key))
		if err != nil {
			return "", err
		}

		// Return Base64 of Encrypted
		// Java: this.cipher.cipher(data) -> returns Base64 string of encrypted data
		// Our encryptDES returns bytes? Java's CipherData.cipher returns String (Base64).
		// So:
		return base64.StdEncoding.EncodeToString(cCert) + "|" + base64.StdEncoding.EncodeToString(cSig), nil
	}

	// No key -> Plain Base64
	return base64.StdEncoding.EncodeToString(certDER) + "|" + base64.StdEncoding.EncodeToString(sigBytes), nil
}

func (s *WebSocketServer) formatError(code string, message string) string {
	// AutoFirma returns error messages often URL encoded or plain depending on context.
	// But mostly "ERR-" prefix is what autoscript.js looks for in some versions,
	// or simple strings.
	// The autoscript.js we read handles "SAF_" as error prefix too.
	// But "ERR-" is a safe bet standard.
	return fmt.Sprintf("ERR-%s: %s", code, message)
}

func (s *WebSocketServer) Stop() {
	close(s.stopChan)
	s.connMux.Lock()
	if s.conn != nil {
		s.conn.Close()
	}
	s.connMux.Unlock()
}
