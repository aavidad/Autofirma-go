package main

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/signer"
	"encoding/base64"
	"fmt"
	"log"
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
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from localhost only
		return true
	},
}

type WebSocketServer struct {
	port     int
	conn     *websocket.Conn
	connMux  sync.Mutex
	ui       *UI
	stopChan chan struct{}
}

func NewWebSocketServer(port int, ui *UI) *WebSocketServer {
	return &WebSocketServer{
		port:     port,
		ui:       ui,
		stopChan: make(chan struct{}),
	}
}

func (s *WebSocketServer) Start() error {
	http.HandleFunc("/", s.handleWebSocket)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	log.Printf("[WebSocket] Starting HTTPS/WSS server on %s", addr)

	go func() {
		// Use TLS for WSS (WebSocket Secure) - required by AutoFirma
		certFile := "server.crt"
		keyFile := "server.key"

		if err := http.ListenAndServeTLS(addr, certFile, keyFile, nil); err != nil {
			log.Printf("[WebSocket] Server error: %v", err)
		}
	}()

	return nil
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

	log.Println("[WebSocket] Client connected")

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
			log.Printf("[WebSocket] Read error: %v", err)
			break
		}

		msg := string(message)
		log.Printf("[WebSocket] Received: %s", msg)

		// Handle echo requests
		if strings.HasPrefix(msg, EchoRequestPrefix) {
			log.Println("[WebSocket] Echo request, responding OK")
			if err := conn.WriteMessage(messageType, []byte(EchoOKResponse)); err != nil {
				log.Printf("[WebSocket] Write error: %v", err)
				break
			}
			continue
		}

		// Handle afirma:// protocol requests
		if strings.HasPrefix(msg, "afirma://") {
			log.Printf("[WebSocket] Processing afirma protocol request")
			result := s.processProtocolRequest(msg)

			// Send result back
			if err := conn.WriteMessage(messageType, []byte(result)); err != nil {
				log.Printf("[WebSocket] Write error: %v", err)
				break
			}
			log.Printf("[WebSocket] Sent result: %s", result)
		}
	}
}

func (s *WebSocketServer) processProtocolRequest(uriString string) string {
	// Parse protocol URI
	state, err := ParseProtocolURI(uriString)
	if err != nil {
		return s.formatError("ERROR_PARSING_URI", err.Error())
	}

	// Download file
	filePath, err := state.DownloadFile()
	if err != nil {
		return s.formatError("ERROR_DOWNLOAD", err.Error())
	}

	// Check if it's an AutoFirma XML request and extract data
	content, err := os.ReadFile(filePath)
	if err == nil && strings.HasPrefix(string(content), "<sign>") {
		actualData, format, err := parseAutoFirmaXML(content)
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
	certs, err := certstore.GetSystemCertificates()
	if err != nil || len(certs) == 0 {
		return s.formatError("ERROR_NO_CERTIFICATES", "No certificates available")
	}

	certID := certs[0].ID

	// Determine format
	format := strings.ToLower(state.SignFormat)
	if format == "" {
		format = "cades" // Default for WebSocket mode
	}

	// Sign
	dataB64 := base64.StdEncoding.EncodeToString(data)
	signatureB64, err := signer.SignData(dataB64, certID, "", format, nil)
	if err != nil {
		return s.formatError("ERROR_SIGNING", err.Error())
	}

	// Upload signature
	if err := state.UploadSignature(signatureB64, ""); err != nil {
		return s.formatError("ERROR_UPLOAD", err.Error())
	}

	// Return success
	return "OK"
}

func (s *WebSocketServer) formatError(code string, message string) string {
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
