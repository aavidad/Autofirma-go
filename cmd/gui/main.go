// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"fmt"
	"flag"
	"log"
	"net/url"
	"os"
	"strings"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"
)

var (
	serverModeFlag    = flag.Bool("server", false, "Run as WebSocket server on port 63117")
	generateCertsFlag = flag.Bool("generate-certs", false, "Generate local TLS certificates and exit")
	installTrustFlag  = flag.Bool("install-trust", false, "Install local Root CA into trust stores (Linux/Windows)")
	trustStatusFlag   = flag.Bool("trust-status", false, "Print trust status of local Root CA (Linux/Windows)")
)

func main() {
	// Parse command-line flags
	flag.Parse()

	// Setup logging
	logPath, err := applog.Init("autofirma-desktop")
	if err != nil {
		log.Printf("No se pudo inicializar logging persistente: %v", err)
	} else {
		log.Printf("Logging inicializado en: %s", logPath)
	}

	log.Printf("Launched with args: %v", os.Args)

	if *generateCertsFlag {
		certFile, keyFile, err := ensureLocalTLSCerts()
		if err != nil {
			log.Printf("Error generando certificados locales: %v", err)
			os.Exit(1)
		}
		log.Printf("Certificados locales listos: cert=%s key=%s", certFile, keyFile)
		return
	}

	if *installTrustFlag {
		if _, _, err := ensureLocalTLSCerts(); err != nil {
			log.Printf("No se pudieron preparar certificados locales: %v", err)
			os.Exit(1)
		}
		lines, err := installLocalTLSTrust()
		for _, line := range lines {
			log.Printf("%s", line)
		}
		if err != nil {
			log.Printf("Fallo instalando confianza TLS local: %v", err)
			os.Exit(1)
		}
		return
	}

	if *trustStatusFlag {
		lines, err := localTLSTrustStatus()
		for _, line := range lines {
			log.Printf("%s", line)
		}
		if err != nil {
			log.Printf("Fallo comprobando confianza TLS local: %v", err)
			os.Exit(1)
		}
		return
	}

	// WebSocket Server Mode
	if *serverModeFlag {
		log.Println("Starting in WebSocket server mode")
		runWebSocketServer()
		return
	}

	// Direct Protocol Handler Mode (existing behavior)
	go func() {
		w := new(app.Window)
		w.Option(app.Title("AutoFirma - Diputación de Granada"), app.Size(unit.Dp(800), unit.Dp(600)))

		// Create UI here to control lifecycle
		ui := NewUI(w)

		if err := loop(w, ui); err != nil {
			log.Fatal(err)
		}

		// Wait for any background work (like uploads) to finish
		log.Println("[Main] Window closed. Waiting for background tasks...")
		ui.PendingWork.Wait()
		log.Println("[Main] Background tasks done. Exiting.")

		os.Exit(0)
	}()
	app.Main()
}

func runWebSocketServer() {
	// Create a hidden window for the UI (needed for certificate selection)
	w := new(app.Window)
	w.Option(
		app.Title("AutoFirma Server"),
		app.Size(unit.Dp(1), unit.Dp(1)), // Minimal size
	)

	ui := NewUI(w)
	ui.IsServerMode = true

	// Start WebSocket server
	server := NewWebSocketServer([]int{DefaultWebSocketPort}, "", ui)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start WebSocket server: %v", err)
	}

	log.Printf("WebSocket server running on port %d", DefaultWebSocketPort)

	// Run UI loop (needed for certificate dialogs)
	go func() {
		if err := loop(w, ui); err != nil {
			log.Fatal(err)
		}
	}()

	app.Main()
}

func loop(w *app.Window, ui *UI) error {
	var ops op.Ops
	// UI passed in now

	// Check for protocol argument
	if len(os.Args) > 1 {
		arg := os.Args[1]
		// Clean quotes if present
		arg = strings.Trim(arg, "\"'")

		if strings.Contains(strings.ToLower(arg), "afirma://") {
			log.Printf("Protocol detected in arg: %s", arg)

			// Detect websocket launch using robust URI parser.
			if _, wsErr := parseWebSocketLaunchURI(arg); wsErr == nil {
				log.Println("Detected 'afirma://websocket' launch request.")
				handleWebSocketLaunch(arg, ui)
				// Do NOT exit, keep running to serve
			} else {
				// Defer slightly to ensure window is ready? Not strictly needed for logic state.
				ui.HandleProtocolInit(arg)
			}
		} else {
			if !strings.HasPrefix(arg, "-") {
				log.Printf("Arg present but no protocol detected: %s", arg)
			}
		}
	}

	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			// Check if we should close the window (e.g. after silent sign click)
			// But do NOT close if we are in server mode
			if ui.ShouldClose && !ui.IsServerMode && !*serverModeFlag {
				log.Println("[Loop] ShouldClose flag set and not in ServerMode. Closing window.")
				return nil
			}

			gtx := app.NewContext(&ops, e)
			ui.Layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
	return nil
}

func handleWebSocketLaunch(uriString string, ui *UI) {
	log.Printf("[Launcher] Handling WebSocket launch request. Raw URI: %s", uriString)
	req, err := parseWebSocketLaunchURI(uriString)
	if err != nil {
		log.Printf("[Launcher] Invalid websocket launch URI: %v", err)
		return
	}

	log.Printf("[Launcher] Starting WebSocket server on one of requested ports: %v (v=%d session=%s)", req.Ports, req.Version, maskSessionForLog(req.SessionID))

	// Start server (async)
	server := NewWebSocketServer(req.Ports, req.SessionID, ui)
	if err := server.Start(); err != nil {
		log.Printf("[Launcher] Failed to start WebSocket server via launch: %v", err)
	} else {
		log.Printf("[Launcher] WebSocket server launched successfully via protocol request")
		// Enter minimalist mode
		ui.IsServerMode = true
		ui.Protocol = &ProtocolState{IsActive: true, Action: "websocket"}
		ui.StatusMsg = "Servidor AutoFirma activo. Esperando solicitudes del navegador..."
		ui.Window.Invalidate()
	}
}

type websocketLaunchRequest struct {
	Ports     []int
	SessionID string
	Version   int
}

func parseWebSocketLaunchURI(uriString string) (*websocketLaunchRequest, error) {
	u, err := url.Parse(strings.TrimSpace(uriString))
	if err != nil {
		return nil, fmt.Errorf("uri invalida: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "afirma") {
		return nil, fmt.Errorf("esquema no soportado")
	}
	action := normalizeProtocolAction(extractProtocolAction(u))
	if action == "" {
		action = normalizeProtocolAction(getQueryParam(u.Query(), "op", "operation", "action"))
	}
	if action != "websocket" {
		return nil, fmt.Errorf("accion no websocket")
	}

	params := u.Query()
	notifyIfInsecureJavaScriptVersion(params)
	version := parseRequestedProtocolVersionWithDefault(params, 4)
	if !isSupportedWebSocketProtocolVersion(version) {
		return nil, fmt.Errorf("version de protocolo no soportada: %d", version)
	}

	portsRaw := getQueryParam(params, "ports", "port", "portsList")
	ports := []int{DefaultWebSocketPort}
	if strings.TrimSpace(portsRaw) != "" {
		parsedPorts, err := parsePortsList(portsRaw)
		if err != nil {
			return nil, fmt.Errorf("puertos invalidos")
		}
		ports = parsedPorts
	}

	return &websocketLaunchRequest{
		Ports:     ports,
		SessionID: getQueryParam(params, "idsession", "idSession"),
		Version:   version,
	}, nil
}

// PartsToValues simple parser for query string
func PartsToValues(query string) url.Values {
	v := url.Values{}
	pairs := strings.Split(query, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		val := ""
		if len(kv) > 1 {
			val = kv[1]
		}
		// Decode if needed (usually is)
		if decoded, err := url.QueryUnescape(val); err == nil {
			val = decoded
		}
		v.Add(key, val)
	}
	return v
}

func maskSessionForLog(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	if len(v) <= 8 {
		return v
	}
	return v[:4] + "..." + v[len(v)-2:]
}
