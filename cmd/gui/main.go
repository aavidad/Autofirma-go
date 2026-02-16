// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"flag"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"
)

func main() {
	// Parse command-line flags
	serverMode := flag.Bool("server", false, "Run as WebSocket server on port 63117")
	flag.Parse()

	// Setup logging
	logPath, err := applog.Init("autofirma-desktop")
	if err != nil {
		log.Printf("No se pudo inicializar logging persistente: %v", err)
	} else {
		log.Printf("Logging inicializado en: %s", logPath)
	}

	log.Printf("Launched with args: %v", os.Args)

	// WebSocket Server Mode
	if *serverMode {
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

	// Start WebSocket server
	server := NewWebSocketServer([]int{DefaultWebSocketPort}, ui)
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

		if strings.Contains(arg, "afirma://") {
			log.Printf("Protocol detected in arg: %s", arg)

			// Detect if it is just a "websocket" launch command
			if strings.Contains(arg, "afirma://websocket") {
				log.Println("Detected 'afirma://websocket' launch request.")
				handleWebSocketLaunch(arg, ui)
				// Do NOT exit, keep running to serve
			} else {
				// Defer slightly to ensure window is ready? Not strictly needed for logic state.
				ui.HandleProtocolInit(arg)
			}
		} else {
			log.Printf("Arg present but no protocol detected: %s", arg)
		}
	}

	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			// Check if we should close the window (e.g. after silent sign click)
			if ui.ShouldClose {
				log.Println("[Loop] ShouldClose flag set. Closing window.")
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

	// Parse ports from URI: afirma://websocket?ports=123,456&...
	// Strip proto
	cleanURI := uriString
	if strings.HasPrefix(cleanURI, "afirma://") {
		cleanURI = strings.TrimPrefix(cleanURI, "afirma://")
	}

	log.Printf("[Launcher] Clean URI for parsing: %s", cleanURI)

	// Handle potential standard URL parsing
	parts := strings.Split(cleanURI, "?")
	if len(parts) < 2 {
		log.Println("[Launcher] No parameters found in websocket launch URI (split failed)")
		return
	}

	log.Printf("[Launcher] Query params string: %s", parts[1])

	params := PartsToValues(parts[1])
	portsStr := params.Get("ports")

	if portsStr == "" {
		log.Println("[Launcher] No 'ports' parameter found via params.Get('ports')")
		// Try manual search in case of encoding weirdness
		if strings.Contains(parts[1], "ports=") {
			log.Println("[Launcher] 'ports=' found in string but parsing failed? dumping params map...")
			for k, v := range params {
				log.Printf("Key: %s, Val: %v", k, v)
			}
		}
		return
	}

	log.Printf("[Launcher] Found ports string: %s", portsStr)

	portStrs := strings.Split(portsStr, ",")
	var ports []int
	for _, pStr := range portStrs {
		pStr = strings.TrimSpace(pStr)
		if p, err := strconv.Atoi(pStr); err == nil {
			ports = append(ports, p)
		} else {
			log.Printf("[Launcher] Failed to parse port '%s': %v", pStr, err)
		}
	}

	if len(ports) == 0 {
		log.Println("[Launcher] No valid ports found to bind after parsing")
		return
	}

	log.Printf("[Launcher] Starting WebSocket server on one of requested ports: %v", ports)

	// Start server (async)
	server := NewWebSocketServer(ports, ui)
	if err := server.Start(); err != nil {
		log.Printf("[Launcher] Failed to start WebSocket server via launch: %v", err)
	} else {
		log.Printf("[Launcher] WebSocket server launched successfully via protocol request")
	}
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
