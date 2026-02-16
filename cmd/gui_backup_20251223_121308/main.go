package main

import (
	"flag"
	"log"
	"os"
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
	logFile, err := os.OpenFile("/tmp/autofirma-launcher.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
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
		if err := loop(w); err != nil {
			log.Fatal(err)
		}
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
	server := NewWebSocketServer(DefaultWebSocketPort, ui)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start WebSocket server: %v", err)
	}

	log.Printf("WebSocket server running on port %d", DefaultWebSocketPort)

	// Run UI loop (needed for certificate dialogs)
	go func() {
		if err := loop(w); err != nil {
			log.Fatal(err)
		}
	}()

	app.Main()
}

func loop(w *app.Window) error {
	var ops op.Ops
	ui := NewUI(w)

	// Check for protocol argument
	if len(os.Args) > 1 {
		arg := os.Args[1]
		// Clean quotes if present
		arg = strings.Trim(arg, "\"'")

		if strings.Contains(arg, "afirma://") {
			log.Printf("Protocol detected in arg: %s", arg)
			// Defer slightly to ensure window is ready? Not strictly needed for logic state.
			ui.HandleProtocolInit(arg)
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
			gtx := app.NewContext(&ops, e)
			ui.Layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}
