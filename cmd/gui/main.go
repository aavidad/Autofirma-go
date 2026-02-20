// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/version"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"
)

var (
	serverModeFlag    = flag.Bool("server", false, "Iniciar como servidor WebSocket en el puerto 63117")
	generateCertsFlag = flag.Bool("generate-certs", false, "Generar certificados TLS locales y salir")
	installTrustFlag  = flag.Bool("install-trust", false, "Instalar la CA local en los almacenes de confianza (Linux/Windows/macOS)")
	trustStatusFlag   = flag.Bool("trust-status", false, "Mostrar el estado de confianza de la CA local (Linux/Windows/macOS)")
	exportJavaCerts   = flag.String("exportar-certs-java", "", "Exportar certificados compatibles con AutoFirma Java al directorio indicado y salir")
	versionFlag       = flag.Bool("version", false, "Mostrar versión de la aplicación y salir")
	detailHelpFlag    = flag.Bool("ayuda-detallada", false, "Mostrar ayuda detallada en castellano y salir")
)

func main() {
	flag.Usage = func() {
		writeSpanishFlagUsage(flag.CommandLine.Output(), os.Args[0])
	}

	// Parse command-line flags
	flag.Parse()

	if *versionFlag {
		fmt.Printf("AutoFirma Dipgra %s\n", version.CurrentVersion)
		fmt.Printf("Compilacion: commit=%s fecha=%s\n", version.BuildCommit, version.BuildDate)
		fmt.Println("Software libre bajo licencia GPLv3.")
		fmt.Println("Creado por Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada).")
		return
	}
	if *detailHelpFlag {
		writeSpanishDetailedUsage(flag.CommandLine.Output(), os.Args[0])
		return
	}

	// Setup logging
	logPath, err := applog.Init("autofirma-desktop")
	if err != nil {
		log.Printf("No se pudo inicializar logging persistente: %v", err)
	} else {
		log.Printf("Logging inicializado en: %s", logPath)
	}

	log.Printf("Lanzado con argumentos: %v", os.Args)

	if *generateCertsFlag {
		certFile, keyFile, err := ensureLocalTLSCerts()
		if err != nil {
			log.Printf("Error generando certificados locales: %v", err)
			os.Exit(1)
		}
		log.Printf("Certificados locales listos: cert=%s key=%s", certFile, keyFile)
		return
	}
	if *exportJavaCerts != "" {
		if _, _, err := ensureLocalTLSCerts(); err != nil {
			log.Printf("No se pudieron preparar certificados locales: %v", err)
			os.Exit(1)
		}
		if err := exportJavaCompatibilityCerts(*exportJavaCerts); err != nil {
			log.Printf("Fallo exportando certificados compatibles de AutoFirma Java: %v", err)
			os.Exit(1)
		}
		log.Printf("Certificados compatibles de AutoFirma Java exportados en: %s", *exportJavaCerts)
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
		log.Println("Iniciando en modo servidor WebSocket")
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
		log.Println("[Main] Ventana cerrada. Esperando tareas en segundo plano...")
		ui.PendingWork.Wait()
		log.Println("[Main] Tareas en segundo plano finalizadas. Saliendo.")

		os.Exit(0)
	}()
	app.Main()
}

func writeSpanishFlagUsage(out io.Writer, program string) {
	_, _ = fmt.Fprintf(out, "Uso de %s:\n", program)
	flag.CommandLine.SetOutput(out)
	flag.CommandLine.PrintDefaults()
	_, _ = fmt.Fprintln(out, "\nConsejo: usa -ayuda-detallada para ver explicación completa de cada opción.")
}

func writeSpanishDetailedUsage(out io.Writer, program string) {
	writeSpanishFlagUsage(out, program)
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Descripción detallada de opciones:")
	_, _ = fmt.Fprintln(out, "  -generate-certs")
	_, _ = fmt.Fprintln(out, "    Genera certificados TLS locales para el canal HTTPS/WSS en loopback (127.0.0.1).")
	_, _ = fmt.Fprintln(out, "    Son necesarios para que el navegador confíe en la conexión local con AutoFirma.")
	_, _ = fmt.Fprintln(out, "  -exportar-certs-java <directorio>")
	_, _ = fmt.Fprintln(out, "    Exporta archivos de compatibilidad Java: autofirma.pfx, Autofirma_ROOT.cer y autofirma.cer.")
	_, _ = fmt.Fprintln(out, "    Uso típico: instaladores de sistema para dejar los certificados en el directorio de instalación.")
	_, _ = fmt.Fprintln(out, "  -install-trust")
	_, _ = fmt.Fprintln(out, "    Instala la CA local en almacenes de confianza (NSS/sistema/keychain) para evitar avisos TLS.")
	_, _ = fmt.Fprintln(out, "  -trust-status")
	_, _ = fmt.Fprintln(out, "    Muestra si la CA local está correctamente confiada en los almacenes detectados.")
	_, _ = fmt.Fprintln(out, "  -server")
	_, _ = fmt.Fprintln(out, "    Inicia AutoFirma en modo servicio WebSocket, esperando solicitudes del navegador.")
	_, _ = fmt.Fprintln(out, "  -version")
	_, _ = fmt.Fprintln(out, "    Muestra la versión actual del binario.")
	_, _ = fmt.Fprintln(out, "  -ayuda-detallada")
	_, _ = fmt.Fprintln(out, "    Muestra esta ayuda ampliada.")
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
		log.Fatalf("No se pudo iniciar el servidor WebSocket: %v", err)
	}

	log.Printf("Servidor WebSocket activo en el puerto %d", DefaultWebSocketPort)

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
			log.Printf("Protocolo detectado en argumento: %s", arg)

			// Detect websocket launch using robust URI parser.
			if _, wsErr := parseWebSocketLaunchURI(arg); wsErr == nil {
				log.Println("Detectada solicitud de arranque 'afirma://websocket'.")
				handleWebSocketLaunch(arg, ui)
				// Do NOT exit, keep running to serve
			} else {
				// Defer slightly to ensure window is ready? Not strictly needed for logic state.
				ui.HandleProtocolInit(arg)
			}
		} else {
			if !strings.HasPrefix(arg, "-") {
				log.Printf("Argumento presente pero sin protocolo detectado: %s", arg)
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
				log.Println("[Loop] Indicador ShouldClose activo y no está en modo servidor. Cerrando ventana.")
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
	log.Printf("[Launcher] Procesando solicitud de arranque WebSocket. URI original: %s", uriString)
	req, err := parseWebSocketLaunchURI(uriString)
	if err != nil {
		log.Printf("[Launcher] URI de arranque WebSocket inválida: %v", err)
		return
	}

	log.Printf("[Launcher] Iniciando servidor WebSocket en uno de los puertos solicitados: %v (v=%d sesión=%s)", req.Ports, req.Version, maskSessionForLog(req.SessionID))
	ui.updateSessionDiagnostics("websocket-launch", "websocket", req.SessionID, "", "launch_received")

	// Start server (async)
	server := NewWebSocketServer(req.Ports, req.SessionID, ui)
	if err := server.Start(); err != nil {
		log.Printf("[Launcher] No se pudo iniciar el servidor WebSocket desde la solicitud: %v", err)
		ui.updateSessionDiagnostics("websocket-launch", "websocket", req.SessionID, "", "launch_error")
	} else {
		log.Printf("[Launcher] Servidor WebSocket iniciado correctamente desde solicitud de protocolo")
		// Enter minimalist mode
		ui.IsServerMode = true
		ui.Protocol = &ProtocolState{IsActive: true, Action: "websocket"}
		ui.StatusMsg = "Servidor AutoFirma activo. Esperando solicitudes del navegador..."
		ui.updateSessionDiagnostics("websocket-launch", "websocket", req.SessionID, "", "launch_ok")
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
