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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"
)

var (
	serverModeFlag     = flag.Bool("server", false, "Iniciar como servidor WebSocket en el puerto 63117")
	restModeFlag       = flag.Bool("rest", false, "Iniciar servidor API REST local")
	restAddrFlag       = flag.String("rest-addr", "127.0.0.1:63118", "Dirección del servidor REST local")
	restTokenFlag      = flag.String("rest-token", "", "Token opcional para autenticar llamadas REST (Bearer/X-API-Token)")
	restCertFPFlag     = flag.String("rest-cert-fingerprints", "", "Lista de huellas SHA-256 permitidas para login por certificado (csv, opcional)")
	restSessionTTLFlag = flag.Duration("rest-session-ttl", 10*time.Minute, "Duración de sesión emitida por login de certificado")
	generateCertsFlag  = flag.Bool("generate-certs", false, "Generar certificados TLS locales y salir")
	installTrustFlag   = flag.Bool("install-trust", false, "Instalar la CA local en los almacenes de confianza (Linux/Windows/macOS)")
	trustStatusFlag    = flag.Bool("trust-status", false, "Mostrar el estado de confianza de la CA local (Linux/Windows/macOS)")
	exportJavaCerts    = flag.String("exportar-certs-java", "", "Exportar certificados compatibles con AutoFirma Java al directorio indicado y salir")
	versionFlag        = flag.Bool("version", false, "Mostrar versión de la aplicación y salir")
	detailHelpFlag     = flag.Bool("ayuda-detallada", false, "Mostrar ayuda detallada en castellano y salir")
	fyneFlag           = flag.Bool("fyne", false, "Forzar interfaz gráfica Fyne")
	gioFlag            = flag.Bool("gio", false, "Forzar interfaz clásica Gio (compatibilidad/protocolo legado)")
	qtFlag             = flag.Bool("qt", false, "Forzar interfaz Qt (requiere binario autofirma-desktop-qt-bin)")
	frontendFlag       = flag.String("frontend", "", "Seleccionar interfaz de escritorio: fyne|gio|qt")

	// Alias REST en castellano.
	restModoCastFlag      = flag.Bool("servidor-rest", false, "Alias de -rest")
	restDirCastFlag       = flag.String("direccion-rest", "", "Alias de -rest-addr")
	restTokenCastFlag     = flag.String("token-rest", "", "Alias de -rest-token")
	restHuellasCastFlag   = flag.String("huellas-cert-rest", "", "Alias de -rest-cert-fingerprints")
	restSesionTTLCastFlag = flag.Duration("ttl-sesion-rest", 0, "Alias de -rest-session-ttl")
	restSocketFlag        = flag.String("rest-socket", "", "Ruta del socket Unix para el servidor REST (IPC)")
	ipcModeFlag           = flag.Bool("ipc", false, "Iniciar en modo IPC binario (Alto rendimiento)")
	ipcSocketFlag         = flag.String("ipc-socket", "/tmp/autofirma_ipc.sock", "Ruta del socket Unix para el modo IPC")
)

func applyRESTSpanishAliases() {
	if *restModoCastFlag {
		*restModeFlag = true
	}
	if v := strings.TrimSpace(*restDirCastFlag); v != "" {
		*restAddrFlag = v
	}
	if v := strings.TrimSpace(*restTokenCastFlag); v != "" {
		*restTokenFlag = v
	}
	if v := strings.TrimSpace(*restHuellasCastFlag); v != "" {
		*restCertFPFlag = v
	}
	if *restSesionTTLCastFlag > 0 {
		*restSessionTTLFlag = *restSesionTTLCastFlag
	}
}

func main() {
	flag.Usage = func() {
		writeSpanishFlagUsage(flag.CommandLine.Output(), os.Args[0])
	}

	// Parse command-line flags
	flag.Parse()
	applyRESTSpanishAliases()

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
	if *restModeFlag {
		addr := strings.TrimSpace(*restAddrFlag)
		sock := strings.TrimSpace(*restSocketFlag)
		if sock != "" {
			log.Printf("Iniciando en modo servidor REST (IPC) en socket Unix: %s", sock)
			if err := runRESTServerOnSocket(sock, strings.TrimSpace(*restTokenFlag), *restSessionTTLFlag, strings.TrimSpace(*restCertFPFlag)); err != nil {
				log.Printf("No se pudo iniciar el servidor REST sobre IPC: %v", err)
				os.Exit(1)
			}
		} else {
			log.Printf("Iniciando en modo servidor REST en %s", addr)
			if err := runRESTServer(addr, strings.TrimSpace(*restTokenFlag), *restSessionTTLFlag, strings.TrimSpace(*restCertFPFlag)); err != nil {
				log.Printf("No se pudo iniciar el servidor REST: %v", err)
				os.Exit(1)
			}
		}
		return
	}

	if *ipcModeFlag {
		sock := strings.TrimSpace(*ipcSocketFlag)
		log.Printf("Iniciando motor IPC en modo headless: %s", sock)
		if err := runIPCServer(sock, NewCoreService()); err != nil {
			log.Printf("Error en servidor IPC: %v", err)
			os.Exit(1)
		}
		return
	}

	if isCLIModeRequested() {
		if err := runCLIMode(); err != nil {
			log.Printf("Error en modo CLI: %v", err)
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

	// UI mode selection:
	// - Fyne es el modo por defecto para uso interactivo y protocolario.
	// - Gio queda disponible como fallback explícito con -gio.
	// - Qt se activa con -qt o -frontend qt, delegando a binario dedicado.
	protocolArg := firstAfirmaProtocolArg(os.Args[1:])
	switch strings.ToLower(strings.TrimSpace(*frontendFlag)) {
	case "":
	case "fyne":
		*fyneFlag = true
		*gioFlag = false
		*qtFlag = false
	case "gio":
		*gioFlag = true
		*fyneFlag = false
		*qtFlag = false
	case "qt":
		*qtFlag = true
		*fyneFlag = false
		*gioFlag = false
	default:
		log.Printf("frontend no soportado: %s (use fyne|gio|qt)", strings.TrimSpace(*frontendFlag))
		os.Exit(1)
	}
	if *qtFlag {
		if err := runQtFrontend(protocolArg); err != nil {
			log.Printf("No se pudo iniciar frontend Qt: %v", err)
			os.Exit(1)
		}
		return
	}
	useFyne := *fyneFlag || !*gioFlag
	if useFyne {
		log.Println("Arrancando en modo Fyne")
		f := NewFyneUI()
		if protocolArg != "" {
			f = NewFyneUIForProtocol()
			log.Printf("[Main] Solicitud protocolaria delegada a Fyne: %s", protocolArg)
			f.HandleProtocolInit(protocolArg)
		}
		f.Run()

		log.Println("[Main] Ventana Fyne cerrada. Saliendo.")
		os.Exit(0)
	}

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

func runQtFrontend(protocolArg string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	candidates := executableCandidates(exeDir, "autofirma-desktop-qt-real")
	candidates = append(candidates, executableCandidates(exeDir, "autofirma-desktop-qt-bin")...)
	candidates = append(candidates, "autofirma-desktop-qt-real", "autofirma-desktop-qt-bin")

	qtBin := ""
	for _, c := range candidates {
		if strings.ContainsRune(c, filepath.Separator) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				qtBin = c
				break
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			qtBin = p
			break
		}
	}
	if qtBin == "" {
		return fmt.Errorf("frontend Qt (autofirma-desktop-qt-real o -bin) no encontrado")
	}

	args := make([]string, 0, len(os.Args)-1)
	skipNext := false
	for _, a := range os.Args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "-qt" || la == "--qt" || la == "-fyne" || la == "--fyne" || la == "-gio" || la == "--gio" {
			continue
		}
		if la == "-frontend" || la == "--frontend" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(la, "-frontend=") || strings.HasPrefix(la, "--frontend=") {
			continue
		}
		// Traducir -ipc a --ipc para el frontend Qt si es necesario
		if la == "-ipc" {
			args = append(args, "--ipc")
			continue
		}
		args = append(args, a)
	}

	if protocolArg != "" {
		found := false
		for _, a := range args {
			if a == protocolArg {
				found = true
				break
			}
		}
		if !found {
			args = append(args, protocolArg)
		}
	}

	cmd := exec.Command(qtBin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Configuración de entorno para librerías Qt empaquetadas (Linux)
	if runtime.GOOS == "linux" {
		runtimeDir := os.Getenv("AUTOFIRMA_QT_RUNTIME_DIR")
		if runtimeDir != "" {
			libDir := filepath.Join(runtimeDir, "lib")
			pluginDir := filepath.Join(runtimeDir, "plugins")
			qmlDir := filepath.Join(runtimeDir, "qml")

			env := os.Environ()
			// Patch LD_LIBRARY_PATH
			foundLD := false
			for i, e := range env {
				if strings.HasPrefix(e, "LD_LIBRARY_PATH=") {
					env[i] = "LD_LIBRARY_PATH=" + libDir + ":" + strings.TrimPrefix(e, "LD_LIBRARY_PATH=")
					foundLD = true
					break
				}
			}
			if !foundLD {
				env = append(env, "LD_LIBRARY_PATH="+libDir)
			}

			// Set QT_PLUGIN_PATH and QML2_IMPORT_PATH
			env = append(env, "QT_PLUGIN_PATH="+pluginDir)
			env = append(env, "QML2_IMPORT_PATH="+qmlDir)

			cmd.Env = env
			log.Printf("[Qt] Usando runtime bundle en: %s", runtimeDir)
		}
	}

	return cmd.Run()
}

func executableCandidates(baseDir, baseName string) []string {
	candidates := []string{filepath.Join(baseDir, baseName)}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, filepath.Join(baseDir, baseName+".exe"))
	}
	return candidates
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
	_, _ = fmt.Fprintln(out, "  -rest [-rest-token <token>] [-rest-cert-fingerprints <sha256,sha256>] [-rest-session-ttl 10m]")
	_, _ = fmt.Fprintln(out, "    Inicia API REST local con token y/o login por certificado (reto firmado).")
	_, _ = fmt.Fprintln(out, "    Endpoints protegidos: /health /certificates /sign /verify /diagnostics/report /security/domains /tls/clear-store /tls/trust-status /tls/install-trust /tls/generate-certs.")
	_, _ = fmt.Fprintln(out, "    Alias castellano: -servidor-rest [-token-rest <token>] [-huellas-cert-rest <sha256,sha256>] [-ttl-sesion-rest 10m] [-direccion-rest 127.0.0.1:63118].")
	_, _ = fmt.Fprintln(out, "  -version")
	_, _ = fmt.Fprintln(out, "    Muestra la versión actual del binario.")
	_, _ = fmt.Fprintln(out, "  -ayuda-detallada")
	_, _ = fmt.Fprintln(out, "    Muestra esta ayuda ampliada.")
	_, _ = fmt.Fprintln(out, "  -fyne")
	_, _ = fmt.Fprintln(out, "    Fuerza el arranque con la interfaz Fyne (por defecto en modo interactivo).")
	_, _ = fmt.Fprintln(out, "  -gio")
	_, _ = fmt.Fprintln(out, "    Fuerza la interfaz clásica Gio (compatibilidad para flujos protocolarios legados).")
	_, _ = fmt.Fprintln(out, "  -qt")
	_, _ = fmt.Fprintln(out, "    Fuerza el arranque con la interfaz Qt (requiere binario adicional).")
	_, _ = fmt.Fprintln(out, "  -frontend fyne|gio|qt")
	_, _ = fmt.Fprintln(out, "    Selecciona explícitamente el frontend de escritorio.")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Opciones de modo CLI (sin interfaz):")
	var cliHelp strings.Builder
	appendCLIDetailedUsage(&cliHelp)
	_, _ = fmt.Fprint(out, cliHelp.String())
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

func firstAfirmaProtocolArg(args []string) string {
	for _, raw := range args {
		arg := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "\"'"))
		if strings.HasPrefix(arg, "afirma://") {
			return strings.Trim(strings.TrimSpace(raw), "\"'")
		}
	}
	return ""
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
