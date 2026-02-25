package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/version"

	"fyne.io/systray"
)

var trayServices = newTrayServiceController()

func runSystrayAndServer(wsServer *WebSocketServer) {
	systray.Run(func() {
		onSystrayReady(wsServer)
	}, onSystrayExit)
}

func onSystrayReady(wsServer *WebSocketServer) {
	// Poner icono básico para que funcione el systray
	systray.SetIcon(applog.LogoRaw)
	systray.SetTooltip("AutoFirma Go Backend")

	status := resolveSystrayServerStatus()
	mStatusMode := systray.AddMenuItem("Modo servidor: "+status.modeLabel, "Modo activo del servidor")
	mStatusMode.Disable()
	mStatusWS := systray.AddMenuItem("WebSocket: activo (puerto "+wsServer.portsStr()+")", "Estado WebSocket")
	mStatusWS.Disable()
	mIPCStatus := systray.AddMenuItem(status.ipcStatusTitle(), "Estado IPC")
	mIPCStatus.Disable()
	mRESTStatus := systray.AddMenuItem(status.restStatusTitle(), "Estado REST")
	mRESTStatus.Disable()

	systray.AddSeparator()

	mToggleIPC := systray.AddMenuItemCheckbox("IPC activo", "Arrancar o parar el servidor IPC local", status.ipcEnabled)
	mToggleREST := systray.AddMenuItemCheckbox("REST activo", "Arrancar o parar el servidor REST local", status.restEnabled)
	trayServices.setIPCExternallyManaged(status.ipcEnabled)
	trayServices.setRESTExternallyManaged(status.restEnabled)
	if status.ipcEnabled {
		mToggleIPC.Disable()
	}
	if status.restEnabled {
		mToggleREST.Disable()
	}

	// Información sobre la aplicación
	mAbout := systray.AddMenuItem("Sobre AutoFirma", "Información de autoría y versión")
	mAbout.AddSubMenuItem("Versión: "+version.CurrentVersion, "").Disable()
	mAbout.AddSubMenuItem("Autor: Alberto Avidad", "").Disable()
	mAbout.AddSubMenuItem("Licencia: GPLv3", "").Disable()

	systray.AddSeparator()

	mControlPanel := systray.AddMenuItem("Abrir panel de control local", "Abre la vista local en el navegador")
	mLogs := systray.AddMenuItem("Ver carpeta de logs", "Abre el directorio de registros")
	mWeb := systray.AddMenuItem("Portal AutoFirma DipGra", "Abre la web de soporte de Diputación")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Cerrar servidor", "Detiene AutoFirma en segundo plano")

	go func() {
		for {
			select {
			case <-mControlPanel.ClickedCh:
				enabled, statusText := trayServices.ensureRESTRunning()
				updateToggleMenuState(mToggleREST, enabled)
				mRESTStatus.SetTitle(statusText)
				if !enabled {
					log.Printf("[Systray] No se puede abrir panel: REST no disponible")
					continue
				}
				url := buildSystrayControlPanelURL()
				log.Printf("[Systray] Abriendo panel local: %s", url)
				_ = openExternal(url)
			case <-mToggleIPC.ClickedCh:
				enabled, statusText := trayServices.toggleIPC()
				updateToggleMenuState(mToggleIPC, enabled)
				mIPCStatus.SetTitle(statusText)
			case <-mToggleREST.ClickedCh:
				enabled, statusText := trayServices.toggleREST()
				updateToggleMenuState(mToggleREST, enabled)
				mRESTStatus.SetTitle(statusText)
			case <-mLogs.ClickedCh:
				logDir := resolveLogDirectory()
				_ = openExternal(logDir)
			case <-mWeb.ClickedCh:
				_ = openExternal("https://autofirma.dipgra.es")
			case <-mQuit.ClickedCh:
				log.Println("[Systray] Solicitud de cierre recibida")
				systray.Quit()
				return
			}
		}
	}()

	// Arranca el servidor web socket en el background
	go func() {
		if err := wsServer.Start(); err != nil {
			log.Fatalf("Error fatal servidor websocket: %v", err)
		}
	}()
}

func onSystrayExit() {
	log.Println("[Systray] Cerrando servidor AutoFirma en segundo plano")
	trayServices.stopAll()
}

type systrayServerStatus struct {
	modeLabel   string
	ipcEnabled  bool
	ipcSocket   string
	restEnabled bool
	restBind    string
}

func resolveSystrayServerStatus() systrayServerStatus {
	mode := normalizeServerMode(strings.TrimSpace(*serverModeKindFlag))
	if mode == "" && *serverModeFlag {
		mode = "websocket"
	}

	st := systrayServerStatus{
		modeLabel:   "websocket",
		ipcEnabled:  false,
		ipcSocket:   strings.TrimSpace(*ipcSocketFlag),
		restEnabled: false,
		restBind:    strings.TrimSpace(*restAddrFlag),
	}
	if st.ipcSocket == "" {
		st.ipcSocket = "/tmp/autofirma_ipc.sock"
	}
	if st.restBind == "" {
		st.restBind = "127.0.0.1:63118"
	}
	if sock := strings.TrimSpace(*restSocketFlag); sock != "" {
		st.restBind = "socket " + sock
	}

	switch mode {
	case "ambas":
		st.modeLabel = "ambas"
		st.ipcEnabled = true
		st.restEnabled = true
	case "websocket":
		st.modeLabel = "websocket"
	case "ipc":
		st.modeLabel = "ipc"
		st.ipcEnabled = true
	case "rest":
		st.modeLabel = "rest"
		st.restEnabled = true
	default:
		if *ipcModeFlag {
			st.ipcEnabled = true
		}
		if *restModeFlag {
			st.restEnabled = true
		}
	}

	return st
}

func (s *WebSocketServer) portsStr() string {
	if len(s.ports) > 0 {
		return fmt.Sprintf("%d", s.ports[0])
	}
	return "Desconocido"
}

func (s systrayServerStatus) ipcStatusTitle() string {
	if s.ipcEnabled {
		return "IPC: activo (" + s.ipcSocket + ")"
	}
	return "IPC: desactivado"
}

func (s systrayServerStatus) restStatusTitle() string {
	if s.restEnabled {
		return "REST: activo (" + s.restBind + ")"
	}
	return "REST: desactivado"
}

func buildSystrayControlPanelURL() string {
	addr := strings.TrimSpace(*restAddrFlag)
	if addr == "" {
		addr = "127.0.0.1:63118"
	}
	scheme := "http"
	if *restTLSFlag {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, addr)
}

func updateToggleMenuState(item *systray.MenuItem, enabled bool) {
	if enabled {
		item.Check()
		return
	}
	item.Uncheck()
}

type trayServiceController struct {
	mu                sync.Mutex
	ipcCmd            *exec.Cmd
	restCmd           *exec.Cmd
	ipcExternallyManaged bool
	restExternallyManaged bool
}

func newTrayServiceController() *trayServiceController {
	return &trayServiceController{}
}

func (c *trayServiceController) setIPCExternallyManaged(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ipcExternallyManaged = v
}

func (c *trayServiceController) setRESTExternallyManaged(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restExternallyManaged = v
}

func (c *trayServiceController) toggleIPC() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ipcExternallyManaged {
		return true, "IPC: activo (gestionado por inicio)"
	}
	if c.ipcCmd != nil && c.ipcCmd.Process != nil {
		c.stopProcessLocked("ipc", &c.ipcCmd)
		return false, "IPC: desactivado"
	}
	args := []string{"--server-modo", "ipc"}
	if socketPath := strings.TrimSpace(*ipcSocketFlag); socketPath != "" {
		args = append(args, "--ipc-socket", socketPath)
	}
	cmd, err := c.startChildLocked(args)
	if err != nil {
		log.Printf("[Systray] Error arrancando IPC: %v", err)
		return false, "IPC: error al arrancar (" + err.Error() + ")"
	}
	c.ipcCmd = cmd
	socketPath := strings.TrimSpace(*ipcSocketFlag)
	if socketPath == "" {
		socketPath = "/tmp/autofirma_ipc.sock"
	}
	return true, "IPC: activo (" + socketPath + ")"
}

func (c *trayServiceController) toggleREST() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.restExternallyManaged {
		return true, "REST: activo (gestionado por inicio)"
	}
	if c.restCmd != nil && c.restCmd.Process != nil {
		c.stopProcessLocked("rest", &c.restCmd)
		return false, "REST: desactivado"
	}
	args := []string{"--server-modo", "rest"}
	if addr := strings.TrimSpace(*restAddrFlag); addr != "" {
		args = append(args, "--rest-addr", addr)
	}
	if *restTLSFlag {
		args = append(args, "--rest-tls")
	}
	if tok := strings.TrimSpace(*restTokenFlag); tok != "" {
		args = append(args, "--rest-token", tok)
	}
	if fp := strings.TrimSpace(*restCertFPFlag); fp != "" {
		args = append(args, "--rest-cert-fingerprints", fp)
	}
	if sock := strings.TrimSpace(*restSocketFlag); sock != "" {
		args = append(args, "--rest-socket", sock)
	}
	cmd, err := c.startChildLocked(args)
	if err != nil {
		log.Printf("[Systray] Error arrancando REST: %v", err)
		return false, "REST: error al arrancar (" + err.Error() + ")"
	}
	c.restCmd = cmd
	bind := strings.TrimSpace(*restAddrFlag)
	if bind == "" {
		bind = "127.0.0.1:63118"
	}
	if sock := strings.TrimSpace(*restSocketFlag); sock != "" {
		return true, "REST: activo (socket " + sock + ")"
	}
	return true, "REST: activo (" + bind + ")"
}

func (c *trayServiceController) ensureRESTRunning() (bool, string) {
	c.mu.Lock()
	already := c.restExternallyManaged || (c.restCmd != nil && c.restCmd.Process != nil)
	c.mu.Unlock()
	if already {
		bind := strings.TrimSpace(*restAddrFlag)
		if bind == "" {
			bind = "127.0.0.1:63118"
		}
		if sock := strings.TrimSpace(*restSocketFlag); sock != "" {
			return true, "REST: activo (socket " + sock + ")"
		}
		return true, "REST: activo (" + bind + ")"
	}
	return c.toggleREST()
}

func (c *trayServiceController) stopAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopProcessLocked("ipc", &c.ipcCmd)
	c.stopProcessLocked("rest", &c.restCmd)
}

func (c *trayServiceController) startChildLocked(args []string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	log.Printf("[Systray] Subproceso arrancado pid=%d args=%v", cmd.Process.Pid, args)
	go func(name string, child *exec.Cmd) {
		err := child.Wait()
		if err != nil {
			log.Printf("[Systray] Subproceso %s finalizado con error: %v", name, err)
		} else {
			log.Printf("[Systray] Subproceso %s finalizado", name)
		}
	}(serviceNameFromArgs(args), cmd)
	return cmd, nil
}

func (c *trayServiceController) stopProcessLocked(name string, slot **exec.Cmd) {
	if *slot == nil || (*slot).Process == nil {
		*slot = nil
		return
	}
	pid := (*slot).Process.Pid
	log.Printf("[Systray] Parando subproceso %s pid=%d", name, pid)
	if err := (*slot).Process.Kill(); err != nil {
		log.Printf("[Systray] Error parando subproceso %s pid=%d: %v", name, pid, err)
	}
	*slot = nil
}

func serviceNameFromArgs(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--server-modo" {
			return args[i+1]
		}
	}
	return "child"
}
