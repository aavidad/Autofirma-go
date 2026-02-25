package main

import (
	"fmt"
	"log"
	"strings"

	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/version"

	"fyne.io/systray"
)

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
	if status.ipcEnabled {
		mIPC := systray.AddMenuItem("IPC: activo ("+status.ipcSocket+")", "Estado IPC")
		mIPC.Disable()
	} else {
		mIPC := systray.AddMenuItem("IPC: desactivado", "Estado IPC")
		mIPC.Disable()
	}
	if status.restEnabled {
		mREST := systray.AddMenuItem("REST: activo ("+status.restBind+")", "Estado REST")
		mREST.Disable()
	} else {
		mREST := systray.AddMenuItem("REST: desactivado", "Estado REST")
		mREST.Disable()
	}

	systray.AddSeparator()

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
				url := fmt.Sprintf("https://127.0.0.1:%s", wsServer.portsStr())
				_ = openExternal(url)
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
}

type systrayServerStatus struct {
	modeLabel  string
	ipcEnabled bool
	ipcSocket  string
	restEnabled bool
	restBind   string
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
