package main

import (
	"fmt"
	"log"

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

	mStatus := systray.AddMenuItem("Puerto activo: "+wsServer.portsStr(), "Estado del socket")
	mStatus.Disable()

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

func (s *WebSocketServer) portsStr() string {
	if len(s.ports) > 0 {
		return fmt.Sprintf("%d", s.ports[0])
	}
	return "Desconocido"
}
