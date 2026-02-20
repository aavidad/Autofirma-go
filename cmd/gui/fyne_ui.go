// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// FyneUI envuelve el estado y referencias de la nueva interfaz
type FyneUI struct {
	App    fyne.App
	Window fyne.Window

	// Elementos dinámicos
	StatusLabel     *widget.Label
	MessageBox      *widget.Entry
	FileLabel       *canvas.Text
	VerifyFileLabel *canvas.Text
	SelectedCertLbl *widget.Label
	CertScroll      *container.Scroll
	TestsStatusBox  *widget.Entry
	WhitelistBox    *widget.Entry
	WhitelistInput  *widget.Entry

	// Estado
	Certs           []protocol.Certificate
	SelectedCert    *protocol.Certificate
	InputFile       string
	LastSigned      string
	IsServerMode    bool
	TestBusy        bool
	StrictCompat    bool
	AllowInvalidPDF bool
	ExpertMode      bool
	ScriptTests     []FyneScriptTest
	ExpertOperation string
	ExportTempPass  string
	VisibleSeal     bool
	SealPage        uint32
	SealX           float64
	SealY           float64
	SealW           float64
	SealH           float64
	PreviewBaseURL  string
	PreviewToken    string
	PreviewFile     string

	Protocol *ProtocolState
	// Modo reducido para invocaciones afirma:// (selector/flujo protocolario).
	ProtocolQuickMode bool

	Core *CoreService
	mu   sync.Mutex
}

type FyneScriptTest struct {
	ID          string
	Nombre      string
	Descripcion string
	Ayuda       string
	Comando     []string
	Selected    bool
}

type FyneUIPreferences struct {
	StrictCompat    bool   `json:"strict_compat"`
	AllowInvalidPDF bool   `json:"allow_invalid_pdf"`
	ExpertMode      bool   `json:"expert_mode"`
	UpdatedAt       string `json:"updated_at"`
}

func NewFyneUI() *FyneUI {
	return newFyneUI(false)
}

func NewFyneUIForProtocol() *FyneUI {
	return newFyneUI(true)
}

func newFyneUI(protocolQuickMode bool) *FyneUI {
	// Fijamos escala visual grande para el nuevo modo Fyne.
	_ = os.Setenv("FYNE_SCALE", "2.0")
	// Evita warning de Fyne cuando LANG=C (tag no válido para locale parser).
	ensureFyneLocale()

	a := app.NewWithID("es.dipgra.autofirma")
	w := a.NewWindow("AutoFirma - Diputación de Granada")
	if protocolQuickMode {
		w.Resize(fyne.NewSize(560, 180))
	} else {
		w.Resize(fyne.NewSize(1100, 750))
	}

	ui := &FyneUI{
		App:               a,
		Window:            w,
		ProtocolQuickMode: protocolQuickMode,
		Core:              NewCoreService(),
		ExpertOperation:   "sign",
		VisibleSeal:       false,
		SealPage:          1,
		SealX:             0.62,
		SealY:             0.04,
		SealW:             0.34,
		SealH:             0.12,
	}
	ui.loadPreferences()
	ui.initScriptTests()

	ui.buildUI()
	w.SetOnDropped(func(_ fyne.Position, items []fyne.URI) {
		ui.handleDroppedItems(items)
	})

	w.SetOnClosed(func() {
		log.Println("[FyneUI] Ventana cerrada.")
	})

	return ui
}

func ensureFyneLocale() {
	lang := strings.TrimSpace(os.Getenv("LANG"))
	lcAll := strings.TrimSpace(os.Getenv("LC_ALL"))
	active := lcAll
	if active == "" {
		active = lang
	}
	if active == "" {
		_ = os.Setenv("LANG", "C.UTF-8")
		return
	}
	if strings.EqualFold(active, "C") || strings.EqualFold(active, "POSIX") {
		if lcAll != "" {
			_ = os.Setenv("LC_ALL", "C.UTF-8")
		} else {
			_ = os.Setenv("LANG", "C.UTF-8")
		}
	}
}

func (ui *FyneUI) Run() {
	ui.Window.ShowAndRun()
}

func (ui *FyneUI) SetStatus(msg string) {
	fyne.Do(func() {
		if ui.StatusLabel != nil {
			ui.StatusLabel.SetText(msg)
		}
		ui.appendMessage(msg)
	})
}

func (ui *FyneUI) appendMessage(msg string) {
	if ui.MessageBox == nil {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	if strings.TrimSpace(ui.MessageBox.Text) == "" {
		ui.MessageBox.SetText(msg)
		return
	}
	ui.MessageBox.SetText(ui.MessageBox.Text + "\n" + msg)
}

func (ui *FyneUI) buildUI() {
	ui.loadCertificates()

	if ui.ProtocolQuickMode {
		ui.StatusLabel = widget.NewLabel("Procesando solicitud protocolaria...")
		ui.MessageBox = widget.NewMultiLineEntry()
		ui.MessageBox.Wrapping = fyne.TextWrapWord
		ui.MessageBox.Disable()
		ui.Window.SetContent(container.NewVBox(
			widget.NewCard("AutoFirma Dipgra", "Modo protocolario", ui.StatusLabel),
			widget.NewCard("Detalle", "", container.NewVScroll(ui.MessageBox)),
		))
		return
	}

	ui.StatusLabel = widget.NewLabel("Seleccione un PDF y un certificado para firmar.")
	ui.MessageBox = widget.NewMultiLineEntry()
	ui.MessageBox.Wrapping = fyne.TextWrapWord
	ui.MessageBox.Disable()
	statusBar := container.NewPadded(widget.NewCard("", "", ui.StatusLabel))
	logCard := widget.NewCard("Mensajes", "Registro de acciones de esta sesión", container.NewVScroll(ui.MessageBox))

	header := ui.buildHeader()

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Firma", theme.DocumentSaveIcon(), ui.buildSignTab()),
		container.NewTabItemWithIcon("Verificar", theme.ConfirmIcon(), ui.buildVerifyTab()),
		container.NewTabItemWithIcon("Diagnóstico", theme.InfoIcon(), ui.buildDiagnosticsTab()),
		container.NewTabItemWithIcon("Seguridad", theme.WarningIcon(), ui.buildSecurityTab()),
		container.NewTabItemWithIcon("Pruebas", theme.MediaPlayIcon(), ui.buildTestsTab()),
		container.NewTabItemWithIcon("Configuración", theme.SettingsIcon(), ui.buildSettingsTab()),
		container.NewTabItemWithIcon("Ayuda", theme.HelpIcon(), ui.buildHelpTab()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// Panel principal redimensionable: arriba contenido y abajo registro de sesión.
	mainSplit := container.NewVSplit(tabs, logCard)
	mainSplit.Offset = 0.72

	ui.Window.SetContent(container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		statusBar,
		nil, nil,
		mainSplit,
	))
}

func (ui *FyneUI) buildHeader() fyne.CanvasObject {
	dipgraBlue := color.NRGBA{R: 0x1E, G: 0x3A, B: 0x7E, A: 0xFF}
	title := canvas.NewText("AutoFirma Dipgra", dipgraBlue)
	title.TextSize = 20
	title.TextStyle = fyne.TextStyle{Bold: true}

	sub := canvas.NewText("Firma electrónica · Diputación de Granada", color.NRGBA{R: 0x70, G: 0x80, B: 0xA0, A: 0xFF})
	sub.TextSize = 11

	bg := canvas.NewRectangle(color.NRGBA{R: 0xF4, G: 0xF7, B: 0xFF, A: 0xFF})

	return container.NewStack(
		bg,
		container.NewPadded(container.NewVBox(title, sub)),
	)
}

func (ui *FyneUI) buildSignTab() fyne.CanvasObject {
	ui.FileLabel = canvas.NewText("Ningún archivo seleccionado", color.NRGBA{R: 110, G: 110, B: 130, A: 200})
	ui.FileLabel.TextSize = 12

	dropZone := ui.buildDropZone(func(name string) {
		ui.FileLabel.Text = name
		ui.FileLabel.Refresh()
		ui.InputFile = name
		ui.SetStatus("PDF cargado: " + name)
	})

	ui.SelectedCertLbl = widget.NewLabel("Ningún certificado seleccionado")

	ui.CertScroll = container.NewHScroll(ui.buildCertCards())

	opSelect := widget.NewSelect([]string{"firmar", "cofirmar", "contrafirmar"}, func(v string) {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "cofirmar":
			ui.ExpertOperation = "cosign"
		case "contrafirmar":
			ui.ExpertOperation = "countersign"
		default:
			ui.ExpertOperation = "sign"
		}
		ui.SetStatus("Operación seleccionada: " + v)
	})
	opSelect.SetSelected("firmar")

	visibleSealChk := widget.NewCheck("Añadir firma visible en PAdES", func(v bool) {
		ui.VisibleSeal = v
	})
	visibleSealChk.SetChecked(ui.VisibleSeal)

	sealPage := widget.NewEntry()
	sealPage.SetText(fmt.Sprintf("%d", ui.SealPage))
	sealPage.SetPlaceHolder("Página")
	sealX := widget.NewEntry()
	sealX.SetText(fmt.Sprintf("%.2f", ui.SealX))
	sealX.SetPlaceHolder("X 0..1")
	sealY := widget.NewEntry()
	sealY.SetText(fmt.Sprintf("%.2f", ui.SealY))
	sealY.SetPlaceHolder("Y 0..1")
	sealW := widget.NewEntry()
	sealW.SetText(fmt.Sprintf("%.2f", ui.SealW))
	sealW.SetPlaceHolder("Ancho 0..1")
	sealH := widget.NewEntry()
	sealH.SetText(fmt.Sprintf("%.2f", ui.SealH))
	sealH.SetPlaceHolder("Alto 0..1")
	openSealWebBtn := widget.NewButtonWithIcon("Abrir visor PDF en navegador", theme.SearchIcon(), func() {
		ui.syncSealValuesFromEntries(sealPage, sealX, sealY, sealW, sealH)
		if !ui.VisibleSeal {
			ui.SetStatus("Activa 'Añadir firma visible en PAdES' para usar el visor.")
			return
		}
		filePath := strings.TrimSpace(ui.InputFile)
		if filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
			ui.SetStatus("Seleccione un PDF para previsualizar el área de firma visible.")
			return
		}
		if err := ui.openPadesPreviewInBrowserFyne(filePath); err != nil {
			ui.SetStatus(withSolution("No se pudo abrir el visor web de sello visible: "+err.Error(), "Reintenta con un PDF local válido."))
			return
		}
		ui.SetStatus("Visor web abierto. Dibuja el área y pulsa 'Guardar área en AutoFirma'.")
	})

	signBtn := widget.NewButtonWithIcon("  Firmar Documento", theme.DocumentSaveIcon(), func() {
		if ui.SelectedCert == nil {
			ui.SetStatus("⚠  Seleccione un certificado antes de firmar.")
			return
		}
		if ui.InputFile == "" {
			ui.SetStatus("⚠  Seleccione o arrastre un documento PDF primero.")
			return
		}
		ui.SetStatus("✓  Firmando documento con certificado seleccionado...")
		ui.syncSealValuesFromEntries(sealPage, sealX, sealY, sealW, sealH)
		go ui.signCurrentFileCore()
	})
	signBtn.Importance = widget.HighImportance

	importBtn := widget.NewButtonWithIcon("  Importar certificado", theme.FolderOpenIcon(), func() {
		if runtime.GOOS == "windows" {
			ui.SetStatus("Abriendo asistente de importación de Windows...")
			exec.Command("rundll32", "cryptext.dll,CryptExtOpenCER").Start()
		} else {
			ui.SetStatus("Por favor, importe su certificado usando la utilidad de su sistema operativo o navegador.")
		}

		// Sugerir recarga al usuario en la barra
		ui.SetStatus("Pulse el botón 🔄 para recargar la lista si ya instaló uno.")
	})

	refreshBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
		ui.SetStatus("Recargando certificados del sistema...")
		ui.loadCertificates()
		if ui.CertScroll != nil {
			ui.CertScroll.Content = ui.buildCertCards()
			ui.CertScroll.Refresh()
		}
		ui.SetStatus("Lista de certificados actualizada.")
	})

	openSignedBtn := widget.NewButtonWithIcon("Abrir firmado", theme.FolderOpenIcon(), func() {
		path := strings.TrimSpace(ui.LastSigned)
		if path == "" {
			ui.SetStatus("No hay PDF firmado para abrir.")
			return
		}
		if err := openExternal(path); err != nil {
			ui.SetStatus("No se pudo abrir el PDF firmado: " + err.Error())
			return
		}
		ui.SetStatus("PDF firmado abierto: " + path)
	})
	openFolderBtn := widget.NewButtonWithIcon("Abrir carpeta", theme.FolderIcon(), func() {
		path := strings.TrimSpace(ui.LastSigned)
		if path == "" {
			ui.SetStatus("No hay PDF firmado para localizar.")
			return
		}
		if err := openContainingFolder(path); err != nil {
			ui.SetStatus("No se pudo abrir la carpeta del PDF firmado: " + err.Error())
			return
		}
		ui.SetStatus("Carpeta del PDF firmado abierta.")
	})
	refreshStatusBtn := widget.NewButtonWithIcon("Actualizar estado", theme.ViewRefreshIcon(), func() {
		ui.SetStatus("Estado actualizado.")
	})

	actionRow := container.NewVBox(
		container.NewHBox(signBtn, importBtn, refreshBtn),
		container.NewHBox(openSignedBtn, openFolderBtn, refreshStatusBtn),
	)

	expertTools := ui.buildExpertToolsSignPanel()

	return container.NewVBox(
		container.NewPadded(dropZone),
		container.NewPadded(container.NewHBox(widget.NewLabel("Operación:"), opSelect)),
		container.NewPadded(container.NewHBox(
			widget.NewIcon(theme.DocumentIcon()), ui.FileLabel,
		)),
		container.NewPadded(container.NewVBox(
			visibleSealChk,
			container.NewHBox(
				widget.NewLabel("Página"), sealPage,
				widget.NewLabel("X"), sealX,
				widget.NewLabel("Y"), sealY,
				widget.NewLabel("W"), sealW,
				widget.NewLabel("H"), sealH,
			),
			openSealWebBtn,
		)),
		widget.NewSeparator(),
		container.NewPadded(
			widget.NewLabelWithStyle("Certificados disponibles:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		),
		container.NewPadded(ui.CertScroll),
		widget.NewSeparator(),
		container.NewPadded(actionRow),
		widget.NewSeparator(),
		container.NewPadded(expertTools),
	)
}

func (ui *FyneUI) buildExpertToolsSignPanel() fyne.CanvasObject {
	if !ui.ExpertMode {
		return widget.NewLabel("Activa modo experto en Configuración para ver herramientas avanzadas.")
	}

	openCertManagerBtn := widget.NewButtonWithIcon("Gestor de certificados", theme.SettingsIcon(), func() {
		if err := openSystemCertificateManager(); err != nil {
			ui.SetStatus(withSolution("No se pudo abrir el gestor de certificados: "+err.Error(), "Ábrelo manualmente desde tu sistema operativo."))
			return
		}
		ui.SetStatus("Gestor de certificados del sistema abierto.")
	})

	exportSelectedBtn := widget.NewButtonWithIcon("Exportar certificado seleccionado", theme.DocumentSaveIcon(), func() {
		go ui.exportSelectedCertificateExpertFyne()
	})
	batchLocalBtn := widget.NewButtonWithIcon("Procesar lote local (JSON/XML)", theme.MediaPlayIcon(), func() {
		if ui.Protocol != nil && normalizeProtocolAction(ui.Protocol.Action) == "batch" {
			go ui.handleProtocolBatchFyne()
			return
		}
		go ui.runLocalBatchFromInputFyne()
	})
	expertSelectBtn := widget.NewButtonWithIcon("Selector avanzado de certificado", theme.AccountIcon(), func() {
		go ui.runExpertSelectCertDialogFyne()
	})
	expertLoadBtn := widget.NewButtonWithIcon("Carga manual (LOAD)", theme.FolderOpenIcon(), func() {
		go ui.runExpertLoadDialogFyne()
	})
	expertSaveBtn := widget.NewButtonWithIcon("Guardado manual (SAVE)", theme.DocumentCreateIcon(), func() {
		go ui.runExpertSaveCopyFyne()
	})

	genPassBtn := widget.NewButtonWithIcon("Generar clave temporal", theme.ContentAddIcon(), func() {
		pass, err := generateStrongTempPassword(24)
		if err != nil {
			ui.SetStatus(withSolution("No se pudo generar clave temporal: "+err.Error(), "Reintenta la generación de clave temporal."))
			return
		}
		ui.ExportTempPass = pass
		ui.SetStatus("Clave temporal fuerte generada para exportación PKCS#12.")
	})

	copyPassBtn := widget.NewButtonWithIcon("Copiar clave temporal", theme.ContentCopyIcon(), func() {
		pass := strings.TrimSpace(ui.ExportTempPass)
		if pass == "" {
			ui.SetStatus(withSolution("No hay clave temporal generada.", "Pulsa 'Generar clave temporal' antes de copiar."))
			return
		}
		if err := copyToClipboard(pass); err != nil {
			ui.SetStatus(withSolution("No se pudo copiar la clave temporal: "+err.Error(), "Cópiala manualmente o revisa permisos del portapapeles."))
			return
		}
		ui.SetStatus("Clave temporal copiada al portapapeles.")
	})

	passInfo := widget.NewLabel("Clave activa: " + maskPasswordPreview(ui.ExportTempPass))
	refreshPassInfoBtn := widget.NewButtonWithIcon("Actualizar clave activa", theme.ViewRefreshIcon(), func() {
		passInfo.SetText("Clave activa: " + maskPasswordPreview(ui.ExportTempPass))
	})

	return container.NewVBox(
		widget.NewLabelWithStyle("Herramientas avanzadas", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewHBox(openCertManagerBtn, exportSelectedBtn),
		container.NewHBox(batchLocalBtn, expertSelectBtn),
		container.NewHBox(expertLoadBtn, expertSaveBtn),
		container.NewHBox(genPassBtn, copyPassBtn, refreshPassInfoBtn),
		passInfo,
	)
}

func (ui *FyneUI) buildVerifyTab() fyne.CanvasObject {
	ui.VerifyFileLabel = canvas.NewText("Ningún PDF seleccionado para verificar", color.NRGBA{R: 110, G: 110, B: 130, A: 200})
	ui.VerifyFileLabel.TextSize = 12
	if strings.TrimSpace(ui.LastSigned) != "" {
		ui.applyLastSignedToVerify()
	}

	browseBtn := widget.NewButtonWithIcon("Seleccionar PDF", theme.FolderOpenIcon(), func() {
		ui.openPDFPicker(func(path string) {
			ui.VerifyFileLabel.Text = path
			ui.VerifyFileLabel.Refresh()
			ui.InputFile = path
			ui.SetStatus("PDF de verificación cargado: " + path)
		})
	})

	verifyBtn := widget.NewButtonWithIcon("Verificar firma", theme.ConfirmIcon(), func() {
		if strings.TrimSpace(ui.InputFile) == "" {
			ui.SetStatus("Seleccione un PDF firmado para verificar.")
			return
		}
		go ui.verifyCurrentFileCore()
	})
	verifyBtn.Importance = widget.HighImportance

	return container.NewPadded(container.NewVBox(
		widget.NewLabel("Seleccione un PDF firmado para verificar su firma digital."),
		container.NewHBox(widget.NewIcon(theme.DocumentIcon()), ui.VerifyFileLabel),
		container.NewHBox(browseBtn, verifyBtn),
	))
}

func (ui *FyneUI) buildDiagnosticsTab() fyne.CanvasObject {
	checkCertsBtn := widget.NewButtonWithIcon("Comprobar certificados", theme.SearchIcon(), func() {
		go ui.checkCertificatesCore()
	})

	checkUpdatesBtn := widget.NewButtonWithIcon("Buscar actualizaciones", theme.ViewRefreshIcon(), func() {
		if err := openExternal("https://autofirma.dipgra.es/version.json"); err != nil {
			ui.SetStatus("No se pudo abrir el endpoint de actualizaciones: " + err.Error())
			return
		}
		ui.SetStatus("Endpoint de actualización abierto.")
	})

	logsBtn := widget.NewButtonWithIcon("Abrir carpeta de logs", theme.FolderOpenIcon(), func() {
		logDir := resolveLogDirectory()
		if err := openExternal(logDir); err != nil {
			ui.SetStatus("No se pudo abrir la carpeta de logs: " + err.Error())
			return
		}
		ui.SetStatus("Carpeta de logs abierta: " + logDir)
	})

	helpBtn := widget.NewButtonWithIcon("Abrir ayuda", theme.HelpIcon(), func() {
		manualPath, err := fyneResolveHelpManualPath()
		if err != nil {
			ui.SetStatus("No se encontró el manual de ayuda: " + err.Error())
			return
		}
		if err := openExternal(manualPath); err != nil {
			ui.SetStatus("No se pudo abrir el manual de ayuda: " + err.Error())
			return
		}
		ui.SetStatus("Manual de ayuda abierto.")
	})

	tlsDiagBtn := widget.NewButtonWithIcon("Diagnóstico TLS", theme.SearchIcon(), func() {
		go ui.runTLSDiagnosticsFyne()
	})
	tlsImportBtn := widget.NewButtonWithIcon("Importar cert TLS", theme.ContentAddIcon(), func() {
		go ui.importTLSCertificateFromDialogFyne()
	})
	tlsClearBtn := widget.NewButtonWithIcon("Vaciar almacén TLS local", theme.DeleteIcon(), func() {
		removed, err := clearEndpointTrustStore()
		if err != nil {
			ui.SetStatus(withSolution("No se pudo vaciar el almacén TLS local: "+summarizeServerBody(err.Error()), "Revisa permisos en ~/.config/AutofirmaDipgra/certs/endpoints."))
			return
		}
		ui.SetStatus(fmt.Sprintf("Almacén TLS local vaciado correctamente (%d certificado(s) eliminados).", removed))
	})
	copyDiagBtn := widget.NewButtonWithIcon("Copiar diagnóstico completo", theme.ContentCopyIcon(), func() {
		report := ui.buildFyneDiagnosticReport()
		if err := copyToClipboard(report); err != nil {
			ui.SetStatus(withSolution("No se pudo copiar el diagnóstico: "+err.Error(), "Copia el texto desde el panel de mensajes."))
			return
		}
		ui.SetStatus("Diagnóstico completo copiado al portapapeles.")
	})
	exportDiagBtn := widget.NewButtonWithIcon("Exportar diagnóstico", theme.DocumentSaveIcon(), func() {
		report := ui.buildFyneDiagnosticReport()
		home, _ := os.UserHomeDir()
		defaultPath := filepath.Join(home, "Descargas", "autofirma_diagnostico.txt")
		targetPath, canceled, err := protocolSaveDialog(defaultPath, "txt,log")
		if canceled {
			ui.SetStatus("Exportación de diagnóstico cancelada.")
			return
		}
		if err != nil {
			ui.SetStatus(withSolution("No se pudo abrir diálogo de guardado de diagnóstico: "+err.Error(), "Reintenta y revisa permisos."))
			return
		}
		targetPath = strings.TrimSpace(targetPath)
		if targetPath == "" {
			ui.SetStatus("No se seleccionó ruta para exportar diagnóstico.")
			return
		}
		if writeErr := os.WriteFile(targetPath, []byte(report), 0o644); writeErr != nil {
			ui.SetStatus(withSolution("No se pudo guardar diagnóstico: "+writeErr.Error(), "Comprueba permisos de escritura en la ruta destino."))
			return
		}
		ui.SetStatus("Diagnóstico exportado en: " + targetPath)
	})

	return container.NewPadded(container.NewVBox(
		widget.NewLabel("Herramientas de diagnóstico y soporte."),
		container.NewHBox(checkCertsBtn, checkUpdatesBtn),
		container.NewHBox(logsBtn, helpBtn),
		container.NewHBox(tlsDiagBtn, tlsImportBtn, tlsClearBtn),
		container.NewHBox(copyDiagBtn, exportDiagBtn),
	))
}

func (ui *FyneUI) buildSecurityTab() fyne.CanvasObject {
	ui.WhitelistInput = widget.NewEntry()
	ui.WhitelistInput.SetPlaceHolder("dominio.ejemplo.es")
	ui.WhitelistBox = widget.NewMultiLineEntry()
	ui.WhitelistBox.Disable()
	ui.refreshWhitelistView()

	addBtn := widget.NewButtonWithIcon("Añadir dominio", theme.ContentAddIcon(), func() {
		host := strings.TrimSpace(ui.WhitelistInput.Text)
		if host == "" {
			ui.SetStatus("Indique un dominio para añadir a la lista blanca.")
			return
		}
		if err := addTrustedSigningDomain(host); err != nil {
			ui.SetStatus("No se pudo añadir dominio a lista blanca: " + err.Error())
			return
		}
		ui.WhitelistInput.SetText("")
		ui.refreshWhitelistView()
		ui.SetStatus("Dominio añadido a lista blanca: " + host)
	})

	removeBtn := widget.NewButtonWithIcon("Quitar dominio", theme.DeleteIcon(), func() {
		host := strings.TrimSpace(ui.WhitelistInput.Text)
		if host == "" {
			ui.SetStatus("Indique el dominio a quitar de lista blanca.")
			return
		}
		if err := removeTrustedSigningDomain(host); err != nil {
			ui.SetStatus("No se pudo quitar dominio de lista blanca: " + err.Error())
			return
		}
		ui.WhitelistInput.SetText("")
		ui.refreshWhitelistView()
		ui.SetStatus("Dominio eliminado de lista blanca: " + host)
	})

	refreshBtn := widget.NewButtonWithIcon("Refrescar", theme.ViewRefreshIcon(), func() {
		ui.refreshWhitelistView()
		ui.SetStatus("Lista blanca actualizada.")
	})

	listCard := widget.NewCard("Dominios permitidos", "", container.NewVScroll(ui.WhitelistBox))
	top := container.NewVBox(
		widget.NewLabel("Gestor de páginas blancas de firma."),
		container.NewHBox(ui.WhitelistInput, addBtn, removeBtn, refreshBtn),
	)
	split := container.NewVSplit(top, listCard)
	split.Offset = 0.22
	return container.NewPadded(split)
}

func (ui *FyneUI) refreshWhitelistView() {
	domains := trustedSigningDomainsSnapshot()
	if len(domains) == 0 {
		ui.WhitelistBox.SetText("(sin dominios en lista blanca)")
		return
	}
	ui.WhitelistBox.SetText(strings.Join(domains, "\n"))
}

func (ui *FyneUI) buildTestsTab() fyne.CanvasObject {
	ui.TestsStatusBox = widget.NewMultiLineEntry()
	ui.TestsStatusBox.Disable()
	ui.TestsStatusBox.SetText("Panel de pruebas listo.")

	runSelectedBtn := widget.NewButtonWithIcon("Ejecutar seleccionadas", theme.MediaPlayIcon(), func() {
		ui.runBackendScriptTests(false)
	})
	runAllBtn := widget.NewButtonWithIcon("Ejecutar todas", theme.MediaPlayIcon(), func() {
		ui.runBackendScriptTests(true)
	})
	selectAllBtn := widget.NewButtonWithIcon("Seleccionar todas", theme.ConfirmIcon(), func() {
		for i := range ui.ScriptTests {
			ui.ScriptTests[i].Selected = true
		}
		ui.buildUI()
		ui.SetStatus("Todas las pruebas marcadas.")
	})
	clearAllBtn := widget.NewButtonWithIcon("Limpiar selección", theme.CancelIcon(), func() {
		for i := range ui.ScriptTests {
			ui.ScriptTests[i].Selected = false
		}
		ui.buildUI()
		ui.SetStatus("Selección de pruebas limpiada.")
	})
	openScriptsDocBtn := widget.NewButtonWithIcon("Abrir guía de scripts", theme.HelpIcon(), func() {
		root, err := fyneResolveScriptsRootDir()
		if err != nil {
			ui.SetStatus("No se encontró directorio base de scripts: " + err.Error())
			return
		}
		doc := filepath.Join(root, "docs", "SCRIPTS_PRUEBAS.md")
		if err := openExternal(doc); err != nil {
			ui.SetStatus("No se pudo abrir la guía de scripts: " + err.Error())
			return
		}
		ui.SetStatus("Guía de scripts abierta.")
	})

	listBox := container.NewVBox()
	for i := range ui.ScriptTests {
		tc := ui.ScriptTests[i]
		idx := i
		chk := widget.NewCheck(tc.Nombre, func(v bool) {
			ui.ScriptTests[idx].Selected = v
		})
		chk.SetChecked(tc.Selected)
		desc := widget.NewLabel(tc.Descripcion)
		runOne := widget.NewButtonWithIcon("Ejecutar", theme.MediaPlayIcon(), func() {
			ui.runSingleBackendScriptTest(idx)
		})
		helpOne := widget.NewButtonWithIcon("Ayuda", theme.HelpIcon(), func() {
			ui.SetStatus(tc.Ayuda)
		})
		row := widget.NewCard(tc.Nombre, "", container.NewVBox(
			desc,
			container.NewHBox(chk, runOne, helpOne),
		))
		listBox.Add(row)
	}

	top := container.NewVBox(
		widget.NewLabel("Pruebas automatizadas del proyecto."),
		container.NewHBox(runSelectedBtn, runAllBtn, selectAllBtn, clearAllBtn, openScriptsDocBtn),
	)
	listPanel := widget.NewCard("Listado de pruebas", "", container.NewVScroll(listBox))
	resultPanel := widget.NewCard("Resultado de pruebas", "", container.NewVScroll(ui.TestsStatusBox))
	split := container.NewVSplit(listPanel, resultPanel)
	split.Offset = 0.62
	return container.NewPadded(container.NewBorder(top, nil, nil, nil, split))
}

func (ui *FyneUI) runSingleBackendScriptTest(index int) {
	if index < 0 || index >= len(ui.ScriptTests) {
		return
	}
	for i := range ui.ScriptTests {
		ui.ScriptTests[i].Selected = i == index
	}
	ui.runBackendScriptTests(false)
}

func (ui *FyneUI) runBackendScriptTests(all bool) {
	ui.mu.Lock()
	if ui.TestBusy {
		ui.mu.Unlock()
		ui.SetStatus("Ya hay pruebas en ejecución.")
		return
	}
	ui.TestBusy = true
	ui.mu.Unlock()

	go func() {
		defer func() {
			ui.mu.Lock()
			ui.TestBusy = false
			ui.mu.Unlock()
		}()
		root, err := fyneResolveScriptsRootDir()
		if err != nil {
			ui.SetStatus("No se encontró directorio de scripts: " + err.Error())
			return
		}

		indices := make([]int, 0, len(ui.ScriptTests))
		for i := range ui.ScriptTests {
			if all || ui.ScriptTests[i].Selected {
				indices = append(indices, i)
			}
		}
		if len(indices) == 0 {
			ui.SetStatus("Seleccione al menos una prueba.")
			return
		}

		ui.setTestsOutput("Iniciando pruebas...\n")
		for _, idx := range indices {
			tc := ui.ScriptTests[idx]
			if len(tc.Comando) == 0 {
				ui.appendTestsOutput(tc.Nombre + ": ERROR comando vacío\n")
				continue
			}
			start := time.Now()
			ui.appendTestsOutput(tc.Nombre + ": EN CURSO\n")
			cmd := exec.Command(tc.Comando[0], tc.Comando[1:]...)
			cmd.Dir = root
			out, runErr := cmd.CombinedOutput()
			if runErr != nil {
				ui.appendTestsOutput(tc.Nombre + ": ERROR\n" + fyneTrimOutputForUI(string(out), 2000) + "\n")
				continue
			}
			ui.appendTestsOutput(tc.Nombre + ": PASADO (" + time.Since(start).Round(time.Millisecond).String() + ")\n")
		}
		ui.appendTestsOutput("Pruebas finalizadas.\n")
	}()
}

func (ui *FyneUI) setTestsOutput(msg string) {
	fyne.Do(func() {
		if ui.TestsStatusBox != nil {
			ui.TestsStatusBox.SetText(msg)
		}
	})
}

func (ui *FyneUI) appendTestsOutput(msg string) {
	fyne.Do(func() {
		if ui.TestsStatusBox == nil {
			return
		}
		if strings.TrimSpace(ui.TestsStatusBox.Text) == "" {
			ui.TestsStatusBox.SetText(msg)
			return
		}
		ui.TestsStatusBox.SetText(ui.TestsStatusBox.Text + msg)
	})
}

func (ui *FyneUI) buildSettingsTab() fyne.CanvasObject {
	strictChk := widget.NewCheck("Compatibilidad estricta", func(v bool) {
		ui.StrictCompat = v
	})
	strictChk.SetChecked(ui.StrictCompat)

	invalidPDFChk := widget.NewCheck("Permitir PDF no válido (bajo responsabilidad)", func(v bool) {
		ui.AllowInvalidPDF = v
	})
	invalidPDFChk.SetChecked(ui.AllowInvalidPDF)

	expertChk := widget.NewCheck("Modo experto", func(v bool) {
		ui.ExpertMode = v
	})
	expertChk.SetChecked(ui.ExpertMode)

	saveBtn := widget.NewButtonWithIcon("Guardar preferencias", theme.DocumentSaveIcon(), func() {
		if err := ui.savePreferences(); err != nil {
			ui.SetStatus("No se pudieron guardar preferencias: " + err.Error())
			return
		}
		ui.SetStatus("Preferencias guardadas.")
	})

	return container.NewPadded(container.NewVBox(
		widget.NewLabel("Opciones de configuración de la aplicación."),
		strictChk,
		invalidPDFChk,
		expertChk,
		saveBtn,
	))
}

func (ui *FyneUI) buildHelpTab() fyne.CanvasObject {
	openHelp := widget.NewButtonWithIcon("Manual exhaustivo", theme.HelpIcon(), func() {
		manualPath, err := fyneResolveHelpManualPath()
		if err != nil {
			ui.SetStatus("No se encontró el manual de ayuda: " + err.Error())
			return
		}
		if err := openExternal(manualPath); err != nil {
			ui.SetStatus("No se pudo abrir el manual de ayuda: " + err.Error())
			return
		}
		ui.SetStatus("Manual exhaustivo abierto.")
	})
	openUser := widget.NewButtonWithIcon("Manual de usuario", theme.DocumentIcon(), func() {
		if err := openExternal("USER_MANUAL.md"); err != nil {
			ui.SetStatus("No se pudo abrir USER_MANUAL.md: " + err.Error())
			return
		}
		ui.SetStatus("Manual de usuario abierto.")
	})
	openDev := widget.NewButtonWithIcon("Manual de desarrollo", theme.DocumentIcon(), func() {
		if err := openExternal("DEVELOPER_MANUAL.md"); err != nil {
			ui.SetStatus("No se pudo abrir DEVELOPER_MANUAL.md: " + err.Error())
			return
		}
		ui.SetStatus("Manual de desarrollo abierto.")
	})

	return container.NewPadded(container.NewVBox(
		widget.NewLabel("Centro de ayuda y documentación."),
		container.NewHBox(openHelp, openUser, openDev),
		widget.NewLabel("Todos los mensajes y resultados quedan reflejados en el panel de mensajes."),
	))
}

func (ui *FyneUI) buildDropZone(onFile func(string)) fyne.CanvasObject {
	bg := canvas.NewRectangle(color.NRGBA{R: 237, G: 244, B: 255, A: 255})
	bg.StrokeColor = color.NRGBA{R: 80, G: 130, B: 210, A: 180}
	bg.StrokeWidth = 2
	bg.CornerRadius = 12

	icon := widget.NewIcon(theme.DocumentIcon())
	label := canvas.NewText("  Arrastra tu PDF aquí  ·  o haz clic para buscar", color.NRGBA{R: 50, G: 80, B: 170, A: 220})
	label.TextSize = 14
	label.TextStyle = fyne.TextStyle{Italic: true}

	inner := container.NewCenter(container.NewHBox(icon, label))

	btn := widget.NewButton("", func() {
		ui.openPDFPicker(onFile)
	})
	btn.Importance = widget.LowImportance

	return container.NewStack(
		container.NewGridWrap(fyne.NewSize(860, 100), bg),
		inner,
		container.NewGridWrap(fyne.NewSize(860, 100), btn),
	)
}

func (ui *FyneUI) openPDFPicker(onFile func(string)) {
	picker := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil {
			ui.SetStatus("Error abriendo selector de archivo: " + err.Error())
			return
		}
		if rc == nil {
			ui.SetStatus("Selección de archivo cancelada.")
			return
		}
		defer rc.Close()

		path := normalizeFynePath(rc.URI().Path())
		if path == "" {
			ui.SetStatus("No se pudo resolver la ruta del archivo seleccionado.")
			return
		}
		if strings.ToLower(filepath.Ext(path)) != ".pdf" {
			ui.SetStatus("Seleccione un archivo PDF (.pdf).")
			return
		}
		onFile(path)
	}, ui.Window)
	picker.SetFilter(storage.NewExtensionFileFilter([]string{".pdf"}))
	picker.Show()
}

func (ui *FyneUI) handleDroppedItems(items []fyne.URI) {
	if len(items) == 0 {
		ui.SetStatus("No se recibió ningún archivo al soltar.")
		return
	}
	for _, it := range items {
		if it == nil {
			continue
		}
		path := normalizeFynePath(it.Path())
		if path == "" {
			continue
		}
		if strings.ToLower(filepath.Ext(path)) != ".pdf" {
			continue
		}
		ui.InputFile = path
		fyne.Do(func() {
			if ui.FileLabel != nil {
				ui.FileLabel.Text = path
				ui.FileLabel.Refresh()
			}
			if ui.VerifyFileLabel != nil {
				ui.VerifyFileLabel.Text = path
				ui.VerifyFileLabel.Refresh()
			}
		})
		ui.SetStatus("PDF cargado por arrastrar y soltar: " + path)
		return
	}
	ui.SetStatus("Los archivos soltados no son PDF válidos para esta operación.")
}

func (ui *FyneUI) syncSealValuesFromEntries(page, x, y, w, h *widget.Entry) {
	if page != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(page.Text)); err == nil && v > 0 {
			ui.SealPage = uint32(v)
		}
	}
	if x != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(x.Text), 64); err == nil {
			ui.SealX = clamp01(v)
		}
	}
	if y != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(y.Text), 64); err == nil {
			ui.SealY = clamp01(v)
		}
	}
	if w != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(w.Text), 64); err == nil {
			ui.SealW = clamp01(v)
		}
	}
	if h != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(h.Text), 64); err == nil {
			ui.SealH = clamp01(v)
		}
	}
}

func (ui *FyneUI) buildFynePadesSignatureOptions() map[string]interface{} {
	if !ui.VisibleSeal {
		return nil
	}
	format := detectLocalSignFormat(ui.InputFile)
	if format != "pades" {
		return nil
	}
	pageW := 595.28
	pageH := 841.89
	x := clamp01(ui.SealX) * pageW
	y := clamp01(ui.SealY) * pageH
	w := clamp01(ui.SealW) * pageW
	h := clamp01(ui.SealH) * pageH
	return map[string]interface{}{
		"visibleSeal":      true,
		"visibleSealRectX": x,
		"visibleSealRectY": y,
		"visibleSealRectW": w,
		"visibleSealRectH": h,
		"page":             ui.SealPage,
	}
}

func (ui *FyneUI) buildCertCards() fyne.CanvasObject {
	var cards []fyne.CanvasObject

	for i, cert := range ui.Certs {
		c := cert // copy range variable for closure
		cIdx := i

		name := certificateBestDisplayName(c)
		title := name
		if len(title) > 20 {
			title = title[:17] + "..."
		}

		icon := theme.AccountIcon()
		if isRepresentationCertificate(c) {
			icon = theme.HomeIcon() // Representation
		}

		content := container.NewVBox(
			container.NewCenter(widget.NewIcon(icon)),
			widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewLabelWithStyle(certValidityStatus(c.ValidFrom, c.ValidTo), fyne.TextAlignCenter, fyne.TextStyle{Italic: true}),
		)

		card := widget.NewCard("", "", content)

		btnText := "Seleccionar"
		btnImportance := widget.LowImportance
		if ui.SelectedCert != nil && ui.SelectedCert.ID == c.ID {
			btnText = "Seleccionado ✓"
			btnImportance = widget.HighImportance
		}

		tapBtn := widget.NewButton(btnText, func() {
			ui.SelectedCert = &ui.Certs[cIdx]
			ui.SetStatus("Certificado actual: " + name)
			// Trigger a re-render of the cards to update the selected state colors
			if ui.CertScroll != nil {
				ui.CertScroll.Content = ui.buildCertCards()
				ui.CertScroll.Refresh()
			}
			if ui.Protocol != nil && normalizeProtocolAction(ui.Protocol.Action) == "batch" {
				go ui.handleProtocolBatchFyne()
			}
		})
		tapBtn.Importance = btnImportance

		// Combine card and button vertically instead of stacking on top of each other
		fullCard := container.NewBorder(nil, container.NewPadded(tapBtn), nil, nil, card)

		cards = append(cards, container.NewGridWrap(fyne.NewSize(205, 185), fullCard))
	}

	// Add Import botón siempre visible
	addContent := container.NewCenter(container.NewVBox(
		container.NewCenter(widget.NewIcon(theme.ContentAddIcon())),
		widget.NewLabelWithStyle("Importar\ncertificado", fyne.TextAlignCenter, fyne.TextStyle{}),
	))
	addCard := widget.NewCard("", "", addContent)
	addTap := widget.NewButton("Buscar en PC", func() {
		if runtime.GOOS == "windows" {
			ui.SetStatus("Abriendo asistente de importación de Windows...")
			exec.Command("rundll32", "cryptext.dll,CryptExtOpenCER").Start()
		} else {
			ui.SetStatus("Abra el almacén de certificados de su SO e importe.")
		}
	})
	addTap.Importance = widget.LowImportance

	fullAddCard := container.NewBorder(nil, container.NewPadded(addTap), nil, nil, addCard)
	cards = append(cards, container.NewGridWrap(fyne.NewSize(205, 185), fullAddCard))

	return container.NewHBox(cards...)
}

func (ui *FyneUI) loadCertificates() {
	certs, err := ui.Core.LoadCertificates()
	if err != nil {
		ui.SetStatus("Error leyendo certificados: " + err.Error())
		log.Printf("Error GetSystemCertificates: %v", err)
		return
	}
	ui.Certs = certs
}

func normalizeFynePath(p string) string {
	if p == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		if len(p) > 2 && p[0] == '/' && p[2] == ':' {
			return p[1:]
		}
	}
	return p
}

func (ui *FyneUI) signCurrentFileCore() {
	if ui.Core == nil {
		ui.SetStatus("Servicio de firma no inicializado.")
		return
	}
	if ui.Protocol != nil {
		ui.signCurrentProtocolCore(ui.Protocol)
		return
	}

	policy := CoreOverwriteRename
	format := detectLocalSignFormat(ui.InputFile)
	target := buildLocalSignedOutputPath(ui.InputFile, format)
	if _, err := os.Stat(target); err == nil {
		overwrite, askErr := protocolConfirmOverwriteDialog(target)
		if askErr != nil {
			ui.SetStatus("No se pudo mostrar confirmación de sobrescritura. Se guardará con nombre alternativo.")
			log.Printf("[FyneUI] confirm overwrite error: %v", askErr)
		} else if overwrite {
			policy = CoreOverwriteForce
		}
	}

	req := CoreSignRequest{
		FilePath:         ui.InputFile,
		CertificateID:    ui.SelectedCert.ID,
		Action:           ui.ExpertOperation,
		Format:           format,
		AllowInvalidPDF:  ui.AllowInvalidPDF,
		SaveToDisk:       true,
		OverwritePolicy:  policy,
		SignatureOptions: ui.buildFynePadesSignatureOptions(),
	}
	start := time.Now()
	res, err := ui.Core.SignFile(req)
	if err != nil {
		ui.SetStatus(withSolution(buildUserSignErrorMessage(err, "pades"), "Seleccione un PDF válido y revise certificado/permisos de carpeta."))
		return
	}
	ui.LastSigned = res.OutputPath
	ui.applyLastSignedToVerify()
	if res.Overwrote {
		ui.SetStatus("¡Firmado con éxito! Se sobrescribió: " + res.OutputPath)
		return
	}
	if res.Renamed {
		ui.SetStatus("¡Firmado con éxito! El archivo existía y se guardó como: " + res.OutputPath)
		return
	}
	ui.SetStatus(fmt.Sprintf("¡Firmado con éxito! Guardado en: %s\nTiempo: %s", res.OutputPath, humanDuration(time.Since(start))))
}

func (ui *FyneUI) exportSelectedCertificateExpertFyne() {
	if ui.SelectedCert == nil {
		ui.SetStatus(withSolution("Seleccione un certificado para exportarlo.", "Elija un certificado de la lista y reintente."))
		return
	}
	cert := *ui.SelectedCert

	safeID := strings.ToLower(strings.TrimSpace(cert.ID))
	safeID = strings.ReplaceAll(safeID, ":", "")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	if safeID == "" || safeID == "-" {
		safeID = "certificado"
	}
	if len(safeID) > 12 {
		safeID = safeID[:12]
	}
	fileName := "certificado_" + safeID + ".p12"
	home, _ := os.UserHomeDir()
	defaultPath := filepath.Join(home, "Descargas", fileName)

	selectedPath, canceled, err := protocolSaveDialog(defaultPath, "p12,pfx")
	if canceled {
		ui.SetStatus("Exportación de certificado cancelada.")
		return
	}
	if err != nil {
		ui.SetStatus(withSolution("No se pudo abrir el diálogo de guardado: "+err.Error(), "Reintenta y comprueba permisos del sistema."))
		return
	}
	selectedPath = strings.TrimSpace(selectedPath)
	if selectedPath == "" {
		ui.SetStatus("No se seleccionó ruta de guardado.")
		return
	}

	pass := strings.TrimSpace(ui.ExportTempPass)
	if pass == "" {
		generated, genErr := generateStrongTempPassword(24)
		if genErr != nil {
			ui.SetStatus(withSolution("No se pudo generar clave temporal de exportación: "+genErr.Error(), "Reintenta la operación."))
			return
		}
		ui.ExportTempPass = generated
		pass = generated
	}
	if !isStrongPassword(pass) {
		ui.SetStatus(withSolution("La clave temporal no cumple requisitos de seguridad alta.", "Genera una nueva clave temporal y vuelve a exportar."))
		return
	}

	p12Path, exportErr := signer.ExportCertificateP12ByID(cert.ID, pass, nil)
	if exportErr != nil {
		ui.SetStatus(withSolution("No se pudo exportar el certificado a PKCS#12: "+exportErr.Error(), "Comprueba si el certificado permite exportación PKCS#12."))
		return
	}
	defer os.Remove(p12Path)

	p12Data, readErr := os.ReadFile(p12Path)
	if readErr != nil {
		ui.SetStatus(withSolution("No se pudo leer el fichero PKCS#12 generado: "+readErr.Error(), "Reintenta la exportación."))
		return
	}
	if writeErr := os.WriteFile(selectedPath, p12Data, 0o600); writeErr != nil {
		ui.SetStatus(withSolution("No se pudo guardar el certificado exportado: "+writeErr.Error(), "Comprueba permisos de escritura en la ruta seleccionada."))
		return
	}
	ui.SetStatus("Certificado exportado en formato PKCS#12 en: " + selectedPath + ". Clave temporal disponible para copiar.")
}

func (ui *FyneUI) runExpertSelectCertDialogFyne() {
	if len(ui.Certs) == 0 {
		ui.SetStatus(withSolution("No hay certificados disponibles.", "Importa o recarga certificados y vuelve a intentarlo."))
		return
	}
	chosen, canceled, err := protocolSelectCertDialog(ui.Certs)
	if canceled {
		ui.SetStatus("Selección avanzada de certificado cancelada.")
		return
	}
	if err != nil {
		ui.SetStatus(withSolution("Error en selección avanzada de certificado: "+err.Error(), "Reintenta la selección y revisa el almacén de certificados."))
		return
	}
	if chosen < 0 || chosen >= len(ui.Certs) {
		ui.SetStatus(withSolution("Selección de certificado inválida.", "Reintenta la selección avanzada."))
		return
	}
	ui.SelectedCert = &ui.Certs[chosen]
	if ui.CertScroll != nil {
		fyne.Do(func() {
			ui.CertScroll.Content = ui.buildCertCards()
			ui.CertScroll.Refresh()
		})
	}
	ui.SetStatus("Selección avanzada de certificado completada.")
}

func (ui *FyneUI) runExpertLoadDialogFyne() {
	initialPath := strings.TrimSpace(ui.InputFile)
	paths, canceled, err := protocolLoadDialog(initialPath, "", false)
	if canceled {
		ui.SetStatus("Carga manual cancelada.")
		return
	}
	if err != nil {
		ui.SetStatus(withSolution("Error en carga manual (LOAD): "+err.Error(), "Revisa permisos y vuelve a intentarlo."))
		return
	}
	if len(paths) == 0 || strings.TrimSpace(paths[0]) == "" {
		ui.SetStatus("No se seleccionó fichero en carga manual.")
		return
	}
	path := strings.TrimSpace(paths[0])
	ui.InputFile = path
	fyne.Do(func() {
		if ui.FileLabel != nil {
			ui.FileLabel.Text = path
			ui.FileLabel.Refresh()
		}
		if ui.VerifyFileLabel != nil {
			ui.VerifyFileLabel.Text = path
			ui.VerifyFileLabel.Refresh()
		}
	})
	ui.SetStatus("Fichero cargado mediante flujo manual LOAD.")
}

func (ui *FyneUI) runExpertSaveCopyFyne() {
	src := strings.TrimSpace(ui.InputFile)
	if src == "" {
		ui.SetStatus(withSolution("Seleccione un fichero para guardado manual.", "Carga primero un fichero origen y reintenta."))
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		ui.SetStatus(withSolution("No se pudo leer el fichero origen para SAVE: "+err.Error(), "Comprueba ruta y permisos de lectura."))
		return
	}
	defaultPath, err := buildSaveTargetPath(filepath.Base(src), strings.TrimPrefix(filepath.Ext(src), "."))
	if err != nil {
		ui.SetStatus(withSolution("No se pudo preparar ruta de guardado: "+err.Error(), "Reintenta con otra ruta o nombre de fichero."))
		return
	}
	selectedPath, canceled, err := protocolSaveDialog(defaultPath, strings.TrimPrefix(filepath.Ext(src), "."))
	if canceled {
		ui.SetStatus("Guardado manual cancelado.")
		return
	}
	if err != nil {
		ui.SetStatus(withSolution("Error en guardado manual (SAVE): "+err.Error(), "Revisa permisos y vuelve a abrir el diálogo de guardado."))
		return
	}
	selectedPath = strings.TrimSpace(selectedPath)
	if selectedPath == "" {
		ui.SetStatus("No se seleccionó ruta de guardado.")
		return
	}
	if writeErr := os.WriteFile(selectedPath, data, 0o644); writeErr != nil {
		ui.SetStatus(withSolution("No se pudo guardar copia manual: "+writeErr.Error(), "Comprueba permisos de escritura en destino."))
		return
	}
	ui.SetStatus("Guardado manual completado en: " + selectedPath)
}

func (ui *FyneUI) runLocalBatchFromInputFyne() {
	if ui.SelectedCert == nil {
		ui.SetStatus(withSolution("Seleccione un certificado para ejecutar el lote.", "Elija un certificado apto para firma."))
		return
	}
	path := strings.TrimSpace(ui.InputFile)
	if path == "" {
		ui.SetStatus(withSolution("Seleccione un fichero de lote JSON/XML.", "Seleccione un fichero .json o .xml y reintente."))
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		ui.SetStatus(withSolution("No se pudo leer el fichero de lote: "+err.Error(), "Compruebe ruta y permisos de lectura."))
		return
	}
	isJSON := strings.EqualFold(filepath.Ext(path), ".json")
	req, err := parseBatchRequest(raw, isJSON)
	if err != nil {
		ui.SetStatus(withSolution("Lote inválido: "+err.Error(), "Revise la estructura del lote (JSON/XML) y vuelva a intentarlo."))
		return
	}
	if len(req.SingleSigns) == 0 {
		ui.SetStatus(withSolution("Lote sin operaciones.", "Incluya al menos una operación de firma en el lote."))
		return
	}
	ui.SetStatus("Procesando lote local...")
	srv := &WebSocketServer{ui: nil}
	certID := strings.TrimSpace(ui.SelectedCert.ID)
	globalExtra := decodeBatchExtraParams(req.ExtraParams)
	results := make([]batchSingleResult, 0, len(req.SingleSigns))
	errorOcurred := false
	for _, item := range req.SingleSigns {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			id = "unknown"
		}
		if errorOcurred && req.StopOnError {
			results = append(results, batchSingleResult{ID: id, Result: batchResultSkipped})
			continue
		}
		res := srv.executeBatchSingle(nil, item, req, certID, globalExtra)
		if res.Result == batchResultError {
			errorOcurred = true
			if req.StopOnError {
				for i := range results {
					results[i].Result = batchResultSkipped
					results[i].Signature = ""
				}
			}
		}
		results = append(results, res)
	}
	respBytes, err := serializeBatchResponse(results, isJSON)
	if err != nil {
		ui.SetStatus(withSolution("No se pudo preparar la respuesta del lote: "+err.Error(), "Reintente el lote y revise la configuración de formato."))
		return
	}
	extOut := ".json"
	if !isJSON {
		extOut = ".xml"
	}
	outPath := strings.TrimSuffix(path, filepath.Ext(path)) + "_resultado_lote" + extOut
	if err := os.WriteFile(outPath, respBytes, 0o644); err != nil {
		ui.SetStatus(withSolution("Lote ejecutado, pero no se pudo guardar resultado: "+err.Error(), "Compruebe permisos de escritura en la carpeta destino."))
		return
	}
	ui.SetStatus("Lote procesado. Resultado guardado en: " + outPath)
}

func (ui *FyneUI) runTLSDiagnosticsFyne() {
	endpoints := []string{"https://autofirma.dipgra.es/version.json"}
	diagLines := make([]string, 0, len(endpoints)+1)
	diagLines = append(diagLines, "Diagnóstico TLS:")
	for _, ep := range endpoints {
		res := diagnoseTLSEndpoint(ep)
		line := fmt.Sprintf("- %s => %s | %s", ep, res.Estado, strings.TrimSpace(res.Detalle))
		if strings.TrimSpace(res.Sugerencia) != "" {
			line += " | Sugerencia: " + strings.TrimSpace(res.Sugerencia)
		}
		diagLines = append(diagLines, line)
	}
	ui.SetStatus(strings.Join(diagLines, "\n"))
}

func (ui *FyneUI) importTLSCertificateFromDialogFyne() {
	paths, canceled, err := protocolLoadDialog("", "crt,cer,pem,der", false)
	if err != nil {
		ui.SetStatus(withSolution("No se pudo abrir selector de certificado: "+summarizeServerBody(err.Error()), "Reintente e indique un fichero .crt/.cer/.pem/.der válido."))
		return
	}
	if canceled || len(paths) == 0 {
		ui.SetStatus("Instalación de certificado TLS cancelada.")
		return
	}
	selected := strings.TrimSpace(paths[0])
	if selected == "" {
		ui.SetStatus(withSolution("Ruta de certificado vacía.", "Seleccione un certificado válido para continuar."))
		return
	}
	cert, err := loadCertificateFromFile(selected)
	if err != nil {
		ui.SetStatus(withSolution("No se pudo leer el certificado: "+summarizeServerBody(err.Error()), "Asegúrese de que el fichero contiene un certificado X.509 válido."))
		return
	}
	lines, installErr := installTrustedCertificateForCurrentOS(selected, cert)
	if saved, savedLines, saveErr := saveEndpointCertificates("manual", []*x509.Certificate{cert}); saveErr != nil {
		lines = append(lines, "[TLS] Almacén local: error guardando certificado: "+summarizeServerBody(saveErr.Error()))
	} else {
		lines = append(lines, savedLines...)
		if saved > 0 {
			lines = append(lines, "[TLS] Almacén local actualizado correctamente.")
		}
	}
	if installErr != nil {
		lines = append(lines, "Resultado: instalación parcial/errores en almacenes del sistema: "+summarizeServerBody(installErr.Error()))
	} else {
		lines = append(lines, "Resultado: certificado instalado en almacenes disponibles.")
	}
	ui.SetStatus(strings.Join(lines, "\n"))
}

func (ui *FyneUI) buildFyneDiagnosticReport() string {
	epDir, epCount := endpointTrustStoreStatus()
	lines := []string{
		"autofirma_dipgra_diagnostico",
		"timestamp=" + time.Now().Format(time.RFC3339),
		"modo_ui=fyne",
		"certificados_detectados=" + fmt.Sprintf("%d", len(ui.Certs)),
		"certificado_seleccionado=" + safeDiagValue(certificateSelectedID(ui.SelectedCert)),
		"input_file=" + safeDiagValue(strings.TrimSpace(ui.InputFile)),
		"last_signed=" + safeDiagValue(strings.TrimSpace(ui.LastSigned)),
		"strict_compat=" + fmt.Sprintf("%t", ui.StrictCompat),
		"allow_invalid_pdf=" + fmt.Sprintf("%t", ui.AllowInvalidPDF),
		"expert_mode=" + fmt.Sprintf("%t", ui.ExpertMode),
		"expert_operation=" + safeDiagValue(strings.TrimSpace(ui.ExpertOperation)),
		"visible_seal=" + fmt.Sprintf("%t", ui.VisibleSeal),
		"seal_page=" + fmt.Sprintf("%d", ui.SealPage),
		"seal_rect=" + fmt.Sprintf("x=%.3f y=%.3f w=%.3f h=%.3f", ui.SealX, ui.SealY, ui.SealW, ui.SealH),
		"whitelist_count=" + fmt.Sprintf("%d", len(trustedSigningDomainsSnapshot())),
		"tls_store_dir=" + safeDiagValue(epDir),
		"tls_store_cert_count=" + fmt.Sprintf("%d", epCount),
	}
	return strings.Join(lines, "\n") + "\n"
}

func certificateSelectedID(cert *protocol.Certificate) string {
	if cert == nil {
		return ""
	}
	return strings.TrimSpace(cert.ID)
}

func (ui *FyneUI) openPadesPreviewInBrowserFyne(filePath string) error {
	if err := ui.ensurePadesPreviewServerFyne(); err != nil {
		return err
	}
	if _, err := os.Stat(filePath); err != nil {
		return err
	}
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	ui.PreviewToken = token
	ui.PreviewFile = filePath
	q := url.Values{}
	q.Set("token", token)
	q.Set("w", "595.28")
	q.Set("h", "841.89")
	previewURL := ui.PreviewBaseURL + "/pades-preview?" + q.Encode()
	return openExternal(previewURL)
}

func (ui *FyneUI) ensurePadesPreviewServerFyne() error {
	if strings.TrimSpace(ui.PreviewBaseURL) != "" {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/pades-preview", ui.handlePadesPreviewPageFyne)
	mux.HandleFunc("/pades-preview/pdf", ui.handlePadesPreviewPDFFyne)
	mux.HandleFunc("/pades-preview/save", ui.handlePadesPreviewSaveFyne)
	srv := &http.Server{Handler: mux}
	ui.PreviewBaseURL = "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

func (ui *FyneUI) handlePadesPreviewPageFyne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" || token != ui.PreviewToken {
		http.Error(w, "token inválido", http.StatusUnauthorized)
		return
	}
	pageW := parseFloatOrDefault(r.URL.Query().Get("w"), 595.28)
	pageH := parseFloatOrDefault(r.URL.Query().Get("h"), 841.89)
	ratio := pageH / pageW
	if ratio <= 0 {
		ratio = 841.89 / 595.28
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, renderPadesPreviewHTML(token, ratio))
}

func (ui *FyneUI) handlePadesPreviewPDFFyne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" || token != ui.PreviewToken {
		http.Error(w, "token inválido", http.StatusUnauthorized)
		return
	}
	filePath := strings.TrimSpace(ui.PreviewFile)
	if filePath == "" {
		http.Error(w, "pdf no disponible", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	http.ServeFile(w, r, filePath)
}

func (ui *FyneUI) handlePadesPreviewSaveFyne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" || token != ui.PreviewToken {
		http.Error(w, "token inválido", http.StatusUnauthorized)
		return
	}
	var req padesSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "json inválido", http.StatusBadRequest)
		return
	}
	if req.Page == 0 {
		req.Page = 1
	}
	ui.SealX = clamp01(req.X)
	ui.SealY = clamp01(req.Y)
	ui.SealW = clamp01(req.W)
	ui.SealH = clamp01(req.H)
	ui.SealPage = req.Page
	ui.SetStatus(fmt.Sprintf("Área recibida del visor web: x=%.1f%% y=%.1f%% ancho=%.1f%% alto=%.1f%%", ui.SealX*100, ui.SealY*100, ui.SealW*100, ui.SealH*100))
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (ui *FyneUI) applyLastSignedToVerify() {
	path := strings.TrimSpace(ui.LastSigned)
	if path == "" {
		return
	}
	ui.InputFile = path
	fyne.Do(func() {
		if ui.VerifyFileLabel != nil {
			ui.VerifyFileLabel.Text = path
			ui.VerifyFileLabel.Refresh()
		}
	})
}

func (ui *FyneUI) verifyCurrentFileCore() {
	if ui.Core == nil {
		ui.SetStatus("Servicio de verificación no inicializado.")
		return
	}
	start := time.Now()
	res, err := ui.Core.VerifyFile(ui.InputFile, "")
	if err != nil {
		ui.SetStatus(withSolution("Error en la verificación: "+translateVerifyErrorToSpanish(err), "Seleccione un PDF firmado válido y reintente."))
		return
	}
	ui.SetStatus(summarizeVerifyResult(res.Result) + "\nTiempo: " + humanDuration(time.Since(start)))
}

func (ui *FyneUI) checkCertificatesCore() {
	if ui.Core == nil {
		ui.SetStatus("Servicio de certificados no inicializado.")
		return
	}
	ui.SetStatus("Comprobando certificados (firma CAdES de prueba)...")
	checked, okCount, failCount := ui.Core.CheckCertificates(ui.Certs)
	ui.Certs = checked
	if ui.CertScroll != nil {
		fyne.Do(func() {
			ui.CertScroll.Content = ui.buildCertCards()
			ui.CertScroll.Refresh()
		})
	}
	ui.SetStatus(fmt.Sprintf("Comprobación finalizada. Aptos: %d, No aptos: %d", okCount, failCount))
}

func hasPDFHeader(path string) (bool, string) {
	f, err := os.Open(path)
	if err != nil {
		return false, "no se pudo abrir (" + err.Error() + ")"
	}
	defer f.Close()

	buf := make([]byte, 5)
	n, err := io.ReadFull(f, buf)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, "archivo demasiado corto para ser PDF"
		}
		return false, "error leyendo cabecera (" + err.Error() + ")"
	}
	if n < 5 || string(buf) != "%PDF-" {
		return false, "cabecera distinta de %PDF-"
	}
	return true, ""
}

func (ui *FyneUI) initScriptTests() {
	if runtime.GOOS == "windows" {
		ps := []string{"powershell", "-ExecutionPolicy", "Bypass", "-File"}
		ui.ScriptTests = []FyneScriptTest{
			{ID: "test_active_go", Nombre: "Tests Go activos", Descripcion: "Ejecuta pruebas de paquetes cmd/ y pkg/.", Ayuda: "Ejecuta go test de paquetes activos.", Comando: append(append([]string{}, ps...), "scripts/windows/test_active_go.ps1"), Selected: true},
			{ID: "smoke_native", Nombre: "Smoke host nativo", Descripcion: "Ping + certificados + firma/verificación base.", Ayuda: "Validación rápida del host nativo.", Comando: append(append([]string{}, ps...), "scripts/windows/smoke_native_host.ps1"), Selected: true},
			{ID: "full_validation", Nombre: "Validación completa (Windows)", Descripcion: "Pipeline completo local para Windows.", Ayuda: "Ejecuta batería integral de validación.", Comando: append(append([]string{}, ps...), "scripts/windows/run_full_validation_windows.ps1"), Selected: false},
		}
		return
	}
	ui.ScriptTests = []FyneScriptTest{
		{ID: "test_active_go", Nombre: "Tests Go activos", Descripcion: "Ejecuta pruebas de paquetes cmd/ y pkg/.", Ayuda: "Ejecuta go test de paquetes activos.", Comando: []string{"bash", "scripts/test_active_go.sh"}, Selected: true},
		{ID: "smoke_native", Nombre: "Smoke host nativo", Descripcion: "Ping + certificados + firma/verificación base.", Ayuda: "Validación rápida del host nativo.", Comando: []string{"bash", "scripts/smoke_native_host.sh"}, Selected: true},
		{ID: "e2e_sign_cades", Nombre: "E2E firma CAdES", Descripcion: "Realiza firma CAdES mínima con certificado activo.", Ayuda: "Comprueba firma real extremo a extremo.", Comando: []string{"bash", "scripts/e2e_native_request.sh", "sign-cades"}, Selected: false},
		{ID: "full_validation", Nombre: "Validación completa", Descripcion: "Pipeline completo local con reporte.", Ayuda: "Ejecuta batería integral de validación.", Comando: []string{"bash", "scripts/run_full_validation.sh"}, Selected: false},
	}
}

func (ui *FyneUI) loadPreferences() {
	path := fynePreferencesPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var prefs FyneUIPreferences
	if err := json.Unmarshal(raw, &prefs); err != nil {
		log.Printf("[FyneUI] No se pudo parsear preferencias: %v", err)
		return
	}
	ui.StrictCompat = prefs.StrictCompat
	ui.AllowInvalidPDF = prefs.AllowInvalidPDF
	ui.ExpertMode = prefs.ExpertMode
}

func (ui *FyneUI) savePreferences() error {
	prefs := FyneUIPreferences{
		StrictCompat:    ui.StrictCompat,
		AllowInvalidPDF: ui.AllowInvalidPDF,
		ExpertMode:      ui.ExpertMode,
		UpdatedAt:       time.Now().Format(time.RFC3339),
	}
	path := fynePreferencesPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0o644)
}

func fynePreferencesPath() string {
	baseDir := filepath.Join(os.Getenv("HOME"), ".config", "AutofirmaDipgra")
	if runtime.GOOS == "windows" {
		if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
			baseDir = filepath.Join(appData, "AutofirmaDipgra")
		}
	}
	return filepath.Join(baseDir, "ui_prefs.json")
}

func fyneResolveScriptsRootDir() (string, error) {
	candidates := make([]string, 0, 5)
	if wd, err := os.Getwd(); err == nil && strings.TrimSpace(wd) != "" {
		candidates = append(candidates, wd)
	}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, exeDir)
		candidates = append(candidates, filepath.Join(exeDir, ".."))
		candidates = append(candidates, filepath.Join(exeDir, "..", ".."))
	}
	candidates = append(candidates, "/opt/autofirma-dipgra")

	for _, c := range candidates {
		root := filepath.Clean(strings.TrimSpace(c))
		if root == "" {
			continue
		}
		markerSh := filepath.Join(root, "scripts", "test_active_go.sh")
		markerPs1 := filepath.Join(root, "scripts", "windows", "test_active_go.ps1")
		if st, err := os.Stat(markerSh); err == nil && !st.IsDir() {
			return root, nil
		}
		if st, err := os.Stat(markerPs1); err == nil && !st.IsDir() {
			return root, nil
		}
	}
	return "", fmt.Errorf("no se encontró directorio de scripts de prueba")
}

func fyneTrimOutputForUI(raw string, maxChars int) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "(sin salida)"
	}
	if maxChars <= 0 || len(s) <= maxChars {
		return s
	}
	return s[:maxChars] + "\n...[salida recortada]..."
}

func fyneResolveHelpManualPath() (string, error) {
	const manualRel = "docs/GUI_AYUDA_EXHAUSTIVA.md"
	candidates := make([]string, 0, 5)

	if wd, err := os.Getwd(); err == nil && strings.TrimSpace(wd) != "" {
		candidates = append(candidates, filepath.Join(wd, manualRel))
	}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(exeDir, manualRel))
		candidates = append(candidates, filepath.Join(exeDir, "GUI_AYUDA_EXHAUSTIVA.md"))
		candidates = append(candidates, filepath.Join(exeDir, "..", manualRel))
	}
	candidates = append(candidates,
		filepath.Join("/opt/autofirma-dipgra", manualRel),
		filepath.Join("/opt/autofirma-dipgra", "GUI_AYUDA_EXHAUSTIVA.md"),
	)

	seen := make(map[string]struct{}, len(candidates))
	for _, p := range candidates {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "", errors.New("no se encontró GUI_AYUDA_EXHAUSTIVA.md en rutas conocidas: " + strings.Join(keys, ", "))
}
