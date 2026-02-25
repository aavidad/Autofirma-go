// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
)

var errProtocolUserCanceled = errors.New("protocol operation canceled by user")

func (ui *FyneUI) HandleProtocolInit(uriString string) {
	ui.SetStatus("Iniciando modo protocolo web...")

	state, err := ParseProtocolURI(uriString)
	if err != nil {
		log.Printf("[FyneUI][Protocol] Error parseando URI protocolaria: %v uri=%q", err, uriString)
		ui.SetStatus("Error protocolo: " + err.Error())
		return
	}

	ui.mu.Lock()
	ui.Protocol = state
	ui.mu.Unlock()

	log.Printf("[FyneUI][Protocol] Solicitud web recibida: %s", protocolRequestSummaryES(state))
	action := normalizeProtocolAction(state.Action)

	if action == "websocket" {
		ui.SetStatus("Solicitud de arranque WebSocket detectada. Iniciando servidor local...")
		go ui.handleWebSocketLaunchFyne(uriString)
		return
	}
	if action == "service" {
		ui.SetStatus("Solicitud de arranque service detectada. Iniciando servicio local...")
		go ui.handleLegacyServiceLaunchFyne(state)
		return
	}

	if action == "selectcert" {
		ui.SetStatus("Solicitud de identificación recibida. Seleccione su certificado.")
		go ui.handleProtocolSelectCertFyne(state)
		return
	}
	if action == "batch" {
		if ui.ProtocolQuickMode {
			ui.SetStatus("Solicitud de lote recibida. Seleccione certificado.")
			go ui.runProtocolQuickBatch(state)
			return
		}
		ui.SetStatus("Solicitud de lote recibida. Seleccione certificado y pulse 'Procesar lote local'.")
		return
	}

	ui.SetStatus("Descargando documento del servidor...")
	go func() {
		path, err := state.DownloadFile()
		if err != nil {
			ui.SetStatus("Error descarga: " + err.Error())
			return
		}

		if strings.TrimSpace(path) != "" {
			content, readErr := os.ReadFile(path)
			if readErr == nil && strings.HasPrefix(string(content), "<sign>") {
				actualData, format, parseErr := parseAutoFirmaXML(content, state)
				if parseErr != nil {
					ui.SetStatus("Error parseando XML: " + parseErr.Error())
					return
				}

				state.SignFormat = format
				ext := ".bin"
				switch strings.ToUpper(strings.TrimSpace(format)) {
				case "PADES":
					ext = ".pdf"
				case "XADES":
					ext = ".xml"
				}

				tmpDataFile, tmpErr := os.CreateTemp(os.TempDir(), "autofirma_xml_data_*"+ext)
				if tmpErr != nil {
					ui.SetStatus("Error guardando datos: " + tmpErr.Error())
					return
				}
				actualPath := tmpDataFile.Name()
				if _, wErr := tmpDataFile.Write(actualData); wErr != nil {
					_ = tmpDataFile.Close()
					_ = os.Remove(actualPath)
					ui.SetStatus("Error guardando datos: " + wErr.Error())
					return
				}
				if cErr := tmpDataFile.Close(); cErr != nil {
					_ = os.Remove(actualPath)
					ui.SetStatus("Error guardando datos: " + cErr.Error())
					return
				}
				path = actualPath
			}
			ui.InputFile = path
			fyneSetFileLabel(ui, path)
			if ui.ProtocolQuickMode {
				ui.SetStatus("Documento descargado. Seleccione certificado para continuar.")
				go ui.runProtocolQuickSign(state)
				return
			}
			ui.SetStatus("Documento descargado. Seleccione certificado y firme.")
			return
		}

		if ui.ProtocolQuickMode {
			ui.SetStatus("Solicitud web sin documento descargable. Seleccione un fichero local para continuar.")
			go ui.runProtocolQuickLocalFileSign(state)
			return
		}
		ui.SetStatus("Iniciado modo firma local web. Seleccione archivo y certificado.")
	}()
}

func (ui *FyneUI) handleWebSocketLaunchFyne(uriString string) {
	req, err := parseWebSocketLaunchURI(uriString)
	if err != nil {
		log.Printf("[FyneUI][Protocol] URI websocket launch inválida: %v", err)
		ui.SetStatus("Error en arranque WebSocket: " + err.Error())
		return
	}
	srv := NewWebSocketServer(req.Ports, req.SessionID, nil)
	srv.signFunc = ui.signWebSocketProtocolInteractive
	srv.saveDialogFuncAlt = protocolSaveDialog
	srv.afterSaveFunc = func(savedPath string, _ int) {
		ui.SetStatus("Firma guardada correctamente en: " + strings.TrimSpace(savedPath) + ". Ya puedes cerrar la app.")
	}
	if err := srv.Start(); err != nil {
		log.Printf("[FyneUI][Protocol] No se pudo iniciar servidor WebSocket: %v", err)
		ui.SetStatus("No se pudo iniciar servidor WebSocket local: " + err.Error())
		return
	}
	ui.mu.Lock()
	ui.WebSocketServer = srv
	ui.Protocol = &ProtocolState{IsActive: true, Action: "websocket"}
	ui.mu.Unlock()
	log.Printf("[FyneUI][Protocol] Servidor WebSocket iniciado en Fyne puertos=%v sesión=%s", req.Ports, maskSessionForLog(req.SessionID))
	ui.SetStatus("Servidor AutoFirma activo. Esperando solicitudes del navegador...")
}

func (ui *FyneUI) handleLegacyServiceLaunchFyne(state *ProtocolState) {
	if state == nil {
		ui.SetStatus("Error en arranque service: estado inválido.")
		return
	}
	srv := NewWebSocketServer([]int{DefaultWebSocketPort}, getQueryParam(state.Params, "idsession", "idSession"), nil)
	srv.signFunc = ui.signWebSocketProtocolInteractive
	srv.saveDialogFuncAlt = protocolSaveDialog
	srv.afterSaveFunc = func(savedPath string, _ int) {
		ui.SetStatus("Firma guardada correctamente en: " + strings.TrimSpace(savedPath) + ". Ya puedes cerrar la app.")
	}
	result := strings.TrimSpace(srv.processServiceRequest(state))
	if result != "OK" {
		log.Printf("[FyneUI][Protocol] Error arrancando service legacy: %s", result)
		ui.SetStatus("No se pudo iniciar servicio local: " + result)
		return
	}
	ui.mu.Lock()
	ui.WebSocketServer = srv
	ui.Protocol = &ProtocolState{IsActive: true, Action: "service", Params: state.Params}
	ui.mu.Unlock()
	log.Printf("[FyneUI][Protocol] Servicio legacy iniciado en Fyne sesión=%s", maskSessionForLog(getQueryParam(state.Params, "idsession", "idSession")))
	ui.SetStatus("Servicio AutoFirma activo. Esperando solicitudes del navegador...")
}

func (ui *FyneUI) signWebSocketProtocolInteractive(state *ProtocolState, filePath string) (SignatureResult, error) {
	if state == nil {
		return SignatureResult{}, fmt.Errorf("estado protocolario inválido")
	}
	ui.SetStatus("Solicitud de firma recibida. Preparando selección de documento/certificado...")
	localPath := strings.TrimSpace(filePath)
	if localPath == "" {
		ui.SetStatus("La web no envió documento descargable. Seleccione un PDF/archivo local.")
		paths, canceled, err := protocolLoadDialog("", "pdf,xml,csig,sig", false)
		if canceled {
			return SignatureResult{}, errProtocolUserCanceled
		}
		if err != nil {
			return SignatureResult{}, fmt.Errorf("error seleccionando fichero local: %w", err)
		}
		if len(paths) == 0 || strings.TrimSpace(paths[0]) == "" {
			return SignatureResult{}, fmt.Errorf("no se seleccionó fichero local")
		}
		localPath = strings.TrimSpace(paths[0])
	}
	ui.InputFile = localPath
	fyneSetFileLabel(ui, localPath)

	certs, err := loadCertificatesForState(state)
	if err != nil {
		return SignatureResult{}, fmt.Errorf("error cargando certificados: %w", err)
	}
	filtered, _ := filterSelectCertByDefaultStore(certs, state)
	if len(filtered) == 0 {
		filtered = certs
	}
	if len(filtered) == 0 {
		return SignatureResult{}, fmt.Errorf("no hay certificados disponibles")
	}
	ui.SetStatus("Seleccione certificado para firmar.")
	chosen, canceled, err := protocolSelectCertDialog(filtered)
	if canceled {
		return SignatureResult{}, errProtocolUserCanceled
	}
	if err != nil {
		return SignatureResult{}, fmt.Errorf("error en selector de certificado: %w", err)
	}
	if chosen < 0 || chosen >= len(filtered) {
		return SignatureResult{}, fmt.Errorf("selección de certificado inválida")
	}
	selected := filtered[chosen]
	for i := range ui.Certs {
		if ui.Certs[i].ID == selected.ID {
			ui.SelectedCert = &ui.Certs[i]
			break
		}
	}

	format := normalizeProtocolFormat(state.SignFormat)
	if format == "" {
		format = detectLocalSignFormat(localPath)
	}
	action := normalizeProtocolAction(state.Action)
	if action == "" {
		action = "sign"
	}
	ui.SetStatus("Firmando documento...")
	req := CoreSignRequest{
		FilePath:         localPath,
		CertificateID:    selected.ID,
		Action:           action,
		Format:           format,
		AllowInvalidPDF:  ui.AllowInvalidPDF,
		SaveToDisk:       false,
		OverwritePolicy:  CoreOverwriteRename,
		SignatureOptions: buildProtocolSignOptions(state, format),
	}
	if action == "sign" {
		choice, askErr := chooseActionForExistingSignedFile(localPath, format)
		if askErr != nil {
			log.Printf("[FyneUI][Protocol] confirm already-signed error: %v", askErr)
		} else if choice == existingSignedChoiceCancel {
			ui.SetStatus("Operación cancelada: el documento ya estaba firmado.")
			return SignatureResult{}, errProtocolUserCanceled
		} else if choice == existingSignedChoiceCoSign {
			action = "cosign"
			req.Action = "cosign"
			ui.SetStatus("Documento ya firmado detectado: se realizará cofirma.")
		} else if choice == existingSignedChoiceCounter {
			action = "countersign"
			req.Action = "countersign"
			ui.SetStatus("Documento ya firmado detectado: se realizará contrafirma.")
		}
	}
	res, err := ui.Core.SignFile(req)
	if err != nil {
		return SignatureResult{}, fmt.Errorf("error firmando (%s): %w", format, err)
	}
	ui.SetStatus("Firma completada. Enviando resultado a la web...")
	log.Printf("[FyneUI][Protocol] Firma WebSocket lista para retorno format=%s file=%s cert=%s", format, filepath.Base(localPath), strings.TrimSpace(selected.ID))
	return SignatureResult{
		SignatureB64: res.SignatureB64,
		CertDER:      selected.Content,
	}, nil
}

func (ui *FyneUI) handleProtocolSelectCertFyne(state *ProtocolState) {
	if state == nil {
		ui.SetStatus("Error protocolo: estado inválido en selectcert.")
		return
	}

	certs, err := loadCertificatesForState(state)
	if err != nil {
		ui.SetStatus("Error cargando certificados para identificación: " + err.Error())
		return
	}
	filtered, _ := filterSelectCertByDefaultStore(certs, state)
	if len(filtered) == 0 {
		filtered = certs
	}
	if len(filtered) == 0 {
		ui.SetStatus("No hay certificados disponibles para identificación.")
		return
	}

	chosen, canceled, err := protocolSelectCertDialog(filtered)
	if canceled {
		ui.SetStatus("Selección de certificado cancelada.")
		ui.notifyProtocolCancelAndClose(state, "selectcert")
		return
	}
	if err != nil {
		ui.SetStatus("Error en selector de certificado: " + err.Error())
		return
	}
	if chosen < 0 || chosen >= len(filtered) || len(filtered[chosen].Content) == 0 {
		ui.SetStatus("Selección de certificado inválida.")
		return
	}

	chosenCert := filtered[chosen]
	for idx := range ui.Certs {
		if ui.Certs[idx].ID == chosenCert.ID {
			ui.SelectedCert = &ui.Certs[idx]
			break
		}
	}
	fyneRefreshCertCards(ui)

	certB64 := base64.StdEncoding.EncodeToString(chosenCert.Content)
	if strings.TrimSpace(state.STServlet) != "" || strings.TrimSpace(state.RTServlet) != "" {
		if err := state.UploadCertificate(certB64); err != nil {
			ui.SetStatus("Error enviando certificado a la web: " + err.Error())
			return
		}
	}

	ui.SetStatus("Certificado de identificación enviado correctamente.")
	go ui.closeProtocolWindowAfterDelay()
}

func (ui *FyneUI) handleProtocolBatchFyne() {
	ui.mu.Lock()
	state := ui.Protocol
	ui.mu.Unlock()

	if state == nil {
		ui.SetStatus("Error protocolo: no hay estado activo para lote.")
		return
	}
	if normalizeProtocolAction(state.Action) != "batch" {
		ui.SetStatus("No hay una operación batch pendiente.")
		return
	}
	if ui.SelectedCert == nil {
		ui.SetStatus("Seleccione un certificado para procesar el lote.")
		return
	}

	ui.SetStatus("Procesando lote protocolario...")
	srv := &WebSocketServer{stickyID: strings.TrimSpace(ui.SelectedCert.ID)}
	state.Params.Set("sticky", "true")
	result := strings.TrimSpace(srv.processBatchRequest(state))
	upper := strings.ToUpper(result)
	if strings.HasPrefix(upper, "SAF_") || strings.HasPrefix(upper, "ERR-") || strings.HasPrefix(upper, "ERROR_") || upper == "CANCEL" {
		ui.SetStatus("Error procesando lote: " + result)
		return
	}

	if strings.TrimSpace(state.STServlet) != "" || strings.TrimSpace(state.RTServlet) != "" {
		if err := state.UploadResultData(result); err != nil {
			ui.SetStatus("Lote procesado, pero falló la subida del resultado: " + err.Error())
			return
		}
		ui.SetStatus("Lote procesado y resultado enviado correctamente.")
		go ui.closeProtocolWindowAfterDelay()
		return
	}

	ui.SetStatus("Lote procesado correctamente (sin subida remota requerida).")
}

func (ui *FyneUI) signCurrentProtocolCore(state *ProtocolState) {
	if state == nil {
		ui.SetStatus("Error protocolo: estado inválido.")
		return
	}
	if ui.SelectedCert == nil {
		ui.SetStatus("Seleccione un certificado para completar la operación.")
		return
	}

	format := normalizeProtocolFormat(state.SignFormat)
	if format == "" {
		format = detectLocalSignFormat(ui.InputFile)
	}
	action := normalizeProtocolAction(state.Action)
	if action == "" {
		action = "sign"
	}

	var stopWait chan struct{}
	if state.ActiveWaiting && strings.TrimSpace(state.STServlet) != "" && strings.TrimSpace(state.RequestID) != "" {
		stopWait = make(chan struct{})
		go func() {
			if err := state.SendWaitSignal(); err != nil {
				log.Printf("[FyneUI][Protocol] fallo WAIT inicial: %v", err)
			}
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopWait:
					return
				case <-ticker.C:
					if err := state.SendWaitSignal(); err != nil {
						log.Printf("[FyneUI][Protocol] fallo WAIT periódico: %v", err)
					}
				}
			}
		}()
	}
	defer func() {
		if stopWait != nil {
			close(stopWait)
		}
	}()

	req := CoreSignRequest{
		FilePath:         ui.InputFile,
		CertificateID:    ui.SelectedCert.ID,
		Action:           action,
		Format:           format,
		AllowInvalidPDF:  ui.AllowInvalidPDF,
		SaveToDisk:       false,
		OverwritePolicy:  CoreOverwriteRename,
		SignatureOptions: buildProtocolSignOptions(state, format),
	}
	if action == "sign" {
		choice, askErr := chooseActionForExistingSignedFile(ui.InputFile, format)
		if askErr != nil {
			log.Printf("[FyneUI][Protocol] confirm already-signed error: %v", askErr)
		} else if choice == existingSignedChoiceCancel {
			ui.SetStatus("Operación cancelada: el documento ya estaba firmado.")
			return
		} else if choice == existingSignedChoiceCoSign {
			action = "cosign"
			req.Action = "cosign"
			ui.SetStatus("Documento ya firmado detectado: se realizará cofirma.")
		} else if choice == existingSignedChoiceCounter {
			action = "countersign"
			req.Action = "countersign"
			ui.SetStatus("Documento ya firmado detectado: se realizará contrafirma.")
		}
	}
	res, err := ui.Core.SignFile(req)
	if err != nil {
		ui.SetStatus(withSolution(buildUserSignErrorMessage(err, format), "Revise formato, certificado y conectividad con la sede."))
		return
	}

	certB64 := base64.StdEncoding.EncodeToString(ui.SelectedCert.Content)
	hasLegacyUpload := strings.TrimSpace(state.STServlet) != "" || strings.TrimSpace(state.RTServlet) != ""
	if hasLegacyUpload {
		if err := state.UploadSignature(res.SignatureB64, certB64); err != nil {
			ui.SetStatus(withSolution(buildAfirmaUploadErrorMessage(err, state.STServlet, state.RTServlet), "Reintente y revise conectividad/TLS con la sede."))
			return
		}
		ui.SetStatus("Firma completada y enviada correctamente a la sede.")
		go ui.closeProtocolWindowAfterDelay()
		return
	}

	if action == "signandsave" {
		if err := ui.saveProtocolSignatureToDialog(state, res.SignatureB64, format); err != nil {
			ui.SetStatus("Firma realizada, pero no se pudo guardar: " + err.Error())
			return
		}
		ui.SetStatus("Firma y guardado completados correctamente.")
		return
	}

	ui.SetStatus("Firma protocolaria completada (sin subida remota).")
}

func (ui *FyneUI) saveProtocolSignatureToDialog(state *ProtocolState, signatureB64 string, format string) error {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("respuesta de firma inválida")
	}
	defaultName := strings.TrimSpace(getQueryParam(state.Params, "filename", "fileName"))
	if defaultName == "" {
		defaultName = "documento_firmado"
	}
	ext := strings.TrimPrefix(filepath.Ext(defaultName), ".")
	if ext == "" {
		switch strings.ToLower(strings.TrimSpace(format)) {
		case "xades":
			ext = "xsig"
		case "cades":
			ext = "csig"
		default:
			ext = "pdf"
		}
	}
	targetPath, err := buildSaveTargetPath(defaultName, ext)
	if err != nil {
		return err
	}
	selectedPath, canceled, err := protocolSaveDialog(targetPath, ext)
	if canceled {
		return fmt.Errorf("guardado cancelado")
	}
	if err != nil {
		return err
	}
	selectedPath = strings.TrimSpace(selectedPath)
	if selectedPath == "" {
		return fmt.Errorf("no se seleccionó ruta de guardado")
	}
	return os.WriteFile(selectedPath, data, 0o644)
}

func (ui *FyneUI) closeProtocolWindowAfterDelay() {
	time.Sleep(500 * time.Millisecond)
	fyne.Do(func() {
		ui.Window.Close()
	})
}

func (ui *FyneUI) runProtocolQuickSign(state *ProtocolState) {
	if err := ui.selectCertificateForProtocol(state); err != nil {
		if errors.Is(err, errProtocolUserCanceled) {
			ui.SetStatus("Operación cancelada por el usuario.")
			ui.notifyProtocolCancelAndClose(state, "sign")
			return
		}
		ui.SetStatus(err.Error())
		return
	}
	ui.signCurrentProtocolCore(state)
}

func (ui *FyneUI) runProtocolQuickLocalFileSign(state *ProtocolState) {
	if state == nil {
		ui.SetStatus("Error protocolo: estado inválido.")
		return
	}
	paths, canceled, err := protocolLoadDialog("", "pdf,xml,csig,sig", false)
	if canceled {
		ui.SetStatus("Operación cancelada por el usuario.")
		ui.notifyProtocolCancelAndClose(state, "sign")
		return
	}
	if err != nil {
		ui.SetStatus("Error seleccionando fichero local: " + err.Error())
		return
	}
	if len(paths) == 0 || strings.TrimSpace(paths[0]) == "" {
		ui.SetStatus("No se seleccionó fichero local.")
		return
	}
	ui.InputFile = strings.TrimSpace(paths[0])
	fyneSetFileLabel(ui, ui.InputFile)
	ui.SetStatus("Fichero local seleccionado. Seleccione certificado para continuar.")
	ui.runProtocolQuickSign(state)
}

func (ui *FyneUI) runProtocolQuickBatch(state *ProtocolState) {
	if err := ui.selectCertificateForProtocol(state); err != nil {
		if errors.Is(err, errProtocolUserCanceled) {
			ui.SetStatus("Operación cancelada por el usuario.")
			ui.notifyProtocolCancelAndClose(state, "batch")
			return
		}
		ui.SetStatus(err.Error())
		return
	}
	ui.handleProtocolBatchFyne()
}

func (ui *FyneUI) selectCertificateForProtocol(state *ProtocolState) error {
	if state == nil {
		return fmt.Errorf("error protocolo: estado inválido")
	}
	certs, err := loadCertificatesForState(state)
	if err != nil {
		return fmt.Errorf("error cargando certificados: %w", err)
	}
	filtered, _ := filterSelectCertByDefaultStore(certs, state)
	if len(filtered) == 0 {
		filtered = certs
	}
	if len(filtered) == 0 {
		return fmt.Errorf("no hay certificados disponibles para esta solicitud")
	}
	chosen, canceled, err := protocolSelectCertDialog(filtered)
	if canceled {
		return errProtocolUserCanceled
	}
	if err != nil {
		return fmt.Errorf("error en selector de certificado: %w", err)
	}
	if chosen < 0 || chosen >= len(filtered) {
		return fmt.Errorf("selección de certificado inválida")
	}

	chosenCert := filtered[chosen]
	// Reflejo de estado para operaciones posteriores (firma/batch).
	ui.SelectedCert = &chosenCert
	for i := range ui.Certs {
		if ui.Certs[i].ID == chosenCert.ID {
			ui.SelectedCert = &ui.Certs[i]
			break
		}
	}
	return nil
}

func (ui *FyneUI) notifyProtocolCancelAndClose(state *ProtocolState, action string) {
	if state == nil {
		go ui.closeProtocolWindowAfterDelay()
		return
	}

	if strings.TrimSpace(state.STServlet) != "" || strings.TrimSpace(state.RTServlet) != "" {
		if err := state.UploadResultData("CANCEL"); err != nil {
			log.Printf("[FyneUI][Protocol] no se pudo notificar cancelación (%s): %v", action, err)
		} else {
			log.Printf("[FyneUI][Protocol] cancelación notificada al servidor (%s).", action)
		}
	}
	go ui.closeProtocolWindowAfterDelay()
}

func fyneSetFileLabel(ui *FyneUI, path string) {
	fyne.Do(func() {
		if ui.InputFileEntry != nil {
			ui.InputFileEntry.SetText(path)
		}
		if ui.VerifyFileLabel != nil {
			ui.VerifyFileLabel.SetText(path)
		}
	})
}

func fyneRefreshCertCards(ui *FyneUI) {
	fyne.Do(func() {
		if ui.CertScroll != nil {
			ui.CertScroll.Content = ui.buildCertCards()
			ui.CertScroll.Refresh()
		}
	})
}
