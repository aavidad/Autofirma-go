// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/signer"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type existingSignedActionChoice string

const (
	existingSignedChoiceContinue existingSignedActionChoice = "continue_sign"
	existingSignedChoiceCoSign   existingSignedActionChoice = "cosign"
	existingSignedChoiceCounter  existingSignedActionChoice = "countersign"
	existingSignedChoiceCancel   existingSignedActionChoice = "cancel"
)

func shouldConfirmAlreadySignedFile(filePath, format string) bool {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return false
	}
	effectiveFormat := normalizeProtocolFormat(format)
	if strings.TrimSpace(effectiveFormat) == "" || strings.EqualFold(strings.TrimSpace(effectiveFormat), "auto") {
		effectiveFormat = detectLocalSignFormat(filePath)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[SignGuard] No se pudo leer fichero para detectar firma previa: %v", err)
		return false
	}
	res, err := signer.VerifyData(base64.StdEncoding.EncodeToString(data), "", effectiveFormat)
	if err != nil || res == nil {
		if err != nil {
			log.Printf("[SignGuard] Verificación previa no concluyente file=%s format=%s err=%v", filepath.Base(filePath), effectiveFormat, err)
		}
		return false
	}
	log.Printf("[SignGuard] Documento ya firmado detectado file=%s format=%s valid=%t", filepath.Base(filePath), strings.TrimSpace(res.Format), res.Valid)
	return true
}

func confirmContinueSigningExistingFile(filePath, format string) (bool, error) {
	if !shouldConfirmAlreadySignedFile(filePath, format) {
		return true, nil
	}
	choice, err := protocolConfirmAlreadySignedActionDialog(filePath, format)
	if err != nil {
		return false, err
	}
	return choice != existingSignedChoiceCancel, nil
}

func chooseActionForExistingSignedFile(filePath, format string) (existingSignedActionChoice, error) {
	if !shouldConfirmAlreadySignedFile(filePath, format) {
		return existingSignedChoiceContinue, nil
	}
	return protocolConfirmAlreadySignedActionDialog(filePath, format)
}

func formatSignedDocHint(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "pades":
		return "El documento PDF ya parece firmado. Si quieres añadir otra firma, normalmente se usa cofirma."
	case "xades":
		return "El XML ya parece firmado. Si quieres añadir otra firma, normalmente se usa cofirma."
	case "cades":
		return "El fichero ya parece una firma CAdES. Firmarlo de nuevo puede fallar o requerir cofirma/contrafirma."
	default:
		return "El fichero ya parece firmado. Firmarlo de nuevo puede fallar o requerir cofirma/contrafirma."
	}
}

func signedDocDialogMessage(filePath, format string) string {
	base := filepath.Base(strings.TrimSpace(filePath))
	if base == "" {
		base = "documento"
	}
	return fmt.Sprintf("%s\n\nFichero: %s\n\nPuedes continuar, cofirmar (añadir firma), contrafirmar (firmar una firma existente) o cancelar.", formatSignedDocHint(format), base)
}
