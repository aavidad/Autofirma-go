// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CoreOverwritePolicy int

const (
	CoreOverwriteFail CoreOverwritePolicy = iota
	CoreOverwriteRename
	CoreOverwriteForce
)

type CoreSignRequest struct {
	FilePath         string
	OutputPath       string
	CertificateID    string
	Action           string
	Format           string
	AllowInvalidPDF  bool
	SaveToDisk       bool
	OverwritePolicy  CoreOverwritePolicy
	SignatureOptions map[string]interface{}
}

type CoreSignResult struct {
	Format       string
	SignatureB64 string
	OutputPath   string
	Renamed      bool
	Overwrote    bool
}

type CoreVerifyResult struct {
	Format string
	Result *protocol.VerifyResult
}

type CoreService struct{}

func NewCoreService() *CoreService {
	return &CoreService{}
}

func (s *CoreService) LoadCertificates() ([]protocol.Certificate, error) {
	return certstore.GetSystemCertificates()
}

func (s *CoreService) CheckCertificates(certs []protocol.Certificate) ([]protocol.Certificate, int, int) {
	probeB64 := base64.StdEncoding.EncodeToString([]byte("autofirma-cert-check"))
	okCount := 0
	failCount := 0
	out := make([]protocol.Certificate, len(certs))
	copy(out, certs)
	for i := range out {
		sigB64, err := signer.SignData(probeB64, out[i].ID, "", "cades", nil)
		if err != nil || strings.TrimSpace(sigB64) == "" {
			out[i].CanSign = false
			out[i].SignIssue = normalizeCheckIssue(err)
			failCount++
			continue
		}
		out[i].CanSign = true
		out[i].SignIssue = ""
		okCount++
	}
	return out, okCount, failCount
}

func (s *CoreService) SignFile(req CoreSignRequest) (*CoreSignResult, error) {
	filePath := strings.TrimSpace(req.FilePath)
	if filePath == "" {
		return nil, fmt.Errorf("no hay fichero seleccionado")
	}
	if strings.TrimSpace(req.CertificateID) == "" {
		return nil, fmt.Errorf("no hay certificado seleccionado")
	}
	if _, err := os.Stat(filePath); err != nil {
		return nil, fmt.Errorf("no se puede acceder al fichero: %w", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error leyendo archivo: %w", err)
	}
	dataB64 := base64.StdEncoding.EncodeToString(data)

	format := normalizeProtocolFormat(strings.TrimSpace(req.Format))
	if format == "" {
		format = detectLocalSignFormat(filePath)
	}
	if format == "pades" && !req.AllowInvalidPDF && isLikelyInvalidPDFForPades(filePath, format) {
		return nil, fmt.Errorf("el archivo no es un PDF válido para PAdES")
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "sign"
	}
	signatureB64, err := protocolSignOperation(action, dataB64, req.CertificateID, "", format, req.SignatureOptions)
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("error decodificando firma: %w", err)
	}

	result := &CoreSignResult{
		Format:       format,
		SignatureB64: signatureB64,
	}

	if !req.SaveToDisk {
		return result, nil
	}

	outPath := buildLocalSignedOutputPath(filePath, format)
	if strings.TrimSpace(req.OutputPath) != "" {
		outPath = req.OutputPath
	}
	outPath, renamed, overwrote, err := resolveOutputPathPolicy(outPath, req.OverwritePolicy)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outPath, signature, 0o644); err != nil {
		return nil, fmt.Errorf("error guardando fichero firmado: %w", err)
	}
	result.OutputPath = outPath
	result.Renamed = renamed
	result.Overwrote = overwrote
	return result, nil
}

func (s *CoreService) VerifyFile(filePath string, format string) (*CoreVerifyResult, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil, fmt.Errorf("no hay fichero seleccionado")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error leyendo archivo: %w", err)
	}
	dataB64 := base64.StdEncoding.EncodeToString(data)

	format = normalizeProtocolFormat(strings.TrimSpace(format))
	if format == "" {
		format = detectLocalSignFormat(filePath)
	}
	res, err := signer.VerifyData(dataB64, "", format)
	if err != nil {
		return nil, err
	}
	return &CoreVerifyResult{Format: format, Result: res}, nil
}

func detectLocalSignFormat(filePath string) string {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(filePath)))
	switch ext {
	case ".xml", ".xsig":
		return "xades"
	case ".csig", ".sig":
		return "cades"
	default:
		return "pades"
	}
}

func buildLocalSignedOutputPath(filePath string, format string) string {
	ext := filepath.Ext(filePath)
	base := strings.TrimSuffix(filePath, ext)
	outPath := base + "_firmado" + ext
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "cades":
		outPath = base + "_firmado.csig"
	case "xades":
		outPath = base + "_firmado.xsig"
	}
	return outPath
}

func resolveOutputPathPolicy(path string, policy CoreOverwritePolicy) (resolved string, renamed bool, overwrote bool, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, false, fmt.Errorf("ruta de salida vacía")
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return path, false, false, nil
		}
		return "", false, false, err
	}

	switch policy {
	case CoreOverwriteForce:
		return path, false, true, nil
	case CoreOverwriteRename:
		newPath, err := nextAvailableSignedPath(path)
		if err != nil {
			return "", false, false, err
		}
		return newPath, true, false, nil
	default:
		return "", false, false, fmt.Errorf("el fichero de salida ya existe")
	}
}

func nextAvailableSignedPath(path string) (string, error) {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; i <= 9999; i++ {
		candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(candidate); err != nil {
			if os.IsNotExist(err) {
				return candidate, nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("no se encontró nombre libre para guardar el fichero firmado")
}

func summarizeVerifyResult(v *protocol.VerifyResult) string {
	if v == nil {
		return "Resultado de verificación vacío."
	}
	if v.Valid {
		out := "✅ VÁLIDO"
		if strings.TrimSpace(v.SignerName) != "" {
			out += "\nFirmante: " + strings.TrimSpace(v.SignerName)
		}
		if strings.TrimSpace(v.SignerEmail) != "" {
			out += "\nEmail: " + strings.TrimSpace(v.SignerEmail)
		}
		if strings.TrimSpace(v.Timestamp) != "" {
			out += "\nFecha: " + strings.TrimSpace(v.Timestamp)
		}
		return out
	}
	reason := strings.TrimSpace(v.Reason)
	if reason == "" {
		reason = "firma no válida"
	}
	return "❌ INVÁLIDO\nRazón: " + reason
}

func humanDuration(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

func translateVerifyErrorToSpanish(err error) string {
	if err == nil {
		return ""
	}
	raw := strings.TrimSpace(err.Error())
	if raw == "" {
		return "error desconocido en verificación"
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "no digital signature in document"):
		return "el documento no contiene ninguna firma digital"
	case strings.Contains(lower, "invalid header"):
		return "la cabecera del fichero no es válida para el formato esperado"
	case strings.Contains(lower, "not a pdf"):
		return "el fichero no es un PDF válido"
	case strings.Contains(lower, "base64"):
		return "los datos de firma están codificados de forma inválida"
	default:
		return raw
	}
}
