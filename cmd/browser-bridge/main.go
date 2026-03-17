// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const signatureChunkSize = 512 * 1024

var chromiumIDPattern = regexp.MustCompile(`[a-p]{32}`)

type nativeAllowlist struct {
	ChromiumIDs []string `json:"chromium_ids"`
	FirefoxIDs  []string `json:"firefox_ids"`
	Require     bool     `json:"require_match"`
}

func main() {
	logPath, err := applog.Init("autofirma-host")
	if err != nil {
		log.Printf("No se pudo inicializar logging persistente: %v", err)
	} else {
		log.Printf("Logging inicializado en: %s", logPath)
	}

	if err := authorizeNativeCaller(os.Args[1:]); err != nil {
		log.Printf("[Host] Acceso denegado: %v", err)
		os.Exit(1)
	}

	log.Println("=== AutoFirma Native Host Iniciado ===")

	for {
		payload, err := readNativeMessage(os.Stdin)
		if err != nil {
			if err == io.EOF {
				log.Println("EOF recibido, saliendo")
				break
			}
			log.Printf("Error leyendo mensaje nativo: %v", err)
			break
		}
		log.Printf("[Host] Mensaje nativo recibido: %s", applog.BytesMeta("payload", payload))

		responses := handleMessage(payload)
		for _, resp := range responses {
			if err := writeNativeMessage(os.Stdout, resp); err != nil {
				log.Printf("Error escribiendo respuesta nativa: %v", err)
				return
			}
			// Reduce risk of buffering issues in browser pipe on very large responses.
			time.Sleep(25 * time.Millisecond)
		}
	}

	log.Println("=== AutoFirma Native Host Detenido ===")
}

func authorizeNativeCaller(args []string) error {
	allow, path, err := loadNativeAllowlist()
	if err != nil {
		return err
	}

	callers := extractCallerIDs(args)
	if len(callers) > 0 {
		log.Printf("[Host] Caller Native Messaging detectado: %v", callers)
	} else {
		log.Printf("[Host] Caller Native Messaging no detectado en argv")
	}

	if allow == nil {
		log.Printf("[Host] Allowlist no encontrada, se permite ejecución sin validación estricta")
		return nil
	}

	allowed := map[string]struct{}{}
	for _, id := range allow.ChromiumIDs {
		id = strings.TrimSpace(strings.ToLower(id))
		if id != "" {
			allowed[id] = struct{}{}
		}
	}
	for _, id := range allow.FirefoxIDs {
		id = strings.TrimSpace(strings.ToLower(id))
		if id != "" {
			allowed[id] = struct{}{}
		}
	}

	if len(allowed) == 0 {
		if allow.Require {
			return fmt.Errorf("allowlist activa en %s pero vacía", path)
		}
		log.Printf("[Host] Allowlist cargada desde %s sin IDs; modo permissivo", path)
		return nil
	}

	for _, caller := range callers {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(caller))]; ok {
			log.Printf("[Host] Caller autorizado por allowlist (%s): %s", path, caller)
			return nil
		}
	}

	if allow.Require {
		return fmt.Errorf("caller no autorizado por allowlist (%s)", path)
	}
	log.Printf("[Host] Caller no coincide con allowlist (%s), pero require_match=false", path)
	return nil
}

func loadNativeAllowlist() (*nativeAllowlist, string, error) {
	candidates := []string{}
	if env := strings.TrimSpace(os.Getenv("AUTOFIRMA_NATIVE_ALLOWLIST_FILE")); env != "" {
		candidates = append(candidates, env)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "native_messaging_allowlist.json"))
	}
	candidates = append(candidates,
		"/etc/autofirma-dipgra/native_messaging_allowlist.json",
		"/usr/local/etc/autofirma-dipgra/native_messaging_allowlist.json",
	)

	for _, path := range candidates {
		if strings.TrimSpace(path) == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, "", fmt.Errorf("no se pudo leer allowlist %s: %w", path, err)
		}
		var cfg nativeAllowlist
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, "", fmt.Errorf("allowlist inválida en %s: %w", path, err)
		}
		return &cfg, path, nil
	}
	return nil, "", nil
}

func extractCallerIDs(args []string) []string {
	ids := map[string]struct{}{}
	for _, raw := range args {
		a := strings.TrimSpace(raw)
		if a == "" {
			continue
		}
		la := strings.ToLower(a)
		if strings.HasPrefix(la, "--parent-window=") || la == "--parent-window" {
			continue
		}

		for _, m := range chromiumIDPattern.FindAllString(la, -1) {
			ids[m] = struct{}{}
		}

		// Firefox suele pasar IDs tipo "extension@dominio".
		if strings.Contains(a, "@") && !strings.Contains(a, "://") {
			ids[strings.ToLower(a)] = struct{}{}
		}
	}

	out := make([]string, 0, len(ids))
	for k := range ids {
		out = append(out, k)
	}
	return out
}

func readNativeMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeNativeMessage(w io.Writer, payload []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(payload))); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
	return nil
}

func normalizeRequestID(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func errorResponse(reqID, msg string) protocol.Response {
	return protocol.Response{
		RequestID: reqID,
		Success:   false,
		Error:     msg,
		Chunk:     0,
	}
}

func handleMessage(data []byte) [][]byte {
	var req protocol.Request
	if err := json.Unmarshal(data, &req); err != nil {
		log.Printf("[Host] Solicitud JSON inválida: %s err=%v", applog.BytesMeta("payload", data), err)
		resp := errorResponse("", "Formato de solicitud inválido")
		encoded, _ := json.Marshal(resp)
		return [][]byte{encoded}
	}

	reqID := normalizeRequestID(req.RequestID)
	log.Printf("[Host] Request: id=%s action=%s cert=%s format=%s pin_set=%t opts=%s data=%s orig=%s sig=%s",
		applog.MaskID(reqID),
		req.Action,
		applog.MaskID(req.CertificateID),
		req.Format,
		strings.TrimSpace(req.PIN) != "",
		applog.OptionKeys(req.SignatureOptions),
		applog.SecretMeta("data", req.Data),
		applog.SecretMeta("originalData", req.OriginalData),
		applog.SecretMeta("signatureData", req.SignatureData),
	)
	resp := protocol.Response{
		RequestID: reqID,
		Chunk:     0,
	}

	switch req.Action {
	case "ping":
		resp.Success = true

	case "getCertificates":
		certs, err := certstore.GetSystemCertificates()
		if err != nil {
			resp = errorResponse(reqID, err.Error())
			break
		}
		resp.Success = true
		resp.Certificates = certs

	case "sign":
		if req.Data == "" || req.CertificateID == "" {
			resp = errorResponse(reqID, "Faltan datos o certificateId")
			break
		}
		signature, err := signer.SignData(req.Data, req.CertificateID, req.PIN, req.Format, req.SignatureOptions)
		if err != nil {
			resp = errorResponse(reqID, err.Error())
			break
		}
		resp.Success = true
		resp.Signature = signature
		resp.SignatureLen = len(signature)

	case "verify":
		result, err := signer.VerifyData(req.OriginalData, req.SignatureData, req.Format)
		if err != nil {
			resp = errorResponse(reqID, err.Error())
			break
		}
		resp.Success = true
		resp.Result = result

	default:
		resp = errorResponse(reqID, "Acción desconocida: "+req.Action)
	}

	if len(resp.Signature) <= signatureChunkSize {
		encoded, _ := json.Marshal(resp)
		log.Printf("[Host] Response: id=%s action=%s success=%t err=%q certs=%d signature=%s chunking=single",
			applog.MaskID(reqID), req.Action, resp.Success, resp.Error, len(resp.Certificates),
			applog.SecretMeta("signature", resp.Signature))
		return [][]byte{encoded}
	}

	totalLen := len(resp.Signature)
	totalChunks := (totalLen + signatureChunkSize - 1) / signatureChunkSize
	log.Printf("[Host] Response chunking: id=%s action=%s success=%t total_signature_len=%d total_chunks=%d",
		applog.MaskID(reqID), req.Action, resp.Success, totalLen, totalChunks)
	parts := make([][]byte, 0, totalChunks)
	for i := 0; i < totalChunks; i++ {
		start := i * signatureChunkSize
		end := start + signatureChunkSize
		if end > totalLen {
			end = totalLen
		}

		chunkResp := resp
		chunkResp.Chunk = i
		chunkResp.TotalChunks = totalChunks
		chunkResp.Signature = resp.Signature[start:end]

		encoded, err := json.Marshal(chunkResp)
		if err != nil {
			fallback, _ := json.Marshal(errorResponse(reqID, "Error interno de fragmentación"))
			return [][]byte{fallback}
		}
		parts = append(parts, encoded)
	}
	return parts
}
